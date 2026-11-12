"""
Collect C++ class / metaclass information from a kernelcache.

Useful references:

- https://developer.apple.com/documentation/kernel/osmetaclassbase
- https://developer.apple.com/library/archive/documentation/DeviceDrivers/Conceptual/WritingDeviceDriver/CPluPlusRuntime/CPlusPlusRuntime.html

Historically this phase reconstructed the RTTI graph by locating OSMetaClass::OSMetaClass and
inspecting the Hex-Rays ctree of every call site. That approach kept breaking whenever Apple shipped
a kernel that IDA's ARM64 decompiler couldn't fully digest. We now delegate class discovery to
`ipsw kernel cpp --json`, which parses the kernelcache directly and hands us the complete class
graph (see ida_kernelcache.ida_helpers.ipsw).
"""
import collections
import re

import idautils
import idc
import ida_hexrays
import ida_xref

from .base_phase import BasePhase
from ida_kernelcache import rtti
from ida_kernelcache.exceptions import PhaseException
from ida_kernelcache.utils import OneToOneMapFactory
from ida_kernelcache.ida_helpers import decompiler, functions, ipsw, names, strings


class CollectClasses(BasePhase):
    """
    Collect information about C++ classes defined in a kernelcache. Arm64 only.

    Populates the KernelCache's class_info_map, which maps the C++ class names and metaclass eas to a
    ClassInfo object containing meta-information about the class. The class vtable addresses reported
    by ipsw are stashed on ``KernelCache.metaclass_to_vtable_ea`` for the CollectVtables phase.

    Every run of this phase clears the class_info_map and re-evaluates it.
    """
    CLASS_BLACKLIST = ['AppleBasebandPCIMessageQueueBase']
    TEMPLATE_BLACKLIST = ['OSValueObject']  # TODO: handling templates in name mangling has to be done first

    def __init__(self, kc):
        super().__init__(kc)

        # Collect associations from class names to metaclass instances and vice versa.
        self._metaclass_to_classname_builder = OneToOneMapFactory()
        # metaclass_ea -> address of the MetaClass helper vtable, when the source provides it
        self._metaclass_to_metavtable_ea: dict[int, int] = {}
        self._metaclass_to_class_size = {}
        self._metaclass_to_super_metaclass = {}
        self._blacklisted: set[str] = set()

        # Statistics
        self._num_succeeded = 0
        self._num_dropped_in_one_to_one_map = 0

    def run(self):
        # Clear out old class information
        self._kc.class_info_map.clear()
        self._kc.metaclass_to_vtable_ea.clear()
        self._kc.metaclass_to_metavtable_ea.clear()

        try:
            self._load_from_ipsw()
            self._source = 'ipsw'
        except PhaseException as ex:
            self.log.warning(f'ipsw class graph unavailable ({ex}); falling back to native RTTI decoding')
            self._load_from_native()
            self._source = 'native'

        self._populate_class_info_map()
        self._kc.metaclass_to_metavtable_ea.update(self._metaclass_to_metavtable_ea)

        # Print statistics
        self.log.info(f'Collection stats:\n'
                      f'* classes from {self._source}:{self._num_succeeded}\n'
                      f'* dropped in one-to-one map:{self._num_dropped_in_one_to_one_map}\n'
                      f'* blacklisted:{len(self._blacklisted)}\n'
                      f'* classes:{len(self._kc.class_info_map)}\n')

    def _load_from_ipsw(self):
        """
        Run `ipsw kernel cpp --json` and load the discovered class graph into the intermediate maps
        that _populate_class_info_map() consumes.
        """
        classes = ipsw.run_kernel_cpp()
        self.log.info(f'ipsw reported {len(classes)} classes')

        for entry in classes:
            class_name = entry['Name']
            metaclass_ea = entry['MetaPtr']
            class_size = entry['Size']
            super_metaclass_ea = entry['SuperMeta']
            vtable_addr = entry['VtableAddr']
            metavtable_addr = entry.get('MetaVtableAddr', 0)

            if not metaclass_ea:
                self.log.warning(f'Skipping {class_name}: ipsw reported a null MetaPtr')
                continue

            self._metaclass_to_classname_builder.add_link(metaclass_ea, class_name)
            self._metaclass_to_class_size[metaclass_ea] = class_size

            # Only store information for non-null super metaclasses (root classes have SuperMeta == 0)
            if super_metaclass_ea:
                self._metaclass_to_super_metaclass[metaclass_ea] = super_metaclass_ea

            # ipsw's VtableAddr points at the first vmethod. Classes without a vtable (== 0) are
            # "optimized" and are handled as such by CollectVtables.
            if vtable_addr:
                self._kc.metaclass_to_vtable_ea[metaclass_ea] = vtable_addr

            if metavtable_addr:
                self._metaclass_to_metavtable_ea[metaclass_ea] = metavtable_addr

            self._num_succeeded += 1

    def _load_from_native(self):
        """
        Fallback when `ipsw` is not available.

        Decode every call to OSMetaClass::OSMetaClass and read its four arguments from
        the Hex-Rays ctree. KEXTs call the constructor through a `j_` auth stub, so
        follow one stub level.
        """
        ctor_ea = self._find_osmetaclass_constructor()
        self._var_expr_errors: dict[str, set[int]] = collections.defaultdict(set)
        # callsite_ea -> the callee the call targets (the constructor or its auth stub)
        callsites: dict[int, int] = {}

        for xref_ea in idautils.CodeRefsTo(ctor_ea, flow=False):
            func_ea = functions.get_func_start(xref_ea, raise_error=False)
            if func_ea != idc.BADADDR and self._is_auth_stub(func_ea):
                for stub_xref in idautils.CodeRefsTo(func_ea, flow=False):
                    callsites[stub_xref] = func_ea
            else:
                callsites[xref_ea] = ctor_ea

        # KEXTs call the constructor through their own auth stub, which does not
        # reference the constructor directly. Walk every OSMetaClass stub.
        for func_ea in idautils.Functions():
            name = idc.get_func_name(func_ea)
            if name.startswith('j_') and 'OSMetaClassC2E' in name:
                for stub_xref in idautils.CodeRefsTo(func_ea, flow=False):
                    callsites[stub_xref] = func_ea

        for callsite_ea, callee_ea in sorted(callsites.items()):
            try:
                if self._handle_callsite(callee_ea, callsite_ea):
                    self._num_succeeded += 1
            except Exception as ex:
                self.log.debug(f'Failed to decode OSMetaClass call at {callsite_ea:#x}: {ex}')

        for classname, eas in self._var_expr_errors.items():
            if classname not in self._kc.class_info_map and classname not in self._blacklisted:
                self.log.debug(f'Unresolved class {classname} at {", ".join(f"{ea:#x}" for ea in eas)}')

        self.log.info(f'Native RTTI decoding: {self._num_succeeded} classes from {len(callsites)} call sites')

    @staticmethod
    def _is_auth_stub(func_ea: int) -> bool:
        return idc.get_func_name(func_ea).startswith('j_')

    def _find_osmetaclass_constructor(self) -> int:
        """Locate OSMetaClass::OSMetaClass by symbol, or by the first reference to "OSObject"."""
        for candidate in ('__ZN11OSMetaClassC2EPKcPKS_j', '_ZN11OSMetaClassC2EPKcPKS_j'):
            ea = names.get_name_ea(candidate)
            if ea != idc.BADADDR:
                return functions.get_func_start(ea)

        osobject_str_ea = strings.find_str('OSObject').ea
        xref_ea = ida_xref.get_first_dref_to(osobject_str_ea)
        if xref_ea != idc.BADADDR:
            cfunc = ida_hexrays.decompile(xref_ea)
            if cfunc is not None:
                visitor = decompiler.FindCallByArgVisitor(osobject_str_ea)
                visitor.apply_to(cfunc.body, parent=None)
                if visitor.found:
                    return visitor.func_ea

        raise PhaseException('Could not locate OSMetaClass::OSMetaClass; install ipsw or fix symbols')

    def _handle_callsite(self, ctor_ea: int, callsite_ea: int) -> bool:
        args_ops = [
            (ida_hexrays.cot_cast, ida_hexrays.cot_ref, ida_hexrays.cot_var, ida_hexrays.cot_obj),
            (ida_hexrays.cot_obj,),
            (ida_hexrays.cot_cast, ida_hexrays.cot_ref, ida_hexrays.cot_num, ida_hexrays.cot_obj),
            (ida_hexrays.cot_num,)
        ]

        visitor = decompiler.FindCallVisitor(ctor_ea, callsite_ea, args_ops)
        cfunc = ida_hexrays.decompile(callsite_ea)
        if cfunc is None:
            return False
        visitor.apply_to(cfunc.body, parent=None)
        if not visitor.found or not visitor.passed_ops_validation:
            return False

        classname_ea = visitor.args[1].obj_ea
        classname = idc.get_strlit_contents(classname_ea)
        if not classname:
            return False
        classname_str = classname.decode(errors='replace')

        metaclass_arg = decompiler.traverse_casts_or_ref_branch(visitor.args[0])
        if metaclass_arg.op == ida_hexrays.cot_var:
            self._var_expr_errors[classname_str].add(callsite_ea)
            return False
        if metaclass_arg.op != ida_hexrays.cot_obj:
            return False
        metaclass_ea = metaclass_arg.obj_ea

        super_arg = decompiler.traverse_casts_or_ref_branch(visitor.args[2])
        if super_arg.op == ida_hexrays.cot_num and not super_arg.numval():
            super_metaclass_ea = 0
        elif super_arg.op == ida_hexrays.cot_obj:
            super_metaclass_ea = super_arg.obj_ea
        else:
            return False

        class_size = visitor.args[3].numval()
        self._metaclass_to_classname_builder.add_link(metaclass_ea, classname_str)
        self._metaclass_to_class_size[metaclass_ea] = class_size
        if super_metaclass_ea:
            self._metaclass_to_super_metaclass[metaclass_ea] = super_metaclass_ea
        self.log.debug(f'Found metaclass info for {classname_str} at {callsite_ea:#x}')
        return True

    def _populate_class_info_map(self):
        """
        We are going to reconstruct the inheritance tree, creating a ClassInfo instance for every class
        and connecting the nodes in the tree according to their relationship.

        Each new instance of ClassInfo will be added to the ClassInfoMap object which indexes it both by
        the classname and the metaclass_ea (each of which should be a unique identifier of this class in the current database)
        """

        # Filter out any class name (and its associated metaclasses) that has multiple metaclasses.
        # This can happen when multiple kexts define a class but only one gets loaded.
        def bad_classname(classname, metaclasses):
            self.log.warning(f'Class {classname} has multiple metaclasses: {", ".join(["{:#x}".format(mc) for mc in metaclasses])}')

        # Filter out any metaclass (and its associated class names) that has multiple class names. I
        # have no idea why this would happen.
        def bad_metaclass(metaclass, classnames):
            self.log.warning(f'Metaclass {metaclass:#x} has multiple classes: {", ".join(classnames)}')

        # Build a one-to-one mapping of metaclass_ea <--> class_name
        one_to_one_map = self._metaclass_to_classname_builder.build(bad_metaclass, bad_classname)
        self._num_dropped_in_one_to_one_map = self._num_succeeded - len(one_to_one_map)

        # Start one iteration by creating every ClassInfo instance for every discovered class
        for metaclass_ea, class_name in one_to_one_map.items():
            if any(class_name.startswith(prefix) for prefix in self.TEMPLATE_BLACKLIST):
                self.log.info(f'Skipping {class_name} because it is in the template blacklist..')
                self._blacklisted.add(class_name)
                continue

            if class_name in self.CLASS_BLACKLIST:
                self.log.info(f'Skipping {class_name} because it is in the class blacklist..')
                self._blacklisted.add(class_name)
                continue

            class_info = rtti.ClassInfo(class_name,
                                        metaclass_ea,
                                        self._metaclass_to_class_size[metaclass_ea])

            self._kc.class_info_map.add_classinfo(class_info)

        for metaclass_ea, class_name, class_info in self._kc.class_info_map.items():

            # The root classes are those that do not have any superclass
            if metaclass_ea not in self._metaclass_to_super_metaclass:
                continue

            super_metaclass_ea = self._metaclass_to_super_metaclass[metaclass_ea]

            # For subclasses make sure that we haven't dropped the superclass in the one-to-one map building process
            if super_metaclass_ea not in one_to_one_map:
                self.log.warning(f'Superclass {super_metaclass_ea:#x} of {class_name} was dropped from the '
                                 f'one-to-one map; treating {class_name} as a root class')
                continue

            superclass_info = self._kc.class_info_map[super_metaclass_ea]

            # Create parent-child link
            self.log.debug(f'{superclass_info.class_name} ===> {class_info.class_name}')
            class_info.superclass = superclass_info
            superclass_info.subclasses.add(class_info)
