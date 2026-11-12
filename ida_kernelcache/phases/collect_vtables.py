import idautils
import idc
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ua
import ida_xref

from ida_kernelcache import consts, rtti
from ida_kernelcache.exceptions import PhaseException
from ida_kernelcache.ida_helpers import decompiler, generators, functions, kcu, names, strings
from .base_phase import BasePhase


class CollectVtables(BasePhase):
    """
    This phase depends on the CollectClasses phase and must run after it.

    CollectClasses stores the address of every class vtable (as reported by `ipsw kernel cpp`) on
    ``KernelCache.metaclass_to_vtable_ea``. Here we walk each vtable to determine its length and build
    the VtableInfo / VtableEntry / VMethodInfo objects.
    """
    SENTINEL_MASK = 0xffffffffffff0000

    def __init__(self, kc):
        super().__init__(kc)

        # Vtables (by vtable_ea) that we have already associated with a class
        self._associated_vtables: set[int] = set()
        self._not_functions_set: set[int] = set()

    def run(self):
        if not self._kc.class_info_map:
            raise PhaseException(f"There are no entries in the KernelCache.classes dictionary.. consider running CollectClasses phase before {self.__class__}")

        self._handle_pure_virtual()
        if not self._kc.metaclass_to_vtable_ea:
            self._collect_vtable_addresses_native()
        self._mark_optimized_classes()
        self._collect_vtables_new()

        for vmethod_ea in self._not_functions_set:
            # TODO: resolve this!
            self.log.debug(f'The function boundaries of the vmethod at {vmethod_ea:#x} are wrong and I could not fix it automatically!')
        self.log.warning(f'There are {len(self._not_functions_set)} virtual methods with wrong function boundaries')

    def _handle_pure_virtual(self):
        # IDA 9.5 names the trap function itself. Fall back to the string xref.
        cxa_pure_virtual_ea = names.get_name_ea(consts.CXA_PURE_VIRTUAL)
        if cxa_pure_virtual_ea != idc.BADADDR:
            cxa_pure_virtual_ea = functions.get_func_start(cxa_pure_virtual_ea)
        else:
            str_ea = strings.find_str(consts.CXA_PURE_VIRTUAL).ea
            candidate = ida_xref.get_first_dref_to(str_ea)
            if candidate == idc.BADADDR:
                raise PhaseException(f'Could not find {consts.CXA_PURE_VIRTUAL} string reference!')

            if ida_xref.get_next_dref_to(str_ea, candidate) != idc.BADADDR:
                raise PhaseException(f'{consts.CXA_PURE_VIRTUAL} string has more than 1 xref!')

            cxa_pure_virtual_ea = functions.get_func_start(candidate)

        self.log.info(f'Found {consts.CXA_PURE_VIRTUAL} at {cxa_pure_virtual_ea:#x}')
        new_func_name = f'_{consts.CXA_PURE_VIRTUAL}'

        if not names.set_ea_name(cxa_pure_virtual_ea, new_func_name):
            self.log.debug(f'Could not rename {consts.CXA_PURE_VIRTUAL} at {cxa_pure_virtual_ea:#x}')

        # Store this information in the VtableInfo class, this will be used when constructing the VtableEntry instances
        rtti.VtableInfo.CXA_PURE_VIRTUAL_EA = cxa_pure_virtual_ea

    def _mark_optimized_classes(self):
        """
        Classes that ipsw did not associate with a vtable are marked as "optimized". They may still
        appear in the inheritance tree as intermediate classes but they have no vtable of their own
        (the compiler didn't emit one, usually because the class overrides nothing).
        """
        num_optimized = 0
        for class_info in self._kc.class_info_map.values():
            if class_info.metaclass_ea not in self._kc.metaclass_to_vtable_ea:
                class_info.optimized = True
                num_optimized += 1
                self.log.debug(f'Marked {class_info.class_name} metaclass_ea:{class_info.metaclass_ea:#x} as optimized without a vtable')
        self.log.info(f'Marked {num_optimized}/{len(self._kc.class_info_map)} classes as optimized (no vtable)')

    def _collect_vtable_addresses_native(self):
        """
        Fill ``metaclass_to_vtable_ea`` without ipsw.

        Every class has a ``::getMetaClass`` method that returns its metaclass. That
        method appears once in the class vtable, at index 7. Find the method, then the
        single ``__const`` data reference to it, and derive the first slot.
        """
        self.log.info('No vtable addresses from ipsw; locating them through ::getMetaClass references')
        num_found = 0
        num_missing = 0
        for metaclass_ea, class_info in self._kc.class_info_map.items_by_type(key_type=int):
            getmetaclass_ea = self._find_getmetaclass_method(metaclass_ea)
            if getmetaclass_ea == idc.BADADDR:
                num_missing += 1
                self.log.debug(f'Could not find {class_info.class_name}::getMetaClass')
                continue

            candidates = list(generators.DataRefsToWithSegmentFilter(getmetaclass_ea, r'.*__const$'))
            if len(candidates) != 1:
                num_missing += 1
                self.log.debug(f'{class_info.class_name}::getMetaClass has {len(candidates)} const xrefs')
                continue

            start_ea = self._vtable_start_from_slot(candidates[0], metaclass_ea)
            self._kc.metaclass_to_vtable_ea[metaclass_ea] = start_ea
            self.log.debug(f'{class_info.class_name} vtable first slot {start_ea:#x}')
            num_found += 1

        self.log.info(f'Located {num_found} vtables through ::getMetaClass, {num_missing} classes without one')
        if not num_found:
            raise PhaseException('Could not locate any vtable; install ipsw for the class/vtable graph')

    @staticmethod
    def _is_vtable_header(header_ea: int) -> bool:
        if header_ea < 0:
            return False
        first = ida_bytes.get_qword(header_ea)
        second = ida_bytes.get_qword(header_ea + 8)
        return first == 0 and second == 0

    def _vtable_start_from_slot(self, slot_ea: int, metaclass_ea: int) -> int:
        """
        Resolve the data reference to the vtable's first slot.

        Normally the reference points at ``getMetaClass`` (slot 7), but IDA may also
        pick a slot-0 thunk that references the metaclass. Check the 16-byte header
        before and after the two candidate positions.
        """
        # The reference is already slot 0.
        if self._is_vtable_header(slot_ea - consts.VTABLE_FIRST_METHOD_OFFSET):
            return slot_ea

        # The reference is slot 7 (getMetaClass); first slot is 56 bytes lower.
        start_ea = slot_ea - consts.VTABLE_GETMETACLASS_OFFSET + consts.VTABLE_FIRST_METHOD_OFFSET
        if self._is_vtable_header(start_ea - consts.VTABLE_FIRST_METHOD_OFFSET):
            return start_ea

        self.log.warning(f'Vtable header not found for metaclass {metaclass_ea:#x}; '
                         f'using first-slot estimate {start_ea:#x}')
        return start_ea

    def _find_getmetaclass_method(self, metaclass_ea: int) -> int:
        candidates: set[int] = set()
        for xref_ea in idautils.DataRefsTo(metaclass_ea):
            func = ida_funcs.get_func(xref_ea)
            if func is None or func.size() > 0x20:
                continue
            func_start = func.start_ea
            if self._is_getmetaclass_method(func_start, metaclass_ea):
                candidates.add(func_start)
            elif self._is_getmetaclass_method_fallback(func_start, metaclass_ea):
                candidates.add(func_start)

        if len(candidates) == 1:
            return candidates.pop()
        return idc.BADADDR

    @staticmethod
    def _is_getmetaclass_method(func_ea: int, metaclass_ea: int) -> bool:
        cfunc = ida_hexrays.decompile(func_ea)
        if cfunc is None:
            return False
        root = cfunc.body
        if root.op != ida_hexrays.cit_block or len(root.cblock) != 1:
            return False
        statement = root.cblock[0]
        if statement.op != ida_hexrays.cit_return:
            return False
        expr = decompiler.traverse_casts_or_ref_branch(statement.creturn.expr)
        return expr.op == ida_hexrays.cot_obj and expr.obj_ea == metaclass_ea

    def _is_getmetaclass_method_fallback(self, func_ea: int, metaclass_ea: int) -> bool:
        """
        Every ::getMetaClass looks like:
            BTI c
            ADRL X0, metaclass_ea
            RET
        """
        mnemonics = ['BTI', 'ADRL', 'RET']
        x0_index = idautils.GetRegisterList().index('X0')
        for mnemonic, insn in zip(mnemonics, generators.Instructions(func_ea, count=3)):
            if mnemonic != insn.get_canon_mnem():
                return False
            if mnemonic == 'BTI':
                if insn.Op1.value != 0x63:
                    return False
            elif mnemonic == 'ADRL':
                if insn.Op1.reg != x0_index or insn.Op2.value != metaclass_ea:
                    return False
        return True

    def _collect_vtables_new(self):
        """
        Iterate the ClassInfo objects top down using BFS and build the VtableInfo for every class that
        ipsw reported a vtable for. ipsw's VtableAddr points at the first virtual method, so the
        plugin's vtable_ea (offset 0, the two leading NULL words) is VtableAddr minus the header.
        """
        num_with_sentinel = 0

        for class_info in self._kc.class_info_map.bfs(must_have_vtable=False):

            # Skip optimized classes that have no vtable
            if class_info.optimized:
                continue

            # ipsw's VtableAddr == plugin's start_ea (first vmethod)
            vtable_start_ea = self._kc.metaclass_to_vtable_ea[class_info.metaclass_ea]
            kcu.ensure_kext_loaded_for_ea(vtable_start_ea)
            vtable_ea = vtable_start_ea - consts.VTABLE_FIRST_METHOD_OFFSET

            if vtable_ea in self._associated_vtables:
                raise PhaseException(f'Vtable {vtable_ea:#x} is already associated with some other class!')
            self._associated_vtables.add(vtable_ea)

            # Walk the vtable from its first method to determine its length
            num_vtable_methods = 0
            has_sentinel = False

            for vmethod_ea in generators.ReadWords(vtable_start_ea, idc.get_segm_end(vtable_ea)):
                # Stop on the first NULL
                if not vmethod_ea:
                    break

                if vmethod_ea & self.SENTINEL_MASK == self.SENTINEL_MASK:
                    # TODO: is this virtual inheritance? If so, how do we parse it?
                    num_with_sentinel += 1
                    self.log.debug(f'{vtable_ea:#x} vtable for {class_info.class_name:50s} Found sentinel! {vmethod_ea:#x}')
                    has_sentinel = True
                    break

                # If this happens this is probably because IDA auto-analysis failed to determine function boundaries correctly
                if functions.get_func_start(vmethod_ea, raise_error=False) != vmethod_ea:
                    # TODO: Rework the force function implementation
                    if functions.force_function(vmethod_ea):
                        self.log.debug(f'Fixed function boundaries at {vmethod_ea:#x}')
                    else:
                        # TODO: solve this by fixing the __noreturn attribute missing from panic functions upon initial analysis
                        self._not_functions_set.add(vmethod_ea)

                num_vtable_methods += 1

            vtable_end_ea = vtable_start_ea + num_vtable_methods * consts.WORD_SIZE
            self.log.debug(f'Found vtable of {class_info.class_name} {vtable_ea:#x}-{vtable_end_ea:#x} num methods:{num_vtable_methods}')

            vtable_info = rtti.VtableInfo(vtable_ea, vtable_end_ea, has_sentinel)
            class_info.vtable_info = vtable_info
            vtable_info.class_info = class_info

            # Now we maintain the VMethodsInfoMap which is a central storage that contains a unique instance of VMethodInfo for every vmethod_ea we encounter.
            # It is important to have unique references to vmethods because on later phases, We process the vtable entries for symbolication.
            # We can encounter the same vmethod in multiple vtable entries and want to have a single source of truth that holds the information that is specific to the vmethod,  e.g. the symbol for that vmethod.
            # For every vmethod_ea we encounter for the first time a new VMethodInfo instance is created.
            # Every VMethodInfo object is associated with the VtableEntry object that contains it and vice versa.
            # Ideally, we would be able to this while constructing the VtableEntry objects in inside the VtableInfo class.
            # However, the entries of a VtableInfo instance are built lazily, upon first access, (and cached in an internal list).
            # Modifying the VMethodsInfo map from that context would require passing a reference to the RTTIDatabase or storing it as global which both are a worse design in my opinion.
            for vtable_entry in vtable_info.entries:
                self._kc.vmethod_info_map.add_relation(vtable_entry)

        if num_with_sentinel:
            self.log.warning(f'{num_with_sentinel} classes are possibly subject to multiple inheritance, which we do not support yet!')
