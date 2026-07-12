import idc

from ida_kernelcache import consts, rtti
from ida_kernelcache.exceptions import PhaseException
from ida_kernelcache.ida_helpers import generators, functions, names, strings
import ida_xref
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
        self._mark_optimized_classes()
        self._collect_vtables_new()

        for vmethod_ea in self._not_functions_set:
            # TODO: resolve this!
            self.log.debug(f'The function boundaries of the vmethod at {vmethod_ea:#x} are wrong and I could not fix it automatically!')
        self.log.warning(f'There are {len(self._not_functions_set)} virtual methods with wrong function boundaries')

    def _handle_pure_virtual(self):
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
            self.log.error(f'Failed to change the function name at {cxa_pure_virtual_ea:#x} to {new_func_name}')

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
