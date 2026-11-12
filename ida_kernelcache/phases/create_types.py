"""
Refer to: https://docs.hex-rays.com/user-guide/user-interface/menu-bar/view/c++-type-details
This is why I set the EA as struct member comments: https://hex-rays.com/blog/igor-tip-of-the-week-15-comments-in-structures-and-enums
"""
import re

import ida_typeinf
import idc

from ida_kernelcache import consts, symbols
from ida_kernelcache.exceptions import FailedToCreateTypeError, PhaseException
from ida_kernelcache.ida_helpers import functions, kcu, types

from .base_phase import BasePhase

# A C struct member must be a plain identifier. Demangled C++ method names can be operators or
# destructors (e.g. 'operator new', '~OSObject') which are not valid identifiers.
_VALID_C_IDENTIFIER = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


class CreateTypes(BasePhase):
    """
    Using the classes and vtables data from previous phases, the CreateTypes phase will define local types in the IDB.
    The struct definitions should represent the inheritance relationship between the classes
    This phase was improved to support the c++ objects support that was added in IDA 7.2, in particular the __cppobj
    attribute and the special _vtbl_layout suffix.

    In IDA a cpp structure has the TAUDT_CPPOBJ flag set in its udt_type_data_t object.
    Inheritance is achieved through a special member which is udm_t that is marked as baseclass at offset 0
    """
    def __init__(self, kc):
        super().__init__(kc)

    def run(self):
        self._create_types_bfs()

    def _create_types_bfs(self):
        """
        Do a breadth first scan. The inheritance relationship is a directed acyclic graph.

        Existing types are merged, not overwritten:
        - a real C++ class type from IDA's type library is kept as is;
        - a flat ``kalloc_type`` struct is rebuilt with its base class;
        - an existing vtable type is kept as is.
        """
        num_created = 0
        num_rebuilt = 0
        num_kept = 0
        num_vtbl_created = 0
        num_vtbl_kept = 0
        func_name_conflicts = 0
        failures = []

        for class_info in self._kc.class_info_map.bfs(must_have_vtable=False):

            # IDA recovers OSMetaClass itself and its layout is not a normal class.
            if class_info.class_name == 'OSMetaClass':
                continue

            try:
                if class_info.class_size % consts.WORD_SIZE:
                    raise PhaseException(f'size {class_info.class_size:#x} is not word aligned')

                action = self._ensure_class_type(class_info)
                if action == 'created':
                    num_created += 1
                elif action == 'rebuilt':
                    num_rebuilt += 1
                else:
                    num_kept += 1

                if not class_info.optimized:
                    vtbl_type_name = self._vtbl_type_name(class_info)
                    if types.get_udt_info(vtbl_type_name) is None:
                        func_name_conflicts += self._create_vtable_type(class_info)
                        num_vtbl_created += 1
                    else:
                        num_vtbl_kept += 1
                    # IDA's own pass types the data at the first slot. Do the same so
                    # the listing and the decompiler see the slot signatures.
                    kcu.ensure_kext_loaded_for_ea(class_info.vtable_info.start_ea)
                    if idc.get_type(class_info.vtable_info.start_ea) is None:
                        types.apply_type_at(class_info.vtable_info.start_ea, vtbl_type_name)
                    self._set_root_vftable_type(class_info)
            except Exception as ex:
                failures.append((class_info.class_name, str(ex)))
                self.log.error(f'Failed to create types for {class_info.class_name}: {ex}')

        self.log.info(f'{num_created} class types created, {num_rebuilt} rebuilt, {num_kept} kept')
        self.log.info(f'{num_vtbl_created} vtable types created, {num_vtbl_kept} kept')
        self.log.info(f'{func_name_conflicts} function name conflicts!')
        if failures:
            self.log.warning(f'{len(failures)} classes failed: '
                             + ', '.join(name for name, _ in failures[:20])
                             + (' ...' if len(failures) > 20 else ''))

    @staticmethod
    def _vtbl_type_name(class_info) -> str:
        return f'{class_info.class_name}_vtbl'

    def _create_vtable_type(self, class_info) -> int:
        """
        Create a flat vtable type for the class. Returns the number of member name conflicts.

        IDA and the C++ ABI both treat a vtable as a flat run of slots at the first
        method address. Do not inherit vtable types from each other.
        """
        func_names: set[str] = set()
        func_decls = []
        conflicts = 0

        for vtable_entry in class_info.vtable_info.entries:
            func_name = consts.VMETHOD_NAME_TEMPLATE.format(index=vtable_entry.index)

            if not vtable_entry.pure_virtual and vtable_entry.vmethod_info.mangled_symbol:
                try:
                    extracted = symbols.extract_method_name(vtable_entry.vmethod_info.mangled_symbol)
                except Exception:
                    extracted = vtable_entry.vmethod_info.mangled_symbol

                # Demangled names can be operators or destructors (e.g. 'operator new',
                # '~OSObject') which are not valid C struct member identifiers.
                if _VALID_C_IDENTIFIER.match(extracted):
                    func_name = extracted
                else:
                    self.log.debug(f'{class_info.class_name} vmethod {vtable_entry.index} has non-identifier '
                                   f'name {extracted!r}; falling back to {func_name}')

            # IDA fails to parse a vtable declaration with two members of the same name.
            if func_name in func_names:
                conflicts += 1
                func_name = consts.VMETHOD_NAME_TEMPLATE.format(index=vtable_entry.index)

            func_names.add(func_name)
            func_sig = self._slot_signature(class_info, vtable_entry)
            func_decls.append(consts.VIRTUAL_FUNC_TEMPLATE.format(
                func_name=func_name,
                func_sig=func_sig,
                vmethod_ea=vtable_entry.vmethod_ea))
            self._apply_slot_prototype(vtable_entry, func_sig)

        vtbl_type_name = self._vtbl_type_name(class_info)
        vtbl_type_decl = consts.VTABLE_DECL_TEMPLATE.format(
            vtable_ea=class_info.vtable_info.start_ea,
            class_name=class_info.class_name,
            virtual_funcs=consts.FIELD_SEP.join(func_decls),
        )
        self._create_type_from_decl(class_info, vtbl_type_decl)

        vtable_local_type = types.LocalType(vtbl_type_name)
        vtable_local_type.udt.set_vftable(True)
        # IDA stores the vftable EA at the first slot, not at the 16-byte header.
        ida_typeinf.set_vftable_ea(vtable_local_type.ordinal, class_info.vtable_info.start_ea)
        self.log.debug(f'Created vtable type for {class_info.class_name}! ordinal: {vtable_local_type.ordinal}')
        return conflicts

    @staticmethod
    def _slot_signature(class_info, vtable_entry) -> str:
        """Build the slot signature, adding real arguments from the mangled symbol."""
        func_sig = f'{class_info.class_name} *self'
        mangled = vtable_entry.vmethod_info.mangled_symbol if vtable_entry.vmethod_info else None
        if not mangled:
            return func_sig
        try:
            extra_args = symbols.method_arguments_string(mangled)
        except Exception:
            return func_sig
        if extra_args and extra_args != 'void':
            extra_args = re.sub(r'(?<=[\w>])([*&])', r' \1', extra_args)
            return f'{func_sig}, {extra_args}'
        return func_sig

    @staticmethod
    def _apply_slot_prototype(vtable_entry, func_sig: str) -> None:
        """Type the function's ``this`` and arguments from the vtable slot."""
        if not vtable_entry.vmethod_info or not vtable_entry.vmethod_info.mangled_symbol:
            return
        # Inherited slots point at the base method; do not retype it with this class.
        if vtable_entry.inherited or vtable_entry.pure_virtual:
            return
        if vtable_entry.vmethod_info.owning_vtable_entry is not vtable_entry:
            return
        ea = vtable_entry.vmethod_ea
        if not functions.is_function_start(ea):
            return
        tif = ida_typeinf.tinfo_t()
        decl = f'__int64 __fastcall prot({func_sig});'
        # parse_decl may return an error string even when it built a usable type.
        ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL)
        if not tif.empty():
            ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)

    def _ensure_class_type(self, class_info) -> str:
        """Create, rebuild or keep the class type. Returns 'created', 'rebuilt' or 'kept'."""
        existing = types.get_udt_info(class_info.class_name)

        if existing is not None:
            # A real C++ type from IDA's type library is authoritative. IDA itself
            # keeps the type library layout when it differs from the allocation size.
            if existing.is_cppobj and (existing.base_type or not class_info.is_subclass()):
                if existing.size != class_info.class_size:
                    self.log.warning(f'{class_info.class_name} type size {existing.size:#x} != '
                                     f'metaclass size {class_info.class_size:#x}; keeping the type')
                return 'kept'

        class_type_decl = self._class_type_decl(class_info)
        self._create_type_from_decl(class_info, class_type_decl, replace=existing is not None)
        return 'rebuilt' if existing is not None else 'created'

    def _class_type_decl(self, class_info) -> str:
        field_decls = []

        if class_info.is_subclass():
            superclass_name = f': {class_info.superclass.class_name}'
        else:
            superclass_name = ''
            # The vtable type is created after the class type; point at it later.
            field_decls.append(consts.VPTR_FIELD)

        field_decls.extend(self._data_field_decls(class_info))

        return consts.CPPOBJ_DECL_TEMPLATE.format(
            metaclass_ea=class_info.metaclass_ea,
            class_name=class_info.class_name,
            superclass_name=superclass_name,
            data_fields=consts.FIELD_SEP.join(field_decls)
        )

    def _set_root_vftable_type(self, class_info) -> None:
        """Give the root class's ``__vftable`` the vtable pointer type."""
        if class_info.is_subclass():
            return
        vtbl_type_name = self._vtbl_type_name(class_info)
        try:
            local_type = types.LocalType(class_info.class_name)
            local_type.set_member_type(0, f'{vtbl_type_name} *')
        except Exception as ex:
            self.log.debug(f'Could not retype {class_info.class_name}.__vftable: {ex}')

    def _data_field_decls(self, class_info) -> list[str]:
        """
        Layout of the fields owned by this class.

        ``kalloc_type`` gives one kind per 8-byte granule for the whole allocation,
        so slice the signature at the superclass size. Without a descriptor, use a
        plain 8-byte field.
        """
        if class_info.is_subclass():
            super_info = types.get_udt_info(class_info.superclass.class_name)
            start_offset = super_info.size if super_info is not None else class_info.superclass.class_size
            start_offset = min(start_offset, class_info.class_size)
        else:
            start_offset = consts.WORD_SIZE
        view = None
        if kcu.is_available():
            view = kcu.best_kalloc_view(class_info.class_name, class_info.class_size)

        decls = []
        for offset in range(start_offset, class_info.class_size, consts.WORD_SIZE):
            kind = view.granule_kind(offset) if view is not None else 0
            if kind & (kcu.GRANULE_PTR | kcu.GRANULE_PAC):
                decls.append(consts.PTR_FIELD_TEMPLATE.format(offset=offset))
            elif kind & kcu.GRANULE_DUAL:
                decls.append(consts.PTR_FIELD_TEMPLATE.format(offset=offset) + ' ///< dual granule')
            else:
                decls.append(consts.DATA_FIELD_TEMPLATE_HEX.format(offset=offset))
        return decls

    def _create_type_from_decl(self, class_info, type_decl: str, replace: bool = False):
        try:
            types.create_type_from_decl(type_decl, replace=replace)
        except FailedToCreateTypeError as ex:
            raise PhaseException(f'Failed to create types for {class_info.class_name}: {ex}')
