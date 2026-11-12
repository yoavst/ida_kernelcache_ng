import ida_funcs
import ida_hexrays
import ida_name
import ida_xref
import idc

import ida_kernelcache.consts as consts
import ida_kernelcache.symbols as symbols
import ida_kernelcache.ida_helpers.names as names
from .base_phase import BasePhase

from typing import TYPE_CHECKING

from .. import rtti
from ..exceptions import PhaseException
from ..ida_helpers import strings, functions, decompiler, kcu

if TYPE_CHECKING:
    from ida_kernelcache.rtti import ClassInfo


class ApplyRTTIInfoPhase(BasePhase):
    """
    Populate IDA with symbols according to the OSMetaClass metadata we've gained so far!
    In high-level this phase will the following:

    - instance symbols for an iOS kernelcache.
    - Search through the kernelcache for OSMetaClass instances and add a symbol for each known instance
    - Populate IDA with virtual method table symbols
    """

    DYNAMIC_CAST_PANIC = '\"OSDynamicCast(AGXAccelerator, driverService)\" @%s:%d'

    def __init__(self, kc):
        super().__init__(kc)

    def run(self):
        for classname, classinfo in self._kc.class_info_map.items_by_type(str):
            self._ensure_owning_kext_loaded(classinfo.metaclass_ea)
            self._add_metaclass_instance_symbol(classinfo)

            # Only operate on classes that have vtable information
            if classinfo.vtable_info:
                self._add_vtable_symbol(classinfo)
                self._add_metaclass_vtable_symbol(classinfo)

        self._apply_vmethod_symbols()

    def _find_safemetacast(self):
        """
        We must first find the EA for OSMetaClass::safeMetaCast
        TODO: finish implementing this!
        """
        panic_str_ea = strings.find_str(self.DYNAMIC_CAST_PANIC).ea
        xref_ea = ida_xref.get_first_cref_to(panic_str_ea)
        if xref_ea == idc.BADADDR:
            raise PhaseException(f'No xref found for {panic_str_ea:#x}')

        if ida_xref.get_next_cref_to(panic_str_ea, xref_ea) != idc.BADADDR:
            raise PhaseException(f'More than 1 xref to {panic_str_ea:#x}')

        func_start = functions.get_func_start(xref_ea, raise_error=True)
        cfunc = ida_hexrays.decompile(func_start)
        if cfunc is None:
            raise PhaseException(f'Failed decompilation of {func_start:#x}')

        visitor = decompiler.FindCallByArgVisitor(panic_str_ea)
        visitor.apply_to(cfunc.body, None)
        if not visitor.found:
            raise PhaseException("Failed to find panic call!")

    def _add_metaclass_instance_symbol(self, classinfo: 'ClassInfo') -> None:
        """
        Add a symbol for the OSMetaClass instance at the specified address.

        IDA 9.5 may have named it already. Keep its name.
        """
        metaclass_instance_symbol = symbols.metaclass_instance_name(classinfo.class_name)
        if not names.set_ea_name(classinfo.metaclass_ea, metaclass_instance_symbol):
            self.log.debug(f'Metaclass symbol at {classinfo.metaclass_ea:#x} not set to {metaclass_instance_symbol}')

    @staticmethod
    def _ensure_owning_kext_loaded(ea: int) -> None:
        if kcu.is_available():
            kcu.ensure_kext_loaded_for_ea(ea)

    def _add_vtable_symbol(self, classinfo: 'ClassInfo') -> None:
        """
        Add a symbol for the virtual method table.

        IDA 9.5 names the vtable at the first slot (ipsw ``VtableAddr``), not at
        the 16-byte header. Keep its name when it exists.
        """
        vtable_symbol = symbols.vtable_name(classinfo.class_name)
        if not names.set_ea_name(classinfo.vtable_info.start_ea, vtable_symbol):
            self.log.debug(f'Vtable symbol at {classinfo.vtable_info.start_ea:#x} not set to {vtable_symbol}')

    def _add_metaclass_vtable_symbol(self, classinfo: 'ClassInfo') -> None:
        metavtable_ea = self._kc.metaclass_to_metavtable_ea.get(classinfo.metaclass_ea)
        if not metavtable_ea:
            return
        symbol = symbols.metaclass_vtable_name(classinfo.class_name)
        if not names.set_ea_name(metavtable_ea, symbol):
            self.log.debug(f'Metaclass vtable symbol at {metavtable_ea:#x} not set to {symbol}')

    def _apply_vmethod_symbols(self) -> None:
        num_invalid_func = 0
        num_multiple_owners = 0
        num_auto_generated = 0
        num_symbolicated = 0

        for vmethod_ea, vmethod_info in self._kc.vmethod_info_map.items():

            # Skip the pure virtual vmethod because it is a special case that has no "owning" vtable method
            if vmethod_ea == rtti.VtableInfo.CXA_PURE_VIRTUAL_EA:
                continue

            # Cannot symbolicate correctly vmethod that don't point to a start of a function, I choose to skip it for now
            # until there is a fix for that
            # TODO: change this to raise an exception after resolving that issue for all vmethods
            if vmethod_info.func is None:
                self.log.warning(f'Skipping symbolication of {vmethod_ea:#x} because its function boundaries are wrong!')
                num_invalid_func += 1
                continue

            vmethod_info.refresh_func()

            if vmethod_info.multiple_owners:
                if vmethod_info.mangled_symbol:
                    self.log.warning(f'VMethod {vmethod_ea:#x} has multiple owners and a symbol {vmethod_info.mangled_symbol}!')
                    # assert not vmethod_info.multiple_owners, f'VMethod {vmethod_ea:#x} has multiple owners and a symbol {vmethod_info.mangled_symbol}!'

                # TODO: Resolve what is the correct class name in such cases
                self.log.warning(f'Skipping symbolication of {vmethod_ea:#x} because it has multiple owners which we do not support yet!')
                num_multiple_owners += 1
                continue

            mangled_symbol = vmethod_info.mangled_symbol
            auto_generate = mangled_symbol is None

            if mangled_symbol is None:
                # Do not replace a real symbol name (for example AppleA7IOP::start)
                # with a generic vmethod_N name.
                current_name = idc.get_func_name(vmethod_ea)
                if current_name and not names.is_auto_generated_name(current_name):
                    auto_generate = False

            if auto_generate:
                vmethod_name = consts.VMETHOD_NAME_TEMPLATE.format(index=vmethod_info.owning_vtable_entry.index)
                mangled_symbol = symbols.mangle_vmethod_name(vmethod_info.owning_class_name, vmethod_name)
                num_auto_generated += 1

            if mangled_symbol is not None:
                if not ida_name.set_name(vmethod_ea, mangled_symbol, ida_name.SN_FORCE):
                    raise PhaseException(f'Failed to set name {mangled_symbol} at {vmethod_ea:#x}')

            # Set a function comment indicating the symbol source
            vmethod_func_comment = consts.VMETHOD_FUNC_CMT_TEMPLATE.format(owning_class=vmethod_info.owning_class_name,
                                                                           owning_vtable_entry_ea=vmethod_info.owning_vtable_entry.entry_ea,
                                                                           pac_diversifier=vmethod_info.owning_vtable_entry.pac_diversifier,
                                                                           symbol_source=vmethod_info.symbol_source.name)
            ida_funcs.set_func_cmt(vmethod_info.func, vmethod_func_comment, repeatable=False)
            num_symbolicated += 1

        self.log.info(f'{num_invalid_func} symbols were skipped because of invalid function boundaries')
        self.log.info(f'{num_multiple_owners} symbols were skipped because of multiple owners edge case that wedo not support yet')
        self.log.info(f'{num_symbolicated - num_auto_generated}/{self._kc.vmethod_info_map.num_symbolicated} vmethod symbols applied to the IDB')
        self.log.info(f'{num_auto_generated}/{num_symbolicated} auto-generated vmethod names applied to the IDB')

    def _symbolicate_overrides_for_classinfo(self):
        """
        TODO: check if there is a need for this logic when the symbol source is PAC_DB, and IPSW_DB
        """
        raise NotImplementedError()
