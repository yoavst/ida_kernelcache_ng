import dataclasses
import time

import ida_auto
import ida_segment
import idaapi
import ida_kernwin
import logging
from ida_kernelcache import rtti, consts
from ida_kernelcache.exceptions import PhaseException
from ida_kernelcache.phases import ALL_PHASES
from ida_kernelcache.ida_helpers import kcu
from ida_kernelcache.ida_helpers.abstractions import Segment

logging.basicConfig(format='%(levelname)-10s %(name)s: %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)


class KernelCache(object):
    """
    I have the assumption that we are always interested in the latest kernelcaches. There isn't much sense in putting
    effort to support old iOS releases. Hopefully we can be satisfied with just supporting that latest iOS major.
    This will not attempt to have any backwards compatibility.
    As long as this project is maintained, Hopefully this class will remain up to date with iOS ker

    Current kernelcaches are delivered as a Mach-O FILESET. IDA 9.0 seems to handle the LC_FILESET_ENTRY load command
    well enough, and it also parses inner Mach-O header of each Kext.
    The current kernelcache I'm working on has 311 kexts and after loading it into IDA we get a total of *4301* segments
    """

    def __init__(self, load: bool = True):
        """
        :param bool load: Whether to enable reloading RTTI information that was previously cached
        """
        super().__init__()
        self._base = None

        # TODO: make this persistent?
        self.rtti_db = rtti.RTTIDatabase()
        if load:
            self.rtti_db.load()
        self.class_info_map = self.rtti_db.class_info_map
        self.vmethod_info_map = self.rtti_db.vmethod_info_map

        # Populated by CollectClasses from the ipsw `VtableAddr` field and consumed by CollectVtables.
        # Maps metaclass_ea -> the address of the first vmethod of the class vtable (ipsw VtableAddr).
        self.metaclass_to_vtable_ea: dict[int, int] = {}
        # metaclass_ea -> address of the class's MetaClass helper vtable
        self.metaclass_to_metavtable_ea: dict[int, int] = {}

        self.segments_list: list[Segment] = []

        for i in range(ida_segment.get_segm_qty()):
            swig_segment = ida_segment.getnseg(i)
            self.segments_list.append(Segment(swig_segment))

    @property
    def base(self):
        """
        Find the kernel base address (the address of the main kernel Mach-O header).
        """
        if self._base is None:
            base = idaapi.get_fileregion_ea(0)
            if base != 0xffffffffffffffff:
                return base
            seg = [seg for seg in map(idaapi.get_segm_by_name, ['__TEXT.HEADER', '__TEXT:HEADER']) if seg]
            if not seg:
                raise RuntimeError("unable to find kernel base")
            self._base = seg[0].start_ea

        return self._base

    @staticmethod
    def is_supported() -> bool:
        """
        Checks that the filetype is compatible before trying to process it.

        """

        if idaapi.IDA_SDK_VERSION < consts.MIN_IDA_SDK_VERSION:
            log.error('Unsupported IDA version. The minimum requirement is to run IDA 9.0!')
            return False

        # IDA 9.5's kernelcache loader is the authoritative check.
        if kcu.is_available():
            return True

        file_type = idaapi.get_file_type_name()
        if ('Mach-O' not in file_type and 'kernelcache' not in file_type) or 'ARM64' not in file_type:
            log.error(f'Unsupported file type: "{file_type}"! This script supports ARM64 kernelcaches only!"')
            return False
        return True

    def process(self, phases: list | None = None):
        """
        TODO: edit this docstring
        Process the kernelcache in IDA for the first time.

         This function performs all the standard processing available in this module:
             * Converts pointers in data segments into offsets.
             * Locates virtual method tables, converts them to offsets, and adds vtable symbols.
             * Locates OSMetaClass instances for top-level classes and adds OSMetaClass symbols.
             * Symbolicates offsets in `__got` sections and stub functions in `__stubs` sections.
             * Symbolicates methods in vtables based on the method names in superclasses.
             * Creates IDA structs representing the C++ classes in the kernel.
         """
        if not self.is_supported():
            return

        if not phases:
            phases = ALL_PHASES

        ida_kernwin.show_wait_box(f'Processing kernelcaches with {len(phases)} phases')

        # Run all phases
        for i, phase_cls in enumerate(phases):
            ida_kernwin.replace_wait_box(f'Processing phase: {phase_cls.__name__} step:{i}/{len(phases)}')
            log.info(f'************************************* Starting phase: {phase_cls.__name__} *************************************')
            phase = phase_cls(self)

            start_time = time.time()
            try:
                phase.run()
            except PhaseException as ex:
                log.error('Encountered an error while processing the kernelcache')
                log.exception(ex)
                break
            except Exception as ex:
                log.error('Encountered an unknown exception while processing')
                log.exception(ex)
                break
            else:
                end_time = time.time()
                log.info(f'************************************* Finished phase: {phase_cls.__name__} time:{end_time-start_time:.3f}s *************************************')

            # Wait for auto analysis to complete after every phase.
            # Honestly I'm not sure if this is needed but the auto analyzer is IDLE it will return immediately
            ida_auto.auto_wait()

        ida_kernwin.hide_wait_box()
