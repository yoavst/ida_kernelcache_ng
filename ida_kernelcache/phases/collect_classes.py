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
from .base_phase import BasePhase
from ida_kernelcache import rtti
from ida_kernelcache.utils import OneToOneMapFactory
from ida_kernelcache.ida_helpers import ipsw


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

        self._load_from_ipsw()
        self._populate_class_info_map()

        # Print statistics
        self.log.info(f'Collection stats:\n'
                      f'* classes from ipsw:{self._num_succeeded}\n'
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

            self._num_succeeded += 1

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
