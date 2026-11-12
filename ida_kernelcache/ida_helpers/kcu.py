"""
ida_kernelcache/ida_helpers/kcu.py

Thin wrapper around IDA 9.5's ``ida_kcu`` service.

The service exposes what the kernelcache loader knows: collections, KEXTs,
regions, KEXT metadata and ``kalloc_type`` descriptors. On IDA < 9.5, or on
non-kernelcache input, ``service()`` returns None and every helper returns an
empty result.
"""
import dataclasses
import logging

try:
    import ida_kcu
except ImportError:  # IDA < 9.5
    ida_kcu = None

log = logging.getLogger(__name__)

# kt_granule_t bits, as stored in one hex digit of kalloc_type_view_t::sig
GRANULE_PTR = 0x1
GRANULE_DATA = 0x2
GRANULE_DUAL = 0x4
GRANULE_PAC = 0x8

_service = None


def service():
    """Return the shared kcu service, or None when it is unavailable.

    A failed lookup is not cached: the plugin initializes before the loader has
    bootstrapped the service, so later calls must be able to retry.
    """
    global _service
    if _service is not None:
        return _service
    if ida_kcu is None:
        return None
    try:
        _service = ida_kcu.get_kcu_svc(ida_kcu.kcu_config_t())
    except Exception as ex:
        log.debug(f'ida_kcu service unavailable: {ex}')
        _service = None
    return _service


def is_available() -> bool:
    return service() is not None


def _copy_str(value) -> str:
    return str(value) if value is not None else ''


@dataclasses.dataclass(frozen=True)
class Region:
    start: int
    size: int
    type: int
    segname: str
    sectname: str
    kext_name: str = ''


@dataclasses.dataclass(frozen=True)
class KextInfo:
    id: str
    name: str
    version: str
    path: str
    executable: str
    iokit_classes: tuple[str, ...]
    loadaddr: int
    execsize: int


@dataclasses.dataclass(frozen=True)
class KallocView:
    site_name: str
    type_name: str
    sig: str
    sig_hdr: str
    ea: int
    size: int
    size_hdr: int
    flags: int
    ptr_depth: int
    var_view: bool

    def granule_kind(self, offset: int) -> int:
        """Kind of the 8-byte granule at ``offset`` in this allocation."""
        index = offset // 8
        if index < 0 or index >= len(self.sig):
            return GRANULE_DATA
        try:
            return int(self.sig[index], 16)
        except ValueError:
            return GRANULE_DATA

    @property
    def is_pointer(self) -> bool:
        return bool(self.ptr_depth)


def _view_from_swig(view) -> KallocView:
    return KallocView(
        site_name=_copy_str(view.site_name),
        type_name=_copy_str(view.type),
        sig=_copy_str(view.sig),
        sig_hdr=_copy_str(view.sig_hdr),
        ea=int(view.ea),
        size=int(view.size),
        size_hdr=int(view.size_hdr),
        flags=int(view.flags),
        ptr_depth=int(view.ptr_depth),
        var_view=bool(view.var_view),
    )


def coords(name: str):
    """Return opaque KEXT coordinates for a bundle id, or None."""
    svc = service()
    if svc is None:
        return None
    try:
        coords = svc.get_kext_coords(name)
    except Exception as ex:
        log.debug(f'get_kext_coords({name!r}) failed: {ex}')
        return None
    return coords if coords.is_valid() else None


def kext_name(coords) -> str:
    svc = service()
    if svc is None or coords is None:
        return ''
    try:
        return _copy_str(svc.get_kext_name(coords))
    except Exception:
        return ''


def kext_by_ea(ea: int):
    svc = service()
    if svc is None:
        return None
    try:
        coords = svc.get_kext_by_ea(ea)
    except Exception:
        return None
    return coords if coords.is_valid() else None


def load_kext(coords) -> bool:
    svc = service()
    if svc is None or coords is None:
        return False
    try:
        return bool(svc.load_kext(coords))
    except Exception as ex:
        log.debug(f'load_kext failed: {ex}')
        return False


_loaded_kexts: set[int] = set()


def ensure_kext_loaded_for_ea(ea: int) -> bool:
    """Map the KEXT that owns ``ea`` when it is not mapped yet."""
    coords = kext_by_ea(ea)
    if coords is None:
        return False
    key = int(coords.packed)
    if key in _loaded_kexts or is_kext_loaded(coords):
        _loaded_kexts.add(key)
        return True
    if load_kext(coords):
        _loaded_kexts.add(key)
        return True
    return False


def kext_names() -> list[str]:
    svc = service()
    if svc is None:
        return []
    names = []
    try:
        for kc in range(svc.get_kcs_count()):
            names.extend(str(n) for n in svc.get_kc_kexts_names(kc))
    except Exception as ex:
        log.debug(f'kext enumeration failed: {ex}')
    return names


def kext_info(coords) -> KextInfo | None:
    svc = service()
    if svc is None or coords is None:
        return None
    try:
        raw = ida_kcu.kcu_kext_info_t()
        if not svc.get_kext_info(raw, coords):
            return None
        return KextInfo(
            id=_copy_str(raw.id),
            name=_copy_str(raw.name),
            version=_copy_str(raw.version),
            path=_copy_str(raw.path),
            executable=_copy_str(raw.executable),
            iokit_classes=tuple(str(c) for c in raw.iokit_classes),
            loadaddr=int(raw.loadaddr),
            execsize=int(raw.execsize),
        )
    except Exception as ex:
        log.debug(f'get_kext_info failed: {ex}')
        return None


def is_kext_loaded(coords) -> bool:
    svc = service()
    if svc is None or coords is None:
        return False
    try:
        return bool(svc.is_kext_loaded(coords))
    except Exception:
        return False


def regions(coords=None) -> list[Region]:
    """KEXT regions, or every region when ``coords`` is None."""
    svc = service()
    if svc is None:
        return []
    out = []
    try:
        if coords is None:
            for index in range(svc.get_regions_count()):
                raw = ida_kcu.kcu_region_info_t()
                if svc.get_region(raw, index):
                    out.append(_region_from_swig(raw))
        else:
            vec = svc.get_kext_regions(coords, True)
            for index in range(vec.size()):
                out.append(_region_from_swig(vec[index]))
    except Exception as ex:
        log.debug(f'region enumeration failed: {ex}')
    return out


def _region_from_swig(raw) -> Region:
    name = ''
    try:
        if raw.kext.is_valid():
            name = kext_name(raw.kext)
    except Exception:
        pass
    return Region(
        start=int(raw.start),
        size=int(raw.size),
        type=int(raw.type),
        segname=_copy_str(raw.segname),
        sectname=_copy_str(raw.sectname),
        kext_name=name,
    )


def kalloc_views(type_name: str | None = None) -> list[KallocView]:
    """Every kalloc_type descriptor, or only those naming ``type_name``."""
    svc = service()
    if svc is None:
        return []
    try:
        vec = svc.get_kalloc_views(type_name)
    except Exception as ex:
        log.debug(f'get_kalloc_views({type_name!r}) failed: {ex}')
        return []
    if not hasattr(vec, 'size'):
        return []
    return [_view_from_swig(vec[index]) for index in range(vec.size())]


def kalloc_view_at(ea: int) -> KallocView | None:
    svc = service()
    if svc is None:
        return None
    try:
        raw = ida_kcu.kcu_kalloc_view_t()
        if not svc.get_kalloc_view(raw, ea):
            return None
        return _view_from_swig(raw)
    except Exception:
        return None


def best_kalloc_view(class_name: str, class_size: int) -> KallocView | None:
    """
    Pick the descriptor that describes ``class_size`` bytes of one object.

    Prefer a fixed view, then any view whose element size matches. A var view
    describes one element only, so it is still useful for field kinds.
    """
    views = [v for v in kalloc_views(class_name) if v.size == class_size]
    if not views:
        return None
    views.sort(key=lambda v: (v.var_view, v.size_hdr))
    return views[0]
