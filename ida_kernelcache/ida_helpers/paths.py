"""Resolve the input file path in both GUI and idalib processes."""
import pathlib

import ida_loader
import ida_nalt
import idc


def input_file_path() -> str:
    """Best-effort path of the input binary.

    ``ida_nalt.get_input_file_path()`` returns None in idalib. Fall back to the
    loader path, then to the database directory plus the root filename.
    """
    for getter in (ida_nalt.get_input_file_path,
                   lambda: ida_loader.get_path(ida_loader.PATH_TYPE_CMD)):
        try:
            value = getter()
        except Exception:
            value = ''
        if value:
            return value

    root_name = ida_nalt.get_root_filename() or ''
    try:
        idb_path = idc.get_idb_path()
    except Exception:
        idb_path = ''
    if idb_path and root_name:
        return str(pathlib.Path(idb_path).parent / root_name)
    return root_name
