"""
Thin wrapper around the `ipsw` CLI (https://github.com/blacktop/ipsw).

`ipsw kernel cpp --json <kernelcache>` discovers every C++ class in the kernelcache and emits the
whole RTTI graph as JSON. We rely on it instead of the (fragile) Hex-Rays based heuristics that used
to reconstruct this information from the decompiler ctree, which keeps breaking whenever Apple ships
a kernel with codegen or instructions that IDA's ARM64 decompiler doesn't understand yet.

Each entry has the following shape (addresses are full, unslid kernel VAs which map directly to IDA
EAs)::

    {
        "Name": "IOService",
        "Bundle": "com.apple.kernel",
        "Size": 136,               # class size in bytes
        "Ctor": <ea>,              # the class constructor
        "MetaPtr": <ea>,           # the OSMetaClass instance (our metaclass_ea)
        "SuperMeta": <ea>,         # the super class OSMetaClass instance (0 for root classes)
        "SuperIndex": -1,
        "MetaVtableAddr": <ea>,    # vtable of the *::MetaClass helper class
        "VtableAddr": <ea>         # vtable of the class itself (points at the FIRST vmethod)
    }

Note on ``VtableAddr``: ipsw reports the address of the first virtual method. The plugin's notion of
``vtable_ea`` is offset 0 of the vtable (the two leading NULL words), so callers must subtract
``consts.VTABLE_FIRST_METHOD_OFFSET`` to convert.
"""
import json
import logging
import os
import shutil
import subprocess

import ida_nalt

from ida_kernelcache.exceptions import PhaseException

log = logging.getLogger(__name__)

IPSW_BINARY = 'ipsw'

# Environment variable that lets the user point us at a specific ipsw binary.
IPSW_ENV_OVERRIDE = 'IPSW'

# Common install locations to fall back on. When IDA is launched from the GUI (Finder/Dock) it does
# NOT inherit the shell PATH, so binaries installed under these dirs are invisible to subprocess.
_COMMON_BIN_DIRS = ['/opt/homebrew/bin', '/usr/local/bin', '/opt/local/bin']

# Cache the resolved absolute path so we don't spawn a login shell on every call.
_resolved_ipsw: str | None = None


def _resolve_ipsw() -> str:
    """
    Find an absolute path to the ipsw binary in a way that works even when IDA was launched from the
    GUI (where the shell PATH / .zshrc is never sourced).

    Resolution order:
        1. The ``IPSW`` environment variable (explicit override).
        2. ``shutil.which`` (works when IDA was started from a terminal).
        3. The user's login+interactive shell (sources .zprofile/.zshrc, matching the terminal).
        4. Common install directories (Homebrew / MacPorts / /usr/local).
    """
    global _resolved_ipsw
    if _resolved_ipsw:
        return _resolved_ipsw

    # 1. Explicit override.
    override = os.environ.get(IPSW_ENV_OVERRIDE)
    if override and os.path.isfile(override) and os.access(override, os.X_OK):
        _resolved_ipsw = override
        log.info(f'Using ipsw from ${IPSW_ENV_OVERRIDE}: {override}')
        return _resolved_ipsw

    # 2. Inherited PATH.
    found = shutil.which(IPSW_BINARY)
    if found:
        _resolved_ipsw = found
        return _resolved_ipsw

    # 3. Ask the user's login+interactive shell to resolve it (picks up .zshrc/.zprofile PATH).
    shell = os.environ.get('SHELL', '/bin/zsh')
    try:
        proc = subprocess.run([shell, '-ilc', f'command -v {IPSW_BINARY}'],
                              capture_output=True, text=True, timeout=15)
        candidate = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ''
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            _resolved_ipsw = candidate
            log.info(f'Resolved ipsw via login shell: {candidate}')
            return _resolved_ipsw
    except (OSError, subprocess.SubprocessError) as ex:
        log.debug(f'Login-shell resolution of ipsw failed: {ex}')

    # 4. Common install directories.
    for bin_dir in _COMMON_BIN_DIRS:
        candidate = os.path.join(bin_dir, IPSW_BINARY)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            _resolved_ipsw = candidate
            log.info(f'Found ipsw at {candidate}')
            return _resolved_ipsw

    raise PhaseException(
        f"'{IPSW_BINARY}' could not be found. Install it (https://github.com/blacktop/ipsw), or set "
        f"the ${IPSW_ENV_OVERRIDE} environment variable to its absolute path. Note: launching IDA "
        f"from the GUI does not inherit your shell PATH.")


def run_kernel_cpp(kernelcache_path: str | None = None) -> list[dict]:
    """
    Run ``ipsw kernel cpp --json`` on the given kernelcache (defaults to the IDA input file) and
    return the parsed list of class dictionaries.

    Raises PhaseException if ipsw is not installed, the invocation fails, or the output is not valid
    JSON.
    """
    if kernelcache_path is None:
        kernelcache_path = ida_nalt.get_input_file_path()

    ipsw_path = _resolve_ipsw()
    cmd = [ipsw_path, 'kernel', 'cpp', '--json', kernelcache_path]
    log.info(f'Running: {" ".join(cmd)}')

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as ex:
        raise PhaseException(f'`ipsw kernel cpp` failed (exit {ex.returncode}):\n{ex.stderr.strip()}')

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as ex:
        raise PhaseException(f'Failed to parse `ipsw kernel cpp --json` output as JSON: {ex}')
