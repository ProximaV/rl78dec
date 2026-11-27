"""Native C++-backed Python SDK for `rl78dec` (Renesas RL78 / 78K0R Decompiler).

Provides:
  1. Direct `rl78dec.*` API (`decompile`, `dump`, `pseudocode`, `decompile_all`, `clear_caches`, `db.*`).
  2. Hex-Rays-compatible `cfunc_t` / `ctree` / `vdui_t` / `Hexrays_Hooks` scripting API.
  3. Dynamic `ida_hexrays` compatibility shim strictly gated to RL78 (`0x8078` / `"rl78"`).
"""

from __future__ import annotations

import ctypes
from typing import Optional

from . import _ffi, ctree, db, hexrays_compat
from .ctree import (
    CV_FAST,
    CV_INSNS,
    CV_PARENTS,
    CV_POST,
    CV_PRUNE,
    CV_RESTART,
    DECOMP_NO_CACHE,
    DecompilationFailure,
    cblock_t,
    cexpr_t,
    cfunc_t,
    cif_t,
    cinsn_t,
    citem_t,
    cnumber_t,
    ctree_visitor_t,
    hexrays_failure_t,
    lvar_t,
    vdui_t,
)
from .hexrays_compat import (
    Hexrays_Hooks,
    clear_cached_cfuncs,
    get_widget_vdui,
    init_hexrays_plugin,
    install_hexrays_callback,
    install_hexrays_compat,
    mark_cfunc_dirty,
    modify_user_lvars,
    open_pseudocode,
    remove_hexrays_callback,
    rename_lvar,
)

__version__ = "2.0.0-native"


def version() -> str:
    v = _ffi.get_dll().rl78dec_abi_version()
    return v.decode("utf-8") if v else __version__


def cfunc(ea: int, flags: int = 0) -> cfunc_t:
    res = hexrays_compat.decompile(ea, None, flags)
    if res is None:
        raise DecompilationFailure(f"Failed to decompile 0x{int(ea):x}", int(ea))
    return res


def decompile(ea: int) -> str:
    dll = _ffi.get_dll()
    err_ptr = ctypes.c_void_p(0)
    txt = _ffi.take_str(dll.rl78dec_abi_decompile_text(int(ea), ctypes.byref(err_ptr)))
    if txt is None:
        err = _ffi.take_str(err_ptr.value) or f"Decompilation failed at 0x{int(ea):x}"
        raise DecompilationFailure(err, int(ea))
    return txt


def dump(ea: int) -> str:
    dll = _ffi.get_dll()
    err_ptr = ctypes.c_void_p(0)
    txt = _ffi.take_str(dll.rl78dec_abi_dump_ir(int(ea), ctypes.byref(err_ptr)))
    if txt is None:
        err = _ffi.take_str(err_ptr.value) or f"IR lift failed at 0x{int(ea):x}"
        raise DecompilationFailure(err, int(ea))
    return txt


def pseudocode(ea: Optional[int] = None) -> Optional[vdui_t]:
    if ea is None:
        import ida_kernwin
        ea = ida_kernwin.get_screen_ea()
    return open_pseudocode(int(ea), 1)


def decompile_all(out_path: Optional[str] = None) -> str:
    dll = _ffi.get_dll()
    ok_cnt = ctypes.c_int(0)
    fail_cnt = ctypes.c_int(0)
    path_b = out_path.encode("utf-8") if out_path else None
    txt = _ffi.take_str(
        dll.rl78dec_abi_decompile_all(path_b, ctypes.byref(ok_cnt), ctypes.byref(fail_cnt))
    )
    return txt or ""


def clear_caches() -> None:
    clear_cached_cfuncs()


def mark_dirty(ea: int, close_views: bool = False) -> None:
    mark_cfunc_dirty(int(ea), close_views)
