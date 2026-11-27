"""Low-level ctypes FFI binding to native rl78dec.dll."""

from __future__ import annotations

import ctypes
import json
import os
from typing import Any, Callable, Optional

_DLL: Optional[ctypes.CDLL] = None
_ACTIVE_EVENT_CBS: dict[int, Any] = {}

EVENT_CB_TYPE = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.c_void_p,
)


def is_rl78_processor() -> bool:
    try:
        import ida_idp
        if ida_idp.ph_get_id() == 0x8078:
            return True
        name = ida_idp.get_idp_name() or ""
        return name.lower().startswith("rl78")
    except Exception:
        return False


def _ensure_ida_plugin_loaded() -> None:
    if not is_rl78_processor():
        return
    try:
        import ida_loader
        ida_loader.load_plugin("rl78dec")
    except Exception:
        pass


def _bind_signatures(dll: ctypes.CDLL) -> None:
    dll.rl78dec_abi_version.argtypes = []
    dll.rl78dec_abi_version.restype = ctypes.c_char_p

    dll.rl78dec_abi_is_rl78_db.argtypes = []
    dll.rl78dec_abi_is_rl78_db.restype = ctypes.c_int

    dll.rl78dec_abi_free_str.argtypes = [ctypes.c_void_p]
    dll.rl78dec_abi_free_str.restype = None

    dll.rl78dec_abi_clear_caches.argtypes = []
    dll.rl78dec_abi_clear_caches.restype = None

    dll.rl78dec_abi_mark_dirty.argtypes = [ctypes.c_uint64, ctypes.c_int]
    dll.rl78dec_abi_mark_dirty.restype = None

    dll.rl78dec_abi_decompile.argtypes = [ctypes.c_uint64, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    dll.rl78dec_abi_decompile.restype = ctypes.c_uint64

    dll.rl78dec_abi_release_cfunc.argtypes = [ctypes.c_uint64]
    dll.rl78dec_abi_release_cfunc.restype = None

    dll.rl78dec_abi_cfunc_text.argtypes = [ctypes.c_uint64]
    dll.rl78dec_abi_cfunc_text.restype = ctypes.c_void_p

    dll.rl78dec_abi_cfunc_json.argtypes = [ctypes.c_uint64, ctypes.c_int]
    dll.rl78dec_abi_cfunc_json.restype = ctypes.c_void_p

    dll.rl78dec_abi_cfunc_mutate_item.argtypes = [
        ctypes.c_uint64,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint64,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]
    dll.rl78dec_abi_cfunc_mutate_item.restype = ctypes.c_int

    dll.rl78dec_abi_cfunc_swap_if.argtypes = [ctypes.c_uint64, ctypes.c_uint32]
    dll.rl78dec_abi_cfunc_swap_if.restype = ctypes.c_int

    dll.rl78dec_abi_cfunc_refresh_ctext.argtypes = [ctypes.c_uint64]
    dll.rl78dec_abi_cfunc_refresh_ctext.restype = ctypes.c_void_p

    dll.rl78dec_abi_decompile_text.argtypes = [ctypes.c_uint64, ctypes.POINTER(ctypes.c_void_p)]
    dll.rl78dec_abi_decompile_text.restype = ctypes.c_void_p

    dll.rl78dec_abi_dump_ir.argtypes = [ctypes.c_uint64, ctypes.POINTER(ctypes.c_void_p)]
    dll.rl78dec_abi_dump_ir.restype = ctypes.c_void_p

    dll.rl78dec_abi_decompile_all.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
    ]
    dll.rl78dec_abi_decompile_all.restype = ctypes.c_void_p

    dll.rl78dec_abi_open_pseudocode.argtypes = [ctypes.c_uint64, ctypes.c_int]
    dll.rl78dec_abi_open_pseudocode.restype = ctypes.c_int

    dll.rl78dec_abi_vdui_is_open.argtypes = []
    dll.rl78dec_abi_vdui_is_open.restype = ctypes.c_int

    dll.rl78dec_abi_vdui_refresh.argtypes = [ctypes.c_int]
    dll.rl78dec_abi_vdui_refresh.restype = ctypes.c_int

    dll.rl78dec_abi_vdui_switch_to.argtypes = [ctypes.c_uint64, ctypes.c_int]
    dll.rl78dec_abi_vdui_switch_to.restype = ctypes.c_int

    dll.rl78dec_abi_vdui_get_state.argtypes = [
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    dll.rl78dec_abi_vdui_get_state.restype = ctypes.c_int

    dll.rl78dec_abi_get_user_data_json.argtypes = [ctypes.c_uint64]
    dll.rl78dec_abi_get_user_data_json.restype = ctypes.c_void_p

    dll.rl78dec_abi_set_user_data_json.argtypes = [ctypes.c_uint64, ctypes.c_char_p]
    dll.rl78dec_abi_set_user_data_json.restype = ctypes.c_int

    dll.rl78dec_abi_rename_lvar.argtypes = [ctypes.c_uint64, ctypes.c_char_p, ctypes.c_char_p]
    dll.rl78dec_abi_rename_lvar.restype = ctypes.c_int

    dll.rl78dec_abi_set_lvar_type.argtypes = [ctypes.c_uint64, ctypes.c_char_p, ctypes.c_char_p]
    dll.rl78dec_abi_set_lvar_type.restype = ctypes.c_int

    dll.rl78dec_abi_set_proto.argtypes = [ctypes.c_uint64, ctypes.c_char_p]
    dll.rl78dec_abi_set_proto.restype = ctypes.c_int

    dll.rl78dec_abi_set_cmt.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_char_p]
    dll.rl78dec_abi_set_cmt.restype = ctypes.c_int

    dll.rl78dec_abi_get_cmt.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
    dll.rl78dec_abi_get_cmt.restype = ctypes.c_void_p

    dll.rl78dec_abi_set_numform.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]
    dll.rl78dec_abi_set_numform.restype = ctypes.c_int

    dll.rl78dec_abi_invert_if.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
    dll.rl78dec_abi_invert_if.restype = ctypes.c_int

    dll.rl78dec_abi_get_hide_casts.argtypes = []
    dll.rl78dec_abi_get_hide_casts.restype = ctypes.c_int

    dll.rl78dec_abi_set_hide_casts.argtypes = [ctypes.c_int]
    dll.rl78dec_abi_set_hide_casts.restype = None

    dll.rl78dec_abi_reset_overrides.argtypes = [ctypes.c_uint64]
    dll.rl78dec_abi_reset_overrides.restype = ctypes.c_int

    dll.rl78dec_abi_register_callback.argtypes = [EVENT_CB_TYPE, ctypes.c_void_p]
    dll.rl78dec_abi_register_callback.restype = ctypes.c_int

    dll.rl78dec_abi_unregister_callback.argtypes = [ctypes.c_int]
    dll.rl78dec_abi_unregister_callback.restype = ctypes.c_int


def get_dll() -> ctypes.CDLL:
    global _DLL
    if _DLL is not None:
        return _DLL

    _ensure_ida_plugin_loaded()

    if os.name == "nt":
        k32 = ctypes.windll.kernel32
        k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
        k32.GetModuleHandleW.restype = ctypes.c_void_p
        hmod = k32.GetModuleHandleW("rl78dec.dll")
        if hmod:
            buf = ctypes.create_unicode_buffer(1024)
            k32.GetModuleFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
            k32.GetModuleFileNameW.restype = ctypes.c_uint32
            if k32.GetModuleFileNameW(hmod, buf, 1024) > 0:
                dll = ctypes.CDLL(buf.value)
                _bind_signatures(dll)
                _DLL = dll
                return _DLL

    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(os.path.dirname(here), "rl78dec.dll"),
        os.path.join(os.path.dirname(os.path.dirname(here)), "build", "rl78dec.dll"),
    ]
    if os.environ.get("APPDATA"):
        candidates.insert(0, os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro", "plugins", "rl78dec.dll"))
    for p in candidates:
        if os.path.isfile(p):
            dll = ctypes.CDLL(p)
            _bind_signatures(dll)
            _DLL = dll
            return _DLL
    raise RuntimeError("Could not locate native rl78dec.dll")


def take_str(ptr: Any) -> Optional[str]:
    if not ptr:
        return None
    addr = int(ptr)
    if addr == 0:
        return None
    raw = ctypes.cast(addr, ctypes.c_char_p).value
    txt = raw.decode("utf-8", errors="replace") if raw is not None else ""
    get_dll().rl78dec_abi_free_str(addr)
    return txt


def take_json(ptr: Any) -> Any:
    s = take_str(ptr)
    if not s:
        return None
    return json.loads(s)


def register_event_cb(py_cb: Callable[[int, int, int], int]) -> int:
    def _trampoline(ev: int, handle: int, aux: int, _ud: Any) -> int:
        try:
            return int(py_cb(ev, handle, aux) or 0)
        except Exception:
            return 0

    c_cb = EVENT_CB_TYPE(_trampoline)
    h = get_dll().rl78dec_abi_register_callback(c_cb, None)
    if h >= 0:
        _ACTIVE_EVENT_CBS[h] = c_cb
    return h


def unregister_event_cb_handle(h: int) -> bool:
    ok = bool(get_dll().rl78dec_abi_unregister_callback(int(h)))
    _ACTIVE_EVENT_CBS.pop(int(h), None)
    return ok
