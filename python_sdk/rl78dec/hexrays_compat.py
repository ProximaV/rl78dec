"""Hex-Rays IDAPython (`ida_hexrays`) compatibility shim for Renesas RL78 databases.

Strictly scopes all behavior to Renesas RL78 (`PH.id == 0x8078` or `"rl78"`):
if the active IDA database uses any other processor architecture, every lookup
delegates transparently to `_orig_ida_hexrays` so x86/x64/ARM/SPU/etc. are untouched.
"""

from __future__ import annotations

import ctypes
import sys
import types
from typing import Any, Callable, Optional

from . import _ffi, ctree
from .ctree import (
    BADADDR,
    CMAT_BUILT,
    CMAT_CASTED,
    CMAT_CPA,
    CMAT_FINAL,
    CMAT_NICE,
    CMAT_TRANS1,
    CMAT_TRANS2,
    CMAT_TRANS3,
    CMAT_ZERO,
    CV_FAST,
    CV_INSNS,
    CV_PARENTS,
    CV_POST,
    CV_PRUNE,
    CV_RESTART,
    DECOMP_ALL_BLKS,
    DECOMP_NO_CACHE,
    DECOMP_NO_WAIT,
    DECOMP_WARNINGS,
    DecompilationFailure,
    OPF_NEW_WINDOW,
    OPF_NO_WAIT,
    OPF_REUSE,
    cblock_t,
    cexpr_t,
    cfunc_t,
    cgoto_t,
    cif_t,
    cinsn_t,
    cit_asm,
    cit_block,
    cit_break,
    cit_continue,
    cit_do,
    cit_empty,
    cit_end,
    cit_expr,
    cit_for,
    cit_goto,
    cit_if,
    cit_return,
    cit_switch,
    cit_throw,
    cit_try,
    cit_while,
    citem_t,
    cloop_t,
    cnumber_t,
    cot_add,
    cot_asg,
    cot_asgadd,
    cot_asgband,
    cot_asgbor,
    cot_asgmul,
    cot_asgsdiv,
    cot_asgshl,
    cot_asgsmod,
    cot_asgsshr,
    cot_asgsub,
    cot_asgudiv,
    cot_asgumod,
    cot_asgushr,
    cot_asgxor,
    cot_band,
    cot_bnot,
    cot_bor,
    cot_call,
    cot_cast,
    cot_comma,
    cot_empty,
    cot_eq,
    cot_fadd,
    cot_fdiv,
    cot_fmul,
    cot_fneg,
    cot_fnum,
    cot_fsub,
    cot_helper,
    cot_idx,
    cot_insn,
    cot_land,
    cot_last,
    cot_lnot,
    cot_lor,
    cot_memref,
    cot_memptr,
    cot_mul,
    cot_neg,
    cot_ne,
    cot_num,
    cot_obj,
    cot_postdec,
    cot_postinc,
    cot_predec,
    cot_preinc,
    cot_ptr,
    cot_ref,
    cot_sdiv,
    cot_sge,
    cot_sgt,
    cot_shl,
    cot_sizeof,
    cot_sle,
    cot_slt,
    cot_smod,
    cot_sshr,
    cot_str,
    cot_sub,
    cot_tern,
    cot_type,
    cot_udiv,
    cot_uge,
    cot_ugt,
    cot_ule,
    cot_ult,
    cot_umod,
    cot_ushr,
    cot_var,
    cot_xor,
    ctree_item_t,
    ctree_visitor_t,
    hexrays_failure_t,
    lvar_locator_t,
    lvar_t,
    vdui_t,
)

hxe_maturity          = 0
hxe_interr            = 3
hxe_func_printed      = 4
hxe_open_pseudocode   = 5
hxe_switch_pseudocode = 6
hxe_refresh_pseudocode = 7
hxe_close_pseudocode  = 8
hxe_curpos            = 9
hxe_double_click      = 10
hxe_keyboard          = 11
hxe_populating_popup  = 12


def _resolve_ea(ea_or_pfn: Any) -> int:
    if hasattr(ea_or_pfn, "start_ea"):
        return int(ea_or_pfn.start_ea)
    return int(ea_or_pfn)


def init_hexrays_plugin(_flags: int = 0) -> bool:
    if not _ffi.is_rl78_processor():
        return False
    try:
        return bool(_ffi.get_dll().rl78dec_abi_is_rl78_db())
    except Exception:
        return False


def get_hexrays_version() -> str:
    v = _ffi.get_dll().rl78dec_abi_version()
    return v.decode("utf-8") if v else "2.0.0-native"


def decompile(ea_or_pfn: Any, hf: Optional[hexrays_failure_t] = None, flags: int = 0) -> Optional[cfunc_t]:
    ea = _resolve_ea(ea_or_pfn)
    dll = _ffi.get_dll()
    err_ptr = ctypes.c_void_p(0)
    handle = dll.rl78dec_abi_decompile(ea, int(flags), ctypes.byref(err_ptr))
    if not handle:
        msg = _ffi.take_str(err_ptr.value) or f"Decompilation failed at 0x{ea:x}"
        if hf is not None:
            hf.code = -1
            hf.errea = ea
            hf.str = msg
            return None
        raise DecompilationFailure(msg, ea)
    return cfunc_t(int(handle), borrow=False)


def decompile_func(pfn: Any, hf: Optional[hexrays_failure_t] = None, flags: int = 0) -> Optional[cfunc_t]:
    return decompile(pfn, hf, flags)


def open_pseudocode(ea: int, flags: int = 0) -> Optional[vdui_t]:
    if not _ffi.get_dll().rl78dec_abi_open_pseudocode(int(ea), int(flags)):
        return None
    return vdui_t()


def get_widget_vdui(widget: Any) -> Optional[vdui_t]:
    if widget is None:
        return None
    try:
        import ida_kernwin
        if ida_kernwin.get_widget_title(widget) != "rl78dec - Pseudocode":
            return None
    except Exception:
        pass
    if not _ffi.get_dll().rl78dec_abi_vdui_is_open():
        return None
    return vdui_t()


def mark_cfunc_dirty(ea: int, close_views: bool = False) -> bool:
    _ffi.get_dll().rl78dec_abi_mark_dirty(int(ea), 1 if close_views else 0)
    return True


def clear_cached_cfuncs() -> None:
    _ffi.get_dll().rl78dec_abi_clear_caches()


def rename_lvar(func_ea: int, old_name: str, new_name: str) -> bool:
    return bool(
        _ffi.get_dll().rl78dec_abi_rename_lvar(
            int(func_ea), old_name.encode("utf-8"), new_name.encode("utf-8")
        )
    )


class lvar_saved_info_t:
    def __init__(self):
        self.ll: Optional[lvar_locator_t] = None
        self.name: str = ""
        self.type: Any = None
        self.cmt: str = ""
        self.flags: int = 0


class user_lvar_modifier_t:
    def modify_lvars(self, _lvinf: Any) -> bool:
        return False


def modify_user_lvars(entry_ea: int, mli: user_lvar_modifier_t) -> bool:
    cf = decompile(entry_ea)
    if cf is None:
        return False
    saved = []
    for lv in cf.lvars:
        si = lvar_saved_info_t()
        si.ll = lv.location
        si.name = lv.name
        si.type = lv._type_str
        si.cmt = lv.cmt
        saved.append(si)

    class _Lvinf:
        def __init__(self, vec):
            self.lvvec = vec

    lvinf = _Lvinf(saved)
    if not mli.modify_lvars(lvinf):
        return False
    changed = False
    for lv, si in zip(cf.lvars, lvinf.lvvec):
        if si.name and si.name != lv.name:
            _ffi.get_dll().rl78dec_abi_rename_lvar(
                int(entry_ea), lv.canonical_name.encode("utf-8"), si.name.encode("utf-8")
            )
            changed = True
        if si.type and str(si.type) != lv._type_str:
            _ffi.get_dll().rl78dec_abi_set_lvar_type(
                int(entry_ea), lv.canonical_name.encode("utf-8"), str(si.type).encode("utf-8")
            )
            changed = True
    return changed


_PY_CALLBACKS: dict[int, int] = {}
_NEXT_PY_CB_HANDLE = 1


def install_hexrays_callback(cb: Callable[[int, Any], int]) -> int:
    global _NEXT_PY_CB_HANDLE

    def _bridge(ev: int, handle: int, aux: int) -> int:
        if ev in (hxe_maturity, hxe_func_printed):
            cf = cfunc_t(int(handle), borrow=True) if handle else None
            return int(cb(ev, cf, int(aux)) or 0)  # type: ignore[call-arg]
        if hxe_open_pseudocode <= ev <= hxe_populating_popup:
            vu = vdui_t()
            return int(cb(ev, vu) or 0)
        return 0

    native_h = _ffi.register_event_cb(_bridge)
    if native_h < 0:
        return -1
    h = _NEXT_PY_CB_HANDLE
    _NEXT_PY_CB_HANDLE += 1
    _PY_CALLBACKS[h] = native_h
    return h


def remove_hexrays_callback(cb_handle_or_fn: Any) -> bool:
    if isinstance(cb_handle_or_fn, int) and cb_handle_or_fn in _PY_CALLBACKS:
        native_h = _PY_CALLBACKS.pop(cb_handle_or_fn)
        return _ffi.unregister_event_cb_handle(native_h)
    return False


class Hexrays_Hooks:
    def __init__(self):
        self._handle: int = -1

    def hook(self) -> bool:
        if self._handle >= 0:
            return True

        def _dispatch(ev: int, handle: int, aux: int) -> int:
            if ev == hxe_maturity:
                cf = cfunc_t(int(handle), borrow=True) if handle else None
                return self.maturity(cf, int(aux)) if cf else 0
            if ev == hxe_func_printed:
                cf = cfunc_t(int(handle), borrow=True) if handle else None
                return self.func_printed(cf) if cf else 0
            if ev == hxe_open_pseudocode:
                return self.open_pseudocode(vdui_t())
            if ev == hxe_switch_pseudocode:
                return self.switch_pseudocode(vdui_t())
            if ev == hxe_refresh_pseudocode:
                return self.refresh_pseudocode(vdui_t())
            if ev == hxe_close_pseudocode:
                return self.close_pseudocode(vdui_t())
            if ev == hxe_curpos:
                return self.curpos(vdui_t())
            if ev == hxe_double_click:
                return self.double_click(vdui_t(), 0)
            if ev == hxe_keyboard:
                return self.keyboard(vdui_t(), int(aux), 0)
            return 0

        self._handle = _ffi.register_event_cb(_dispatch)
        return self._handle >= 0

    def unhook(self) -> bool:
        if self._handle < 0:
            return False
        ok = _ffi.unregister_event_cb_handle(self._handle)
        self._handle = -1
        return ok

    def maturity(self, _cfunc: cfunc_t, _new_maturity: int) -> int:
        return 0

    def func_printed(self, _cfunc: cfunc_t) -> int:
        return 0

    def open_pseudocode(self, _vu: vdui_t) -> int:
        return 0

    def switch_pseudocode(self, _vu: vdui_t) -> int:
        return 0

    def refresh_pseudocode(self, _vu: vdui_t) -> int:
        return 0

    def close_pseudocode(self, _vu: vdui_t) -> int:
        return 0

    def curpos(self, _vu: vdui_t) -> int:
        return 0

    def double_click(self, _vu: vdui_t, _shift_state: int) -> int:
        return 0

    def keyboard(self, _vu: vdui_t, _key_code: int, _shift_state: int) -> int:
        return 0


class _HexraysDynamicProxy(types.ModuleType):
    """Module proxy installed at `sys.modules['ida_hexrays']`.

    Routes calls to `rl78dec.hexrays_compat` ONLY when the active IDA processor
    is Renesas RL78; otherwise delegates transparently to `_orig_mod`.
    """

    def __init__(self, compat_mod: types.ModuleType, orig_mod: Optional[types.ModuleType]):
        super().__init__("ida_hexrays")
        object.__setattr__(self, "_compat_mod", compat_mod)
        object.__setattr__(self, "_orig_mod", orig_mod)

    def __getattr__(self, name: str) -> Any:
        compat_mod = object.__getattribute__(self, "_compat_mod")
        orig_mod = object.__getattribute__(self, "_orig_mod")
        if _ffi.is_rl78_processor():
            if hasattr(compat_mod, name):
                return getattr(compat_mod, name)
            if orig_mod is not None and hasattr(orig_mod, name):
                return getattr(orig_mod, name)
            raise AttributeError(f"module 'ida_hexrays' (rl78dec shim) has no attribute {name!r}")
        if orig_mod is not None:
            return getattr(orig_mod, name)
        if hasattr(compat_mod, name):
            return getattr(compat_mod, name)
        raise AttributeError(f"module 'ida_hexrays' has no attribute {name!r}")


_INSTALLED_PROXY: Optional[_HexraysDynamicProxy] = None


def install_hexrays_compat() -> bool:
    global _INSTALLED_PROXY
    if _INSTALLED_PROXY is not None:
        sys.modules["ida_hexrays"] = _INSTALLED_PROXY
        return True

    orig_mod: Optional[types.ModuleType] = sys.modules.get("ida_hexrays")
    if orig_mod is None:
        try:
            import importlib
            orig_mod = importlib.import_module("ida_hexrays")
        except Exception:
            orig_mod = None

    compat_mod = sys.modules[__name__]
    proxy = _HexraysDynamicProxy(compat_mod, orig_mod)
    _INSTALLED_PROXY = proxy
    sys.modules["ida_hexrays"] = proxy
    return True
