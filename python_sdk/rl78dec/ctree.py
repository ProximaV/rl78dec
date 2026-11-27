"""Hex-Rays-compatible Python ctree AST, lvar_t, cfunc_t, vdui_t, and visitor classes."""

from __future__ import annotations

import ctypes
from typing import Any, Optional
from . import _ffi

cot_empty    = 0
cot_comma    = 1
cot_asg      = 2
cot_asgbor   = 3
cot_asgxor   = 4
cot_asgband  = 5
cot_asgadd   = 6
cot_asgsub   = 7
cot_asgmul   = 8
cot_asgsshr  = 9
cot_asgushr  = 10
cot_asgshl   = 11
cot_asgsdiv  = 12
cot_asgudiv  = 13
cot_asgsmod  = 14
cot_asgumod  = 15
cot_tern     = 16
cot_lor      = 17
cot_land     = 18
cot_bor      = 19
cot_xor      = 20
cot_band     = 21
cot_eq       = 22
cot_ne       = 23
cot_sge      = 24
cot_uge      = 25
cot_sle      = 26
cot_ule      = 27
cot_sgt      = 28
cot_ugt      = 29
cot_slt      = 30
cot_ult      = 31
cot_sshr     = 32
cot_ushr     = 33
cot_shl      = 34
cot_add      = 35
cot_sub      = 36
cot_mul      = 37
cot_sdiv     = 38
cot_udiv     = 39
cot_smod     = 40
cot_umod     = 41
cot_fadd     = 42
cot_fsub     = 43
cot_fmul     = 44
cot_fdiv     = 45
cot_fneg     = 46
cot_neg      = 47
cot_cast     = 48
cot_lnot     = 49
cot_bnot     = 50
cot_ptr      = 51
cot_ref      = 52
cot_postinc  = 53
cot_postdec  = 54
cot_preinc   = 55
cot_predec   = 56
cot_call     = 57
cot_idx      = 58
cot_memref   = 59
cot_memptr   = 60
cot_num      = 61
cot_fnum     = 62
cot_str      = 63
cot_obj      = 64
cot_var      = 65
cot_insn     = 66
cot_sizeof   = 67
cot_helper   = 68
cot_type     = 69
cot_last     = 69

cit_empty    = 70
cit_block    = 71
cit_expr     = 72
cit_if       = 73
cit_for      = 74
cit_while    = 75
cit_do       = 76
cit_switch   = 77
cit_break    = 78
cit_continue = 79
cit_return   = 80
cit_goto     = 81
cit_asm      = 82
cit_try      = 83
cit_throw    = 84
cit_end      = 85

CV_FAST    = 0x0000
CV_PRUNE   = 0x0001
CV_PARENTS = 0x0002
CV_POST    = 0x0004
CV_RESTART = 0x0008
CV_INSNS   = 0x0010

CMAT_ZERO   = 0
CMAT_BUILT  = 1
CMAT_TRANS1 = 2
CMAT_NICE   = 3
CMAT_TRANS2 = 4
CMAT_CPA    = 5
CMAT_TRANS3 = 6
CMAT_CASTED = 7
CMAT_FINAL  = 8

DECOMP_WARNINGS = 0x0001
DECOMP_NO_WAIT  = 0x0002
DECOMP_NO_CACHE = 0x0004
DECOMP_ALL_BLKS = 0x0008

OPF_REUSE      = 0
OPF_NEW_WINDOW = 1
OPF_NO_WAIT    = 2

BADADDR = 0xFFFFFFFFFFFFFFFF


class hexrays_failure_t:
    def __init__(self, code: int = -1, errea: int = BADADDR, message: str = ""):
        self.code = code
        self.errea = errea
        self.str = message

    def desc(self) -> str:
        if self.errea != BADADDR:
            return f"0x{self.errea:X}: {self.str}"
        return self.str


class DecompilationFailure(RuntimeError):
    def __init__(self, message: str, ea: int = BADADDR):
        super().__init__(message)
        self.info = hexrays_failure_t(-1, ea, message)


class simpleline_shim_t:
    def __init__(self, line: str, bgcolor: int = 0xFFFFFFFF):
        self.line = line
        self.bgcolor = bgcolor

    def __str__(self) -> str:
        return self.line


class lvar_locator_t:
    def __init__(self, is_stk: bool, reg: int, stk_off: int, defea: int):
        self._is_stk = is_stk
        self._reg = reg
        self._stk_off = stk_off
        self.ea = defea

    def is_stkoff(self) -> bool:
        return self._is_stk

    def is_reg1(self) -> bool:
        return not self._is_stk and self._reg >= 0

    def reg1(self) -> int:
        return self._reg

    def stkoff(self) -> int:
        return self._stk_off


class lvar_t:
    def __init__(self, cfunc_ref: "cfunc_t", raw: dict[str, Any]):
        self._cfunc = cfunc_ref
        self.idx: int = raw["idx"]
        self.name: str = raw["name"]
        self.canonical_name: str = raw["canon"]
        self._type_str: str = raw["type"]
        self.cmt: str = raw.get("cmt", "")
        self.width: int = raw.get("width", 2)
        self.defea: int = raw["defea"] if raw.get("defea") is not None else BADADDR
        self.location = lvar_locator_t(
            bool(raw.get("loc_stk", False)),
            int(raw.get("loc_reg", -1)),
            int(raw.get("loc_off", 0)),
            self.defea,
        )
        self.is_arg_var: bool = bool(raw.get("is_arg", False))
        self.is_thisarg: bool = bool(raw.get("is_this", False))
        self.is_result_var: bool = bool(raw.get("is_res", False))
        self._is_stk: bool = bool(raw.get("is_stk", False))
        self.has_user_name: bool = bool(raw.get("user_name", False))
        self.has_user_type: bool = bool(raw.get("user_type", False))

    def is_stk_var(self) -> bool:
        return self._is_stk

    def is_reg_var(self) -> bool:
        return not self._is_stk

    def get_stkoff(self) -> int:
        return self.location.stkoff()

    def type(self) -> Any:
        try:
            import ida_typeinf
            tif = ida_typeinf.tinfo_t()
            decl = f"{self._type_str} x;"
            if ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL):
                return tif
        except Exception:
            pass
        return self._type_str

    def __repr__(self) -> str:
        return f"<lvar_t {self._type_str} {self.name}>"


class var_ref_t:
    def __init__(self, idx: int = -1, lvars: Optional[list[lvar_t]] = None):
        self.idx = idx
        self._lvars = lvars

    def getv(self) -> Optional[lvar_t]:
        if self._lvars is not None and 0 <= self.idx < len(self._lvars):
            return self._lvars[self.idx]
        return None


class cnumber_t:
    def __init__(self, owner: "cexpr_t", val: int = 0, bits: int = 16, repr_str: str = ""):
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_val", val & 0xFFFFFFFFFFFFFFFF)
        object.__setattr__(self, "bits", bits)
        object.__setattr__(self, "repr", repr_str)

    @property
    def _value(self) -> int:
        return self._val

    @_value.setter
    def _value(self, new_v: int) -> None:
        v64 = int(new_v) & 0xFFFFFFFFFFFFFFFF
        object.__setattr__(self, "_val", v64)
        self._owner._sync_mutation()

    def value(self, _tif: Any = None) -> int:
        return self._val


class citem_t:
    def __init__(self, cfunc_ref: "cfunc_t", obj_id: int, op: int, ea: int, label_num: int = -1):
        object.__setattr__(self, "_cfunc", cfunc_ref)
        object.__setattr__(self, "obj_id", obj_id)
        object.__setattr__(self, "_op", op)
        object.__setattr__(self, "ea", ea)
        object.__setattr__(self, "label_num", label_num)

    @property
    def op(self) -> int:
        return self._op

    @op.setter
    def op(self, new_op: int) -> None:
        object.__setattr__(self, "_op", int(new_op))
        self._sync_mutation()

    def is_expr(self) -> bool:
        return cot_empty <= self._op <= cot_last

    @property
    def cexpr(self) -> Optional["cexpr_t"]:
        return self if isinstance(self, cexpr_t) else None

    @property
    def cinsn(self) -> Optional["cinsn_t"]:
        return self if isinstance(self, cinsn_t) else None

    def _sync_mutation(self) -> None:
        pass


class cexpr_t(citem_t):
    def __init__(self, cfunc_ref: "cfunc_t", raw: dict[str, Any]):
        ea = raw["ea"] if raw.get("ea") is not None else BADADDR
        super().__init__(cfunc_ref, int(raw["id"]), int(raw["op"]), ea, int(raw.get("lbl", -1)))
        object.__setattr__(self, "type_str", raw.get("ty", ""))
        object.__setattr__(self, "ptrsize", int(raw.get("ps", 0)))
        object.__setattr__(self, "x", None)
        object.__setattr__(self, "y", None)
        object.__setattr__(self, "z", None)
        object.__setattr__(self, "a", [])
        object.__setattr__(self, "v", var_ref_t(int(raw.get("v", -1)), cfunc_ref.lvars))
        object.__setattr__(
            self,
            "n",
            cnumber_t(self, int(raw.get("n", 0)), int(raw.get("nb", 16)), raw.get("nr", "")),
        )
        oea = raw.get("oea")
        object.__setattr__(self, "obj_ea", int(oea) if oea is not None else BADADDR)
        object.__setattr__(self, "_string", raw.get("s", ""))
        object.__setattr__(self, "_helper", raw.get("h", ""))
        object.__setattr__(self, "_txt", raw.get("txt", ""))

    @property
    def string(self) -> str:
        return self._string

    @string.setter
    def string(self, val: str) -> None:
        object.__setattr__(self, "_string", str(val))
        self._sync_mutation()

    @property
    def helper(self) -> str:
        return self._helper

    @helper.setter
    def helper(self, val: str) -> None:
        object.__setattr__(self, "_helper", str(val))
        self._sync_mutation()

    def numval(self) -> int:
        return self.n._value

    def print1(self, _ud: Any = None) -> str:
        return self._txt

    def dstr(self) -> str:
        return self._txt

    def _sync_mutation(self) -> None:
        if self._cfunc._handle:
            _ffi.get_dll().rl78dec_abi_cfunc_mutate_item(
                self._cfunc._handle,
                self.obj_id,
                self._op,
                self.n._value,
                self.v.idx,
                self._string.encode("utf-8") if self._string else None,
                self._helper.encode("utf-8") if self._helper else None,
            )
            self._cfunc._dirty_text = True


class cblock_t(list):
    def size(self) -> int:
        return len(self)

    def empty(self) -> bool:
        return len(self) == 0


class cif_t:
    def __init__(self, owner: "cinsn_t"):
        self._owner = owner
        self.expr: Optional[cexpr_t] = None
        self.ithen: Optional[cinsn_t] = None
        self.ielse: Optional[cinsn_t] = None

    def swap_branches(self) -> bool:
        if not self._owner._cfunc._handle or self.ielse is None:
            return False
        ok = bool(_ffi.get_dll().rl78dec_abi_cfunc_swap_if(self._owner._cfunc._handle, self._owner.obj_id))
        if ok:
            self.ithen, self.ielse = self.ielse, self.ithen
            self._owner._cfunc._dirty_text = True
        return ok


class cloop_t:
    def __init__(self):
        self.expr: Optional[cexpr_t] = None
        self.body: Optional[cinsn_t] = None


class creturn_t:
    def __init__(self):
        self.expr: Optional[cexpr_t] = None


class cgoto_t:
    def __init__(self, label_num: int = -1, target_name: str = ""):
        self.label_num = label_num
        self.target_name = target_name


class cswitch_case_t:
    def __init__(self, values: Optional[list[int]] = None, body: Optional["cinsn_t"] = None):
        self.values: list[int] = list(values or [])
        self.body: Optional[cinsn_t] = body


class cswitch_t:
    def __init__(self):
        self.expr: Optional[cexpr_t] = None
        self.cases: list[cswitch_case_t] = []
        self.def_body: Optional[cinsn_t] = None


class cinsn_t(citem_t):
    def __init__(self, cfunc_ref: "cfunc_t", raw: dict[str, Any]):
        ea = raw["ea"] if raw.get("ea") is not None else BADADDR
        super().__init__(cfunc_ref, int(raw["id"]), int(raw["op"]), ea, int(raw.get("lbl", -1)))
        object.__setattr__(self, "cblock", cblock_t())
        object.__setattr__(self, "_cexpr_node", None)
        object.__setattr__(self, "cif", cif_t(self))
        object.__setattr__(self, "cloop", cloop_t())
        object.__setattr__(self, "cwhile", self.cloop)
        object.__setattr__(self, "cdo", self.cloop)
        object.__setattr__(self, "cfor", self.cloop)
        object.__setattr__(self, "creturn", creturn_t())
        object.__setattr__(self, "cgoto", cgoto_t(int(raw.get("gl", -1)), raw.get("gt", "")))
        object.__setattr__(self, "cswitch", cswitch_t())
        object.__setattr__(self, "user_cmt", raw.get("cmt", ""))

    @property
    def cexpr(self) -> Optional[cexpr_t]:  # type: ignore[override]
        return self._cexpr_node

    def dstr(self) -> str:
        if self._op == cit_expr and self._cexpr_node is not None:
            return f"{self._cexpr_node.dstr()};"
        return f"<cinsn_t op={self._op} ea=0x{self.ea:x}>"


class ctree_visitor_t:
    def __init__(self, cv_flags: int = CV_FAST):
        self.cv_flags = cv_flags
        self.parents: list[citem_t] = []

    def maintain_parents(self) -> bool:
        return (self.cv_flags & CV_PARENTS) != 0

    def must_prune(self) -> bool:
        return (self.cv_flags & CV_PRUNE) != 0

    def is_postorder(self) -> bool:
        return (self.cv_flags & CV_POST) != 0

    def only_insns(self) -> bool:
        return (self.cv_flags & CV_INSNS) != 0

    def prune_now(self) -> None:
        self.cv_flags |= CV_PRUNE

    def clr_prune(self) -> None:
        self.cv_flags &= ~CV_PRUNE

    def parent_item(self) -> Optional[citem_t]:
        return self.parents[-1] if self.parents else None

    def parent_expr(self) -> Optional[cexpr_t]:
        p = self.parent_item()
        return p if isinstance(p, cexpr_t) else None

    def parent_insn(self) -> Optional[cinsn_t]:
        p = self.parent_item()
        return p if isinstance(p, cinsn_t) else None

    def visit_insn(self, _insn: cinsn_t) -> int:
        return 0

    def visit_expr(self, _expr: cexpr_t) -> int:
        return 0

    def leave_insn(self, _insn: cinsn_t) -> int:
        return 0

    def leave_expr(self, _expr: cexpr_t) -> int:
        return 0

    def apply_to(self, item: Optional[citem_t], parent: Optional[citem_t] = None) -> int:
        self.parents.clear()
        if parent is not None:
            self.parents.append(parent)
        return self._walk(item, exprs_only=False)

    def apply_to_exprs(self, item: Optional[citem_t], parent: Optional[citem_t] = None) -> int:
        self.parents.clear()
        if parent is not None:
            self.parents.append(parent)
        return self._walk(item, exprs_only=True)

    def _walk(self, item: Optional[citem_t], exprs_only: bool) -> int:
        if item is None:
            return 0
        self.clr_prune()
        is_e = isinstance(item, cexpr_t)

        if not self.is_postorder():
            if is_e:
                if not self.only_insns():
                    rc = self.visit_expr(item)
                    if rc != 0:
                        return rc
            elif not exprs_only:
                rc = self.visit_insn(item)
                if rc != 0:
                    return rc

        if self.must_prune():
            self.clr_prune()
            return 0

        pushed = self.maintain_parents()
        if pushed:
            self.parents.append(item)

        rc = 0
        if isinstance(item, cexpr_t):
            if not self.only_insns():
                for child in (item.x, item.y, item.z):
                    if child is not None:
                        rc = self._walk(child, exprs_only)
                        if rc != 0:
                            break
                if rc == 0 and item.a:
                    for arg in item.a:
                        rc = self._walk(arg, exprs_only)
                        if rc != 0:
                            break
        elif isinstance(item, cinsn_t):
            op = item.op
            if op == cit_block:
                for st in item.cblock:
                    rc = self._walk(st, exprs_only)
                    if rc != 0:
                        break
            elif op == cit_expr:
                if not self.only_insns() and item._cexpr_node is not None:
                    rc = self._walk(item._cexpr_node, exprs_only)
            elif op == cit_if:
                if not self.only_insns() and item.cif.expr is not None:
                    rc = self._walk(item.cif.expr, exprs_only)
                if rc == 0 and item.cif.ithen is not None:
                    rc = self._walk(item.cif.ithen, exprs_only)
                if rc == 0 and item.cif.ielse is not None:
                    rc = self._walk(item.cif.ielse, exprs_only)
            elif op in (cit_while, cit_do, cit_for):
                if op == cit_while and not self.only_insns() and item.cloop.expr is not None:
                    rc = self._walk(item.cloop.expr, exprs_only)
                if rc == 0 and item.cloop.body is not None:
                    rc = self._walk(item.cloop.body, exprs_only)
                if rc == 0 and op == cit_do and not self.only_insns() and item.cloop.expr is not None:
                    rc = self._walk(item.cloop.expr, exprs_only)
            elif op == cit_return:
                if not self.only_insns() and item.creturn.expr is not None:
                    rc = self._walk(item.creturn.expr, exprs_only)
            elif op == cit_switch:
                if not self.only_insns() and item.cswitch.expr is not None:
                    rc = self._walk(item.cswitch.expr, exprs_only)
                if rc == 0:
                    for sc in item.cswitch.cases:
                        if sc.body is not None:
                            rc = self._walk(sc.body, exprs_only)
                            if rc != 0:
                                break
                if rc == 0 and item.cswitch.def_body is not None:
                    rc = self._walk(item.cswitch.def_body, exprs_only)

        if pushed:
            self.parents.pop()

        if rc != 0:
            return rc

        if self.is_postorder():
            if is_e:
                if not self.only_insns():
                    return self.leave_expr(item)
            elif not exprs_only:
                return self.leave_insn(item)
        return 0


class cfunc_t:
    def __init__(self, handle: int, borrow: bool = False):
        self._handle = handle
        self._borrow = borrow
        self._dirty_text = False

        dll = _ffi.get_dll()
        raw = _ffi.take_json(dll.rl78dec_abi_cfunc_json(handle, 1))
        if not raw:
            raise DecompilationFailure("Failed to deserialize cfunc_t from rl78dec.dll")

        self.entry_ea: int = int(raw["entry_ea"])
        self.func_name: str = raw["func_name"]
        self.ret_type: str = raw["ret_type"]
        self.signature_line: str = raw["signature_line"]
        self.hdrlines: int = int(raw["hdrlines"])
        self.maturity: int = CMAT_FINAL
        self._lines: list[str] = raw["lines"]
        self._sv: list[simpleline_shim_t] = [simpleline_shim_t(s) for s in raw["sv"]]
        self.lvars: list[lvar_t] = [lvar_t(self, lv) for lv in raw["lvars"]]
        self.argidx: list[int] = [int(x) for x in raw.get("argidx", [])]
        self.arguments: list[lvar_t] = [self.lvars[i] for i in self.argidx if 0 <= i < len(self.lvars)]

        raw_items = raw.get("items", [])
        self.treeitems: list[Optional[citem_t]] = [None] * len(raw_items)
        for node_raw in raw_items:
            if node_raw is None:
                continue
            nid = int(node_raw["id"])
            if node_raw.get("k") == "e":
                self.treeitems[nid] = cexpr_t(self, node_raw)
            else:
                self.treeitems[nid] = cinsn_t(self, node_raw)

        def _get(idx: Optional[int]) -> Optional[citem_t]:
            if idx is None or idx < 0 or idx >= len(self.treeitems):
                return None
            return self.treeitems[idx]

        for node_raw in raw_items:
            if node_raw is None:
                continue
            node = self.treeitems[int(node_raw["id"])]
            if isinstance(node, cexpr_t):
                object.__setattr__(node, "x", _get(node_raw.get("x")))
                object.__setattr__(node, "y", _get(node_raw.get("y")))
                object.__setattr__(node, "z", _get(node_raw.get("z")))
                if "a" in node_raw:
                    object.__setattr__(node, "a", [c for c in (_get(aid) for aid in node_raw["a"]) if c is not None])
            elif isinstance(node, cinsn_t):
                if "blk" in node_raw:
                    for sid in node_raw["blk"]:
                        child = _get(sid)
                        if isinstance(child, cinsn_t):
                            node.cblock.append(child)
                if "e" in node_raw:
                    object.__setattr__(node, "_cexpr_node", _get(node_raw["e"]))
                if "ic" in node_raw:
                    node.cif.expr = _get(node_raw.get("ic"))  # type: ignore[assignment]
                    node.cif.ithen = _get(node_raw.get("it"))  # type: ignore[assignment]
                    node.cif.ielse = _get(node_raw.get("ie"))  # type: ignore[assignment]
                if "lb" in node_raw or "lc" in node_raw:
                    node.cloop.expr = _get(node_raw.get("lc"))  # type: ignore[assignment]
                    node.cloop.body = _get(node_raw.get("lb"))  # type: ignore[assignment]
                if "re" in node_raw:
                    node.creturn.expr = _get(node_raw.get("re"))  # type: ignore[assignment]
                if "sw_cases" in node_raw or "se" in node_raw:
                    node.cswitch.expr = _get(node_raw.get("se"))  # type: ignore[assignment]
                    for sc_raw in node_raw.get("sw_cases", []):
                        sc = cswitch_case_t(
                            [int(v) for v in sc_raw.get("vals", [])],
                            _get(sc_raw.get("b")),  # type: ignore[arg-type]
                        )
                        node.cswitch.cases.append(sc)
                    node.cswitch.def_body = _get(node_raw.get("sw_def"))  # type: ignore[assignment]

        body_id = int(raw.get("body_id", -1))
        self.body: Optional[cinsn_t] = _get(body_id)  # type: ignore[assignment]

        self.eamap: dict[int, list[cinsn_t]] = {}
        for ea_str, id_list in raw.get("eamap", {}).items():
            ea_int = int(ea_str)
            self.eamap[ea_int] = [c for c in (_get(cid) for cid in id_list) if isinstance(c, cinsn_t)]

    def __del__(self) -> None:
        if getattr(self, "_handle", 0) and not getattr(self, "_borrow", True):
            try:
                _ffi.get_dll().rl78dec_abi_release_cfunc(self._handle)
            except Exception:
                pass
            self._handle = 0

    def get_pseudocode(self) -> list[simpleline_shim_t]:
        if self._dirty_text:
            self.refresh_func_ctext()
        return self._sv

    def get_lvars(self) -> list[lvar_t]:
        return self.lvars

    def get_eamap(self) -> dict[int, list[cinsn_t]]:
        return self.eamap

    def refresh_func_ctext(self) -> None:
        if not self._handle:
            return
        dll = _ffi.get_dll()
        _ffi.take_str(dll.rl78dec_abi_cfunc_refresh_ctext(self._handle))
        raw = _ffi.take_json(dll.rl78dec_abi_cfunc_json(self._handle, 0))
        if raw:
            self._lines = raw["lines"]
            self._sv = [simpleline_shim_t(s) for s in raw["sv"]]
        self._dirty_text = False

    def __str__(self) -> str:
        if self._dirty_text:
            self.refresh_func_ctext()
        return "\n".join(self._lines)

    def __repr__(self) -> str:
        return f"<cfunc_t {self.func_name} @ 0x{self.entry_ea:x}>"


class ctree_item_t:
    def __init__(self, item: Optional[citem_t]):
        self.it = item
        self.e: Optional[cexpr_t] = item if isinstance(item, cexpr_t) else None
        self.i: Optional[cinsn_t] = item if isinstance(item, cinsn_t) else None

    def is_citem(self) -> bool:
        return self.it is not None


class vdui_t:
    def __init__(self):
        self.cfunc: Optional[cfunc_t] = None
        self.func_ea: int = BADADDR
        self.lineno: int = 0
        self.col: int = 0
        self.item = ctree_item_t(None)
        self._sync_state()

    def _sync_state(self) -> bool:
        dll = _ffi.get_dll()
        fea = ctypes.c_uint64(0)
        cfh = ctypes.c_uint64(0)
        ln = ctypes.c_int(0)
        col = ctypes.c_int(0)
        cid = ctypes.c_uint32(0xFFFFFFFF)
        if not dll.rl78dec_abi_vdui_get_state(
            ctypes.byref(fea),
            ctypes.byref(cfh),
            ctypes.byref(ln),
            ctypes.byref(col),
            ctypes.byref(cid),
        ):
            return False
        self.func_ea = int(fea.value)
        self.lineno = int(ln.value)
        self.col = int(col.value)
        if cfh.value:
            self.cfunc = cfunc_t(int(cfh.value), borrow=True)
            item_idx = int(cid.value)
            if 0 <= item_idx < len(self.cfunc.treeitems):
                self.item = ctree_item_t(self.cfunc.treeitems[item_idx])
        return True

    def valid(self) -> bool:
        return bool(_ffi.get_dll().rl78dec_abi_vdui_is_open())

    def refresh_view(self, redo_mba: bool = True) -> bool:
        ok = bool(_ffi.get_dll().rl78dec_abi_vdui_refresh(1 if redo_mba else 0))
        if ok:
            self._sync_state()
        return ok

    def refresh_ctext(self, activate: bool = True) -> bool:
        _ = activate
        return self.refresh_view(redo_mba=False)

    def switch_to(self, cfunc_or_ea: Any, activate: bool = True) -> bool:
        _ = activate
        ea = cfunc_or_ea.entry_ea if isinstance(cfunc_or_ea, cfunc_t) else int(cfunc_or_ea)
        ok = bool(_ffi.get_dll().rl78dec_abi_vdui_switch_to(ea, 1))
        if ok:
            self._sync_state()
        return ok

    def get_current_item(self, _mouse: int = 0) -> bool:
        return self._sync_state()

    def rename_lvar(self, lvar: lvar_t, new_name: str, _is_user_name: bool = True) -> bool:
        ok = bool(
            _ffi.get_dll().rl78dec_abi_rename_lvar(
                self.func_ea, lvar.canonical_name.encode("utf-8"), new_name.encode("utf-8")
            )
        )
        if ok:
            self._sync_state()
        return ok

    def set_lvar_type(self, lvar: lvar_t, new_type: Any) -> bool:
        ok = bool(
            _ffi.get_dll().rl78dec_abi_set_lvar_type(
                self.func_ea, lvar.canonical_name.encode("utf-8"), str(new_type).encode("utf-8")
            )
        )
        if ok:
            self._sync_state()
        return ok
