"""
Pseudo-C back-end for the RL78 decompiler.

Registers print as themselves (``a``, ``ax``, ``hl`` ...); memory is ``mem8`` /
``mem16`` indexed by an address expression, with documented SFRs and saddr/RAM
cells shown by name.  Relational conditions come from the flag provenance in
:mod:`rl78dec.structure`; ``ZF``/``CY``/``HF`` appear only where a comparison
could not be recovered.
"""

from . import ir, sfr, opt
from . import structure as S


_PRECEDENCE = {
    "*": 10, "/": 10, "%": 10,
    "+": 9, "-": 9,
    "<<": 8, ">>": 8,
    "<": 7, "<=": 7, ">": 7, ">=": 7,
    "==": 6, "!=": 6,
    "&": 5,
    "^": 4,
    "|": 3,
    "&&": 2,
    "||": 1,
}


def _find_struct_member(struct_def, offset):
    if not struct_def or "members" not in struct_def:
        return None
    for m in struct_def["members"]:
        if m["offset"] == offset:
            return m["name"]
    for m in struct_def["members"]:
        if m["offset"] <= offset < m["offset"] + m.get("size", 1):
            return m["name"]
    return None


def _extract_base_and_offset(addr):
    """If addr is a base var + constant offset, return (var_node, offset)."""
    if isinstance(addr, (ir.Var, ir.Reg)):
        return addr, 0
    if isinstance(addr, ir.Bin) and addr.op == "+":
        if isinstance(addr.l, (ir.Var, ir.Reg)) and isinstance(addr.r, (ir.Const, int)):
            return addr.l, (addr.r.value if isinstance(addr.r, ir.Const) else addr.r)
        if isinstance(addr.r, (ir.Var, ir.Reg)) and isinstance(addr.l, (ir.Const, int)):
            return addr.r, (addr.l.value if isinstance(addr.l, ir.Const) else addr.l)
    if isinstance(addr, ir.Bin) and addr.op == "-":
        if isinstance(addr.l, (ir.Var, ir.Reg)) and isinstance(addr.r, (ir.Const, int)):
            return addr.l, -(addr.r.value if isinstance(addr.r, ir.Const) else addr.r)
    return None, None


def _expr_struct_type(e, var_structs, symbol_structs):
    if isinstance(e, ir.Const):
        name = getattr(e, "name", None)
        if name and name in symbol_structs:
            return symbol_structs[name]
        if e.value in symbol_structs:
            return symbol_structs[e.value]
    elif isinstance(e, (ir.Var, ir.Reg)):
        return var_structs.get(e.name)
    elif isinstance(e, ir.Bin):
        if e.op in ("+", "-"):
            st = _expr_struct_type(e.l, var_structs, symbol_structs)
            if st:
                return st
            if e.op == "+":
                st = _expr_struct_type(e.r, var_structs, symbol_structs)
                if st:
                    return st
    return None


def _infer_struct_pointers(func, struct_defs, symbol_structs, user_types=None, sig=None):
    var_structs = {}
    if user_types:
        for vname, tstr in user_types.items():
            if not isinstance(tstr, str):
                continue
            clean = tstr.strip()
            if clean.endswith("*"):
                base = clean[:-1].strip()
                if base in struct_defs:
                    var_structs[vname] = base
    if sig and getattr(sig, "params", None):
        for p in sig.params:
            if getattr(p, "type_str", None) and p.type_str.strip().endswith("*"):
                base = p.type_str.strip()[:-1].strip()
                if base in struct_defs:
                    var_structs[p.name] = base

    if not struct_defs or not symbol_structs:
        return var_structs

    changed = True
    while changed:
        changed = False
        for blk in func.blocks.values():
            for s in blk.stmts:
                if isinstance(s, ir.Assign) and isinstance(s.dst, (ir.Var, ir.Reg)):
                    st = _expr_struct_type(s.src, var_structs, symbol_structs)
                    if st and var_structs.get(s.dst.name) != st:
                        var_structs[s.dst.name] = st
                        changed = True
    return var_structs


def _infer_far_pointers(func, sig=None, frame_info=None):
    """Identify 20/32-bit far pointer variables and variables derived from them (var -> root_far_name)."""
    far_vars = {}
    if sig and getattr(sig, "params", None):
        for p in sig.params:
            tstr = (getattr(p, "type_str", None) or "").strip()
            if tstr == "uint32_t" or getattr(p, "location", None) == "ax:bc":
                far_vars[p.name] = p.name
    if frame_info:
        for name, (var, width) in (getattr(frame_info, "args", None) or {}).items():
            if width == "d":
                far_vars[name] = name
        for name, (var, width) in (getattr(frame_info, "locals", None) or {}).items():
            if width == "d":
                far_vars[name] = name
        for name, (var, width) in (getattr(frame_info, "virtual_vars", None) or {}).items():
            if width == "d":
                far_vars[name] = name

    if not far_vars:
        return far_vars

    hidden = frame_info.hidden_stmts if frame_info else frozenset()

    def _far_root(e):
        if isinstance(e, (ir.Var, ir.Reg)):
            return far_vars.get(e.name)
        if isinstance(e, ir.Bin) and e.op in ("+", "-"):
            r = _far_root(e.l)
            if r:
                return r
            if e.op == "+":
                return _far_root(e.r)
        return None

    changed = True
    while changed:
        changed = False
        for blk in func.blocks.values():
            for s in blk.stmts:
                if id(s) in hidden:
                    continue
                if isinstance(s, ir.Assign) and isinstance(s.dst, (ir.Var, ir.Reg)):
                    if isinstance(s.dst, ir.Var) and getattr(s.dst, "width", None) == "b":
                        continue
                    root = _far_root(s.src)
                    if root and far_vars.get(s.dst.name) != root:
                        far_vars[s.dst.name] = root
                        changed = True
    return far_vars


def _extract_far_base(addr, far_vars):
    if not far_vars:
        return None
    if isinstance(addr, (ir.Var, ir.Reg)):
        return far_vars.get(addr.name)
    if isinstance(addr, ir.Bin) and addr.op in ("+", "-"):
        r = _extract_far_base(addr.l, far_vars)
        if r:
            return r
        if addr.op == "+":
            return _extract_far_base(addr.r, far_vars)
    return None


def _seg_extracts_var(seg):
    """If seg is (uint8_t)(v >> 16), (uint16_t)(v >> 16), or v >> 16, return v.name."""
    e = seg
    if isinstance(e, ir.Un) and e.op in ("(uint8_t)", "(uint16_t)"):
        e = e.e
    if isinstance(e, ir.Bin) and e.op == ">>" and isinstance(e.r, ir.Const) and e.r.value == 16:
        if isinstance(e.l, (ir.Var, ir.Reg)):
            return e.l.name
    return None


def _seg_matches_far(seg, root_name):
    if seg is None:
        return True
    return _seg_extracts_var(seg) == root_name


class _Emit:
    def __init__(self, namer, block_starts=frozenset(), hidden=frozenset(),
                 user_renames=None, var_structs=None, far_vars=None):
        self.namer = namer
        self.block_starts = block_starts
        self.hidden = hidden
        self.user_renames = user_renames or {}
        self.var_structs = dict(var_structs or {})
        self.far_vars = dict(far_vars or {})
        self.used_labels = set()
        self._pending = []


    # -- expressions --------------------------------------------------------

    def expr(self, e, top=True, parent_op=None, is_right=False):
        if isinstance(e, ir.Const):
            if getattr(e, "name", None):
                return self.user_renames.get(e.name, e.name)
            if hasattr(self.namer, "cell_names") and self.namer.cell_names and e.value in self.namer.cell_names:
                n = self.namer.cell_names[e.value]
                return self.user_renames.get(n, n)
            if hasattr(self.namer, "symbol_structs") and self.namer.symbol_structs and e.value in self.namer.symbol_structs:
                if hasattr(self.namer, "_lookup"):
                    n = self.namer._lookup(e.value)
                    if n:
                        return self.user_renames.get(n, n)
            if e.width == "a" and e.value >= 0x1000:
                return "0x%05X" % e.value
            return str(e.value) if e.value < 10 else "0x%X" % e.value
        if isinstance(e, (ir.Reg, ir.Var)):
            return self.user_renames.get(e.name, e.name)
        if isinstance(e, ir.Mem):
            return self._mem(e)
        if isinstance(e, ir.Bit):
            return "((%s >> %d) & 1)" % (self.expr(e.base, False), e.bit)
        if isinstance(e, ir.Bin):
            e = opt.simplify_math(e)
            if not isinstance(e, ir.Bin):
                return self.expr(e, top, parent_op, is_right)
            my_prec = _PRECEDENCE.get(e.op, 0)
            l_str = self.expr(e.l, False, e.op, False)
            r_str = self.expr(e.r, False, e.op, True)
            s = "%s %s %s" % (l_str, e.op, r_str)
            if parent_op is not None:
                p_prec = _PRECEDENCE.get(parent_op, 0)
                if parent_op in ("<<", ">>", "&", "|", "^") and e.op in ("+", "-", "*", "/", "%"):
                    return "(%s)" % s
                if my_prec < p_prec:
                    return "(%s)" % s
                if my_prec == p_prec and is_right and parent_op in ("-", "/", "%"):
                    return "(%s)" % s
            return s
        if isinstance(e, ir.Un):
            inner = self.expr(e.e, False)
            if isinstance(e.e, ir.Bin):
                return "%s(%s)" % (e.op, inner)
            return "%s%s" % (e.op, inner)
        if isinstance(e, ir.IntrExpr):
            if not e.args:
                return e.name
            if e.name == "mulu":
                if len(e.args) == 2:
                    return "(uint16_t)%s * %s" % (self.expr(e.args[0], False), self.expr(e.args[1], False))
            elif e.name in ("sar", "sarw"):
                if len(e.args) == 2:
                    cast = "int16_t" if (e.name == "sarw" or getattr(e.args[0], "width", None) == "w") else "int8_t"
                    return "((%s)%s >> %s)" % (cast, self.expr(e.args[0], False), self.expr(e.args[1], False))
            elif e.name == "rol":
                if len(e.args) == 1:
                    a = self.expr(e.args[0], False)
                    return "((%s << 1) | (%s >> 7))" % (a, a)
            elif e.name == "ror":
                if len(e.args) == 1:
                    a = self.expr(e.args[0], False)
                    return "((%s >> 1) | (%s << 7))" % (a, a)
            elif e.name in ("rolc", "rolwc"):
                if len(e.args) == 1:
                    return "((%s << 1) | CY)" % self.expr(e.args[0], False)
            elif e.name == "rorc":
                if len(e.args) == 1:
                    return "((%s >> 1) | (CY << 7))" % self.expr(e.args[0], False)
            return "%s(%s)" % (e.name, ", ".join(self.expr(a) for a in e.args))
        return "?"

    def _is_global_addr(self, val, es=False, seg=None):
        if not isinstance(val, int):
            return False
        if 0x10000 <= val <= 0xFFFFF or 0xFE20 <= val <= 0xFFFF:
            return True
        if hasattr(self.namer, "cell_names") and val in self.namer.cell_names:
            return True
        if hasattr(self.namer, "_lookup") and self.namer._lookup(val):
            return True
        if sfr.name_for(val) is not None:
            return True
        is_rom_seg0 = isinstance(seg, ir.Const) and seg.value == 0
        if (es or is_rom_seg0) and 0x1000 <= val < 0x10000:
            return True
        return False

    def _struct_deref(self, addr):
        if not self.var_structs or not getattr(self.namer, "struct_defs", None):
            return None
        if isinstance(addr, ir.Bin):
            addr = opt.simplify_math(addr)
        base_var, offset = _extract_base_and_offset(addr)
        if base_var and offset is not None:
            st_name = self.var_structs.get(base_var.name)
            if st_name and st_name in self.namer.struct_defs:
                mname = _find_struct_member(self.namer.struct_defs[st_name], offset)
                if mname:
                    vname = self.user_renames.get(base_var.name, base_var.name)
                    return f"{vname}->{mname}"
        return None

    def _deref(self, ctype, expr_node):
        s = self.expr(expr_node, False)
        if isinstance(expr_node, (ir.Var, ir.Reg)):
            return "*(%s *)%s" % (ctype, s)
        return "*(%s *)(%s)" % (ctype, s)

    def _mem(self, e):
        ctype = "uint16_t" if e.width == "w" else "uint8_t"
        if getattr(e, "name", None):
            return self.user_renames.get(e.name, e.name)

        sd = self._struct_deref(e.addr)
        if sd:
            return sd

        addr = opt.simplify_math(e.addr) if isinstance(e.addr, ir.Bin) else e.addr
        if isinstance(addr, ir.Const):
            addr = addr.value

        seg = getattr(e, "seg", None)
        if isinstance(seg, ir.Bin):
            seg = opt.simplify_math(seg)
        seg_val = (seg.value & 0xF) if isinstance(seg, ir.Const) else (seg & 0xF if isinstance(seg, int) else None)

        # Constant segment + constant offset -> single 20-bit linear address symbol
        if e.es and seg_val is not None and isinstance(addr, int):
            linear = ((seg_val << 16) | (addr & 0xFFFF)) & 0xFFFFF
            name = self.namer.cell(linear)
            return self.user_renames.get(name, name)

        # Already-20-bit far pointer (consolidated uint32_t param, uint32_t return, or derived pointer)
        if isinstance(addr, ir.Expr):
            far_root = _extract_far_base(addr, self.far_vars)
            if far_root is not None and (not e.es or _seg_matches_far(seg, far_root)):
                return self._deref(ctype, addr)

        # Check if addr is an addition of a base global address and an index
        if isinstance(addr, ir.Bin) and addr.op == "+":
            # Check if one side is an explicitly named constant
            if isinstance(addr.l, ir.Const) and getattr(addr.l, "name", None):
                base_name = self.user_renames.get(addr.l.name, addr.l.name)
                return "%s[%s]" % (base_name, self.expr(addr.r))
            if isinstance(addr.r, ir.Const) and getattr(addr.r, "name", None):
                base_name = self.user_renames.get(addr.r.name, addr.r.name)
                return "%s[%s]" % (base_name, self.expr(addr.l))

            if not e.es or seg_val is not None:
                l_val = addr.l.value if isinstance(addr.l, ir.Const) else (addr.l if isinstance(addr.l, int) else None)
                r_val = addr.r.value if isinstance(addr.r, ir.Const) else (addr.r if isinstance(addr.r, int) else None)

                base_addr = None
                idx_expr = None

                if l_val is not None and self._is_global_addr(l_val, e.es, seg):
                    if e.es and seg_val is not None:
                        base_addr = ((seg_val << 16) | (l_val & 0xFFFF)) & 0xFFFFF
                    else:
                        base_addr = (0xF0000 | l_val) if (0xFE20 <= l_val <= 0xFFFF and seg is None) else l_val
                    idx_expr = addr.r
                elif r_val is not None and self._is_global_addr(r_val, e.es, seg):
                    if e.es and seg_val is not None:
                        base_addr = ((seg_val << 16) | (r_val & 0xFFFF)) & 0xFFFFF
                    else:
                        base_addr = (0xF0000 | r_val) if (0xFE20 <= r_val <= 0xFFFF and seg is None) else r_val
                    idx_expr = addr.l

                if base_addr is not None and idx_expr is not None:
                    base_name = self.namer.cell(base_addr)
                    base_name = self.user_renames.get(base_name, base_name)
                    return "%s[%s]" % (base_name, self.expr(idx_expr))

        if isinstance(addr, ir.Bin) and addr.op == "-" and (not e.es or seg_val is not None):
            l_val = addr.l.value if isinstance(addr.l, ir.Const) else (addr.l if isinstance(addr.l, int) else None)
            if l_val is not None and self._is_global_addr(l_val, e.es, seg):
                if e.es and seg_val is not None:
                    base_addr = ((seg_val << 16) | (l_val & 0xFFFF)) & 0xFFFFF
                else:
                    base_addr = (0xF0000 | l_val) if (0xFE20 <= l_val <= 0xFFFF and seg is None) else l_val
                base_name = self.namer.cell(base_addr)
                base_name = self.user_renames.get(base_name, base_name)
                return "%s[-(%s)]" % (base_name, self.expr(addr.r))

        if isinstance(addr, ir.Expr):
            if e.es:
                if seg_val is not None:
                    if seg_val == 0:
                        return self._deref(ctype, addr)
                    off_str = self.expr(addr, False, "|", True)
                    return "*(%s *)(0x%X0000 | %s)" % (ctype, seg_val, off_str)
                if seg is not None:
                    seg_str = self.expr(seg, False)
                    if isinstance(seg, ir.Bin):
                        seg_str = "(%s)" % seg_str
                else:
                    seg_str = "es"
                off_str = self.expr(addr, False, "|", True)
                return "*(%s *)(((uint32_t)%s << 16) | %s)" % (ctype, seg_str, off_str)
            return self._deref(ctype, addr)

        if e.es:
            if seg is not None:
                seg_str = self.expr(seg, False)
                if isinstance(seg, ir.Bin):
                    seg_str = "(%s)" % seg_str
            else:
                seg_str = "es"
            return "*(%s *)(((uint32_t)%s << 16) | 0x%04X)" % (ctype, seg_str, addr & 0xFFFF)

        name = self.namer.cell(addr)
        return self.user_renames.get(name, name)

    # -- statements ---------------------------------------------------------

    def stmt(self, s):
        if isinstance(s, ir.Assign):
            return "%s = %s;" % (self.expr(s.dst), self.expr(s.src))
        if isinstance(s, ir.Swap):
            return "SWAP(%s, %s);" % (self.expr(s.a), self.expr(s.b))
        if isinstance(s, ir.Call):
            args_str = ", ".join(self.expr(a) for a in s.args)
            if s.target is not None:
                call_str = "%s(%s)" % (self.namer.code(s.target), args_str)
            else:
                call_str = "(*%s)(%s)" % (self.expr(s.expr), args_str)
            if s.dst is not None:
                return "%s = %s;" % (self.expr(s.dst), call_str)
            return "%s;" % call_str
        if isinstance(s, ir.Intrinsic):
            if s.name == "brk":
                if s.args and isinstance(s.args[0], ir.Const):
                    return "brk();   /* swi -> %s */" % self.namer.code(s.args[0].value)
                return "brk();   /* swi [0x007E] */"
            call = "%s(%s);" % (s.name, ", ".join(self.expr(a) for a in s.args))
            return call + ("   /* %s */" % s.note if s.note else "")
        return "/* %s */" % type(s).__name__


    # -- tree ---------------------------------------------------------------

    def emit(self, nodes, ind):
        pad = "    " * ind
        for n in nodes:
            if isinstance(n, S.SLabel):
                self._pending.append((ind, None, n.ea))
            elif isinstance(n, S.SStmt):
                if id(n.stmt) in self.hidden:
                    continue
                self._pending.append((ind, pad + self.stmt(n.stmt), getattr(n.stmt, "ea", None)))
            elif isinstance(n, S.SRet):
                ret_ea = getattr(n, "ea", None)
                ret_kind = getattr(n, "kind", "ret")
                suffix = ("   /* %s */" % ret_kind) if ret_kind in ("reti", "retb") else ""
                if getattr(n, "val", None) is not None:
                    self._pending.append((ind, pad + "return %s;%s" % (self.expr(n.val), suffix), ret_ea))
                else:
                    self._pending.append((ind, pad + "return;%s" % suffix, ret_ea))

            elif isinstance(n, S.SGoto):
                if n.ea in self.block_starts:
                    self.used_labels.add(n.ea)
                    self._pending.append((ind, pad + "goto %s;" % self.namer.label(n.ea), n.ea))
                else:                       # out-of-function tail jump
                    self._pending.append((ind, pad + "JUMPOUT(%s);" % self._ext(n.ea), n.ea))
            elif isinstance(n, S.SIfGoto):
                if n.ea in self.block_starts:
                    self.used_labels.add(n.ea)
                    tail = "goto %s;" % self.namer.label(n.ea)
                else:
                    tail = "JUMPOUT(%s);" % self._ext(n.ea)
                self._pending.append((ind, pad + "if (%s) %s" % (self.expr(n.cond), tail), getattr(n, "ea", None)))
            elif isinstance(n, S.SBreak):
                self._pending.append((ind, pad + "break;", getattr(n, "ea", None)))
            elif isinstance(n, S.SBreakIf):
                self._pending.append((ind, pad + "if (%s) break;" % self.expr(n.cond), getattr(n, "ea", None)))
            elif isinstance(n, S.SContinue):
                if n.cond is None:
                    self._pending.append((ind, pad + "continue;", getattr(n, "ea", None)))
                else:
                    self._pending.append((ind, pad + "if (%s) continue;" % self.expr(n.cond), getattr(n, "ea", None)))
            elif isinstance(n, S.SIf):
                self._pending.append((ind, pad + "if (%s) {" % self.expr(n.cond), getattr(n, "ea", None)))
                self.emit(n.then, ind + 1)
                if n.els:
                    self._pending.append((ind, pad + "} else {", None))
                    self.emit(n.els, ind + 1)
                self._pending.append((ind, pad + "}", None))
            elif isinstance(n, S.SSwitch):
                self._pending.append((ind, pad + "switch (%s) {" % self.expr(n.expr), getattr(n, "ea", None)))
                for vals, body in n.cases:
                    for v in sorted(vals):
                        self._pending.append((ind, pad + "case %d:" % v, None))
                    self.emit(body, ind + 1)
                    if not (body and isinstance(body[-1], (S.SRet, S.SGoto, S.SBreak))):
                        self._pending.append((ind + 1, pad + "    break;", None))
                if n.default:
                    self._pending.append((ind, pad + "default:", None))
                    self.emit(n.default, ind + 1)
                    if not (n.default and isinstance(n.default[-1], (S.SRet, S.SGoto, S.SBreak))):
                        self._pending.append((ind + 1, pad + "    break;", None))
                self._pending.append((ind, pad + "}", None))
            elif isinstance(n, S.SWhile):
                self._emit_while(n, ind)

    def _emit_while(self, n, ind):
        pad = "    " * ind
        body = list(n.body)
        tail = None
        ea = getattr(n, "ea", None)
        if body and isinstance(body[-1], S.SContinue) and body[-1].cond is not None:
            tail = body[-1].cond
            body = body[:-1]
        if tail is not None:
            self._pending.append((ind, pad + "do {", ea))
            self.emit(body, ind + 1)
            self._pending.append((ind, pad + "} while (%s);" % self.expr(tail), ea))
        else:
            self._pending.append((ind, pad + "while (1) {", ea))
            self.emit(body, ind + 1)
            self._pending.append((ind, pad + "}", ea))

    def _ext(self, ea):
        n = self.namer.code_names.get(ea) if hasattr(self.namer, "code_names") else None
        return n or "0x%05X" % ea

    def flush(self):
        lines = []
        line_eas = []
        for ind, text, ea in self._pending:
            if text is None:
                if ea in self.used_labels:
                    lines.append("%s:" % self.namer.label(ea))
                    line_eas.append(ea)
                continue
            lines.append(text)
            line_eas.append(ea)
        return lines, line_eas


class CodeLines(list):
    pass


def generate(func, tree, namer, frame_info=None, sig=None, banner=None,
             user_renames=None, user_types=None, user_comments=None, with_ea=False):
    hidden = frame_info.hidden_stmts if frame_info else frozenset()
    u_renames = dict(getattr(frame_info, "user_renames", {}) or {})
    if user_renames:
        u_renames.update(user_renames)
    u_types = dict(getattr(frame_info, "user_types", {}) or {})
    if user_types:
        u_types.update(user_types)
    u_comments = user_comments or {}

    struct_defs = getattr(namer, "struct_defs", {}) or {}
    symbol_structs = getattr(namer, "symbol_structs", {}) or {}
    var_structs = _infer_struct_pointers(func, struct_defs, symbol_structs, user_types=u_types, sig=sig)
    far_vars = _infer_far_pointers(func, sig=sig, frame_info=frame_info)

    em = _Emit(namer, block_starts=frozenset(func.blocks), hidden=hidden,
               user_renames=u_renames, var_structs=var_structs, far_vars=far_vars)
    em.emit(tree, 1)
    body, body_eas = em.flush()
    out = CodeLines()
    line_eas = []

    def _add_line(text, ea=None):
        out.append(text)
        line_eas.append(ea)

    if banner:
        for b_ln in banner:
            _add_line(b_ln, None)

    fn_entry = func.entry
    if sig is not None:
        fn_name = namer.code(fn_entry)
        ret_t = u_types.get("__return__", sig.ret_type)
        if sig.params:
            param_parts = []
            for p in sig.params:
                p_name = u_renames.get(p.name, p.name)
                p_type = u_types.get(p.name, u_types.get(p_name, p.type_str))
                param_parts.append(f"{p_type} {p_name}")
            pstr = ", ".join(param_parts)
        else:
            pstr = "void"
        _add_line(f"{ret_t} {fn_name}({pstr})", fn_entry)
    else:
        _add_line("void %s(void)" % namer.code(fn_entry), fn_entry)

    _add_line("{", fn_entry)

    decls = []
    if frame_info and frame_info.locals:
        for name, (var, width) in sorted(frame_info.locals.items(), key=lambda kv: kv[1][0].offset):
            eff_name = u_renames.get(name, name)
            default_t = "uint32_t" if (width == "d" or name in far_vars) else ("uint16_t" if width == "w" else "uint8_t")
            if name in var_structs:
                default_t = f"{var_structs[name]} *"
            tstr = u_types.get(name, u_types.get(eff_name, default_t))
            sep = "" if tstr.endswith("*") else " "
            decls.append("    %s%s%s;" % (tstr, sep, eff_name))
    if frame_info and getattr(frame_info, "virtual_vars", None):
        def sort_key(kv):
            name = kv[0]
            if name.startswith("v") and name[1:].isdigit():
                return (0, int(name[1:]))
            return (1, name)
        for name, (var, width) in sorted(frame_info.virtual_vars.items(), key=sort_key):
            if frame_info.locals and name in frame_info.locals:
                continue
            eff_name = u_renames.get(name, name)
            default_t = "uint32_t" if (width == "d" or name in far_vars) else ("uint16_t" if width == "w" else "uint8_t")
            if name in var_structs:
                default_t = f"{var_structs[name]} *"
            tstr = u_types.get(name, u_types.get(eff_name, default_t))
            sep = "" if tstr.endswith("*") else " "
            decls.append("    %s%s%s;" % (tstr, sep, eff_name))

    for d in decls:
        _add_line(d, None)
    if decls and body:
        _add_line("", None)

    for b_ln, b_ea in zip(body, body_eas):
        if b_ea is not None and u_comments:
            comm = u_comments.get(b_ea) or u_comments.get(str(b_ea)) or u_comments.get(hex(b_ea))
            if comm:
                b_ln = f"{b_ln}  // {comm}"
        _add_line(b_ln, b_ea)

    _add_line("}", fn_entry)

    out.line_eas = line_eas
    if with_ea:
        return out, line_eas
    return out
