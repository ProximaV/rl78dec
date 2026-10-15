"""
Pseudo-C back-end for the RL78 decompiler.

Registers print as themselves (``a``, ``ax``, ``hl`` ...); memory is ``mem8`` /
``mem16`` indexed by an address expression, with documented SFRs and saddr/RAM
cells shown by name.  Relational conditions come from the flag provenance in
:mod:`rl78dec.structure`; ``ZF``/``CY``/``HF`` appear only where a comparison
could not be recovered.
"""

from . import ir, sfr
from . import structure as S


class _Emit:
    def __init__(self, namer, block_starts=frozenset(), hidden=frozenset(), user_renames=None):
        self.namer = namer
        self.block_starts = block_starts
        self.hidden = hidden
        self.user_renames = user_renames or {}
        self.used_labels = set()
        self._pending = []


    # -- expressions --------------------------------------------------------

    def expr(self, e, top=True):
        if isinstance(e, ir.Const):
            if e.width == "a":
                return "0x%05X" % e.value
            return str(e.value) if e.value < 10 else "0x%X" % e.value
        if isinstance(e, (ir.Reg, ir.Var)):
            return self.user_renames.get(e.name, e.name)
        if isinstance(e, ir.Mem):
            return self._mem(e)
        if isinstance(e, ir.Bit):
            return "((%s >> %d) & 1)" % (self.expr(e.base, False), e.bit)
        if isinstance(e, ir.Bin):
            s = "%s %s %s" % (self.expr(e.l, False), e.op, self.expr(e.r, False))
            return s if top else "(%s)" % s
        if isinstance(e, ir.Un):
            return "%s%s" % (e.op, self.expr(e.e, False))
        if isinstance(e, ir.IntrExpr):
            if not e.args:
                return e.name
            return "%s(%s)" % (e.name, ", ".join(self.expr(a) for a in e.args))
        return "?"

    def _is_global_addr(self, val, es=False):
        if not isinstance(val, int):
            return False
        if 0xF0000 <= val <= 0xFFFFF or 0xFE20 <= val <= 0xFFFF:
            return True
        if hasattr(self.namer, "cell_names") and val in self.namer.cell_names:
            return True
        if hasattr(self.namer, "_lookup") and self.namer._lookup(val):
            return True
        if sfr.name_for(val) is not None:
            return True
        if es and 0x800 <= val < 0x80000:
            return True
        return False

    def _mem(self, e):
        w = "16" if e.width == "w" else "8"
        addr = e.addr
        if isinstance(addr, ir.Const):
            addr = addr.value

        # Check if addr is an addition of a base global address and an index
        if isinstance(addr, ir.Bin) and addr.op == "+":
            l_val = addr.l.value if isinstance(addr.l, ir.Const) else (addr.l if isinstance(addr.l, int) else None)
            r_val = addr.r.value if isinstance(addr.r, ir.Const) else (addr.r if isinstance(addr.r, int) else None)

            base_addr = None
            idx_expr = None

            if l_val is not None and self._is_global_addr(l_val, e.es):
                base_addr = (0xF0000 | l_val) if (0xFE20 <= l_val <= 0xFFFF and not e.es) else l_val
                idx_expr = addr.r
            elif r_val is not None and self._is_global_addr(r_val, e.es):
                base_addr = (0xF0000 | r_val) if (0xFE20 <= r_val <= 0xFFFF and not e.es) else r_val
                idx_expr = addr.l

            if base_addr is not None and idx_expr is not None:
                base_name = self.namer.cell(base_addr)
                base_name = self.user_renames.get(base_name, base_name)
                return "%s[%s]" % (base_name, self.expr(idx_expr))

        if isinstance(addr, ir.Bin) and addr.op == "-":
            l_val = addr.l.value if isinstance(addr.l, ir.Const) else (addr.l if isinstance(addr.l, int) else None)
            if l_val is not None and self._is_global_addr(l_val, e.es):
                base_addr = (0xF0000 | l_val) if (0xFE20 <= l_val <= 0xFFFF and not e.es) else l_val
                base_name = self.namer.cell(base_addr)
                base_name = self.user_renames.get(base_name, base_name)
                return "%s[-(%s)]" % (base_name, self.expr(addr.r))

        if isinstance(addr, ir.Expr):
            pre = "es_mem" if e.es else "mem"
            return "%s%s[%s]" % (pre, w, self.expr(addr))

        if e.es:
            full_addr = ((0xF0000 | addr) if addr < 0x10000 else addr)
            if hasattr(self.namer, "_lookup"):
                n = self.namer._lookup(full_addr) or self.namer._lookup(addr)
                if n:
                    return self.user_renames.get(n, n)
            if hasattr(self.namer, "cell_names") and (full_addr in self.namer.cell_names or addr in self.namer.cell_names):
                n = self.namer.cell(full_addr if full_addr in self.namer.cell_names else addr)
                return self.user_renames.get(n, n)
            return "es_mem%s[0x%04X]" % (w, addr & 0xFFFF)

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
                self._pending.append((ind, pad + self.stmt(n.stmt), None))
            elif isinstance(n, S.SRet):
                if getattr(n, "val", None) is not None:
                    self._pending.append((ind, pad + "return %s;" % self.expr(n.val), None))
                else:
                    self._pending.append((ind, pad + "return;", None))

            elif isinstance(n, S.SGoto):
                if n.ea in self.block_starts:
                    self.used_labels.add(n.ea)
                    self._pending.append((ind, pad + "goto %s;" % self.namer.label(n.ea), None))
                else:                       # out-of-function tail jump
                    self._pending.append((ind, pad + "JUMPOUT(%s);" % self._ext(n.ea), None))
            elif isinstance(n, S.SIfGoto):
                if n.ea in self.block_starts:
                    self.used_labels.add(n.ea)
                    tail = "goto %s;" % self.namer.label(n.ea)
                else:
                    tail = "JUMPOUT(%s);" % self._ext(n.ea)
                self._pending.append((ind, pad + "if (%s) %s" % (self.expr(n.cond), tail), None))
            elif isinstance(n, S.SBreak):
                self._pending.append((ind, pad + "break;", None))
            elif isinstance(n, S.SBreakIf):
                self._pending.append((ind, pad + "if (%s) break;" % self.expr(n.cond), None))
            elif isinstance(n, S.SContinue):
                if n.cond is None:
                    self._pending.append((ind, pad + "continue;", None))
                else:
                    self._pending.append((ind, pad + "if (%s) continue;" % self.expr(n.cond), None))
            elif isinstance(n, S.SIf):
                self._pending.append((ind, pad + "if (%s) {" % self.expr(n.cond), None))
                self.emit(n.then, ind + 1)
                if n.els:
                    self._pending.append((ind, pad + "} else {", None))
                    self.emit(n.els, ind + 1)
                self._pending.append((ind, pad + "}", None))
            elif isinstance(n, S.SSwitch):
                self._pending.append((ind, pad + "switch (%s) {" % self.expr(n.expr), None))
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
        if body and isinstance(body[-1], S.SContinue) and body[-1].cond is not None:
            tail = body[-1].cond
            body = body[:-1]
        if tail is not None:
            self._pending.append((ind, pad + "do {", None))
            self.emit(body, ind + 1)
            self._pending.append((ind, pad + "} while (%s);" % self.expr(tail), None))
        else:
            self._pending.append((ind, pad + "while (1) {", None))
            self.emit(body, ind + 1)
            self._pending.append((ind, pad + "}", None))

    def _ext(self, ea):
        n = self.namer.code_names.get(ea) if hasattr(self.namer, "code_names") else None
        return n or "0x%05X" % ea

    def flush(self):
        out = []
        for ind, text, label_ea in self._pending:
            if label_ea is not None:
                if label_ea in self.used_labels:
                    out.append("%s:" % self.namer.label(label_ea))
                continue
            out.append(text)
        return out


def generate(func, tree, namer, frame_info=None, sig=None, banner=None, user_renames=None, user_types=None):
    hidden = frame_info.hidden_stmts if frame_info else frozenset()
    u_renames = dict(getattr(frame_info, "user_renames", {}) or {})
    if user_renames:
        u_renames.update(user_renames)
    u_types = dict(getattr(frame_info, "user_types", {}) or {})
    if user_types:
        u_types.update(user_types)

    em = _Emit(namer, block_starts=frozenset(func.blocks), hidden=hidden, user_renames=u_renames)
    em.emit(tree, 1)
    body = em.flush()
    out = []
    if banner:
        out.extend(banner)
    if sig is not None:
        # Render signature with applied parameter renames and type overrides
        fn_name = namer.code(func.entry)
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
        out.append(f"{ret_t} {fn_name}({pstr})")
    else:
        out.append("void %s(void)" % namer.code(func.entry))
    out.append("{")
    decls = []
    if frame_info and frame_info.locals:
        for name, (var, width) in sorted(frame_info.locals.items(), key=lambda kv: kv[1][0].offset):
            eff_name = u_renames.get(name, name)
            default_t = "uint16_t" if width == "w" else "uint8_t"
            tstr = u_types.get(name, u_types.get(eff_name, default_t))
            decls.append("    %s %s;" % (tstr, eff_name))
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
            default_t = "uint16_t" if width == "w" else "uint8_t"
            tstr = u_types.get(name, u_types.get(eff_name, default_t))
            decls.append("    %s %s;" % (tstr, eff_name))
    if decls:
        out.extend(decls)
        if body:
            out.append("")
    out.extend(body)
    out.append("}")
    return out

