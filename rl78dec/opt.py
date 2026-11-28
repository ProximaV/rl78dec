"""
Conservative, block-local optimisation for RL78 IR.

Propagates register constants and copies into later uses within a basic block
and folds constant expressions.

Key features:
- Atom-level constant tracking: register pairs (AX, BC, DE, HL, SP) decompose into
  low and high byte atoms. Writing A updates A without clobbering X; reading AX
  composes from A and X.
- Copy propagation: copies between registers/temporaries are tracked and killed
  whenever any atom of the source or destination is overwritten.
- Register bank tracking: default RB0 at block/function entry. 'sel rbN' switches
  the active bank and clears all GPR constants/copies. Direct PSW writes or
  bank-flag modifications mark the bank unknown and clear GPRs.
- Memory-mapped GPR aliasing: stores/loads to/from addresses in the active GPR bank
  (0xFFEE0..0xFFEFF) are canonicalised as register accesses.
- Address canonicalisation: known ES constants fold into ES-prefixed addresses;
  near pointers fold to 0xF0000 | addr.
- Swap support: ir.Swap(a, b) swaps tracked constants/copies between operands
  without substituting their lvalue arguments.
- Lvalue protection: destination arguments of intrinsics (pop, set_bit, clr_bit)
  are protected from constant substitution.
- Result flags: FlagDef("result") uses the post-assignment value of the destination.
"""

from . import ir, regs

_OPS = {
    "+": lambda a, b: a + b,
    "-": lambda a, b: a - b,
    "*": lambda a, b: a * b,
    "|": lambda a, b: a | b,
    "&": lambda a, b: a & b,
    "^": lambda a, b: a ^ b,
    "<<": lambda a, b: a << (b & 31),
    ">>": lambda a, b: a >> (b & 31),
}

_LVAL_ARGS = {
    "pop": {0},
    "set_bit": {0},
    "clr_bit": {0},
}


def simplify_math(e):
    if not isinstance(e, ir.Bin):
        return e

    l = simplify_math(e.l) if isinstance(e.l, ir.Bin) else e.l
    r = simplify_math(e.r) if isinstance(e.r, ir.Bin) else e.r
    e = ir.Bin(e.op, l, r)

    if e.op not in ("+", "-"):
        return e

    terms = {}        # base_expr -> net_coefficient (int)
    named_consts = {} # Const -> coeff
    const_val = 0
    const_width = "b"

    def collect(node, mult):
        nonlocal const_val, const_width
        if isinstance(node, ir.Bin):
            if node.op == "+":
                collect(node.l, mult)
                collect(node.r, mult)
                return
            elif node.op == "-":
                collect(node.l, mult)
                collect(node.r, -mult)
                return
            elif node.op == "*":
                if isinstance(node.r, ir.Const) and getattr(node.r, "name", None) is None:
                    collect(node.l, mult * node.r.value)
                    return
                elif isinstance(node.l, ir.Const) and getattr(node.l, "name", None) is None:
                    collect(node.r, mult * node.l.value)
                    return
        elif isinstance(node, ir.Const):
            if getattr(node, "name", None):
                named_consts[node] = named_consts.get(node, 0) + mult
                return
            else:
                const_val += mult * node.value
                if node.width == "a" or abs(const_val) > 0xFFFF:
                    const_width = "a"
                elif node.width == "w" and const_width != "a":
                    const_width = "w"
                elif abs(const_val) > 0xFF and const_width == "b":
                    const_width = "w"
                return
        elif isinstance(node, ir.Un) and node.op == "-":
            collect(node.e, -mult)
            return

        terms[node] = terms.get(node, 0) + mult

    collect(e, 1)

    parts = []
    # 1. Variables and general terms
    for term, coeff in terms.items():
        if coeff == 0:
            continue
        if coeff == 1:
            parts.append((term, 1))
        elif coeff > 1:
            width = getattr(term, "width", "w")
            parts.append((ir.Bin("*", term, ir.Const(coeff, width)), 1))
        else:
            width = getattr(term, "width", "w")
            parts.append((ir.Bin("*", term, ir.Const(-coeff, width)), -1))

    # 2. Named constants
    for nconst, coeff in named_consts.items():
        if coeff == 0:
            continue
        if coeff == 1:
            parts.append((nconst, 1))
        elif coeff > 1:
            parts.append((ir.Bin("*", nconst, ir.Const(coeff, nconst.width)), 1))
        else:
            parts.append((ir.Bin("*", nconst, ir.Const(-coeff, nconst.width)), -1))

    # 3. Numeric constant
    if const_val != 0:
        if abs(const_val) > 0xFFFF:
            const_width = "a"
        elif abs(const_val) > 0xFF and const_width == "b":
            const_width = "w"
        if const_val > 0:
            parts.append((ir.Const(const_val, const_width), 1))
        else:
            parts.append((ir.Const(-const_val, const_width), -1))

    if not parts:
        return ir.Const(0)

    first_term, first_sign = parts[0]
    res = first_term if first_sign > 0 else ir.Un("-", first_term)
    for p, sign in parts[1:]:
        if sign > 0:
            res = ir.Bin("+", res, p)
        else:
            res = ir.Bin("-", res, p)
    return res


def _fold(e):
    if isinstance(e, ir.Bin):
        l, r = _fold(e.l), _fold(e.r)
        if isinstance(l, ir.Const) and isinstance(r, ir.Const) and e.op in _OPS:
            w = "a" if "a" in (l.width, r.width) else ("w" if "w" in (l.width, r.width) else "b")
            v = _OPS[e.op](l.value, r.value)
            if v is not None:
                return ir.Const(v, w)
        if isinstance(r, ir.Const) and r.value == 0 and e.op in ("+", "-", "|", "^", "<<", ">>"):
            return l
        if isinstance(l, ir.Const) and l.value == 0 and e.op in ("+", "|", "^"):
            return r
        if isinstance(r, ir.Const) and r.value == 1 and e.op == "*":
            return l
        if isinstance(l, ir.Const) and l.value == 1 and e.op == "*":
            return r
        if (isinstance(r, ir.Const) and r.value == 0 and e.op == "*") or (isinstance(l, ir.Const) and l.value == 0 and e.op == "*"):
            return ir.Const(0)

        if e.op in ("+", "-"):
            return simplify_math(ir.Bin(e.op, l, r))

        return ir.Bin(e.op, l, r)
    if isinstance(e, ir.Un):
        sub = _fold(e.e)
        if isinstance(sub, ir.Const):
            if e.op == "!":
                return ir.Const(0 if sub.value else 1, sub.width)
            if e.op == "~":
                return ir.Const(~sub.value, sub.width)
        return ir.Un(e.op, sub)
    if isinstance(e, ir.Mem):
        return ir.Mem(_fold(e.addr) if isinstance(e.addr, ir.Expr) else e.addr,
                      e.width, e.es, e.name,
                      _fold(e.seg) if isinstance(e.seg, ir.Expr) else e.seg)
    if isinstance(e, ir.Bit):
        base = _fold(e.base)
        if isinstance(base, ir.Const):
            return ir.Const((base.value >> e.bit) & 1)
        return ir.Bit(base, e.bit)
    if isinstance(e, ir.IntrExpr):
        return ir.IntrExpr(e.name, [_fold(a) for a in e.args])
    return e


def _mentions_any_atom(e, target_atoms):
    if isinstance(e, ir.Reg):
        return bool(set(regs.atoms(e.name)) & target_atoms)
    if isinstance(e, ir.Var):
        return False
    if isinstance(e, ir.Bin):
        return _mentions_any_atom(e.l, target_atoms) or _mentions_any_atom(e.r, target_atoms)
    if isinstance(e, ir.Un):
        return _mentions_any_atom(e.e, target_atoms)
    if isinstance(e, ir.Mem):
        return ((isinstance(e.addr, ir.Expr) and _mentions_any_atom(e.addr, target_atoms)) or
                (isinstance(e.seg, ir.Expr) and _mentions_any_atom(e.seg, target_atoms)))
    if isinstance(e, ir.Bit):
        return _mentions_any_atom(e.base, target_atoms)
    if isinstance(e, ir.IntrExpr):
        return any(_mentions_any_atom(a, target_atoms) for a in e.args)
    return False


def _mentions_var(e, var_name):
    if isinstance(e, (ir.Var, ir.StackVar)):
        return e.name == var_name
    if isinstance(e, ir.Bin):
        return _mentions_var(e.l, var_name) or _mentions_var(e.r, var_name)
    if isinstance(e, ir.Un):
        return _mentions_var(e.e, var_name)
    if isinstance(e, ir.Mem):
        return ((isinstance(e.addr, ir.Expr) and _mentions_var(e.addr, var_name)) or
                (isinstance(e.seg, ir.Expr) and _mentions_var(e.seg, var_name)))
    if isinstance(e, ir.Bit):
        return _mentions_var(e.base, var_name)
    if isinstance(e, ir.IntrExpr):
        return any(_mentions_var(a, var_name) for a in e.args)
    return False


def _mentions_mem(e, target_addr=None):
    if isinstance(e, ir.Mem):
        if target_addr is None:
            return True
        raw = e.addr if isinstance(e.addr, int) else (e.addr.value if isinstance(e.addr, ir.Const) else None)
        return raw is None or raw == target_addr
    if isinstance(e, ir.Bin):
        return _mentions_mem(e.l, target_addr) or _mentions_mem(e.r, target_addr)
    if isinstance(e, ir.Un):
        return _mentions_mem(e.e, target_addr)
    if isinstance(e, ir.Bit):
        return _mentions_mem(e.base, target_addr)
    if isinstance(e, ir.IntrExpr):
        return any(_mentions_mem(a, target_addr) for a in e.args)
    return False


class Env:
    def __init__(self, bank=0):
        self.bank = bank              # active register bank (0..3 or None for unknown)
        self.atom_consts = {}         # atom (str) -> int (0..255)
        self.copies = {}              # reg_name (str) -> Expr
        self.var_consts = {}          # var_name (str) -> int
        self.var_copies = {}          # var_name (str) -> Expr
        self.const_names = {}         # reg_name (str) -> str
        self.es_expr = None           # symbolic Expr last written to ES
        self.es_fallback = None       # memory backing for ES if es_expr reg is clobbered
        self.seg_cells = {}           # saddr scratch addr (0xFFE20..0xFFEFF) -> Expr
        self.reg_seg_hint = {}        # byte reg -> Const/Mem/Expr hint for MOV ES, A

    def clear(self):
        self.atom_consts.clear()
        self.copies.clear()
        self.var_copies.clear()
        self.const_names.clear()
        self.es_expr = None
        self.es_fallback = None
        self.seg_cells.clear()
        self.reg_seg_hint.clear()

    def _kill_var_seg_deps(self, name):
        if self.es_fallback is not None and _mentions_var(self.es_fallback, name):
            self.es_fallback = None
        if self.es_expr is not None and _mentions_var(self.es_expr, name):
            self.es_expr = self.es_fallback
            self.es_fallback = None
        for k in [k for k, v in self.seg_cells.items() if _mentions_var(v, name)]:
            self.seg_cells.pop(k, None)
        for k in [k for k, v in self.reg_seg_hint.items() if _mentions_var(v, name)]:
            self.reg_seg_hint.pop(k, None)

    def invalidate_mem(self, addr=None):
        if addr is None:
            self.seg_cells.clear()
        else:
            self.seg_cells.pop(addr, None)
            for k in [k for k, v in self.seg_cells.items() if _mentions_mem(v, addr)]:
                self.seg_cells.pop(k, None)
        if self.es_fallback is not None and _mentions_mem(self.es_fallback, addr):
            self.es_fallback = None
        if self.es_expr is not None and _mentions_mem(self.es_expr, addr):
            self.es_expr = self.es_fallback
            self.es_fallback = None
        for k in [k for k, v in self.reg_seg_hint.items() if _mentions_mem(v, addr)]:
            self.reg_seg_hint.pop(k, None)

    def set_var_const(self, name, val):
        self.var_copies.pop(name, None)
        self.var_consts[name] = val
        self._kill_var_seg_deps(name)

    def set_var_copy(self, name, expr):
        self.var_consts.pop(name, None)
        self.var_copies[name] = expr
        self._kill_var_seg_deps(name)

    def kill_var(self, name):
        self.var_consts.pop(name, None)
        self.var_copies.pop(name, None)
        self._kill_var_seg_deps(name)

    def set_bank(self, bank):
        if self.bank != bank:
            self.bank = bank
            self.clear_gprs()

    def clear_gprs(self):
        for a in regs.GPR_ATOMS:
            self.atom_consts.pop(a, None)
            self.const_names.pop(a, None)
        for pair in regs.PAIRS:
            if any(a in regs.GPR_ATOMS for a in regs.atoms(pair)):
                self.const_names.pop(pair, None)
        to_del = [k for k, v in self.copies.items()
                  if any(a in regs.GPR_ATOMS for a in regs.atoms(k)) or
                     _mentions_any_atom(v, regs.GPR_ATOMS)]
        for k in to_del:
            self.copies.pop(k, None)
        to_del_vars = [k for k, v in self.var_copies.items()
                       if _mentions_any_atom(v, regs.GPR_ATOMS)]
        for k in to_del_vars:
            self.var_copies.pop(k, None)
        if self.es_fallback is not None and _mentions_any_atom(self.es_fallback, regs.GPR_ATOMS):
            self.es_fallback = None
        if self.es_expr is not None and _mentions_any_atom(self.es_expr, regs.GPR_ATOMS):
            self.es_expr = self.es_fallback
            self.es_fallback = None
        for k in [k for k, v in self.seg_cells.items() if _mentions_any_atom(v, regs.GPR_ATOMS)]:
            self.seg_cells.pop(k, None)
        self.reg_seg_hint.clear()

    def lookup_const(self, reg_name):
        name = self.const_names.get(reg_name)
        if reg_name in regs.PAIRS:
            v = regs.compose(reg_name, self.atom_consts)
            if v is not None:
                return ir.Const(v, "w", name=name)
            return None
        v = self.atom_consts.get(reg_name)
        if v is not None:
            return ir.Const(v, "b", name=name)
        return None

    def kill(self, reg_name):
        target_atoms = set(regs.atoms(reg_name))
        for a in target_atoms:
            self.atom_consts.pop(a, None)
            self.const_names.pop(a, None)
            for pair in regs.PAIRS:
                if a in regs.atoms(pair):
                    self.const_names.pop(pair, None)
        self.const_names.pop(reg_name, None)
        to_del = [k for k, v in self.copies.items()
                  if bool(set(regs.atoms(k)) & target_atoms) or
                     _mentions_any_atom(v, target_atoms)]
        for k in to_del:
            self.copies.pop(k, None)
        to_del_vars = [k for k, v in self.var_copies.items()
                       if _mentions_any_atom(v, target_atoms)]
        for k in to_del_vars:
            self.var_copies.pop(k, None)
        if "es" in target_atoms:
            self.es_expr = None
            self.es_fallback = None
        else:
            if self.es_fallback is not None and _mentions_any_atom(self.es_fallback, target_atoms):
                self.es_fallback = None
            if self.es_expr is not None and _mentions_any_atom(self.es_expr, target_atoms):
                self.es_expr = self.es_fallback
                self.es_fallback = None
        for k in [k for k, v in self.seg_cells.items() if _mentions_any_atom(v, target_atoms)]:
            self.seg_cells.pop(k, None)
        for k in [k for k, v in self.reg_seg_hint.items()
                  if bool(set(regs.atoms(k)) & target_atoms) or _mentions_any_atom(v, target_atoms)]:
            self.reg_seg_hint.pop(k, None)

    def set_const(self, reg_name, val, name=None):
        self.kill(reg_name)
        if reg_name in regs.PAIRS:
            decomp = regs.decompose(reg_name, val)
            for a, byte_val in decomp.items():
                self.atom_consts[a] = byte_val
        else:
            self.atom_consts[reg_name] = val & 0xFF
        if name:
            self.const_names[reg_name] = name

    def set_copy(self, dst_name, src_expr):
        self.kill(dst_name)
        dst_atoms = set(regs.atoms(dst_name))
        if not _mentions_any_atom(src_expr, dst_atoms):
            self.copies[dst_name] = src_expr

    def swap(self, a_reg, b_reg):
        old_a_const = self.lookup_const(a_reg)
        old_b_const = self.lookup_const(b_reg)
        old_a_copy = self.copies.get(a_reg)
        old_b_copy = self.copies.get(b_reg)

        self.kill(a_reg)
        self.kill(b_reg)

        if old_b_const is not None:
            self.set_const(a_reg, old_b_const.value, getattr(old_b_const, "name", None))
        elif old_b_copy is not None:
            self.set_copy(a_reg, old_b_copy)

        if old_a_const is not None:
            self.set_const(b_reg, old_a_const.value, getattr(old_a_const, "name", None))
        elif old_a_copy is not None:
            self.set_copy(b_reg, old_a_copy)


def _subst(e, env, is_lval=False):
    if isinstance(e, ir.Reg):
        c = env.lookup_const(e.name)
        if c is not None:
            return c
        cp = env.copies.get(e.name)
        if cp is not None:
            return cp
        return e
    if isinstance(e, (ir.Var, ir.StackVar)):
        c = env.var_consts.get(e.name)
        if c is not None:
            return ir.Const(c, e.width)
        cp = env.var_copies.get(e.name)
        if cp is not None:
            return cp
        if isinstance(e, ir.Var):
            return env.copies.get(e.name, e)
        return e
    if isinstance(e, ir.Bin):
        # pair >> 8 extracts the high byte atom of the register pair
        if e.op == ">>" and isinstance(e.r, ir.Const) and e.r.value == 8:
            if isinstance(e.l, ir.Reg) and e.l.name in regs.PAIRS:
                hi_atom = regs.PAIRS[e.l.name][1]
                return _subst(ir.Reg(hi_atom, "b"), env)
        return ir.Bin(e.op, _subst(e.l, env), _subst(e.r, env))
    if isinstance(e, ir.Un):
        return ir.Un(e.op, _subst(e.e, env))
    if isinstance(e, ir.Bit):
        return ir.Bit(_subst(e.base, env), e.bit)
    if isinstance(e, ir.IntrExpr):
        return ir.IntrExpr(e.name, [_subst(a, env) for a in e.args])
    if isinstance(e, ir.Mem):
        addr = _fold(_subst(e.addr, env)) if isinstance(e.addr, ir.Expr) else e.addr
        es = e.es
        seg = _fold(_subst(e.seg, env)) if isinstance(e.seg, ir.Expr) else e.seg
        if es:
            es_val = None
            c_es = env.atom_consts.get("es")
            if c_es is not None:
                es_val = c_es & 0xF
                seg = None
            elif env.es_expr is not None:
                seg = env.es_expr
            elif isinstance(seg, ir.Const):
                es_val = seg.value & 0xF
            elif isinstance(seg, int):
                es_val = seg & 0xF

            if es_val is not None:
                es_hi = (es_val & 0xF) << 16
                if isinstance(addr, ir.Const):
                    addr = (es_hi | (addr.value & 0xFFFF)) & 0xFFFFF
                    es = False
                    seg = ir.Const(0, "b") if es_val == 0 else None
                elif isinstance(addr, int):
                    addr = (es_hi | (addr & 0xFFFF)) & 0xFFFFF
                    es = False
                    seg = ir.Const(0, "b") if es_val == 0 else None
                elif isinstance(addr, ir.Bin) and addr.op == "+":
                    # Only fold ES segment into a base address (>= 0x1000 or named symbol),
                    # never into small struct/field offsets like [de + 3] or [hl + 0xCA].
                    if isinstance(addr.l, ir.Const) and (addr.l.value >= 0x1000 or getattr(addr.l, "name", None)):
                        addr = ir.Bin("+", ir.Const((es_hi | (addr.l.value & 0xFFFF)) & 0xFFFFF, "a", name=getattr(addr.l, "name", None)), addr.r)
                        es = False
                        seg = ir.Const(0, "b") if es_val == 0 else None
                    elif isinstance(addr.r, ir.Const) and (addr.r.value >= 0x1000 or getattr(addr.r, "name", None)):
                        addr = ir.Bin("+", addr.l, ir.Const((es_hi | (addr.r.value & 0xFFFF)) & 0xFFFFF, "a", name=getattr(addr.r, "name", None)))
                        es = False
                        seg = ir.Const(0, "b") if es_val == 0 else None
                    else:
                        seg = ir.Const(es_val & 0xF, "b")
                else:
                    seg = ir.Const(es_val & 0xF, "b")
        else:
            # Only promote 16-bit near addresses into mirror segment 0xF0000 when seg is None
            # (so resolved ES=0 ROM addresses with seg=Const(0) stay in segment 0 across passes).
            if seg is None:
                if isinstance(addr, ir.Const):
                    v = addr.value
                    addr = ((0xF0000 | v) & 0xFFFFF) if v < 0x10000 else v
                elif isinstance(addr, int):
                    if addr < 0x10000:
                        addr = (0xF0000 | addr) & 0xFFFFF
                elif isinstance(addr, ir.Bin) and addr.op == "+":
                    if isinstance(addr.l, ir.Const) and 0x8000 <= addr.l.value < 0x10000:
                        addr = ir.Bin("+", ir.Const((0xF0000 | addr.l.value) & 0xFFFFF, "a", name=getattr(addr.l, "name", None)), addr.r)
                    elif isinstance(addr.r, ir.Const) and 0x8000 <= addr.r.value < 0x10000:
                        addr = ir.Bin("+", addr.l, ir.Const((0xF0000 | addr.r.value) & 0xFFFFF, "a", name=getattr(addr.r, "name", None)))

        # GPR / Special reg alias check
        if not es and isinstance(addr, int):
            gpr = regs.gpr_alias(addr, e.width, env.bank)
            if gpr is not None:
                r = ir.Reg(gpr, e.width)
                return r if is_lval else _subst(r, env)
            spec = regs.special_reg(addr, e.width)
            if spec is not None:
                r = ir.Reg(spec, e.width)
                return r if is_lval else _subst(r, env)

        return ir.Mem(addr, e.width, es, e.name, seg)

    return e


def _clobber(env, s):
    if s.name == "sel":
        if s.args and isinstance(s.args[0], ir.Reg) and s.args[0].name.startswith("rb"):
            try:
                b = int(s.args[0].name[2:])
                env.set_bank(b)
            except ValueError:
                env.set_bank(None)
        else:
            env.set_bank(None)
        return
    if s.name in ("push", "ei", "di", "nop"):
        return
    if s.name == "pop" and s.args and isinstance(s.args[0], ir.Reg):
        reg_name = s.args[0].name
        if reg_name == "psw":
            env.set_bank(None)
            env.kill("psw")
        else:
            env.kill(reg_name)
        return
    if s.name in ("set_bit", "clr_bit"):
        if s.args:
            tgt = s.args[0]
            if isinstance(tgt, ir.Bit):
                tgt = tgt.base
            if isinstance(tgt, ir.Reg):
                if tgt.name == "psw":
                    env.set_bank(None)
                env.kill(tgt.name)
            elif isinstance(tgt, ir.Mem):
                raw = tgt.addr if isinstance(tgt.addr, int) else (
                    tgt.addr.value if isinstance(tgt.addr, ir.Const) else None
                )
                env.invalidate_mem(raw)
        return
    env.clear()


def _same_lval(a, b):
    if isinstance(a, ir.Reg) and isinstance(b, ir.Reg):
        return a.name == b.name
    if isinstance(a, ir.Var) and isinstance(b, ir.Var):
        return a.name == b.name
    return False


def _extract_op_const(src):
    if isinstance(src, ir.Bin) and src.op in ("+", "-", "<<", ">>", "&", "|", "^"):
        if isinstance(src.r, ir.Const):
            return src.op, src.l, src.r.value, src.r.width
        if src.op in ("+", "&", "|", "^") and isinstance(src.l, ir.Const):
            return src.op, src.r, src.l.value, src.l.width
    return None


def _coalesce_stmts(stmts):
    """Peephole combine consecutive arithmetic/bitwise operations on the same register/variable."""
    changed = True
    while changed:
        changed = False
        new_stmts = []
        i = 0
        while i < len(stmts):
            if i + 1 < len(stmts):
                s1 = stmts[i]
                s2 = stmts[i + 1]
                if (isinstance(s1, ir.Assign) and isinstance(s2, ir.Assign) and
                        _same_lval(s1.dst, s2.dst)):
                    dst = s1.dst
                    is_gpr = isinstance(dst, ir.Reg) and dst.name not in ("sp", "psw", "spl", "sph")
                    is_var = isinstance(dst, ir.Var)
                    if is_gpr or is_var:
                        if not (s1.flag is not None and s2.flag is None):
                            op1_info = _extract_op_const(s1.src)
                            op2_info = _extract_op_const(s2.src)
                            if op1_info and op2_info:
                                op1, base1, c1, w1 = op1_info
                                op2, base2, c2, w2 = op2_info
                                if _same_lval(base2, dst):
                                    combined_src = None
                                    width = getattr(dst, "width", "w")
                                    if op1 == "+" and op2 == "+":
                                        combined_src = ir.Bin("+", base1, ir.Const(c1 + c2, width))
                                    elif op1 == "-" and op2 == "-":
                                        combined_src = ir.Bin("-", base1, ir.Const(c1 + c2, width))
                                    elif op1 == "+" and op2 == "-":
                                        if c1 > c2:
                                            combined_src = ir.Bin("+", base1, ir.Const(c1 - c2, width))
                                        elif c1 == c2:
                                            combined_src = base1
                                        else:
                                            combined_src = ir.Bin("-", base1, ir.Const(c2 - c1, width))
                                    elif op1 == "-" and op2 == "+":
                                        if c2 > c1:
                                            combined_src = ir.Bin("+", base1, ir.Const(c2 - c1, width))
                                        elif c2 == c1:
                                            combined_src = base1
                                        else:
                                            combined_src = ir.Bin("-", base1, ir.Const(c1 - c2, width))
                                    elif op1 == "<<" and op2 == "<<":
                                        combined_src = ir.Bin("<<", base1, ir.Const(c1 + c2, width))
                                    elif op1 == ">>" and op2 == ">>":
                                        combined_src = ir.Bin(">>", base1, ir.Const(c1 + c2, width))
                                    elif op1 == "&" and op2 == "&":
                                        combined_src = ir.Bin("&", base1, ir.Const(c1 & c2, width))
                                    elif op1 == "|" and op2 == "|":
                                        combined_src = ir.Bin("|", base1, ir.Const(c1 | c2, width))
                                    elif op1 == "^" and op2 == "^":
                                        combined_src = ir.Bin("^", base1, ir.Const(c1 ^ c2, width))

                                    if combined_src is not None:
                                        if _same_lval(dst, combined_src) and s2.flag is None:
                                            i += 2
                                            changed = True
                                            continue
                                        flag = s2.flag
                                        comb = ir.Assign(s1.ea, dst, combined_src, flag=flag)
                                        new_stmts.append(comb)
                                        i += 2
                                        changed = True
                                        continue
            new_stmts.append(stmts[i])
            i += 1
        stmts = new_stmts
    return stmts


def _coalesce_block(block):
    block.stmts = _coalesce_stmts(block.stmts)


def _subst_reg(e, old_reg, new_reg):
    if isinstance(e, ir.Reg):
        if e.name == old_reg.name:
            return ir.Reg(new_reg.name, width=e.width)
        return e
    if isinstance(e, ir.Bin):
        return ir.Bin(e.op, _subst_reg(e.l, old_reg, new_reg), _subst_reg(e.r, old_reg, new_reg))
    if isinstance(e, ir.Un):
        return ir.Un(e.op, _subst_reg(e.e, old_reg, new_reg))
    if isinstance(e, ir.IntrExpr):
        return ir.IntrExpr(e.name, [_subst_reg(a, old_reg, new_reg) for a in e.args])
    if isinstance(e, ir.Mem):
        addr = _subst_reg(e.addr, old_reg, new_reg) if isinstance(e.addr, ir.Expr) else e.addr
        seg = _subst_reg(e.seg, old_reg, new_reg) if isinstance(e.seg, ir.Expr) else e.seg
        return ir.Mem(addr, width=e.width, es=e.es, name=e.name, seg=seg)
    if isinstance(e, ir.Bit):
        return ir.Bit(_subst_reg(e.base, old_reg, new_reg), e.bit)
    return e


def _eliminate_swap_sandwiches(func):
    """
    Eliminate accumulator placeholder swap sequences:
      XCH acc, other
      <operations on acc>
      XCH acc, other
    Rewrites the middle operations to target 'other' directly and removes both XCH swaps.
    """
    for b in func.blocks.values():
        stmts = b.stmts
        i = 0
        while i < len(stmts):
            s1 = stmts[i]
            if isinstance(s1, ir.Swap) and isinstance(s1.a, ir.Reg) and isinstance(s1.b, ir.Reg):
                reg_a, reg_b = s1.a, s1.b
                j = i + 1
                match_j = None
                while j < len(stmts):
                    s2 = stmts[j]
                    if isinstance(s2, ir.Swap) and isinstance(s2.a, ir.Reg) and isinstance(s2.b, ir.Reg):
                        if {s2.a.name, s2.b.name} == {reg_a.name, reg_b.name}:
                            match_j = j
                            break
                    if isinstance(s2, (ir.Call, ir.Branch, ir.Goto, ir.Ret)):
                        break
                    j += 1
                if match_j is not None:
                    middle = stmts[i + 1 : match_j]
                    acc = reg_a if reg_a.name in ("a", "ax") else (reg_b if reg_b.name in ("a", "ax") else reg_a)
                    other = reg_b if acc == reg_a else reg_a

                    can_transform = True
                    for m_s in middle:
                        if isinstance(m_s, ir.Assign):
                            if isinstance(m_s.dst, ir.Reg) and m_s.dst.name == other.name:
                                can_transform = False
                                break
                        elif isinstance(m_s, ir.Compare):
                            pass
                        else:
                            can_transform = False
                            break

                    if can_transform:
                        new_middle = []
                        for m_s in middle:
                            if isinstance(m_s, ir.Assign):
                                new_dst = _subst_reg(m_s.dst, acc, other)
                                new_src = _subst_reg(m_s.src, acc, other)
                                new_flag = None
                                if m_s.flag:
                                    fa = _subst_reg(m_s.flag.a, acc, other) if m_s.flag.a else None
                                    fb = _subst_reg(m_s.flag.b, acc, other) if m_s.flag.b else None
                                    new_flag = ir.FlagDef(m_s.flag.kind, a=fa, b=fb)
                                new_middle.append(ir.Assign(m_s.ea, new_dst, new_src, flag=new_flag))
                            elif isinstance(m_s, ir.Compare):
                                fa = _subst_reg(m_s.flag.a, acc, other) if m_s.flag.a else None
                                fb = _subst_reg(m_s.flag.b, acc, other) if m_s.flag.b else None
                                new_middle.append(ir.Compare(m_s.ea, ir.FlagDef(m_s.flag.kind, a=fa, b=fb)))
                        stmts = stmts[:i] + new_middle + stmts[match_j + 1:]
                        b.stmts = stmts
                        continue
            i += 1


def _lower_swaps(func):
    """
    Lower any remaining standalone ir.Swap(a, b) into value assignments via a temporary variable:
      t = a
      a = b
      b = t
    This enables regular SSA dataflow, copy propagation, and dead code elimination.
    """
    temp_counter = 0
    for b in func.blocks.values():
        new_stmts = []
        for s in b.stmts:
            if isinstance(s, ir.Swap):
                w = getattr(s.a, "width", "b")
                t_var = ir.Var(f"_swap_{temp_counter}", width=w)
                temp_counter += 1
                new_stmts.append(ir.Assign(s.ea, t_var, s.a))
                new_stmts.append(ir.Assign(s.ea, s.a, s.b))
                new_stmts.append(ir.Assign(s.ea, s.b, t_var))
            else:
                new_stmts.append(s)
        b.stmts = new_stmts


def _opt_block(block, default_bank=0, initial_env=None):
    _coalesce_block(block)
    env = initial_env if initial_env is not None else Env(bank=default_bank)
    replaced_rhs = {}
    for s in block.stmts:
        if isinstance(s, ir.Assign):
            old_src = s.src
            s.src = _fold(_subst(s.src, env))
            if s.src is not old_src:
                replaced_rhs[id(old_src)] = s.src

            if isinstance(s.dst, ir.Mem):
                s.dst = _subst(s.dst, env, is_lval=True)
                if isinstance(s.dst, ir.Mem):
                    raw_addr = s.dst.addr if isinstance(s.dst.addr, int) else (
                        s.dst.addr.value if isinstance(s.dst.addr, ir.Const) else None
                    )
                    if raw_addr is not None and not s.dst.es:
                        gpr = regs.gpr_alias(raw_addr, s.dst.width, env.bank)
                        if gpr is not None:
                            s.dst = ir.Reg(gpr, s.dst.width)
                        else:
                            spec = regs.special_reg(raw_addr, s.dst.width)
                            if spec is not None:
                                s.dst = ir.Reg(spec, s.dst.width)

            if s.flag is not None:
                if s.flag.kind == "result":
                    s.flag.a = s.src if isinstance(s.src, ir.Const) else s.dst
                else:
                    if s.flag.a is not None:
                        s.flag.a = _fold(_subst(s.flag.a, env))
                    if s.flag.b is not None:
                        s.flag.b = _fold(_subst(s.flag.b, env))

            if isinstance(s.dst, ir.Reg):
                if s.dst.name == "es":
                    eff = None
                    fallback = None
                    if isinstance(s.src, ir.Const):
                        eff = ir.Const(s.src.value & 0xF, "b")
                    elif isinstance(s.src, ir.Reg):
                        c = env.lookup_const(s.src.name)
                        if c is not None:
                            eff = ir.Const(c.value & 0xF, "b")
                        elif s.src.name in env.reg_seg_hint:
                            eff = env.reg_seg_hint[s.src.name]
                        else:
                            eff = s.src
                    elif isinstance(s.src, ir.Mem) and not s.src.es:
                        src_raw = s.src.addr if isinstance(s.src.addr, int) else (
                            s.src.addr.value if isinstance(s.src.addr, ir.Const) else None
                        )
                        if src_raw in env.seg_cells:
                            eff = env.seg_cells[src_raw]
                            if src_raw < 0xFFF00:
                                fallback = s.src
                        elif src_raw is not None and src_raw < 0xFFF00:
                            eff = s.src
                    elif isinstance(s.src, (ir.Var, ir.StackVar)):
                        if s.src.name in env.var_consts:
                            eff = ir.Const(env.var_consts[s.src.name] & 0xF, "b")
                        else:
                            eff = s.src

                    if isinstance(eff, ir.Const):
                        s.src = ir.Const(eff.value & 0xF, "b")
                        env.set_const("es", eff.value & 0xF)
                    else:
                        env.kill("es")
                        if eff is not None:
                            env.es_expr = eff
                            env.es_fallback = fallback
                elif s.dst.name == "psw":
                    env.set_bank(None)
                    env.kill("psw")
                else:
                    hint = None
                    if s.dst.width == "b":
                        if isinstance(s.src, ir.Mem) and not s.src.es:
                            src_raw = s.src.addr if isinstance(s.src.addr, int) else (
                                s.src.addr.value if isinstance(s.src.addr, ir.Const) else None
                            )
                            if src_raw in env.seg_cells:
                                hint = env.seg_cells[src_raw]
                            elif src_raw is not None and src_raw < 0xFFF00:
                                hint = s.src
                        elif isinstance(s.src, ir.Reg) and s.src.name in env.reg_seg_hint:
                            hint = env.reg_seg_hint[s.src.name]

                    if isinstance(s.src, ir.Const):
                        env.set_const(s.dst.name, s.src.value, getattr(s.src, "name", None))
                    elif isinstance(s.src, ir.Reg) and env.lookup_const(s.src.name) is not None:
                        c = env.lookup_const(s.src.name)
                        env.set_const(s.dst.name, c.value, getattr(c, "name", None))
                    elif isinstance(s.src, (ir.Reg, ir.Var, ir.StackVar)):
                        if isinstance(s.src, (ir.Var, ir.StackVar)) and s.src.name in env.var_consts:
                            env.set_const(s.dst.name, env.var_consts[s.src.name])
                        else:
                            env.set_copy(s.dst.name, s.src)
                    else:
                        env.kill(s.dst.name)

                    if hint is not None and not _mentions_any_atom(hint, set(regs.atoms(s.dst.name))):
                        env.reg_seg_hint[s.dst.name] = hint
            elif isinstance(s.dst, ir.Mem):
                raw_addr = None
                if not s.dst.es:
                    raw_addr = s.dst.addr if isinstance(s.dst.addr, int) else (
                        s.dst.addr.value if isinstance(s.dst.addr, ir.Const) else None
                    )
                seg_val_expr = None
                if raw_addr is not None and s.dst.width == "b" and 0xFFE20 <= raw_addr <= 0xFFEFF:
                    if isinstance(s.src, ir.Const):
                        seg_val_expr = ir.Const(s.src.value & 0xF, "b")
                    elif isinstance(s.src, ir.Reg) and s.src.name in env.reg_seg_hint:
                        seg_val_expr = env.reg_seg_hint[s.src.name]
                    elif isinstance(s.src, ir.Mem) and not s.src.es:
                        src_raw = s.src.addr if isinstance(s.src.addr, int) else (
                            s.src.addr.value if isinstance(s.src.addr, ir.Const) else None
                        )
                        if src_raw in env.seg_cells:
                            seg_val_expr = env.seg_cells[src_raw]
                        elif src_raw is not None and src_raw < 0xFFF00:
                            seg_val_expr = s.src
                    elif isinstance(s.src, (ir.Reg, ir.Var, ir.StackVar)):
                        seg_val_expr = s.src
                env.invalidate_mem(raw_addr)
                if seg_val_expr is not None and raw_addr is not None and not _mentions_mem(seg_val_expr, raw_addr):
                    env.seg_cells[raw_addr] = seg_val_expr
            elif isinstance(s.dst, (ir.StackVar, ir.Var)):
                if isinstance(s.src, ir.Const):
                    env.set_var_const(s.dst.name, s.src.value)
                elif isinstance(s.src, ir.Reg):
                    c = env.lookup_const(s.src.name)
                    if c is not None:
                        env.set_var_const(s.dst.name, c.value)
                    elif not s.dst.name.startswith("_s"):
                        env.set_var_copy(s.dst.name, s.src)
                    else:
                        env.kill_var(s.dst.name)
                elif isinstance(s.src, (ir.StackVar, ir.Var)):
                    if s.src.name in env.var_consts:
                        env.set_var_const(s.dst.name, env.var_consts[s.src.name])
                    else:
                        env.set_var_copy(s.dst.name, s.src)
                else:
                    env.kill_var(s.dst.name)
            elif isinstance(s.dst, ir.Bit):
                if isinstance(s.dst.base, ir.Reg) and s.dst.base.name == "psw":
                    if s.dst.bit in (3, 5):
                        env.set_bank(None)
                    env.kill("psw")
                elif isinstance(s.dst.base, ir.Reg):
                    env.kill(s.dst.base.name)
                elif isinstance(s.dst.base, ir.Mem):
                    raw = None
                    if not s.dst.base.es:
                        raw = s.dst.base.addr if isinstance(s.dst.base.addr, int) else (
                            s.dst.base.addr.value if isinstance(s.dst.base.addr, ir.Const) else None
                        )
                    env.invalidate_mem(raw)

        elif isinstance(s, ir.Swap):
            if isinstance(s.a, ir.Mem):
                s.a = _subst(s.a, env, is_lval=True)
                if isinstance(s.a, ir.Mem):
                    raw_addr = s.a.addr if isinstance(s.a.addr, int) else (
                        s.a.addr.value if isinstance(s.a.addr, ir.Const) else None
                    )
                    if raw_addr is not None and not s.a.es:
                        gpr = regs.gpr_alias(raw_addr, s.a.width, env.bank)
                        if gpr is not None:
                            s.a = ir.Reg(gpr, s.a.width)
            if isinstance(s.b, ir.Mem):
                s.b = _subst(s.b, env, is_lval=True)
                if isinstance(s.b, ir.Mem):
                    raw_addr = s.b.addr if isinstance(s.b.addr, int) else (
                        s.b.addr.value if isinstance(s.b.addr, ir.Const) else None
                    )
                    if raw_addr is not None and not s.b.es:
                        gpr = regs.gpr_alias(raw_addr, s.b.width, env.bank)
                        if gpr is not None:
                            s.b = ir.Reg(gpr, s.b.width)

            if isinstance(s.a, ir.Reg) and isinstance(s.b, ir.Reg):
                env.swap(s.a.name, s.b.name)
            else:
                if isinstance(s.a, ir.Reg):
                    env.kill(s.a.name)
                elif isinstance(s.a, ir.Mem):
                    raw = None if s.a.es else (s.a.addr if isinstance(s.a.addr, int) else (
                        s.a.addr.value if isinstance(s.a.addr, ir.Const) else None))
                    env.invalidate_mem(raw)
                if isinstance(s.b, ir.Reg):
                    env.kill(s.b.name)
                elif isinstance(s.b, ir.Mem):
                    raw = None if s.b.es else (s.b.addr if isinstance(s.b.addr, int) else (
                        s.b.addr.value if isinstance(s.b.addr, ir.Const) else None))
                    env.invalidate_mem(raw)

        elif isinstance(s, ir.Compare):
            if s.flag.a is not None:
                s.flag.a = _fold(_subst(s.flag.a, env))
            if s.flag.b is not None:
                s.flag.b = _fold(_subst(s.flag.b, env))

        elif isinstance(s, ir.Branch):
            if s.bittest is not None:
                base, sense = s.bittest
                s.bittest = (_fold(_subst(base, env)), sense)

        elif isinstance(s, ir.Switch):
            s.expr = _fold(_subst(s.expr, env))

        elif isinstance(s, ir.Intrinsic):
            lval_indices = _LVAL_ARGS.get(s.name, set())
            new_args = []
            for i, a in enumerate(s.args):
                if i in lval_indices:
                    if isinstance(a, ir.Mem):
                        new_args.append(_subst(a, env, is_lval=True))
                    elif isinstance(a, ir.Bit) and isinstance(a.base, ir.Mem):
                        new_args.append(ir.Bit(_subst(a.base, env, is_lval=True), a.bit))
                    else:
                        new_args.append(a)
                else:
                    new_args.append(_fold(_subst(a, env)))
            s.args = new_args
            _clobber(env, s)

        elif isinstance(s, ir.Call):
            if s.args and replaced_rhs:
                s.args = [replaced_rhs.get(id(a), a) for a in s.args]
            env.clear()
    _coalesce_block(block)


_ES_UNDEF = object()
_ES_TOP = object()


def _compute_block_es(func, preds):
    """Forward dataflow analysis to compute entry ES value (Const or symbolic Expr) per block."""
    in_es = {b_ea: _ES_UNDEF for b_ea in func.blocks}
    out_es = {b_ea: _ES_UNDEF for b_ea in func.blocks}
    if func.entry in in_es:
        in_es[func.entry] = _ES_TOP

    def _meet(a, b):
        if a is _ES_UNDEF:
            return b
        if b is _ES_UNDEF:
            return a
        if a is _ES_TOP or b is _ES_TOP:
            return _ES_TOP
        return a if a == b else _ES_TOP

    def _kill_val(cur, dst):
        if cur is _ES_UNDEF or cur is _ES_TOP:
            return cur
        if isinstance(dst, ir.Reg):
            if _mentions_any_atom(cur, set(regs.atoms(dst.name))):
                return _ES_TOP
        elif isinstance(dst, (ir.Var, ir.StackVar)):
            if _mentions_var(cur, dst.name):
                return _ES_TOP
        elif isinstance(dst, ir.Mem):
            raw = None if dst.es else (dst.addr if isinstance(dst.addr, int) else (
                dst.addr.value if isinstance(dst.addr, ir.Const) else None))
            if _mentions_mem(cur, raw):
                return _ES_TOP
        return cur

    ordered = func.ordered()
    changed = True
    iterations = 0
    while changed and iterations < 32:
        changed = False
        iterations += 1
        for b in ordered:
            if b.start == func.entry:
                cur = _ES_TOP
            else:
                cur = _ES_UNDEF
                for p_ea in preds.get(b.start, []):
                    cur = _meet(cur, out_es.get(p_ea, _ES_UNDEF))
            in_es[b.start] = cur

            local_load = {}
            for s in b.stmts:
                if isinstance(s, ir.Assign):
                    if isinstance(s.dst, ir.Reg) and s.dst.name == "es":
                        val = s.src
                        if isinstance(val, ir.Reg) and val.name in local_load:
                            val = local_load[val.name]
                        if isinstance(val, ir.Const):
                            cur = ir.Const(val.value & 0xF, "b")
                        elif isinstance(val, (ir.StackVar, ir.Var, ir.Reg)):
                            cur = val
                        elif isinstance(val, ir.Mem) and not val.es:
                            src_raw = val.addr if isinstance(val.addr, int) else (
                                val.addr.value if isinstance(val.addr, ir.Const) else None)
                            cur = val if (src_raw is not None and src_raw < 0xFFF00) else _ES_TOP
                        else:
                            cur = _ES_TOP
                    else:
                        cur = _kill_val(cur, s.dst)
                        if isinstance(s.dst, ir.Reg):
                            tatoms = set(regs.atoms(s.dst.name))
                            for k in [k for k, v in local_load.items()
                                      if bool(set(regs.atoms(k)) & tatoms) or _mentions_any_atom(v, tatoms)]:
                                local_load.pop(k, None)
                            if s.dst.width == "b":
                                if isinstance(s.src, ir.Const):
                                    local_load[s.dst.name] = ir.Const(s.src.value & 0xF, "b")
                                elif isinstance(s.src, ir.StackVar):
                                    local_load[s.dst.name] = s.src
                                elif isinstance(s.src, ir.Mem) and not s.src.es:
                                    src_raw = s.src.addr if isinstance(s.src.addr, int) else (
                                        s.src.addr.value if isinstance(s.src.addr, ir.Const) else None)
                                    if src_raw is not None and src_raw < 0xFFF00:
                                        local_load[s.dst.name] = s.src
                        elif isinstance(s.dst, (ir.Var, ir.StackVar)):
                            for k in [k for k, v in local_load.items() if _mentions_var(v, s.dst.name)]:
                                local_load.pop(k, None)
                        elif isinstance(s.dst, ir.Mem):
                            raw = None if s.dst.es else (s.dst.addr if isinstance(s.dst.addr, int) else (
                                s.dst.addr.value if isinstance(s.dst.addr, ir.Const) else None))
                            for k in [k for k, v in local_load.items() if _mentions_mem(v, raw)]:
                                local_load.pop(k, None)
                        elif isinstance(s.dst, ir.Bit):
                            cur = _kill_val(cur, s.dst.base)
                elif isinstance(s, ir.Swap):
                    cur = _kill_val(cur, s.a)
                    cur = _kill_val(cur, s.b)
                    local_load.clear()
                elif isinstance(s, ir.Call):
                    cur = _ES_TOP
                    local_load.clear()
                elif isinstance(s, ir.Intrinsic):
                    if s.name == "sel":
                        if cur not in (_ES_UNDEF, _ES_TOP) and _mentions_any_atom(cur, regs.GPR_ATOMS):
                            cur = _ES_TOP
                        local_load.clear()
                    elif s.name in ("push", "ei", "di", "nop"):
                        pass
                    elif s.name in ("pop", "set_bit", "clr_bit"):
                        if s.args:
                            tgt = s.args[0].base if isinstance(s.args[0], ir.Bit) else s.args[0]
                            cur = _kill_val(cur, tgt)
                            if isinstance(tgt, ir.Reg):
                                local_load.pop(tgt.name, None)
                    else:
                        cur = _ES_TOP
                        local_load.clear()

            if cur != out_es.get(b.start, _ES_UNDEF):
                out_es[b.start] = cur
                changed = True

    return in_es


def optimize(func, default_bank=0):
    import copy

    # Phase 0: Eliminate accumulator placeholder swap sequences and lower remaining swaps
    _eliminate_swap_sandwiches(func)
    _lower_swaps(func)

    # Pass 1: Intra-block local optimizations
    for b in func.ordered():
        _opt_block(b, default_bank=default_bank)

    # Collect single-assigned StackVar / Var constants across func
    var_assigns = {}
    for b in func.blocks.values():
        for s in b.stmts:
            if isinstance(s, ir.Assign) and isinstance(s.dst, (ir.StackVar, ir.Var)):
                var_assigns.setdefault(s.dst.name, []).append(s.src)

    func_consts = {}
    for name, srcs in var_assigns.items():
        if len(srcs) == 1 and isinstance(srcs[0], ir.Const):
            func_consts[name] = srcs[0].value

    # Build CFG predecessor mapping
    preds = {}
    for b_start, b in func.blocks.items():
        for kind, succ_ea in b.succ:
            preds.setdefault(succ_ea, []).append(b_start)

    # Inter-block ES dataflow across joins and loops
    in_es = _compute_block_es(func, preds)

    # Pass 2: Forward chaining across CFG along single-predecessor edges + ES dataflow
    out_envs = {}
    for b in func.ordered():
        p_list = preds.get(b.start, [])
        if len(p_list) == 1 and p_list[0] in out_envs:
            env = copy.deepcopy(out_envs[p_list[0]])
        else:
            env = Env(bank=default_bank)

        for vname, val in func_consts.items():
            if vname not in env.var_consts:
                env.var_consts[vname] = val

        es_entry = in_es.get(b.start, _ES_TOP)
        if env.atom_consts.get("es") is None:
            if isinstance(es_entry, ir.Const):
                env.set_const("es", es_entry.value & 0xF)
            elif es_entry not in (_ES_UNDEF, _ES_TOP) and env.es_expr is None:
                env.es_expr = es_entry

        _opt_block(b, default_bank=default_bank, initial_env=env)
        out_envs[b.start] = env

    return func
