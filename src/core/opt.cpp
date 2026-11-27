#include "rl78dec/opt.hpp"

#include <cstdlib>
#include <functional>
#include <map>
#include <unordered_map>
#include <unordered_set>

#include "rl78dec/sfr.hpp"

namespace rl78dec {

namespace {

bool is_lval_arg(const std::string &intr_name, size_t idx) {
    if (intr_name == "pop" || intr_name == "set_bit" || intr_name == "clr_bit") return idx == 0;
    return false;
}

bool mentions_any_atom(const ExprPtr &e, AtomMask mask) {
    if (!e || mask == 0) return false;
    switch (e->kind) {
        case ExprKind::Reg:
            return (reg_atoms_named(e->name) & mask) != 0;
        case ExprKind::Bin:
            return mentions_any_atom(e->l, mask) || mentions_any_atom(e->r, mask);
        case ExprKind::Un:
            return mentions_any_atom(e->l, mask);
        case ExprKind::Bit:
            return mentions_any_atom(e->base, mask);
        case ExprKind::Mem:
            return !e->has_static_addr && mentions_any_atom(e->addr, mask);
        case ExprKind::Intr:
            for (const auto &a : e->args) if (mentions_any_atom(a, mask)) return true;
            return false;
        default:
            return false;
    }
}

struct Env {
    std::optional<int> bank = 0;
    std::unordered_map<std::string, uint8_t> atom_consts;
    std::unordered_map<std::string, ExprPtr> copies;
    std::unordered_map<std::string, uint32_t> var_consts;
    std::unordered_map<std::string, ExprPtr> var_copies;
    std::unordered_map<std::string, std::string> const_names;
    bool allow_gpr_alias = true;

    void clear() {
        atom_consts.clear();
        copies.clear();
        var_copies.clear();
        const_names.clear();
    }

    void set_var_const(const std::string &nm, uint32_t val) {
        var_copies.erase(nm);
        var_consts[nm] = val;
    }

    void set_var_copy(const std::string &nm, const ExprPtr &expr) {
        var_consts.erase(nm);
        var_copies[nm] = expr;
    }

    void kill_var(const std::string &nm) {
        var_consts.erase(nm);
        var_copies.erase(nm);
    }

    void set_bank(std::optional<int> b) {
        if (bank != b) {
            bank = b;
            clear_gprs();
        }
    }

    void clear_gprs() {
        static const char *kGprAtoms[8] = {"x", "a", "c", "b", "e", "d", "l", "h"};
        for (const char *a : kGprAtoms) {
            atom_consts.erase(a);
            const_names.erase(a);
        }
        const_names.erase("ax");
        const_names.erase("bc");
        const_names.erase("de");
        const_names.erase("hl");
        for (auto it = copies.begin(); it != copies.end();) {
            if ((reg_atoms_named(it->first) & atom::GPR_8) != 0 || mentions_any_atom(it->second, atom::GPR_8)) {
                it = copies.erase(it);
            } else {
                ++it;
            }
        }
        for (auto it = var_copies.begin(); it != var_copies.end();) {
            if (mentions_any_atom(it->second, atom::GPR_8)) it = var_copies.erase(it);
            else ++it;
        }
    }

    void kill(const std::string &rname) {
        AtomMask mask = reg_atoms_named(rname);
        static const std::pair<const char *, AtomMask> kAllAtoms[] = {
            {"x", atom::X}, {"a", atom::A}, {"c", atom::C}, {"b", atom::B},
            {"e", atom::E}, {"d", atom::D}, {"l", atom::L}, {"h", atom::H},
            {"es", atom::ES}, {"cs", atom::CS}, {"spl", atom::SPL}, {"sph", atom::SPH},
            {"psw", atom::PSW}, {"cy", atom::CY}, {"z", atom::Z}, {"rbs", atom::RBS},
        };
        for (const auto &[anm, am] : kAllAtoms) {
            if (mask & am) {
                atom_consts.erase(anm);
                const_names.erase(anm);
            }
        }
        static const char *kPairs[] = {"ax", "bc", "de", "hl", "sp"};
        for (const char *p : kPairs) {
            if (reg_atoms_named(p) & mask) const_names.erase(p);
        }
        const_names.erase(rname);
        for (auto it = copies.begin(); it != copies.end();) {
            if ((reg_atoms_named(it->first) & mask) != 0 || mentions_any_atom(it->second, mask)) {
                it = copies.erase(it);
            } else {
                ++it;
            }
        }
        for (auto it = var_copies.begin(); it != var_copies.end();) {
            if (mentions_any_atom(it->second, mask)) it = var_copies.erase(it);
            else ++it;
        }
    }

    ExprPtr lookup_const(const std::string &rname) const {
        std::string sym;
        if (auto it = const_names.find(rname); it != const_names.end()) sym = it->second;
        if (is_pair_name(rname)) {
            auto [lo, hi] = pair_halves(rname);
            auto lit = atom_consts.find(lo);
            auto hit = atom_consts.find(hi);
            if (lit != atom_consts.end() && hit != atom_consts.end()) {
                uint32_t v = (static_cast<uint32_t>(hit->second) << 8) | lit->second;
                return Expr::make_const(v, Width::W, sym);
            }
            return nullptr;
        }
        auto it = atom_consts.find(rname);
        if (it != atom_consts.end()) return Expr::make_const(it->second, Width::B, sym);
        return nullptr;
    }

    void set_const(const std::string &rname, uint32_t val, const std::string &sym_name = "") {
        kill(rname);
        if (is_pair_name(rname)) {
            auto [lo, hi] = pair_halves(rname);
            atom_consts[lo] = static_cast<uint8_t>(val & 0xFFu);
            atom_consts[hi] = static_cast<uint8_t>((val >> 8) & 0xFFu);
        } else {
            atom_consts[rname] = static_cast<uint8_t>(val & 0xFFu);
        }
        if (!sym_name.empty()) const_names[rname] = sym_name;
    }

    void set_copy(const std::string &dst_name, const ExprPtr &src_expr) {
        kill(dst_name);
        AtomMask dst_mask = reg_atoms_named(dst_name);
        if (!mentions_any_atom(src_expr, dst_mask)) copies[dst_name] = src_expr;
    }

    void swap(const std::string &a_reg, const std::string &b_reg) {
        ExprPtr old_a_const = lookup_const(a_reg);
        ExprPtr old_b_const = lookup_const(b_reg);
        ExprPtr old_a_copy = copies.count(a_reg) ? copies[a_reg] : nullptr;
        ExprPtr old_b_copy = copies.count(b_reg) ? copies[b_reg] : nullptr;
        kill(a_reg);
        kill(b_reg);
        if (old_b_const) set_const(a_reg, old_b_const->value, old_b_const->name);
        else if (old_b_copy) set_copy(a_reg, old_b_copy);
        if (old_a_const) set_const(b_reg, old_a_const->value, old_a_const->name);
        else if (old_a_copy) set_copy(b_reg, old_a_copy);
    }

    void invalidate_mem_derived() {
        auto has_mem = [](const auto &self, const ExprPtr &e) -> bool {
            if (!e) return false;
            if (e->kind == ExprKind::Mem) return true;
            if (e->kind == ExprKind::Bin) return self(self, e->l) || self(self, e->r);
            if (e->kind == ExprKind::Un) return self(self, e->l);
            if (e->kind == ExprKind::Bit) return self(self, e->base);
            if (e->kind == ExprKind::Intr) {
                for (const auto &a : e->args) if (self(self, a)) return true;
            }
            return false;
        };
        for (auto it = copies.begin(); it != copies.end();) {
            if (has_mem(has_mem, it->second)) it = copies.erase(it);
            else ++it;
        }
        for (auto it = var_copies.begin(); it != var_copies.end();) {
            if (has_mem(has_mem, it->second)) it = var_copies.erase(it);
            else ++it;
        }
    }
};

ExprPtr fold_expr(const ExprPtr &e) {
    if (!e) return nullptr;
    if (e->kind == ExprKind::Bin) {
        ExprPtr l = fold_expr(e->l);
        ExprPtr r = fold_expr(e->r);
        if (l && r && l->kind == ExprKind::Const && r->kind == ExprKind::Const &&
            l->name.empty() && r->name.empty()) {
            Width w = Width::B;
            if (l->width == Width::A || r->width == Width::A) w = Width::A;
            else if (l->width == Width::W || r->width == Width::W) w = Width::W;
            else if (l->width == Width::D || r->width == Width::D) w = Width::D;

            uint32_t lv = l->value, rv = r->value;
            uint32_t res = 0;
            bool handled = true;
            if (e->op == "+")      res = lv + rv;
            else if (e->op == "-") res = lv - rv;
            else if (e->op == "*") res = lv * rv;
            else if (e->op == "|") res = lv | rv;
            else if (e->op == "&") res = lv & rv;
            else if (e->op == "^") res = lv ^ rv;
            else if (e->op == "<<") res = lv << (rv & 31u);
            else if (e->op == ">>") res = lv >> (rv & 31u);
            else handled = false;
            if (handled) {
                if (e->op == "+" && w == Width::B && res > 0xFFu && e->width != Width::B) w = Width::W;
                return Expr::make_const(res, (e->width == Width::D || e->width == Width::A) ? e->width : w);
            }
        }
        if (r && r->kind == ExprKind::Const && r->value == 0 && r->name.empty() &&
            (e->op == "+" || e->op == "-" || e->op == "|" || e->op == "^" || e->op == "<<" || e->op == ">>")) {
            if (e->width == Width::A && l && l->width != Width::A) {
                return Expr::make_un("u32", l, Width::A);
            }
            return l;
        }
        if (l && l->kind == ExprKind::Const && l->value == 0 && l->name.empty() &&
            (e->op == "+" || e->op == "|" || e->op == "^")) {
            if (e->width == Width::A && r && r->width != Width::A) {
                return Expr::make_un("u32", r, Width::A);
            }
            return r;
        }
        if (r && r->kind == ExprKind::Const && r->value == 1 && r->name.empty() && e->op == "*") return l;
        if (l && l->kind == ExprKind::Const && l->value == 1 && l->name.empty() && e->op == "*") return r;
        if ((r && r->kind == ExprKind::Const && r->value == 0 && r->name.empty() && e->op == "*") ||
            (l && l->kind == ExprKind::Const && l->value == 0 && l->name.empty() && e->op == "*")) {
            return Expr::make_const(0, e->width);
        }
        if (e->op == "+" || e->op == "-") {
            return simplify_math(Expr::make_bin(e->op, l, r, e->width));
        }
        return Expr::make_bin(e->op, l, r, e->width);
    }
    if (e->kind == ExprKind::Un) {
        ExprPtr sub = fold_expr(e->l);
        if (sub && sub->kind == ExprKind::Const) {
            if (e->op == "!") return Expr::make_const(sub->value ? 0u : 1u, sub->width);
            if (e->op == "~") return Expr::make_const(~sub->value, sub->width);
            if (e->op == "u8")  return Expr::make_const(sub->value & 0xFFu, e->width == Width::A ? Width::A : Width::B, sub->name);
            if (e->op == "u16") return Expr::make_const(sub->value & 0xFFFFu, e->width == Width::A ? Width::A : Width::W, sub->name);
            if (e->op == "u32") return Expr::make_const(sub->value, e->width == Width::A ? Width::A : Width::D, sub->name);
            if (e->op == "i8") {
                uint32_t sv = static_cast<uint32_t>(static_cast<int32_t>(static_cast<int8_t>(sub->value & 0xFFu)));
                return Expr::make_const(sv, e->width == Width::A ? Width::A : Width::B, sub->name);
            }
            if (e->op == "i16") {
                uint32_t sv = static_cast<uint32_t>(static_cast<int32_t>(static_cast<int16_t>(sub->value & 0xFFFFu)));
                return Expr::make_const(sv, e->width == Width::A ? Width::A : Width::W, sub->name);
            }
            if (e->op == "i32") return Expr::make_const(sub->value, e->width == Width::A ? Width::A : Width::D, sub->name);
        }
        return Expr::make_un(e->op, sub, e->width);
    }
    if (e->kind == ExprKind::Mem) {
        if (e->has_static_addr) return e;
        ExprPtr addr = fold_expr(e->addr);
        bool lin = e->addr_is_linear || (!e->es && addr && addr->width == Width::A);
        if (addr && addr->kind == ExprKind::Const) {
            return Expr::make_mem_abs(addr->value, e->width, e->es, e->name, lin);
        }
        return Expr::make_mem_addr(addr, e->width, e->es, e->name, lin);
    }
    if (e->kind == ExprKind::Bit) {
        ExprPtr b = fold_expr(e->base);
        if (b && b->kind == ExprKind::Const) {
            return Expr::make_const((b->value >> e->bit) & 1u, Width::B);
        }
        return Expr::make_bit(b, e->bit);
    }
    if (e->kind == ExprKind::Intr) {
        std::vector<ExprPtr> na;
        na.reserve(e->args.size());
        for (const auto &a : e->args) na.push_back(fold_expr(a));
        return Expr::make_intr(e->name, std::move(na), e->width);
    }
    return e;
}

ExprPtr subst_expr(const ExprPtr &e, const Env &env) {
    if (!e) return nullptr;
    switch (e->kind) {
        case ExprKind::Reg: {
            if (auto c = env.lookup_const(e->name)) return c;
            if (auto it = env.copies.find(e->name); it != env.copies.end()) return expr_clone(it->second);
            return e;
        }
        case ExprKind::Var:
        case ExprKind::StackVar: {
            if (auto it = env.var_consts.find(e->name); it != env.var_consts.end()) {
                return Expr::make_const(it->second, e->width);
            }
            if (auto it = env.var_copies.find(e->name); it != env.var_copies.end()) return expr_clone(it->second);
            if (e->kind == ExprKind::Var) {
                if (auto it = env.copies.find(e->name); it != env.copies.end()) return expr_clone(it->second);
            }
            return e;
        }
        case ExprKind::Bin: {
            if (e->op == ">>" && e->r && e->r->kind == ExprKind::Const && e->r->value == 8 &&
                e->l && e->l->kind == ExprKind::Reg && is_pair_name(e->l->name)) {
                auto [lo, hi] = pair_halves(e->l->name);
                return subst_expr(Expr::make_reg(hi, Width::B), env);
            }
            return Expr::make_bin(e->op, subst_expr(e->l, env), subst_expr(e->r, env), e->width);
        }
        case ExprKind::Un:
            return Expr::make_un(e->op, subst_expr(e->l, env), e->width);
        case ExprKind::Bit:
            return Expr::make_bit(subst_expr(e->base, env), e->bit);
        case ExprKind::Intr: {
            std::vector<ExprPtr> na;
            for (const auto &a : e->args) na.push_back(subst_expr(a, env));
            return Expr::make_intr(e->name, std::move(na), e->width);
        }
        case ExprKind::Mem: {
            Width stat_w = (!e->es && e->addr_is_linear) ? Width::A : Width::W;
            ExprPtr addr_expr = e->has_static_addr ? Expr::make_const(e->static_addr, stat_w, e->name)
                                                   : fold_expr(subst_expr(e->addr, env));
            bool es = e->es;
            bool linear = e->addr_is_linear;
            if (es) {
                auto es_it = env.atom_consts.find("es");
                if (es_it != env.atom_consts.end()) {
                    uint32_t es_val = static_cast<uint32_t>(es_it->second) & 0xFu;
                    if (addr_expr && addr_expr->kind == ExprKind::Const) {
                        uint32_t lin = ((es_val << 16) | (addr_expr->value & 0xFFFFu)) & 0xFFFFFu;
                        addr_expr = Expr::make_const(lin, Width::A, addr_expr->name);
                        es = false;
                        linear = true;
                    } else if (addr_expr && addr_expr->kind == ExprKind::Bin &&
                               (addr_expr->op == "+" || addr_expr->op == "-")) {
                        if (addr_expr->l && addr_expr->l->kind == ExprKind::Const && addr_expr->l->value < 0x10000u) {
                            uint32_t lin = ((es_val << 16) | (addr_expr->l->value & 0xFFFFu)) & 0xFFFFFu;
                            addr_expr = Expr::make_bin(addr_expr->op,
                                                       Expr::make_const(lin, Width::A, addr_expr->l->name),
                                                       addr_expr->r, Width::A);
                            es = false;
                            linear = true;
                        } else if (addr_expr->op == "+" && addr_expr->r && addr_expr->r->kind == ExprKind::Const &&
                                   addr_expr->r->value < 0x10000u) {
                            uint32_t lin = ((es_val << 16) | (addr_expr->r->value & 0xFFFFu)) & 0xFFFFFu;
                            addr_expr = Expr::make_bin("+", addr_expr->l,
                                                       Expr::make_const(lin, Width::A, addr_expr->r->name), Width::A);
                            es = false;
                            linear = true;
                        } else {
                            if (es_val != 0x0Fu) {
                                addr_expr = Expr::make_bin("|", Expr::make_const(es_val << 16, Width::A),
                                                           Expr::make_un("u16", addr_expr, Width::W), Width::A);
                                linear = true;
                            } else {
                                linear = e->addr_is_linear || (addr_expr && addr_expr->width == Width::A);
                            }
                            es = false;
                        }
                    } else if (addr_expr) {
                        if (es_val != 0x0Fu) {
                            addr_expr = Expr::make_bin("|", Expr::make_const(es_val << 16, Width::A),
                                                       Expr::make_un("u16", addr_expr, Width::W), Width::A);
                            linear = true;
                        } else {
                            linear = e->addr_is_linear || (addr_expr->width == Width::A);
                        }
                        es = false;
                    }
                }
            } else {
                if (addr_expr && addr_expr->kind == ExprKind::Const) {
                    uint32_t v = addr_expr->value;
                    if (!linear && addr_expr->width != Width::A && v < 0x10000u) {
                        addr_expr = Expr::make_const((0xF0000u | v) & 0xFFFFFu, Width::A, addr_expr->name);
                    }
                    linear = true;
                }
            }

            if (!es && addr_expr && addr_expr->kind == ExprKind::Const) {
                uint32_t raw_a = addr_expr->value;
                if (env.allow_gpr_alias) {
                    if (auto gpr = gpr_alias(raw_a, e->width, env.bank); gpr.has_value()) {
                        return subst_expr(Expr::make_reg(*gpr, e->width), env);
                    }
                }
                if (auto sp = special_reg(raw_a, e->width); sp.has_value()) {
                    return subst_expr(Expr::make_reg(*sp, e->width), env);
                }
                return Expr::make_mem_abs(raw_a, e->width, false, e->name, true);
            }
            return Expr::make_mem_addr(addr_expr, e->width, es, e->name, linear);
        }
        default:
            return e;
    }
}

void clobber_intrinsic(Env &env, const Stmt &s) {
    if (s.name == "sel") {
        if (!s.args.empty() && s.args[0]->kind == ExprKind::Reg && s.args[0]->name.rfind("rb", 0) == 0) {
            int b = std::atoi(s.args[0]->name.c_str() + 2);
            if (b >= 0 && b <= 3) env.set_bank(b);
            else env.set_bank(std::nullopt);
        } else {
            env.set_bank(std::nullopt);
        }
        return;
    }
    if (s.name == "push" || s.name == "ei" || s.name == "di" || s.name == "nop") return;
    if (s.name == "pop" && !s.args.empty() && s.args[0]->kind == ExprKind::Reg) {
        const std::string &rn = s.args[0]->name;
        if (rn == "psw") {
            env.set_bank(std::nullopt);
            env.kill("psw");
        } else {
            env.kill(rn);
        }
        return;
    }
    env.clear();
}

bool same_lval(const ExprPtr &a, const ExprPtr &b) {
    if (!a || !b || a->kind != b->kind) return false;
    if (a->kind == ExprKind::Reg || a->kind == ExprKind::Var) return a->name == b->name;
    return false;
}

struct OpConstInfo {
    std::string op;
    ExprPtr base;
    uint32_t c = 0;
};

std::optional<OpConstInfo> extract_op_const(const ExprPtr &src) {
    if (!src || src->kind != ExprKind::Bin) return std::nullopt;
    const std::string &op = src->op;
    if (op != "+" && op != "-" && op != "<<" && op != ">>" && op != "&" && op != "|" && op != "^") {
        return std::nullopt;
    }
    if (src->r && src->r->kind == ExprKind::Const && src->r->name.empty()) {
        return OpConstInfo{op, src->l, src->r->value};
    }
    if ((op == "+" || op == "&" || op == "|" || op == "^") &&
        src->l && src->l->kind == ExprKind::Const && src->l->name.empty()) {
        return OpConstInfo{op, src->r, src->l->value};
    }
    return std::nullopt;
}

void coalesce_block(Block &b) {
    bool changed = true;
    while (changed) {
        changed = false;
        std::vector<StmtPtr> next_stmts;
        next_stmts.reserve(b.stmts.size());
        size_t i = 0;
        while (i < b.stmts.size()) {
            if (i + 1 < b.stmts.size()) {
                const auto &s1 = b.stmts[i];
                const auto &s2 = b.stmts[i + 1];
                if (s1->kind == StmtKind::Assign && s2->kind == StmtKind::Assign &&
                    same_lval(s1->dst, s2->dst)) {
                    const ExprPtr &dst = s1->dst;
                    bool is_gpr = dst->kind == ExprKind::Reg &&
                                  dst->name != "sp" && dst->name != "psw" &&
                                  dst->name != "spl" && dst->name != "sph" && dst->name != "cy";
                    bool is_var = (dst->kind == ExprKind::Var);
                    bool s1_has_flags = (s1->z_flag != nullptr || s1->cy_flag != nullptr);
                    bool s2_has_flags = (s2->z_flag != nullptr || s2->cy_flag != nullptr);
                    if ((is_gpr || is_var) && !(s1_has_flags && !s2_has_flags)) {
                        auto i1 = extract_op_const(s1->src);
                        auto i2 = extract_op_const(s2->src);
                        if (i1.has_value() && i2.has_value() && same_lval(i2->base, dst)) {
                            ExprPtr comb_src;
                            Width w = dst->width;
                            const std::string &op1 = i1->op, &op2 = i2->op;
                            uint32_t c1 = i1->c, c2 = i2->c;
                            if (op1 == "+" && op2 == "+") comb_src = Expr::make_bin("+", i1->base, Expr::make_const(c1 + c2, w), w);
                            else if (op1 == "-" && op2 == "-") comb_src = Expr::make_bin("-", i1->base, Expr::make_const(c1 + c2, w), w);
                            else if (op1 == "+" && op2 == "-") {
                                if (c1 > c2) comb_src = Expr::make_bin("+", i1->base, Expr::make_const(c1 - c2, w), w);
                                else if (c1 == c2) comb_src = i1->base;
                                else comb_src = Expr::make_bin("-", i1->base, Expr::make_const(c2 - c1, w), w);
                            } else if (op1 == "-" && op2 == "+") {
                                if (c2 > c1) comb_src = Expr::make_bin("+", i1->base, Expr::make_const(c2 - c1, w), w);
                                else if (c2 == c1) comb_src = i1->base;
                                else comb_src = Expr::make_bin("-", i1->base, Expr::make_const(c1 - c2, w), w);
                            } else if (op1 == "<<" && op2 == "<<") comb_src = Expr::make_bin("<<", i1->base, Expr::make_const(c1 + c2, w), w);
                            else if (op1 == ">>" && op2 == ">>") comb_src = Expr::make_bin(">>", i1->base, Expr::make_const(c1 + c2, w), w);
                            else if (op1 == "&" && op2 == "&") comb_src = Expr::make_bin("&", i1->base, Expr::make_const(c1 & c2, w), w);
                            else if (op1 == "|" && op2 == "|") comb_src = Expr::make_bin("|", i1->base, Expr::make_const(c1 | c2, w), w);
                            else if (op1 == "^" && op2 == "^") comb_src = Expr::make_bin("^", i1->base, Expr::make_const(c1 ^ c2, w), w);

                            if (comb_src) {
                                if (same_lval(dst, comb_src) && !s2_has_flags) {
                                    i += 2;
                                    changed = true;
                                    continue;
                                }
                                auto ns = make_assign(s1->ea, dst, comb_src, s2->z_flag, s2->cy_flag);
                                next_stmts.push_back(ns);
                                i += 2;
                                changed = true;
                                continue;
                            }
                        }
                    }
                }
            }
            next_stmts.push_back(b.stmts[i]);
            ++i;
        }
        b.stmts = std::move(next_stmts);
    }
}

ExprPtr subst_reg_in_expr(const ExprPtr &e, const std::string &old_r, const std::string &new_r) {
    if (!e) return nullptr;
    if (e->kind == ExprKind::Reg && e->name == old_r) return Expr::make_reg(new_r, e->width);
    if (e->kind == ExprKind::Bin) return Expr::make_bin(e->op, subst_reg_in_expr(e->l, old_r, new_r), subst_reg_in_expr(e->r, old_r, new_r), e->width);
    if (e->kind == ExprKind::Un) return Expr::make_un(e->op, subst_reg_in_expr(e->l, old_r, new_r), e->width);
    if (e->kind == ExprKind::Bit) return Expr::make_bit(subst_reg_in_expr(e->base, old_r, new_r), e->bit);
    if (e->kind == ExprKind::Mem && !e->has_static_addr) {
        return Expr::make_mem_addr(subst_reg_in_expr(e->addr, old_r, new_r), e->width, e->es, e->name);
    }
    if (e->kind == ExprKind::Intr) {
        std::vector<ExprPtr> na;
        for (const auto &a : e->args) na.push_back(subst_reg_in_expr(a, old_r, new_r));
        return Expr::make_intr(e->name, std::move(na), e->width);
    }
    return e;
}

void eliminate_swap_sandwiches(Function &func) {
    for (const auto &[bid, b] : func.blocks) {
        auto &stmts = b->stmts;
        size_t i = 0;
        while (i < stmts.size()) {
            const auto &s1 = stmts[i];
            if (s1->kind == StmtKind::Swap && s1->a && s1->b &&
                s1->a->kind == ExprKind::Reg && s1->b->kind == ExprKind::Reg) {
                std::string ra = s1->a->name, rb = s1->b->name;
                std::optional<size_t> match_j;
                for (size_t j = i + 1; j < stmts.size(); ++j) {
                    const auto &s2 = stmts[j];
                    if (s2->kind == StmtKind::Swap && s2->a && s2->b &&
                        s2->a->kind == ExprKind::Reg && s2->b->kind == ExprKind::Reg) {
                        if ((s2->a->name == ra && s2->b->name == rb) ||
                            (s2->a->name == rb && s2->b->name == ra)) {
                            match_j = j;
                            break;
                        }
                    }
                    if (s2->kind == StmtKind::Call || s2->kind == StmtKind::Branch ||
                        s2->kind == StmtKind::Goto || s2->kind == StmtKind::Ret) {
                        break;
                    }
                }
                if (match_j.has_value()) {
                    std::string acc = (ra == "a" || ra == "ax") ? ra : ((rb == "a" || rb == "ax") ? rb : ra);
                    std::string other = (acc == ra) ? rb : ra;
                    bool ok = true;
                    for (size_t k = i + 1; k < *match_j; ++k) {
                        const auto &ms = stmts[k];
                        if (ms->kind == StmtKind::Assign) {
                            if (ms->dst->kind == ExprKind::Reg && ms->dst->name == other) {
                                ok = false;
                                break;
                            }
                        } else if (ms->kind != StmtKind::Compare) {
                            ok = false;
                            break;
                        }
                    }
                    if (ok) {
                        auto subst_flag = [&](const FlagDefPtr &fl) -> FlagDefPtr {
                            if (!fl) return nullptr;
                            auto nf = clone_flag(fl);
                            nf->a = subst_reg_in_expr(nf->a, acc, other);
                            nf->b = subst_reg_in_expr(nf->b, acc, other);
                            nf->c = subst_reg_in_expr(nf->c, acc, other);
                            return nf;
                        };
                        std::vector<StmtPtr> rep;
                        for (size_t k = i + 1; k < *match_j; ++k) {
                            const auto &ms = stmts[k];
                            if (ms->kind == StmtKind::Assign) {
                                rep.push_back(make_assign(ms->ea,
                                                          subst_reg_in_expr(ms->dst, acc, other),
                                                          subst_reg_in_expr(ms->src, acc, other),
                                                          subst_flag(ms->z_flag),
                                                          subst_flag(ms->cy_flag)));
                            } else if (ms->kind == StmtKind::Compare) {
                                rep.push_back(make_compare(ms->ea, subst_flag(ms->z_flag), subst_flag(ms->cy_flag)));
                            }
                        }
                        stmts.erase(stmts.begin() + i, stmts.begin() + *match_j + 1);
                        stmts.insert(stmts.begin() + i, rep.begin(), rep.end());
                        continue;
                    }
                }
            }
            ++i;
        }
    }
}

void lower_swaps(Function &func) {
    int tmp_cnt = 0;
    for (const auto &[bid, b] : func.blocks) {
        std::vector<StmtPtr> out;
        out.reserve(b->stmts.size());
        for (const auto &s : b->stmts) {
            if (s->kind == StmtKind::Swap && s->a && s->b) {
                auto tvar = Expr::make_var("_swap_" + std::to_string(tmp_cnt++), s->a->width);
                out.push_back(make_assign(s->ea, tvar, s->a));
                out.push_back(make_assign(s->ea, s->a, s->b));
                out.push_back(make_assign(s->ea, s->b, tvar));
            } else {
                out.push_back(s);
            }
        }
        b->stmts = std::move(out);
    }
}

void opt_block(Block &b, std::optional<int> default_bank, const Env *initial_env, Env *out_env,
               bool allow_gpr_alias = true) {
    coalesce_block(b);
    Env env = initial_env ? *initial_env : Env{};
    if (!initial_env) env.bank = default_bank;
    env.allow_gpr_alias = allow_gpr_alias;

    auto update_flag_exprs = [&](FlagDef &fl, bool is_post_result, const ExprPtr &dst_expr, const ExprPtr &src_expr) {
        if (is_post_result && fl.kind == FlagKind::Result) {
            fl.a = (src_expr && src_expr->kind == ExprKind::Const) ? src_expr : dst_expr;
            return;
        }
        if (fl.a) fl.a = fold_expr(subst_expr(fl.a, env));
        if (fl.b) fl.b = fold_expr(subst_expr(fl.b, env));
        if (fl.c) fl.c = fold_expr(subst_expr(fl.c, env));
    };

    for (const auto &s : b.stmts) {
        if (s->kind == StmtKind::Assign) {
            s->src = fold_expr(subst_expr(s->src, env));

            if (s->z_flag && s->z_flag->kind != FlagKind::Result) {
                update_flag_exprs(*s->z_flag, false, s->dst, s->src);
            }
            if (s->cy_flag) {
                update_flag_exprs(*s->cy_flag, false, s->dst, s->src);
            }

            if (s->dst->kind == ExprKind::Mem) {
                s->dst = subst_expr(s->dst, env);
                if (s->dst->kind == ExprKind::Mem && s->dst->has_static_addr) {
                    std::optional<std::string> gpr = env.allow_gpr_alias
                        ? gpr_alias(s->dst->static_addr, s->dst->width, env.bank)
                        : std::nullopt;
                    if (gpr.has_value()) {
                        s->dst = Expr::make_reg(*gpr, s->dst->width);
                    } else if (auto sp = special_reg(s->dst->static_addr, s->dst->width); sp.has_value()) {
                        s->dst = Expr::make_reg(*sp, s->dst->width);
                    }
                }
                if (s->dst->kind == ExprKind::Mem) {
                    env.invalidate_mem_derived();
                }
            }

            if (s->z_flag && s->z_flag->kind == FlagKind::Result) {
                update_flag_exprs(*s->z_flag, true, s->dst, s->src);
            }

            if (s->dst->kind == ExprKind::Reg) {
                const std::string &dn = s->dst->name;
                if (dn == "psw") {
                    env.set_bank(std::nullopt);
                    env.kill("psw");
                } else if (s->src->kind == ExprKind::Const) {
                    env.set_const(dn, s->src->value, s->src->name);
                } else if (s->src->kind == ExprKind::Reg && env.lookup_const(s->src->name)) {
                    auto c = env.lookup_const(s->src->name);
                    env.set_const(dn, c->value, c->name);
                } else if (s->src->kind == ExprKind::Reg || s->src->kind == ExprKind::Var || s->src->kind == ExprKind::StackVar) {
                    if ((s->src->kind == ExprKind::Var || s->src->kind == ExprKind::StackVar) &&
                        env.var_consts.count(s->src->name)) {
                        env.set_const(dn, env.var_consts[s->src->name]);
                    } else {
                        env.set_copy(dn, s->src);
                    }
                } else {
                    env.kill(dn);
                }
            } else if (s->dst->kind == ExprKind::StackVar || s->dst->kind == ExprKind::Var) {
                const std::string &dn = s->dst->name;
                if (s->src->kind == ExprKind::Const) {
                    env.set_var_const(dn, s->src->value);
                } else if (s->src->kind == ExprKind::Reg) {
                    if (auto c = env.lookup_const(s->src->name)) {
                        env.set_var_const(dn, c->value);
                    } else if (dn.rfind("_s", 0) != 0) {
                        env.set_var_copy(dn, s->src);
                    } else {
                        env.kill_var(dn);
                    }
                } else if (s->src->kind == ExprKind::StackVar || s->src->kind == ExprKind::Var) {
                    if (env.var_consts.count(s->src->name)) {
                        env.set_var_const(dn, env.var_consts[s->src->name]);
                    } else {
                        env.set_var_copy(dn, s->src);
                    }
                } else {
                    env.kill_var(dn);
                }
            } else if (s->dst->kind == ExprKind::Bit && s->dst->base && s->dst->base->kind == ExprKind::Reg) {
                const std::string &bn = s->dst->base->name;
                if (bn == "psw") {
                    if (s->dst->bit == 3 || s->dst->bit == 5) env.set_bank(std::nullopt);
                    env.kill("psw");
                } else {
                    env.kill(bn);
                }
            }
            if (s->z_flag && !(s->dst && s->dst->kind == ExprKind::Reg && s->dst->name == "z")) {
                env.kill("z");
            }
            if (s->cy_flag && !(s->dst && s->dst->kind == ExprKind::Reg && s->dst->name == "cy")) {
                env.kill("cy");
            }
        } else if (s->kind == StmtKind::Compare) {
            if (s->z_flag)  update_flag_exprs(*s->z_flag, false, nullptr, nullptr);
            if (s->cy_flag) update_flag_exprs(*s->cy_flag, false, nullptr, nullptr);
            if (s->z_flag) env.kill("z");
            if (s->cy_flag) {
                if (s->cy_flag->kind == FlagKind::CarryVal && s->cy_flag->a && s->cy_flag->a->kind == ExprKind::Const) {
                    env.set_const("cy", s->cy_flag->a->value ? 1u : 0u);
                } else {
                    env.kill("cy");
                }
            }
        } else if (s->kind == StmtKind::Branch) {
            if (s->has_bittest) s->bittest_expr = fold_expr(subst_expr(s->bittest_expr, env));
            auto fold_br_flag = [&](const FlagDefPtr &fl) {
                if (!fl) return;
                if (fl->a) fl->a = fold_expr(subst_expr(fl->a, env));
                if (fl->b) fl->b = fold_expr(subst_expr(fl->b, env));
                if (fl->c) fl->c = fold_expr(subst_expr(fl->c, env));
            };
            // Pure folding of branch flags when no origin conflict exists
            if (s->z_flag && s->z_flag->origin_stmt_id == 0) fold_br_flag(s->z_flag);
            if (s->cy_flag && s->cy_flag->origin_stmt_id == 0) fold_br_flag(s->cy_flag);
            // Also fold any static ES: Mem inside existing FlagDef without clobbering post-origin vars
            auto fold_static_mem = [&](auto &self, const ExprPtr &fe) -> ExprPtr {
                if (!fe) return nullptr;
                if (fe->kind == ExprKind::Mem) {
                    if (fe->es && env.atom_consts.count("es") && fe->has_static_addr) {
                        uint32_t lin = ((static_cast<uint32_t>(env.atom_consts.at("es")) << 16) | (fe->static_addr & 0xFFFFu)) & 0xFFFFFu;
                        return Expr::make_mem_abs(lin, fe->width, false, fe->name, true);
                    }
                    return fold_expr(fe);
                }
                if (fe->kind == ExprKind::Bin) return fold_expr(Expr::make_bin(fe->op, self(self, fe->l), self(self, fe->r), fe->width));
                if (fe->kind == ExprKind::Un) return fold_expr(Expr::make_un(fe->op, self(self, fe->l), fe->width));
                if (fe->kind == ExprKind::Bit) return Expr::make_bit(self(self, fe->base), fe->bit);
                return fe;
            };
            auto fold_mem_only = [&](const FlagDefPtr &fl) {
                if (!fl) return;
                if (fl->a) fl->a = fold_static_mem(fold_static_mem, fl->a);
                if (fl->b) fl->b = fold_static_mem(fold_static_mem, fl->b);
                if (fl->c) fl->c = fold_static_mem(fold_static_mem, fl->c);
            };
            fold_mem_only(s->z_flag);
            fold_mem_only(s->cy_flag);
        } else if (s->kind == StmtKind::Switch) {
            s->expr = fold_expr(subst_expr(s->expr, env));
        } else if (s->kind == StmtKind::Intrinsic) {
            for (size_t i = 0; i < s->args.size(); ++i) {
                if (is_lval_arg(s->name, i)) {
                    if (s->args[i]->kind == ExprKind::Mem) s->args[i] = subst_expr(s->args[i], env);
                } else {
                    s->args[i] = fold_expr(subst_expr(s->args[i], env));
                }
            }
            clobber_intrinsic(env, *s);
        } else if (s->kind == StmtKind::Call) {
            env.clear();
        }
    }
    coalesce_block(b);
    {
        std::vector<StmtPtr> filtered;
        filtered.reserve(b.stmts.size());
        for (const auto &st : b.stmts) {
            bool is_self_reg_noop = st && st->kind == StmtKind::Assign && !st->z_flag && !st->cy_flag &&
                                     st->dst && st->src && st->dst->kind == ExprKind::Reg &&
                                     st->src->kind == ExprKind::Reg && st->dst->name == st->src->name;
            if (!is_self_reg_noop) filtered.push_back(st);
        }
        b.stmts.swap(filtered);
    }
    if (out_env) *out_env = std::move(env);
}

} // namespace

ExprPtr simplify_math(const ExprPtr &e) {
    if (!e || e->kind != ExprKind::Bin) return e;
    ExprPtr l = (e->l && e->l->kind == ExprKind::Bin) ? simplify_math(e->l) : e->l;
    ExprPtr r = (e->r && e->r->kind == ExprKind::Bin) ? simplify_math(e->r) : e->r;
    if (e->op != "+" && e->op != "-") return Expr::make_bin(e->op, l, r, e->width);

    struct TermEntry { ExprPtr expr; int64_t coeff = 0; };
    std::vector<TermEntry> terms;
    std::vector<TermEntry> named_consts;
    int64_t const_val = 0;
    Width const_width = Width::B;

    auto add_term = [](std::vector<TermEntry> &vec, const ExprPtr &node, int64_t mult) {
        for (auto &t : vec) {
            if (expr_eq(t.expr, node)) { t.coeff += mult; return; }
        }
        vec.push_back({node, mult});
    };

    std::function<void(const ExprPtr &, int64_t)> collect = [&](const ExprPtr &node, int64_t mult) {
        if (!node) return;
        if (node->kind == ExprKind::Bin) {
            if (node->op == "+") { collect(node->l, mult); collect(node->r, mult); return; }
            if (node->op == "-") { collect(node->l, mult); collect(node->r, -mult); return; }
            if (node->op == "*") {
                if (node->r && node->r->kind == ExprKind::Const && node->r->name.empty()) {
                    collect(node->l, mult * static_cast<int64_t>(node->r->value));
                    return;
                }
                if (node->l && node->l->kind == ExprKind::Const && node->l->name.empty()) {
                    collect(node->r, mult * static_cast<int64_t>(node->l->value));
                    return;
                }
            }
        } else if (node->kind == ExprKind::Const) {
            if (!node->name.empty()) {
                add_term(named_consts, node, mult);
                return;
            }
            const_val += mult * static_cast<int64_t>(node->value);
            if (node->width == Width::A || std::llabs(const_val) > 0xFFFF) const_width = Width::A;
            else if (node->width == Width::W && const_width != Width::A) const_width = Width::W;
            else if (std::llabs(const_val) > 0xFF && const_width == Width::B) const_width = Width::W;
            return;
        } else if (node->kind == ExprKind::Un && node->op == "-") {
            collect(node->l, -mult);
            return;
        }
        add_term(terms, node, mult);
    };

    collect(Expr::make_bin(e->op, l, r, e->width), 1);

    std::vector<std::pair<ExprPtr, int>> parts;
    for (const auto &t : terms) {
        if (t.coeff == 0) continue;
        if (t.coeff == 1) parts.emplace_back(t.expr, 1);
        else if (t.coeff == -1) parts.emplace_back(t.expr, -1);
        else if (t.coeff > 1) parts.emplace_back(Expr::make_bin("*", t.expr, Expr::make_const(static_cast<uint32_t>(t.coeff), t.expr->width), t.expr->width), 1);
        else parts.emplace_back(Expr::make_bin("*", t.expr, Expr::make_const(static_cast<uint32_t>(-t.coeff), t.expr->width), t.expr->width), -1);
    }
    for (const auto &nc : named_consts) {
        if (nc.coeff == 0) continue;
        if (nc.coeff == 1) parts.emplace_back(nc.expr, 1);
        else if (nc.coeff > 1) parts.emplace_back(Expr::make_bin("*", nc.expr, Expr::make_const(static_cast<uint32_t>(nc.coeff), nc.expr->width), nc.expr->width), 1);
        else parts.emplace_back(Expr::make_bin("*", nc.expr, Expr::make_const(static_cast<uint32_t>(-nc.coeff), nc.expr->width), nc.expr->width), -1);
    }
    if (const_val != 0) {
        if (std::llabs(const_val) > 0xFFFF) const_width = Width::A;
        else if (std::llabs(const_val) > 0xFF && const_width == Width::B) const_width = Width::W;
        if (const_val > 0) parts.emplace_back(Expr::make_const(static_cast<uint32_t>(const_val), const_width), 1);
        else parts.emplace_back(Expr::make_const(static_cast<uint32_t>(-const_val), const_width), -1);
    }
    if (parts.empty()) return Expr::make_const(0, e->width);

    ExprPtr res = (parts[0].second > 0) ? parts[0].first : Expr::make_un("-", parts[0].first, e->width);
    for (size_t i = 1; i < parts.size(); ++i) {
        res = Expr::make_bin(parts[i].second > 0 ? "+" : "-", res, parts[i].first, e->width);
    }
    return res;
}

struct EsVal {
    enum Kind : uint8_t { Top = 0, Const, Dynamic } kind = Top;
    uint8_t val = 0x0F;
    bool operator==(const EsVal &o) const { return kind == o.kind && (kind != Const || val == o.val); }
    bool operator!=(const EsVal &o) const { return !(*this == o); }
};

EsVal meet_es_val(EsVal a, EsVal b) {
    if (a.kind == EsVal::Top) return b;
    if (b.kind == EsVal::Top) return a;
    if (a.kind == EsVal::Dynamic || b.kind == EsVal::Dynamic) return {EsVal::Dynamic, 0};
    if (a.val == b.val) return a;
    return {EsVal::Dynamic, 0};
}

void step_es_stmt(const Stmt &s, EsVal &cur, const IDatabaseProvider *db) {
    if (s.kind == StmtKind::Assign && s.dst && s.dst->kind == ExprKind::Reg && s.dst->name == "es") {
        if (s.src && s.src->kind == ExprKind::Const) {
            cur = {EsVal::Const, static_cast<uint8_t>(s.src->value & 0xFu)};
        } else {
            cur = {EsVal::Dynamic, 0};
        }
        return;
    }
    if (s.kind == StmtKind::Call) {
        if (s.target.has_value() && db) {
            CalleeEsInfo ce = db->get_callee_es_effect(*s.target);
            if (ce.effect == CalleeEsEffect::Preserved) return;
            if (ce.effect == CalleeEsEffect::ReturnsConst) {
                cur = {EsVal::Const, static_cast<uint8_t>(ce.const_val & 0xFu)};
                return;
            }
        }
        cur = {EsVal::Dynamic, 0};
        return;
    }
    if (s.kind == StmtKind::Intrinsic) {
        if (s.name == "pop" && !s.args.empty() && s.args[0] &&
            s.args[0]->kind == ExprKind::Reg && s.args[0]->name == "es") {
            cur = {EsVal::Dynamic, 0};
        }
    }
}

ExprPtr fold_es_in_expr(const ExprPtr &e, uint8_t es_val_u8) {
    if (!e) return nullptr;
    uint32_t es_val = static_cast<uint32_t>(es_val_u8) & 0xFu;
    switch (e->kind) {
        case ExprKind::Mem: {
            ExprPtr na = e->has_static_addr ? nullptr : fold_es_in_expr(e->addr, es_val_u8);
            if (!e->es) {
                if (!e->has_static_addr && na != e->addr) {
                    return Expr::make_mem_addr(na, e->width, false, e->name, e->addr_is_linear);
                }
                return e;
            }
            if (e->has_static_addr) {
                uint32_t lin = ((es_val << 16) | (e->static_addr & 0xFFFFu)) & 0xFFFFFu;
                return Expr::make_mem_abs(lin, e->width, false, e->name, true);
            }
            if (na && na->kind == ExprKind::Const) {
                uint32_t lin = ((es_val << 16) | (na->value & 0xFFFFu)) & 0xFFFFFu;
                return Expr::make_mem_abs(lin, e->width, false, e->name, true);
            }
            if (na && na->kind == ExprKind::Bin && (na->op == "+" || na->op == "-")) {
                if (na->l && na->l->kind == ExprKind::Const && na->l->value < 0x10000u) {
                    uint32_t lin = ((es_val << 16) | (na->l->value & 0xFFFFu)) & 0xFFFFFu;
                    ExprPtr comb = Expr::make_bin(na->op, Expr::make_const(lin, Width::A, na->l->name), na->r, Width::A);
                    return Expr::make_mem_addr(comb, e->width, false, e->name, true);
                }
                if (na->op == "+" && na->r && na->r->kind == ExprKind::Const && na->r->value < 0x10000u) {
                    uint32_t lin = ((es_val << 16) | (na->r->value & 0xFFFFu)) & 0xFFFFFu;
                    ExprPtr comb = Expr::make_bin("+", na->l, Expr::make_const(lin, Width::A, na->r->name), Width::A);
                    return Expr::make_mem_addr(comb, e->width, false, e->name, true);
                }
            }
            if (na) {
                if (es_val == 0x0Fu) {
                    return Expr::make_mem_addr(na, e->width, false, e->name,
                                               e->addr_is_linear || (na->width == Width::A));
                }
                ExprPtr seg_addr = Expr::make_bin("|", Expr::make_const(es_val << 16, Width::A),
                                                  Expr::make_un("u16", na, Width::W), Width::A);
                return Expr::make_mem_addr(seg_addr, e->width, false, e->name, true);
            }
            return e;
        }
        case ExprKind::Bin: {
            ExprPtr nl = fold_es_in_expr(e->l, es_val_u8);
            ExprPtr nr = fold_es_in_expr(e->r, es_val_u8);
            return (nl == e->l && nr == e->r) ? e : Expr::make_bin(e->op, nl, nr, e->width);
        }
        case ExprKind::Un: {
            ExprPtr nl = fold_es_in_expr(e->l, es_val_u8);
            return (nl == e->l) ? e : Expr::make_un(e->op, nl, e->width);
        }
        case ExprKind::Bit: {
            ExprPtr nb = fold_es_in_expr(e->base, es_val_u8);
            return (nb == e->base) ? e : Expr::make_bit(nb, e->bit);
        }
        case ExprKind::Intr: {
            std::vector<ExprPtr> na;
            bool chg = false;
            for (const auto &a : e->args) {
                ExprPtr x = fold_es_in_expr(a, es_val_u8);
                if (x != a) chg = true;
                na.push_back(x);
            }
            return chg ? Expr::make_intr(e->name, std::move(na), e->width) : e;
        }
        default:
            return e;
    }
}

void fold_es_in_flag(const FlagDefPtr &fl, uint8_t es_val_u8) {
    if (!fl) return;
    if (fl->a) fl->a = fold_es_in_expr(fl->a, es_val_u8);
    if (fl->b) fl->b = fold_es_in_expr(fl->b, es_val_u8);
    if (fl->c) fl->c = fold_es_in_expr(fl->c, es_val_u8);
}

std::unordered_map<uint32_t, EsVal> propagate_and_fold_es(Function &func, const IDatabaseProvider *db) {
    auto order = func.ordered();
    std::unordered_map<uint32_t, std::vector<uint32_t>> preds;
    for (const auto &b : order) {
        for (const auto &[how, tgt] : b->succ) preds[tgt].push_back(b->start);
    }

    EsVal entry_seed{EsVal::Dynamic, 0};
    if (db) {
        if (auto e = db->get_es_at(func.entry); e.has_value()) {
            entry_seed = {EsVal::Const, static_cast<uint8_t>(*e & 0xFu)};
        }
    }

    std::unordered_map<uint32_t, EsVal> in_es, out_es;
    for (int iter = 0; iter < 64; ++iter) {
        bool changed = false;
        for (const auto &b : order) {
            EsVal cur = (b->start == func.entry) ? entry_seed : EsVal{EsVal::Top, 0};
            if (auto pit = preds.find(b->start); pit != preds.end()) {
                for (uint32_t p : pit->second) {
                    if (auto oit = out_es.find(p); oit != out_es.end()) {
                        cur = meet_es_val(cur, oit->second);
                    }
                }
            }
            in_es[b->start] = cur;
            for (const auto &s : b->stmts) step_es_stmt(*s, cur, db);
            auto it = out_es.find(b->start);
            if (it == out_es.end() || it->second != cur) {
                out_es[b->start] = cur;
                changed = true;
            }
        }
        if (!changed) break;
    }

    for (const auto &b : order) {
        EsVal cur = in_es[b->start];
        for (const auto &s : b->stmts) {
            if (cur.kind == EsVal::Const) {
                if (s->dst) s->dst = fold_es_in_expr(s->dst, cur.val);
                if (s->src) s->src = fold_es_in_expr(s->src, cur.val);
                if (s->a)   s->a   = fold_es_in_expr(s->a, cur.val);
                if (s->b)   s->b   = fold_es_in_expr(s->b, cur.val);
                if (s->expr) s->expr = fold_es_in_expr(s->expr, cur.val);
                for (auto &a : s->args) a = fold_es_in_expr(a, cur.val);
                if (s->val) s->val = fold_es_in_expr(s->val, cur.val);
                if (s->has_bittest && s->bittest_expr) s->bittest_expr = fold_es_in_expr(s->bittest_expr, cur.val);
                fold_es_in_flag(s->z_flag, cur.val);
                fold_es_in_flag(s->cy_flag, cur.val);
            }
            step_es_stmt(*s, cur, db);
        }
    }
    return in_es;
}

void optimize(Function &func, std::optional<int> default_bank, const IDatabaseProvider *db,
              bool allow_gpr_alias) {
    eliminate_swap_sandwiches(func);
    lower_swaps(func);

    auto order = func.ordered();
    for (const auto &b : order) {
        opt_block(*b, default_bank, nullptr, nullptr, allow_gpr_alias);
    }

    auto in_es = propagate_and_fold_es(func, db);

    std::unordered_map<uint32_t, std::vector<uint32_t>> preds;
    for (const auto &[bid, b] : func.blocks) {
        for (const auto &[how, tgt] : b->succ) preds[tgt].push_back(b->start);
    }

    std::unordered_map<uint32_t, Env> out_envs;
    for (const auto &b : order) {
        Env in_env;
        bool has_in = false;
        auto pit = preds.find(b->start);
        if (pit != preds.end() && pit->second.size() == 1) {
            auto oit = out_envs.find(pit->second[0]);
            if (oit != out_envs.end()) {
                in_env = oit->second;
                has_in = true;
            }
        }
        if (!has_in) in_env.bank = default_bank;
        in_env.allow_gpr_alias = allow_gpr_alias;
        auto eit = in_es.find(b->start);
        if (eit != in_es.end() && eit->second.kind == EsVal::Const) {
            in_env.atom_consts["es"] = eit->second.val;
        }

        Env b_out;
        opt_block(*b, default_bank, &in_env, &b_out, allow_gpr_alias);
        out_envs[b->start] = std::move(b_out);
    }
}

} // namespace rl78dec
