#include "rl78dec/vars.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <functional>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "rl78dec/sfr.hpp"

namespace rl78dec {

namespace {

// Track the 8 GPR byte atoms (0..7: X, A, C, B, E, D, L, H)
constexpr int kNumAtoms = 8;

const char *kAtomNames[kNumAtoms] = {"x", "a", "c", "b", "e", "d", "l", "h"};

int atom_index(AtomMask m) {
    for (int i = 0; i < kNumAtoms; ++i) {
        if (m == (1u << i)) return i;
    }
    return -1;
}

std::vector<int> atom_indices(AtomMask m) {
    std::vector<int> out;
    for (int i = 0; i < kNumAtoms; ++i) {
        if (m & (1u << i)) out.push_back(i);
    }
    return out;
}

AtomMask gpr_atoms_of(const std::string &reg_name) {
    return reg_atoms_named(reg_name) & atom::GPR_8;
}

struct ReachingState {
    // For each atom 0..7: sorted list of defining statement IDs (0 = function entry)
    std::array<std::vector<uint64_t>, kNumAtoms> defs;

    bool operator==(const ReachingState &o) const { return defs == o.defs; }
    bool operator!=(const ReachingState &o) const { return defs != o.defs; }
};

void add_def(std::vector<uint64_t> &vec, uint64_t id) {
    if (std::find(vec.begin(), vec.end(), id) == vec.end()) {
        vec.push_back(id);
        std::sort(vec.begin(), vec.end());
    }
}

void merge_state(ReachingState &dst, const ReachingState &src) {
    for (int i = 0; i < kNumAtoms; ++i) {
        for (uint64_t id : src.defs[i]) add_def(dst.defs[i], id);
    }
}

struct NodeKey {
    uint64_t def_id = 0;
    int atom = 0;
    bool operator==(const NodeKey &o) const { return def_id == o.def_id && atom == o.atom; }
};

struct NodeKeyHash {
    size_t operator()(const NodeKey &k) const {
        return std::hash<uint64_t>{}(k.def_id) * 1315423911u + static_cast<size_t>(k.atom);
    }
};

class UnionFind {
public:
    int get_or_add(const NodeKey &k) {
        auto it = idx_.find(k);
        if (it != idx_.end()) return it->second;
        int id = static_cast<int>(nodes_.size());
        idx_[k] = id;
        nodes_.push_back(k);
        parent_.push_back(id);
        is_word_.push_back(false);
        return id;
    }

    int find(int x) {
        while (parent_[x] != x) {
            parent_[x] = parent_[parent_[x]];
            x = parent_[x];
        }
        return x;
    }

    void unite(int a, int b) {
        a = find(a);
        b = find(b);
        if (a == b) return;
        if (b < a) std::swap(a, b);
        parent_[b] = a;
        if (is_word_[b]) is_word_[a] = true;
    }

    void mark_word(int x) { is_word_[find(x)] = true; }
    bool is_word(int x) { return is_word_[find(x)]; }
    size_t size() const { return nodes_.size(); }
    const NodeKey &key(int x) const { return nodes_[x]; }

private:
    std::unordered_map<NodeKey, int, NodeKeyHash> idx_;
    std::vector<NodeKey> nodes_;
    std::vector<int> parent_;
    std::vector<bool> is_word_;
};

bool expr_has_side_effect(const ExprPtr &e) {
    if (!e) return false;
    if (e->kind == ExprKind::Intr) return true;
    if (e->kind == ExprKind::Bin) return expr_has_side_effect(e->l) || expr_has_side_effect(e->r);
    if (e->kind == ExprKind::Un) return expr_has_side_effect(e->l);
    if (e->kind == ExprKind::Mem) return !e->has_static_addr && expr_has_side_effect(e->addr);
    if (e->kind == ExprKind::Bit) return expr_has_side_effect(e->base);
    return false;
}

bool flag_uses_pre_state(FlagKind k) {
    return k != FlagKind::Result && k != FlagKind::Cmp0;
}

ExprPtr map_var_expr(const ExprPtr &v_expr, Width var_w, const std::string &reg_name) {
    if (var_w == Width::B || is_pair_name(reg_name)) {
        return v_expr;
    }
    auto poa = pair_of_atom(reg_name);
    if (!poa.has_value()) return v_expr;
    if (poa->second == 1) {
        // High byte of 16-bit pair
        return Expr::make_bin("&",
                              Expr::make_bin(">>", v_expr, Expr::make_const(8, Width::B), Width::W),
                              Expr::make_const(0xFF, Width::B),
                              Width::B);
    }
    // Low byte of 16-bit pair
    return Expr::make_bin("&", v_expr, Expr::make_const(0xFF, Width::B), Width::B);
}

void collect_var_names(const ExprPtr &e, std::unordered_set<std::string> &out) {
    if (!e) return;
    if (e->kind == ExprKind::Var || e->kind == ExprKind::StackVar) {
        out.insert(e->name);
        return;
    }
    if (e->kind == ExprKind::Bin) {
        collect_var_names(e->l, out);
        collect_var_names(e->r, out);
    } else if (e->kind == ExprKind::Un) {
        collect_var_names(e->l, out);
    } else if (e->kind == ExprKind::Mem) {
        collect_var_names(e->addr, out);
    } else if (e->kind == ExprKind::Bit) {
        collect_var_names(e->base, out);
    } else if (e->kind == ExprKind::Intr) {
        for (const auto &a : e->args) collect_var_names(a, out);
    }
}

ExprPtr subst_var_name(const ExprPtr &e, const std::string &old_nm, const ExprPtr &repl) {
    if (!e) return nullptr;
    switch (e->kind) {
        case ExprKind::Var:
        case ExprKind::StackVar:
            if (e->name == old_nm) return expr_clone(repl);
            return e;
        case ExprKind::Bin: {
            ExprPtr nl = subst_var_name(e->l, old_nm, repl);
            ExprPtr nr = subst_var_name(e->r, old_nm, repl);
            if (nl == e->l && nr == e->r) return e;
            return Expr::make_bin(e->op, nl, nr, e->width);
        }
        case ExprKind::Un: {
            ExprPtr nl = subst_var_name(e->l, old_nm, repl);
            if (nl == e->l) return e;
            return Expr::make_un(e->op, nl, e->width);
        }
        case ExprKind::Mem: {
            if (e->has_static_addr) return e;
            ExprPtr na = subst_var_name(e->addr, old_nm, repl);
            if (na == e->addr) return e;
            return Expr::make_mem_addr(na, e->width, e->es, e->name);
        }
        case ExprKind::Bit: {
            ExprPtr nb = subst_var_name(e->base, old_nm, repl);
            if (nb == e->base) return e;
            return Expr::make_bit(nb, e->bit);
        }
        case ExprKind::Intr: {
            std::vector<ExprPtr> nargs;
            bool chg = false;
            for (const auto &a : e->args) {
                ExprPtr na = subst_var_name(a, old_nm, repl);
                if (na != a) chg = true;
                nargs.push_back(na);
            }
            if (!chg) return e;
            return Expr::make_intr(e->name, std::move(nargs), e->width);
        }
        default:
            return e;
    }
}

void collect_expr_vars_to_frame(const ExprPtr &e, FrameInfo &fi,
                                const std::unordered_set<std::string> &arg_names) {
    if (!e) return;
    switch (e->kind) {
        case ExprKind::StackVar:
        case ExprKind::Var: {
            if (!e->name.empty() && !arg_names.count(e->name) && !fi.args.count(e->name)) {
                auto it = fi.locals.find(e->name);
                if (it == fi.locals.end()) {
                    fi.locals[e->name] = FrameInfo::VarDecl{e, e->width};
                } else if (width_bytes(e->width) > width_bytes(it->second.width)) {
                    it->second.width = e->width;
                }
            }
            break;
        }
        case ExprKind::Bin:
            collect_expr_vars_to_frame(e->l, fi, arg_names);
            collect_expr_vars_to_frame(e->r, fi, arg_names);
            break;
        case ExprKind::Un:
            collect_expr_vars_to_frame(e->l, fi, arg_names);
            break;
        case ExprKind::Mem:
            if (!e->has_static_addr) collect_expr_vars_to_frame(e->addr, fi, arg_names);
            break;
        case ExprKind::Bit:
            collect_expr_vars_to_frame(e->base, fi, arg_names);
            break;
        case ExprKind::Intr:
            for (const auto &a : e->args) collect_expr_vars_to_frame(a, fi, arg_names);
            break;
        default:
            break;
    }
}

} // namespace

void recover_variables(Function &func, const FunctionSig &sig, FrameInfo &frame_info,
                       const IDatabaseProvider * /*db*/) {
    auto order = func.ordered();
    if (order.empty()) return;

    // 1. Replace homed stack argument slots with argument names across the IR first
    std::unordered_map<std::string, const Param *> reg_param_map;
    std::unordered_map<int64_t, const Param *> stk_param_map;
    std::unordered_set<std::string> arg_names;
    for (const auto &p : sig.params) {
        arg_names.insert(p.name);
        if (gpr_atoms_of(p.location) != 0) {
            reg_param_map[p.location] = &p;
        } else if (p.location.rfind("stk+", 0) == 0) {
            int64_t off = std::strtoll(p.location.c_str() + 4, nullptr, 10);
            stk_param_map[off] = &p;
        }
    }
    for (const auto &[slot_off, arg_nm] : frame_info.homed_slot_to_arg) {
        arg_names.insert(arg_nm);
    }

    auto rewrite_stk_expr = [&](auto &self, const ExprPtr &e) -> ExprPtr {
        if (!e) return nullptr;
        switch (e->kind) {
            case ExprKind::StackVar: {
                auto hit = frame_info.homed_slot_to_arg.find(e->offset);
                if (hit != frame_info.homed_slot_to_arg.end()) {
                    return Expr::make_var(hit->second, e->width);
                }
                if (e->is_arg) {
                    auto sit = stk_param_map.find(e->offset);
                    if (sit != stk_param_map.end()) {
                        return Expr::make_var(sit->second->name, e->width);
                    }
                }
                return e;
            }
            case ExprKind::Bin: {
                ExprPtr nl = self(self, e->l);
                ExprPtr nr = self(self, e->r);
                if (nl == e->l && nr == e->r) return e;
                return Expr::make_bin(e->op, nl, nr, e->width);
            }
            case ExprKind::Un: {
                ExprPtr nl = self(self, e->l);
                if (nl == e->l) return e;
                return Expr::make_un(e->op, nl, e->width);
            }
            case ExprKind::Mem: {
                if (e->has_static_addr) return e;
                ExprPtr na = self(self, e->addr);
                if (na == e->addr) return e;
                return Expr::make_mem_addr(na, e->width, e->es, e->name);
            }
            case ExprKind::Bit: {
                ExprPtr nb = self(self, e->base);
                if (nb == e->base) return e;
                return Expr::make_bit(nb, e->bit);
            }
            case ExprKind::Intr: {
                std::vector<ExprPtr> nargs;
                bool chg = false;
                for (const auto &a : e->args) {
                    ExprPtr na = self(self, a);
                    if (na != a) chg = true;
                    nargs.push_back(na);
                }
                if (!chg) return e;
                return Expr::make_intr(e->name, std::move(nargs), e->width);
            }
            default:
                return e;
        }
    };

    auto apply_stmt_rewrite = [&](Stmt *s, const auto &fn) {
        if (s->dst) s->dst = fn(fn, s->dst);
        if (s->src) s->src = fn(fn, s->src);
        if (s->a)   s->a   = fn(fn, s->a);
        if (s->b)   s->b   = fn(fn, s->b);
        if (s->expr) s->expr = fn(fn, s->expr);
        for (auto &a : s->args) a = fn(fn, a);
        if (s->val) s->val = fn(fn, s->val);
        if (s->bittest_expr) s->bittest_expr = fn(fn, s->bittest_expr);
        auto rw_flag = [&](const FlagDefPtr &f) {
            if (!f) return;
            if (f->a) f->a = fn(fn, f->a);
            if (f->b) f->b = fn(fn, f->b);
            if (f->c) f->c = fn(fn, f->c);
        };
        rw_flag(s->z_flag);
        rw_flag(s->cy_flag);
    };

    for (const auto &b : order) {
        for (const auto &s : b->stmts) {
            if (frame_info.hidden_stmts.count(s->id)) continue;
            apply_stmt_rewrite(s.get(), rewrite_stk_expr);
        }
    }

    // 2. Reaching definitions over 8 GPR byte atoms
    std::unordered_map<uint32_t, std::vector<uint32_t>> preds;
    for (const auto &b : order) {
        for (const auto &[how, tgt] : b->succ) preds[tgt].push_back(b->start);
    }

    ReachingState entry_state;
    for (int i = 0; i < kNumAtoms; ++i) entry_state.defs[i] = {0};

    auto transfer_stmt = [&](const Stmt *s, ReachingState &st) {
        if (!s || frame_info.hidden_stmts.count(s->id)) return;
        if (s->kind == StmtKind::Assign && s->dst && s->dst->kind == ExprKind::Reg) {
            AtomMask m = gpr_atoms_of(s->dst->name);
            for (int idx : atom_indices(m)) st.defs[idx] = {s->id};
        } else if (s->kind == StmtKind::Swap) {
            if (s->a && s->a->kind == ExprKind::Reg) {
                for (int idx : atom_indices(gpr_atoms_of(s->a->name))) st.defs[idx] = {s->id};
            }
            if (s->b && s->b->kind == ExprKind::Reg) {
                for (int idx : atom_indices(gpr_atoms_of(s->b->name))) st.defs[idx] = {s->id};
            }
        } else if (s->kind == StmtKind::Call) {
            // Return reg + caller-saved registers get fresh definition ID = s->id
            AtomMask clobber = atom::CALLER_SAVED;
            if (s->dst && s->dst->kind == ExprKind::Reg) {
                clobber |= gpr_atoms_of(s->dst->name);
            }
            for (int idx : atom_indices(clobber)) st.defs[idx] = {s->id};
        } else if (s->kind == StmtKind::Intrinsic && s->name == "pop" &&
                   !s->args.empty() && s->args[0]->kind == ExprKind::Reg) {
            for (int idx : atom_indices(gpr_atoms_of(s->args[0]->name))) st.defs[idx] = {s->id};
        } else if (s->kind == StmtKind::Intrinsic && s->name == "sel") {
            // SEL RBn switches register bank: sever reaching definitions of all 8 GPR atoms
            for (int idx = 0; idx < kNumAtoms; ++idx) st.defs[idx] = {s->id};
        }
    };

    std::unordered_map<uint32_t, ReachingState> blk_in, blk_out;
    for (int iter = 0; iter < 32; ++iter) {
        bool changed = false;
        for (const auto &b : order) {
            ReachingState in;
            auto pit = preds.find(b->start);
            bool no_preds = (pit == preds.end() || pit->second.empty());
            if (b->start == func.entry || no_preds) in = entry_state;
            if (!no_preds) {
                for (uint32_t p : pit->second) {
                    if (auto oit = blk_out.find(p); oit != blk_out.end()) {
                        merge_state(in, oit->second);
                    }
                }
            }
            if (blk_in[b->start] != in) {
                blk_in[b->start] = in;
            }
            ReachingState cur = in;
            for (const auto &s : b->stmts) transfer_stmt(s.get(), cur);
            if (blk_out.find(b->start) == blk_out.end() || blk_out[b->start] != cur) {
                blk_out[b->start] = std::move(cur);
                changed = true;
            }
        }
        if (!changed) break;
    }

    // Record exact pre/post reaching state for every statement ID
    std::unordered_map<uint64_t, ReachingState> stmt_pre, stmt_post;
    for (const auto &b : order) {
        ReachingState cur = blk_in[b->start];
        for (const auto &s : b->stmts) {
            stmt_pre[s->id] = cur;
            transfer_stmt(s.get(), cur);
            stmt_post[s->id] = cur;
        }
    }

    // 3. Build Def-Use Webs via UnionFind
    UnionFind uf;
    std::unordered_set<NodeKey, NodeKeyHash> used_defs;

    // Seed parameter webs on entry_id = 0 and track 8-bit register parameter atoms
    AtomMask byte_param_atoms = 0;
    for (const auto &[loc, p] : reg_param_map) {
        AtomMask m = gpr_atoms_of(loc);
        auto idxs = atom_indices(m);
        if (idxs.empty()) continue;
        bool is_byte_p = (idxs.size() == 1 && !is_pair_name(loc) && p->type_str != "uint16_t" && p->type_str != "int16_t");
        if (is_byte_p) byte_param_atoms |= m;
        int first = uf.get_or_add(NodeKey{0, idxs[0]});
        if (idxs.size() > 1 || is_pair_name(loc)) uf.mark_word(first);
        for (size_t i = 1; i < idxs.size(); ++i) {
            int n = uf.get_or_add(NodeKey{0, idxs[i]});
            uf.unite(first, n);
        }
    }

    auto bind_read_reg = [&](const std::string &rname, const ReachingState &rs) {
        AtomMask m = gpr_atoms_of(rname);
        if (m == 0) {
            return;
        }
        auto idxs = atom_indices(m);
        bool pair_read = (idxs.size() > 1) || is_pair_name(rname);
        if (pair_read && idxs.size() == 2) {
            // Do not promote an 8-bit register param (entry_id == 0) to a 16-bit web on a mixed pair read!
            bool hits_byte_param = false;
            for (int idx : idxs) {
                if (byte_param_atoms & (1u << idx)) {
                    for (uint64_t d : rs.defs[idx]) {
                        if (d == 0) hits_byte_param = true;
                    }
                }
            }
            if (hits_byte_param) {
                for (int idx : idxs) {
                    int a = -1;
                    for (uint64_t d : rs.defs[idx]) {
                        NodeKey nk{d, idx};
                        used_defs.insert(nk);
                        int nid = uf.get_or_add(nk);
                        if (a < 0) a = nid;
                        else uf.unite(a, nid);
                    }
                }
                return;
            }
        }
        int anchor = -1;
        for (int idx : idxs) {
            for (uint64_t d : rs.defs[idx]) {
                NodeKey nk{d, idx};
                used_defs.insert(nk);
                int nid = uf.get_or_add(nk);
                if (anchor < 0) anchor = nid;
                else uf.unite(anchor, nid);
            }
        }
        if (anchor >= 0 && pair_read) uf.mark_word(anchor);
    };

    auto collect_expr_reads = [&](auto &self, const ExprPtr &e, const ReachingState &rs) -> void {
        if (!e) return;
        switch (e->kind) {
            case ExprKind::Reg:
                if (e->name == "de_bc") {
                    bind_read_reg("de", rs);
                    bind_read_reg("bc", rs);
                } else {
                    bind_read_reg(e->name, rs);
                }
                break;
            case ExprKind::Bin:
                self(self, e->l, rs);
                self(self, e->r, rs);
                break;
            case ExprKind::Un:
                self(self, e->l, rs);
                break;
            case ExprKind::Mem:
                if (!e->has_static_addr) self(self, e->addr, rs);
                break;
            case ExprKind::Bit:
                self(self, e->base, rs);
                break;
            case ExprKind::Intr:
                for (const auto &a : e->args) self(self, a, rs);
                break;
            default:
                break;
        }
    };

    auto register_def_reg = [&](uint64_t sid, const std::string &rname) {
        if (rname == "de_bc") return;
        AtomMask m = gpr_atoms_of(rname);
        auto idxs = atom_indices(m);
        if (idxs.empty()) return;
        int anchor = uf.get_or_add(NodeKey{sid, idxs[0]});
        if (idxs.size() > 1 || is_pair_name(rname)) uf.mark_word(anchor);
        for (size_t i = 1; i < idxs.size(); ++i) {
            uf.unite(anchor, uf.get_or_add(NodeKey{sid, idxs[i]}));
        }
    };

    std::unordered_set<uint64_t> flag_origin_used;
    for (const auto &b : order) {
        for (const auto &s : b->stmts) {
            if (frame_info.hidden_stmts.count(s->id)) continue;
            const ReachingState &pre = stmt_pre[s->id];
            const ReachingState &post = stmt_post[s->id];

            if (s->kind == StmtKind::Assign) {
                if (s->dst) {
                    if (s->dst->kind == ExprKind::Reg) {
                        register_def_reg(s->id, s->dst->name);
                    } else {
                        collect_expr_reads(collect_expr_reads, s->dst, pre);
                    }
                }
                collect_expr_reads(collect_expr_reads, s->src, pre);
                // Note: Assign flags might propagate to a Branch, collect uses on original stmt too?
                // Only collect FlagDef reads on Compare/Branch where flag is actually tested!
            } else if (s->kind == StmtKind::Swap) {
                if (s->a && s->a->kind == ExprKind::Reg) {
                    bind_read_reg(s->a->name, pre);
                    register_def_reg(s->id, s->a->name);
                } else collect_expr_reads(collect_expr_reads, s->a, pre);
                if (s->b && s->b->kind == ExprKind::Reg) {
                    bind_read_reg(s->b->name, pre);
                    register_def_reg(s->id, s->b->name);
                } else collect_expr_reads(collect_expr_reads, s->b, pre);
            } else if (s->kind == StmtKind::Compare || s->kind == StmtKind::Branch) {
                if (s->has_bittest && s->bittest_expr) {
                    collect_expr_reads(collect_expr_reads, s->bittest_expr, pre);
                }
                auto scan_flag = [&](const FlagDefPtr &f) {
                    if (!f) return;
                    const ReachingState *rs_ptr = &pre;
                    if (f->origin_stmt_id != 0) {
                        flag_origin_used.insert(f->origin_stmt_id);
                        if (flag_uses_pre_state(f->kind)) {
                            if (auto it = stmt_pre.find(f->origin_stmt_id); it != stmt_pre.end()) rs_ptr = &it->second;
                        } else {
                            if (auto it = stmt_post.find(f->origin_stmt_id); it != stmt_post.end()) rs_ptr = &it->second;
                        }
                    }
                    collect_expr_reads(collect_expr_reads, f->a, *rs_ptr);
                    collect_expr_reads(collect_expr_reads, f->b, *rs_ptr);
                    collect_expr_reads(collect_expr_reads, f->c, *rs_ptr);
                };
                scan_flag(s->z_flag);
                scan_flag(s->cy_flag);
            } else if (s->kind == StmtKind::Call) {
                collect_expr_reads(collect_expr_reads, s->expr, pre);
                for (const auto &a : s->args) collect_expr_reads(collect_expr_reads, a, pre);
                if (s->dst && s->dst->kind == ExprKind::Reg) register_def_reg(s->id, s->dst->name);
            } else if (s->kind == StmtKind::Ret) {
                collect_expr_reads(collect_expr_reads, s->val, pre);
            } else if (s->kind == StmtKind::Switch) {
                collect_expr_reads(collect_expr_reads, s->expr, pre);
            } else if (s->kind == StmtKind::Intrinsic) {
                for (const auto &a : s->args) collect_expr_reads(collect_expr_reads, a, pre);
            }
        }
    }

    // 4. Dead Store Elimination for pure GPR assigns whose defs have zero reads & unused flags
    for (const auto &b : order) {
        for (auto &s : b->stmts) {
            if (frame_info.hidden_stmts.count(s->id)) continue;
            if (s->kind != StmtKind::Assign || !s->dst || s->dst->kind != ExprKind::Reg) continue;
            AtomMask m = gpr_atoms_of(s->dst->name);
            if (m == 0) continue; // keep sp/es/cs/psw writes
            if (flag_origin_used.count(s->id)) continue;
            if (expr_has_side_effect(s->src)) continue;
            bool any_used = false;
            for (int idx : atom_indices(m)) {
                if (used_defs.count(NodeKey{s->id, idx})) {
                    any_used = true;
                    break;
                }
            }
            if (!any_used) {
                s->kind = StmtKind::Nop;
                s->dst.reset();
                s->src.reset();
                s->z_flag.reset();
                s->cy_flag.reset();
            }
        }
    }

    // 5. Assign final variable names & widths per UnionFind representative
    std::unordered_map<int, std::string> rep_name;
    std::unordered_map<int, Width> rep_width;

    // Bind params first
    for (const auto &p : sig.params) {
        AtomMask m = gpr_atoms_of(p.location);
        if (m == 0) continue;
        auto idxs = atom_indices(m);
        int rep = uf.find(uf.get_or_add(NodeKey{0, idxs[0]}));
        bool is_byte_param = (idxs.size() == 1 && !is_pair_name(p.location) &&
                              p.type_str != "uint16_t" && p.type_str != "int16_t");
        Width pw = (p.location.size() == 2 && is_pair_name(p.location)) ? Width::W : Width::B;
        if (p.type_str == "uint16_t" || p.type_str == "int16_t") pw = Width::W;
        if (!is_byte_param && uf.is_word(rep)) pw = Width::W;
        rep_name[rep] = p.name;
        rep_width[rep] = pw;
        frame_info.args[p.name] = FrameInfo::VarDecl{Expr::make_var(p.name, pw), pw};
    }

    // Assign v0, v1, ... deterministically in CFG statement order
    int v_counter = 0;
    auto assign_rep_if_needed = [&](int rep) {
        if (rep_name.count(rep)) return;
        std::string nm = "v" + std::to_string(v_counter++);
        Width w = uf.is_word(rep) ? Width::W : Width::B;
        rep_name[rep] = nm;
        rep_width[rep] = w;
        frame_info.locals[nm] = FrameInfo::VarDecl{Expr::make_var(nm, w), w};
    };

    for (const auto &b : order) {
        for (const auto &s : b->stmts) {
            if (frame_info.hidden_stmts.count(s->id) || s->kind == StmtKind::Nop) continue;
            auto ensure_reg_def = [&](const ExprPtr &d) {
                if (!d || d->kind != ExprKind::Reg) return;
                AtomMask m = gpr_atoms_of(d->name);
                auto idxs = atom_indices(m);
                if (idxs.empty()) return;
                int rep = uf.find(uf.get_or_add(NodeKey{s->id, idxs[0]}));
                assign_rep_if_needed(rep);
            };
            if (s->kind == StmtKind::Assign || s->kind == StmtKind::Call) ensure_reg_def(s->dst);
            if (s->kind == StmtKind::Swap) {
                ensure_reg_def(s->a);
                ensure_reg_def(s->b);
            }
        }
    }

    // Also ensure any remaining entry/uninit read webs get names
    for (size_t i = 0; i < uf.size(); ++i) {
        assign_rep_if_needed(uf.find(static_cast<int>(i)));
    }

    auto resolve_reg_read = [&](const std::string &rname, const ReachingState &rs) -> ExprPtr {
        if (rname == "de_bc") {
            ExprPtr de_v = nullptr, bc_v = nullptr;
            if (!rs.defs[4].empty()) {
                int rep = uf.find(uf.get_or_add(NodeKey{rs.defs[4][0], 4}));
                de_v = Expr::make_var(rep_name[rep], rep_width[rep]);
            } else {
                de_v = Expr::make_const(0, Width::W);
            }
            if (!rs.defs[2].empty()) {
                int rep = uf.find(uf.get_or_add(NodeKey{rs.defs[2][0], 2}));
                bc_v = Expr::make_var(rep_name[rep], rep_width[rep]);
            } else {
                bc_v = Expr::make_const(0, Width::W);
            }
            return Expr::make_bin("|",
                                  Expr::make_bin("<<", de_v, Expr::make_const(16, Width::B), Width::D),
                                  bc_v, Width::D);
        }
        AtomMask m = gpr_atoms_of(rname);
        if (m == 0) return Expr::make_reg(rname);
        auto idxs = atom_indices(m);
        if (idxs.empty() || rs.defs[idxs[0]].empty()) {
            Width fw = is_pair_name(rname) ? Width::W : (idxs.size() > 1 ? Width::W : Width::B);
            return Expr::make_const(0, fw);
        }
        if (idxs.size() == 2 && is_pair_name(rname)) {
            int rep0 = uf.find(uf.get_or_add(NodeKey{rs.defs[idxs[0]][0], idxs[0]}));
            int rep1 = !rs.defs[idxs[1]].empty()
                         ? uf.find(uf.get_or_add(NodeKey{rs.defs[idxs[1]][0], idxs[1]}))
                         : rep0;
            if (rep0 != rep1) {
                // Pair spans two distinct byte webs (e.g. uint8_t param in high byte + local in low byte)
                ExprPtr lo_e = map_var_expr(Expr::make_var(rep_name[rep0], rep_width[rep0]), rep_width[rep0], kAtomNames[idxs[0]]);
                ExprPtr hi_e = map_var_expr(Expr::make_var(rep_name[rep1], rep_width[rep1]), rep_width[rep1], kAtomNames[idxs[1]]);
                return Expr::make_bin(
                    "|",
                    Expr::make_bin("<<", Expr::make_un("u16", hi_e, Width::W), Expr::make_const(8, Width::B), Width::W),
                    Expr::make_un("u16", Expr::make_un("u8", lo_e, Width::B), Width::W),
                    Width::W);
            }
        }
        int rep = uf.find(uf.get_or_add(NodeKey{rs.defs[idxs[0]][0], idxs[0]}));
        const std::string &vnm = rep_name[rep];
        Width vw = rep_width[rep];
        return map_var_expr(Expr::make_var(vnm, vw), vw, rname);
    };

    auto rewrite_expr_with_rs = [&](auto &self, const ExprPtr &e, const ReachingState &rs) -> ExprPtr {
        if (!e) return nullptr;
        switch (e->kind) {
            case ExprKind::Reg:
                return resolve_reg_read(e->name, rs);
            case ExprKind::Bin: {
                ExprPtr nl = self(self, e->l, rs);
                ExprPtr nr = self(self, e->r, rs);
                return Expr::make_bin(e->op, nl, nr, e->width);
            }
            case ExprKind::Un:
                return Expr::make_un(e->op, self(self, e->l, rs), e->width);
            case ExprKind::Mem:
                if (e->has_static_addr) return e;
                return Expr::make_mem_addr(self(self, e->addr, rs), e->width, e->es, e->name);
            case ExprKind::Bit:
                return Expr::make_bit(self(self, e->base, rs), e->bit);
            case ExprKind::Intr: {
                std::vector<ExprPtr> nargs;
                for (const auto &a : e->args) nargs.push_back(self(self, a, rs));
                return Expr::make_intr(e->name, std::move(nargs), e->width);
            }
            default:
                return e;
        }
    };

    auto resolve_reg_def = [&](uint64_t sid, const std::string &rname, std::string &out_var, Width &out_w) -> bool {
        AtomMask m = gpr_atoms_of(rname);
        auto idxs = atom_indices(m);
        if (idxs.empty()) return false;
        int rep = uf.find(uf.get_or_add(NodeKey{sid, idxs[0]}));
        out_var = rep_name[rep];
        out_w = rep_width[rep];
        return true;
    };

    // 6. Rewrite all instructions from Reg -> Var/StackVar + handle subregister partial pair writes
    std::unordered_map<uint64_t, std::string> stmt_def_varname;
    for (const auto &b : order) {
        for (const auto &s : b->stmts) {
            if (frame_info.hidden_stmts.count(s->id) || s->kind == StmtKind::Nop) continue;
            const ReachingState &pre = stmt_pre[s->id];
            const ReachingState &post = stmt_post[s->id];

            if (s->kind == StmtKind::Assign) {
                ExprPtr new_src = rewrite_expr_with_rs(rewrite_expr_with_rs, s->src, pre);
                if (s->dst && s->dst->kind == ExprKind::Reg && gpr_atoms_of(s->dst->name) != 0) {
                    std::string rname = s->dst->name;
                    std::string vnm;
                    Width vw = Width::B;
                    if (resolve_reg_def(s->id, rname, vnm, vw)) {
                        stmt_def_varname[s->id] = vnm;
                        ExprPtr v_var = Expr::make_var(vnm, vw);
                        if (vw == Width::W && is_gpr_byte_name(rname)) {
                            // Partial 8-bit write to a 16-bit pair variable
                            auto poa = pair_of_atom(rname);
                            ExprPtr masked_rhs = Expr::make_bin("&", new_src, Expr::make_const(0xFF, Width::W), Width::W);
                            if (poa.has_value() && poa->second == 1) {
                                // High byte: (v & 0x00FF) | ((rhs & 0xFF) << 8)
                                ExprPtr keep_lo = Expr::make_bin("&", v_var, Expr::make_const(0x00FF, Width::W), Width::W);
                                if (new_src->kind == ExprKind::Const && (new_src->value & 0xFFu) == 0) {
                                    new_src = keep_lo;
                                } else {
                                    ExprPtr hi_part = Expr::make_bin("<<", masked_rhs, Expr::make_const(8, Width::B), Width::W);
                                    new_src = Expr::make_bin("|", keep_lo, hi_part, Width::W);
                                }
                            } else {
                                // Low byte: (v & 0xFF00) | (rhs & 0xFF)
                                ExprPtr keep_hi = Expr::make_bin("&", v_var, Expr::make_const(0xFF00, Width::W), Width::W);
                                if (new_src->kind == ExprKind::Const && (new_src->value & 0xFFu) == 0) {
                                    new_src = keep_hi;
                                } else {
                                    new_src = Expr::make_bin("|", keep_hi, masked_rhs, Width::W);
                                }
                            }
                        }
                        s->dst = v_var;
                    }
                } else if (s->dst) {
                    s->dst = rewrite_expr_with_rs(rewrite_expr_with_rs, s->dst, pre);
                }
                s->src = new_src;

                auto rw_own_flag = [&](const FlagDefPtr &f) {
                    if (!f) return;
                    const ReachingState &rs = flag_uses_pre_state(f->kind) ? pre : post;
                    if (f->a) f->a = rewrite_expr_with_rs(rewrite_expr_with_rs, f->a, rs);
                    if (f->b) f->b = rewrite_expr_with_rs(rewrite_expr_with_rs, f->b, rs);
                    if (f->c) f->c = rewrite_expr_with_rs(rewrite_expr_with_rs, f->c, rs);
                };
                rw_own_flag(s->z_flag);
                rw_own_flag(s->cy_flag);
            } else if (s->kind == StmtKind::Swap) {
                // Swap semantics: both a and b resolved as their webs
                if (s->a && s->a->kind == ExprKind::Reg) {
                    std::string vnm;
                    Width vw = Width::B;
                    if (resolve_reg_def(s->id, s->a->name, vnm, vw)) s->a = Expr::make_var(vnm, vw);
                }
                if (s->b && s->b->kind == ExprKind::Reg) {
                    std::string vnm;
                    Width vw = Width::B;
                    if (resolve_reg_def(s->id, s->b->name, vnm, vw)) s->b = Expr::make_var(vnm, vw);
                }
            } else if (s->kind == StmtKind::Compare || s->kind == StmtKind::Branch) {
                if (s->has_bittest && s->bittest_expr) {
                    s->bittest_expr = rewrite_expr_with_rs(rewrite_expr_with_rs, s->bittest_expr, pre);
                }
                auto rw_br_flag = [&](const FlagDefPtr &f) {
                    if (!f) return;
                    const ReachingState *rs_ptr = &pre;
                    if (f->origin_stmt_id != 0) {
                        if (flag_uses_pre_state(f->kind)) {
                            if (auto it = stmt_pre.find(f->origin_stmt_id); it != stmt_pre.end()) rs_ptr = &it->second;
                        } else {
                            if (auto it = stmt_post.find(f->origin_stmt_id); it != stmt_post.end()) rs_ptr = &it->second;
                        }
                    }
                    if (f->a) f->a = rewrite_expr_with_rs(rewrite_expr_with_rs, f->a, *rs_ptr);
                    if (f->b) f->b = rewrite_expr_with_rs(rewrite_expr_with_rs, f->b, *rs_ptr);
                    if (f->c) f->c = rewrite_expr_with_rs(rewrite_expr_with_rs, f->c, *rs_ptr);
                };
                rw_br_flag(s->z_flag);
                rw_br_flag(s->cy_flag);
            } else if (s->kind == StmtKind::Call) {
                if (s->expr) s->expr = rewrite_expr_with_rs(rewrite_expr_with_rs, s->expr, pre);
                for (auto &a : s->args) a = rewrite_expr_with_rs(rewrite_expr_with_rs, a, pre);
                if (s->dst && s->dst->kind == ExprKind::Reg) {
                    if (s->dst->name == "de_bc") {
                        std::string vnm = "v" + std::to_string(v_counter++);
                        s->dst = Expr::make_var(vnm, Width::D);
                        frame_info.locals[vnm] = FrameInfo::VarDecl{s->dst, Width::D};
                    } else {
                        std::string vnm;
                        Width vw = Width::B;
                        if (resolve_reg_def(s->id, s->dst->name, vnm, vw)) {
                            s->dst = Expr::make_var(vnm, vw);
                            stmt_def_varname[s->id] = vnm;
                        }
                    }
                }
            } else if (s->kind == StmtKind::Ret) {
                if (s->val) s->val = rewrite_expr_with_rs(rewrite_expr_with_rs, s->val, pre);
            } else if (s->kind == StmtKind::Switch) {
                if (s->expr) s->expr = rewrite_expr_with_rs(rewrite_expr_with_rs, s->expr, pre);
            } else if (s->kind == StmtKind::Intrinsic) {
                for (auto &a : s->args) a = rewrite_expr_with_rs(rewrite_expr_with_rs, a, pre);
            }
        }
    }

    // 7. Flag pre-value clobber safety:
    // If a Branch uses a FlagDef whose leaf expressions (Var / StackVar / Mem) are overwritten
    // by its own origin_stmt (when flag_uses_pre_state) or by ANY intervening statement before Branch,
    // snapshot those leaf expressions into _pre_N right before the first clobber!
    std::unordered_map<uint64_t, BlockPtr> stmt_to_block;
    std::unordered_map<uint64_t, size_t> stmt_to_idx;
    for (const auto &b : order) {
        for (size_t i = 0; i < b->stmts.size(); ++i) {
            stmt_to_block[b->stmts[i]->id] = b;
            stmt_to_idx[b->stmts[i]->id] = i;
        }
    }

    auto expr_clobbered_by_stmt = [&](const ExprPtr &leaf, const Stmt *w) -> bool {
        if (!leaf || !w || frame_info.hidden_stmts.count(w->id) || w->kind == StmtKind::Nop) return false;
        if (w->kind == StmtKind::Call) {
            if (leaf->kind == ExprKind::Mem) return true;
            if (w->dst && (leaf->kind == ExprKind::Var || leaf->kind == ExprKind::StackVar) &&
                w->dst->kind == leaf->kind && w->dst->name == leaf->name) return true;
            return false;
        }
        ExprPtr w_dst;
        if (w->kind == StmtKind::Assign) w_dst = w->dst;
        else if (w->kind == StmtKind::Intrinsic &&
                 (w->name == "set_bit" || w->name == "clr_bit" || w->name == "xor_bit" || w->name == "pop") &&
                 !w->args.empty()) {
            w_dst = w->args[0];
        } else {
            return false;
        }
        if (!w_dst) return false;
        if (w_dst->kind == ExprKind::Bit && w_dst->base) w_dst = w_dst->base;
        if (leaf->kind == ExprKind::Var || leaf->kind == ExprKind::StackVar) {
            return (w_dst->kind == ExprKind::Var || w_dst->kind == ExprKind::StackVar) &&
                   w_dst->name == leaf->name;
        }
        if (leaf->kind == ExprKind::Mem && w_dst->kind == ExprKind::Mem) {
            if (leaf->has_static_addr && w_dst->has_static_addr) {
                uint32_t a1 = leaf->static_addr, e1 = a1 + static_cast<uint32_t>(width_bytes(leaf->width));
                uint32_t a2 = w_dst->static_addr, e2 = a2 + static_cast<uint32_t>(width_bytes(w_dst->width));
                return (a1 < e2) && (a2 < e1);
            }
            return true;
        }
        return false;
    };

    auto collect_leaf_locs = [&](auto &self, const ExprPtr &e, std::vector<ExprPtr> &out_leaves) -> void {
        if (!e) return;
        if (e->kind == ExprKind::Var || e->kind == ExprKind::StackVar || e->kind == ExprKind::Mem) {
            for (const auto &prev : out_leaves) {
                if (expr_eq(prev, e)) return;
            }
            out_leaves.push_back(e);
            if (e->kind == ExprKind::Mem && !e->has_static_addr) self(self, e->addr, out_leaves);
            return;
        }
        if (e->kind == ExprKind::Bin) { self(self, e->l, out_leaves); self(self, e->r, out_leaves); }
        else if (e->kind == ExprKind::Un) { self(self, e->l, out_leaves); }
        else if (e->kind == ExprKind::Bit) { self(self, e->base, out_leaves); }
        else if (e->kind == ExprKind::Intr) { for (const auto &a : e->args) self(self, a, out_leaves); }
    };

    auto replace_expr_eq = [&](auto &self, const ExprPtr &e, const ExprPtr &target, const ExprPtr &repl) -> ExprPtr {
        if (!e) return nullptr;
        if (expr_eq(e, target)) return expr_clone(repl);
        if (e->kind == ExprKind::Bin) {
            ExprPtr nl = self(self, e->l, target, repl);
            ExprPtr nr = self(self, e->r, target, repl);
            return (nl == e->l && nr == e->r) ? e : Expr::make_bin(e->op, nl, nr, e->width);
        }
        if (e->kind == ExprKind::Un) {
            ExprPtr nl = self(self, e->l, target, repl);
            return (nl == e->l) ? e : Expr::make_un(e->op, nl, e->width);
        }
        if (e->kind == ExprKind::Mem && !e->has_static_addr) {
            ExprPtr na = self(self, e->addr, target, repl);
            return (na == e->addr) ? e : Expr::make_mem_addr(na, e->width, e->es, e->name);
        }
        if (e->kind == ExprKind::Bit) {
            ExprPtr nb = self(self, e->base, target, repl);
            return (nb == e->base) ? e : Expr::make_bit(nb, e->bit);
        }
        if (e->kind == ExprKind::Intr) {
            std::vector<ExprPtr> na;
            bool chg = false;
            for (const auto &a : e->args) {
                ExprPtr x = self(self, a, target, repl);
                if (x != a) chg = true;
                na.push_back(x);
            }
            return chg ? Expr::make_intr(e->name, std::move(na), e->width) : e;
        }
        return e;
    };

    int pre_tmp_idx = 0;
    struct PendingSnapshot {
        uint64_t anchor_id = 0;
        bool insert_after = false;
        ExprPtr src_expr;
        std::string tmp_name;
    };
    std::vector<PendingSnapshot> snapshots;

    for (const auto &b : order) {
        for (size_t bi = 0; bi < b->stmts.size(); ++bi) {
            const auto &s = b->stmts[bi];
            if (s->kind != StmtKind::Branch || frame_info.hidden_stmts.count(s->id)) continue;
            auto protect_flag = [&](const FlagDefPtr &f) {
                if (!f || f->origin_stmt_id == 0) return;
                auto obit = stmt_to_block.find(f->origin_stmt_id);
                if (obit == stmt_to_block.end()) return;
                BlockPtr ob = obit->second;
                size_t oi = stmt_to_idx[f->origin_stmt_id];

                // Collect path of statements starting at origin (inclusive iff pre_state) up to strictly before branch s
                std::vector<const Stmt *> check_path;
                bool start_incl = flag_uses_pre_state(f->kind);
                if (ob == b) {
                    size_t start_k = start_incl ? oi : (oi + 1);
                    for (size_t k = start_k; k < bi; ++k) check_path.push_back(ob->stmts[k].get());
                } else {
                    size_t start_k = start_incl ? oi : (oi + 1);
                    for (size_t k = start_k; k < ob->stmts.size(); ++k) check_path.push_back(ob->stmts[k].get());
                    for (size_t k = 0; k < bi; ++k) check_path.push_back(b->stmts[k].get());
                }
                if (check_path.empty()) return;

                std::vector<ExprPtr> leaves;
                collect_leaf_locs(collect_leaf_locs, f->a, leaves);
                collect_leaf_locs(collect_leaf_locs, f->b, leaves);
                collect_leaf_locs(collect_leaf_locs, f->c, leaves);

                for (const auto &leaf : leaves) {
                    const Stmt *first_clobber = nullptr;
                    for (const Stmt *w : check_path) {
                        if (expr_clobbered_by_stmt(leaf, w)) { first_clobber = w; break; }
                    }
                    if (!first_clobber) continue;
                    std::string tmp_nm = "_pre_" + std::to_string(pre_tmp_idx++);
                    ExprPtr repl = Expr::make_var(tmp_nm, leaf->width);
                    // Snapshot immediately before first_clobber (when first_clobber == origin_stmt -> before origin;
                    // if first_clobber is after origin, snapshot before first_clobber!)
                    snapshots.push_back(PendingSnapshot{first_clobber->id, false, expr_clone(leaf), tmp_nm});
                    if (f->a) f->a = replace_expr_eq(replace_expr_eq, f->a, leaf, repl);
                    if (f->b) f->b = replace_expr_eq(replace_expr_eq, f->b, leaf, repl);
                    if (f->c) f->c = replace_expr_eq(replace_expr_eq, f->c, leaf, repl);
                }
            };
            protect_flag(s->z_flag);
            protect_flag(s->cy_flag);
        }
    }

    for (const auto &snap : snapshots) {
        auto bit = stmt_to_block.find(snap.anchor_id);
        if (bit == stmt_to_block.end()) continue;
        BlockPtr blk = bit->second;
        for (size_t i = 0; i < blk->stmts.size(); ++i) {
            if (blk->stmts[i]->id == snap.anchor_id) {
                ExprPtr tv = Expr::make_var(snap.tmp_name, snap.src_expr->width);
                frame_info.locals[snap.tmp_name] = FrameInfo::VarDecl{tv, snap.src_expr->width};
                size_t ins_pos = snap.insert_after ? (i + 1) : i;
                blk->stmts.insert(blk->stmts.begin() + static_cast<ptrdiff_t>(ins_pos),
                                  make_assign(blk->stmts[i]->ea, tv, snap.src_expr));
                break;
            }
        }
    }

    // 8. Register all remaining StackVars / Vars into frame_info.locals so C declarations are complete
    for (const auto &b : order) {
        for (const auto &s : b->stmts) {
            if (frame_info.hidden_stmts.count(s->id) || s->kind == StmtKind::Nop) continue;
            collect_expr_vars_to_frame(s->dst, frame_info, arg_names);
            collect_expr_vars_to_frame(s->src, frame_info, arg_names);
            collect_expr_vars_to_frame(s->a, frame_info, arg_names);
            collect_expr_vars_to_frame(s->b, frame_info, arg_names);
            collect_expr_vars_to_frame(s->expr, frame_info, arg_names);
            for (const auto &a : s->args) collect_expr_vars_to_frame(a, frame_info, arg_names);
            collect_expr_vars_to_frame(s->val, frame_info, arg_names);
            if (s->has_bittest) collect_expr_vars_to_frame(s->bittest_expr, frame_info, arg_names);
        }
    }
}

} // namespace rl78dec
