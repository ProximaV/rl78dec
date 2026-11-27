#include "rl78dec/cfg.hpp"

#include <algorithm>
#include <unordered_map>
#include <unordered_set>

#include "rl78dec/lifter.hpp"

namespace rl78dec {

namespace {

uint32_t skip_target(const std::map<uint32_t, DecodedInsn> &insns, uint32_t ea) {
    auto it = insns.find(ea);
    if (it == insns.end()) return ea;
    uint32_t n1 = ea + static_cast<uint32_t>(it->second.size);
    auto nxt = insns.find(n1);
    return nxt != insns.end() ? (n1 + static_cast<uint32_t>(nxt->second.size)) : n1;
}

std::vector<std::pair<std::string, uint32_t>> cfg_succ(const std::map<uint32_t, DecodedInsn> &insns,
                                                       const DecodedInsn &ins) {
    if (ins.sw.has_value()) {
        std::vector<std::pair<std::string, uint32_t>> out;
        for (uint32_t t : ins.sw->targets) out.emplace_back("switch", t);
        return out;
    }
    uint32_t nxt = ins.ea + static_cast<uint32_t>(ins.size);
    if (is_skip_mnem(ins.mnem)) {
        return {{"cond", skip_target(insns, ins.ea)}, {"fall", nxt}};
    }
    if (ins.mnem == Mnem::Br) {
        if (auto t = target_of(ins); t.has_value()) return {{"jump", *t}};
        return {};
    }
    if (is_ret_mnem(ins.mnem) || ins.mnem == Mnem::Stop || ins.mnem == Mnem::Brk1) {
        return {};
    }
    if (is_cond_branch_mnem(ins.mnem) || is_bit_branch_mnem(ins.mnem)) {
        std::vector<std::pair<std::string, uint32_t>> out;
        if (auto t = target_of(ins); t.has_value()) out.emplace_back("cond", *t);
        out.emplace_back("fall", nxt);
        return out;
    }
    return {{"fall", nxt}};
}

std::set<uint32_t> collect_body(const std::map<uint32_t, DecodedInsn> &insns,
                                uint32_t entry,
                                const std::set<uint32_t> &entry_set) {
    std::set<uint32_t> body;
    std::vector<uint32_t> work{entry};
    while (!work.empty()) {
        uint32_t ea = work.back();
        work.pop_back();
        if (body.count(ea) || !insns.count(ea)) continue;
        body.insert(ea);
        for (const auto &[how, tgt] : cfg_succ(insns, insns.at(ea))) {
            if (insns.count(tgt) && (tgt == entry || how == "switch" || !entry_set.count(tgt))) {
                work.push_back(tgt);
            }
        }
    }
    return body;
}

std::set<uint32_t> find_leaders(const std::map<uint32_t, DecodedInsn> &insns, const std::set<uint32_t> &body) {
    std::set<uint32_t> leaders;
    for (uint32_t ea : body) {
        const auto &ins = insns.at(ea);
        for (const auto &[how, tgt] : cfg_succ(insns, ins)) {
            if ((how == "cond" || how == "jump" || how == "switch") && body.count(tgt)) {
                leaders.insert(tgt);
            }
        }
        if (is_cond_branch_mnem(ins.mnem) || is_bit_branch_mnem(ins.mnem) || is_skip_mnem(ins.mnem) ||
            ins.mnem == Mnem::Call || ins.mnem == Mnem::Callt || ins.mnem == Mnem::Brk ||
            is_stop_mnem(ins.mnem) || is_ret_mnem(ins.mnem) || ins.sw.has_value()) {
            uint32_t nxt = ea + static_cast<uint32_t>(ins.size);
            if (body.count(nxt)) leaders.insert(nxt);
        }
    }
    return leaders;
}

StmtPtr make_skip_branch(const std::map<uint32_t, DecodedInsn> &insns, const DecodedInsn &ins) {
    const char *cond = "z";
    switch (ins.mnem) {
        case Mnem::Skc:  cond = "cy";  break;
        case Mnem::Sknc: cond = "ncy"; break;
        case Mnem::Skz:  cond = "z";   break;
        case Mnem::Sknz: cond = "nz";  break;
        case Mnem::Skh:  cond = "h";   break;
        case Mnem::Sknh: cond = "nh";  break;
        default: break;
    }
    return make_branch(ins.ea, cond, skip_target(insns, ins.ea), ins.ea + static_cast<uint32_t>(ins.size));
}

} // namespace

bool expr_reads_cy(const ExprPtr &e) {
    if (!e) return false;
    if (e->kind == ExprKind::Reg && e->name == "cy") return true;
    if (e->kind == ExprKind::Bit && e->base && e->base->kind == ExprKind::Reg &&
        e->base->name == "psw" && e->bit == 0) {
        return true;
    }
    if (e->kind == ExprKind::Bin) return expr_reads_cy(e->l) || expr_reads_cy(e->r);
    if (e->kind == ExprKind::Un) return expr_reads_cy(e->l);
    if (e->kind == ExprKind::Mem) return !e->has_static_addr && expr_reads_cy(e->addr);
    if (e->kind == ExprKind::Bit) return expr_reads_cy(e->base);
    if (e->kind == ExprKind::Intr) {
        for (const auto &a : e->args) if (expr_reads_cy(a)) return true;
    }
    return false;
}

namespace {

bool expr_reads_z_or_psw6(const ExprPtr &e) {
    if (!e) return false;
    if (e->kind == ExprKind::Reg && e->name == "z") return true;
    if (e->kind == ExprKind::Bit && e->base && e->base->kind == ExprKind::Reg &&
        e->base->name == "psw" && e->bit == 6) {
        return true;
    }
    if (e->kind == ExprKind::Bin) return expr_reads_z_or_psw6(e->l) || expr_reads_z_or_psw6(e->r);
    if (e->kind == ExprKind::Un) return expr_reads_z_or_psw6(e->l);
    if (e->kind == ExprKind::Mem) return !e->has_static_addr && expr_reads_z_or_psw6(e->addr);
    if (e->kind == ExprKind::Bit) return expr_reads_z_or_psw6(e->base);
    if (e->kind == ExprKind::Intr) {
        for (const auto &a : e->args) if (expr_reads_z_or_psw6(a)) return true;
    }
    return false;
}

bool expr_reads_whole_psw(const ExprPtr &e) {
    if (!e) return false;
    if (e->kind == ExprKind::Bit && e->base && e->base->kind == ExprKind::Reg && e->base->name == "psw") {
        return false;
    }
    if (e->kind == ExprKind::Reg && e->name == "psw") return true;
    if (e->kind == ExprKind::Bin) return expr_reads_whole_psw(e->l) || expr_reads_whole_psw(e->r);
    if (e->kind == ExprKind::Un) return expr_reads_whole_psw(e->l);
    if (e->kind == ExprKind::Mem) return !e->has_static_addr && expr_reads_whole_psw(e->addr);
    if (e->kind == ExprKind::Bit) return expr_reads_whole_psw(e->base);
    if (e->kind == ExprKind::Intr) {
        for (const auto &a : e->args) if (expr_reads_whole_psw(a)) return true;
    }
    return false;
}

ExprPtr rewrite_psw_flag_bits(const ExprPtr &e) {
    if (!e) return nullptr;
    if (e->kind == ExprKind::Bit && e->base && e->base->kind == ExprKind::Reg && e->base->name == "psw") {
        if (e->bit == 0) return Expr::make_reg("cy", Width::B);
        if (e->bit == 6) return Expr::make_reg("z", Width::B);
        return e;
    }
    switch (e->kind) {
        case ExprKind::Bin: {
            ExprPtr nl = rewrite_psw_flag_bits(e->l);
            ExprPtr nr = rewrite_psw_flag_bits(e->r);
            return (nl == e->l && nr == e->r) ? e : Expr::make_bin(e->op, nl, nr, e->width);
        }
        case ExprKind::Un: {
            ExprPtr nl = rewrite_psw_flag_bits(e->l);
            return (nl == e->l) ? e : Expr::make_un(e->op, nl, e->width);
        }
        case ExprKind::Mem: {
            if (e->has_static_addr) return e;
            ExprPtr na = rewrite_psw_flag_bits(e->addr);
            return (na == e->addr) ? e : Expr::make_mem_addr(na, e->width, e->es, e->name, e->addr_is_linear);
        }
        case ExprKind::Bit: {
            ExprPtr nb = rewrite_psw_flag_bits(e->base);
            return (nb == e->base) ? e : Expr::make_bit(nb, e->bit);
        }
        case ExprKind::Intr: {
            std::vector<ExprPtr> na;
            bool chg = false;
            for (const auto &a : e->args) {
                ExprPtr r = rewrite_psw_flag_bits(a);
                if (r != a) chg = true;
                na.push_back(r);
            }
            return chg ? Expr::make_intr(e->name, std::move(na), e->width) : e;
        }
        default:
            return e;
    }
}

} // namespace

uint32_t cy_width_mask(Width w) {
    switch (w) {
        case Width::B: return 0xFFu;
        case Width::W: return 0xFFFFu;
        case Width::A: return 0xFFFFFu;
        case Width::D: return 0xFFFFFFFFu;
    }
    return 0xFFu;
}

ExprPtr wrap_u_cy(const ExprPtr &e, Width w) {
    if (!e) return Expr::make_const(0, w);
    if (e->kind == ExprKind::Const) return Expr::make_const(e->value & cy_width_mask(w), w, e->name);
    return Expr::make_un(w == Width::B ? "u8" : (w == Width::W ? "u16" : "u32"), expr_clone(e), w);
}

namespace {

ExprPtr materialize_z_expr(const FlagDef &f) {
    switch (f.kind) {
        case FlagKind::Cmp:
            return Expr::make_bin("==", wrap_u_cy(f.a, f.width), wrap_u_cy(f.b, f.width), Width::B);
        case FlagKind::Cmps:
            return Expr::make_bin("==", wrap_u_cy(f.a, Width::B), wrap_u_cy(f.b, Width::B), Width::B);
        case FlagKind::Cmp0:
        case FlagKind::Result:
            return Expr::make_bin("==", wrap_u_cy(f.a, f.width), Expr::make_const(0, f.width), Width::B);
        case FlagKind::Sub:
            if (!f.c) {
                return Expr::make_bin("==", wrap_u_cy(f.a, f.width), wrap_u_cy(f.b, f.width), Width::B);
            } else {
                ExprPtr diff = Expr::make_bin("-",
                                              Expr::make_bin("-", wrap_u_cy(f.a, f.width), wrap_u_cy(f.b, f.width), f.width),
                                              wrap_u_cy(f.c, Width::B), f.width);
                return Expr::make_bin("==", wrap_u_cy(diff, f.width), Expr::make_const(0, f.width), Width::B);
            }
        case FlagKind::Add: {
            ExprPtr sum = Expr::make_bin("+", wrap_u_cy(f.a, f.width), wrap_u_cy(f.b, f.width), f.width);
            if (f.c) sum = Expr::make_bin("+", sum, wrap_u_cy(f.c, Width::B), f.width);
            return Expr::make_bin("==", wrap_u_cy(sum, f.width), Expr::make_const(0, f.width), Width::B);
        }
        case FlagKind::Movs:
            return Expr::make_bin("==", wrap_u_cy(f.b, Width::B), Expr::make_const(0, Width::B), Width::B);
        default:
            return nullptr;
    }
}

} // namespace

ExprPtr materialize_cy_expr(const FlagDef &f) {
    switch (f.kind) {
        case FlagKind::Cmp:
            return Expr::make_bin("<", wrap_u_cy(f.a, f.width), wrap_u_cy(f.b, f.width), Width::B);
        case FlagKind::Cmp0:
            return Expr::make_const(0, Width::B);
        case FlagKind::Sub: {
            ExprPtr ua = Expr::make_un("u32", wrap_u_cy(f.a, f.width), Width::D);
            ExprPtr ub = Expr::make_un("u32", wrap_u_cy(f.b, f.width), Width::D);
            if (f.c) ub = Expr::make_bin("+", ub, Expr::make_un("u32", wrap_u_cy(f.c, Width::B), Width::D), Width::D);
            return Expr::make_bin("<", ua, ub, Width::B);
        }
        case FlagKind::Add: {
            ExprPtr ua = Expr::make_un("u32", wrap_u_cy(f.a, f.width), Width::D);
            ExprPtr ub = Expr::make_un("u32", wrap_u_cy(f.b, f.width), Width::D);
            ExprPtr sum = Expr::make_bin("+", ua, ub, Width::D);
            if (f.c) sum = Expr::make_bin("+", sum, Expr::make_un("u32", wrap_u_cy(f.c, Width::B), Width::D), Width::D);
            return Expr::make_bin(">", sum, Expr::make_const(cy_width_mask(f.width), Width::D), Width::B);
        }
        case FlagKind::CarryVal:
            return f.a ? expr_clone(f.a) : Expr::make_reg("cy");
        case FlagKind::Movs: {
            ExprPtr za = Expr::make_bin("==", wrap_u_cy(f.a, Width::B), Expr::make_const(0, Width::B), Width::B);
            ExprPtr zb = Expr::make_bin("==", wrap_u_cy(f.b, Width::B), Expr::make_const(0, Width::B), Width::B);
            return Expr::make_bin("||", za, zb, Width::B);
        }
        case FlagKind::Cmps: {
            ExprPtr neq = Expr::make_bin("!=", wrap_u_cy(f.a, Width::B), wrap_u_cy(f.b, Width::B), Width::B);
            ExprPtr c0  = Expr::make_bin("==", wrap_u_cy(f.c, Width::B), Expr::make_const(0, Width::B), Width::B);
            ExprPtr a0  = Expr::make_bin("==", wrap_u_cy(f.a, Width::B), Expr::make_const(0, Width::B), Width::B);
            return Expr::make_bin("||", neq, Expr::make_bin("||", c0, a0, Width::B), Width::B);
        }
        default:
            return Expr::make_reg("cy");
    }
}

void duplicate_epilogue_returns(Function &func, const FrameInfo &fi) {
    bool changed = true;
    int guard = 0;
    while (changed && guard++ < 16) {
        changed = false;
        std::unordered_set<uint32_t> pure_ret_blocks;
        for (const auto &[bid, b] : func.blocks) {
            if (bid == func.entry || b->stmts.empty()) continue;
            const auto &last = b->stmts.back();
            if (last->kind != StmtKind::Ret || last->ret_kind != "ret" || last->val != nullptr) continue;
            bool all_hidden = true;
            for (size_t i = 0; i + 1 < b->stmts.size(); ++i) {
                const auto &s = b->stmts[i];
                if (s->kind != StmtKind::Nop && !fi.hidden_stmts.count(s->id)) {
                    all_hidden = false;
                    break;
                }
            }
            if (all_hidden) pure_ret_blocks.insert(bid);
        }
        if (pure_ret_blocks.empty()) break;

        for (const auto &[bid, b] : func.blocks) {
            if (pure_ret_blocks.count(bid) || b->succ.size() != 1) continue;
            uint32_t tgt = b->succ[0].second;
            if (!pure_ret_blocks.count(tgt)) continue;
            const auto &ret_blk = func.blocks.at(tgt);
            uint32_t ret_ea = ret_blk->stmts.back()->ea;
            if (b->term == TermKind::Goto) {
                if (!b->stmts.empty() && b->stmts.back()->kind == StmtKind::Goto) {
                    ret_ea = b->stmts.back()->ea;
                    b->stmts.back() = make_ret(ret_ea, "ret", nullptr);
                } else {
                    b->stmts.push_back(make_ret(ret_ea, "ret", nullptr));
                }
                b->term = TermKind::Ret;
                b->succ.clear();
                changed = true;
            } else if (b->term == TermKind::Fall) {
                b->stmts.push_back(make_ret(ret_ea, "ret", nullptr));
                b->term = TermKind::Ret;
                b->succ.clear();
                changed = true;
            }
        }

        if (changed) {
            std::unordered_set<uint32_t> referenced;
            referenced.insert(func.entry);
            for (const auto &[bid, b] : func.blocks) {
                for (const auto &[how, tgt] : b->succ) referenced.insert(tgt);
            }
            for (uint32_t rbid : pure_ret_blocks) {
                if (!referenced.count(rbid)) func.blocks.erase(rbid);
            }
        }
    }
}

void thread_condition_jumps(Function &func, const FrameInfo &fi) {
    auto get_pure_flag_branch = [&](uint32_t bid) -> StmtPtr {
        if (bid == func.entry) return nullptr;
        auto it = func.blocks.find(bid);
        if (it == func.blocks.end() || it->second->term != TermKind::Branch || it->second->stmts.empty()) {
            return nullptr;
        }
        const auto &b = it->second;
        for (size_t i = 0; i + 1 < b->stmts.size(); ++i) {
            const auto &s = b->stmts[i];
            if (s->kind != StmtKind::Nop && !fi.hidden_stmts.count(s->id)) return nullptr;
        }
        const auto &br = b->stmts.back();
        if (br->kind != StmtKind::Branch || br->has_bittest) return nullptr;
        if (br->cond != "z" && br->cond != "nz" && br->cond != "cy" && br->cond != "ncy") return nullptr;
        return br;
    };

    bool any_redirected = false;
    for (const auto &[bid, b] : func.blocks) {
        if (b->term != TermKind::Branch || b->stmts.empty()) continue;
        auto &brA = b->stmts.back();
        if (brA->kind != StmtKind::Branch || brA->has_bittest) continue;
        if (brA->cond != "z" && brA->cond != "nz" && brA->cond != "cy" && brA->cond != "ncy") continue;

        uint32_t tgt = brA->branch_target;
        if (tgt == bid) continue;
        StmtPtr brB = get_pure_flag_branch(tgt);
        if (!brB) continue;

        bool a_is_z = (brA->cond == "z" || brA->cond == "nz");
        bool b_is_z = (brB->cond == "z" || brB->cond == "nz");
        if (a_is_z != b_is_z) continue;

        bool b_taken = (brA->cond == brB->cond);
        uint32_t new_tgt = b_taken ? brB->branch_target : brB->fallthrough;
        if (new_tgt == tgt || new_tgt == bid) continue;

        brA->branch_target = new_tgt;
        if (new_tgt == brA->fallthrough) {
            uint32_t ea = brA->ea;
            b->stmts.back() = make_goto(ea, new_tgt);
            b->term = TermKind::Goto;
            b->succ = {{"jump", new_tgt}};
        } else {
            for (auto &edge : b->succ) {
                if (edge.first == "cond") edge.second = new_tgt;
            }
        }
        any_redirected = true;
    }

    if (any_redirected) {
        bool pruned = true;
        while (pruned) {
            pruned = false;
            std::unordered_set<uint32_t> referenced{func.entry};
            for (const auto &[bid, b] : func.blocks) {
                for (const auto &[how, tgt] : b->succ) referenced.insert(tgt);
            }
            for (auto it = func.blocks.begin(); it != func.blocks.end();) {
                if (!referenced.count(it->first)) {
                    it = func.blocks.erase(it);
                    pruned = true;
                } else {
                    ++it;
                }
            }
        }
    }
}

void resolve_flags(Function &func) {
    struct FlagState {
        FlagDefPtr z;
        FlagDefPtr cy;
        std::set<uint64_t> z_origins;
        std::set<uint64_t> cy_origins;
        bool z_uninit = false;
        bool cy_uninit = false;

        bool same_dataflow(const FlagState &o) const {
            return z_uninit == o.z_uninit && cy_uninit == o.cy_uninit &&
                   z_origins == o.z_origins && cy_origins == o.cy_origins;
        }
    };

    std::unordered_map<uint64_t, FlagDefPtr> z_defs, cy_defs;
    for (const auto &[bid, b] : func.blocks) {
        std::vector<StmtPtr> expanded;
        expanded.reserve(b->stmts.size());
        for (const auto &s : b->stmts) {
            // Normalize `bt/bf psw.0` -> `bc/bnc` and `bt/bf psw.6` -> `bz/bnz`,
            // and `set_bit/clr_bit/xor_bit` on `psw.0` (CY) / `psw.6` (ZF)
            if (s->kind == StmtKind::Branch && s->has_bittest && s->bittest_expr &&
                s->bittest_expr->kind == ExprKind::Bit && s->bittest_expr->base &&
                s->bittest_expr->base->kind == ExprKind::Reg && s->bittest_expr->base->name == "psw") {
                uint8_t bit = s->bittest_expr->bit;
                if (!s->btclr_clear && (bit == 0 || bit == 6)) {
                    s->has_bittest = false;
                    s->bittest_expr = nullptr;
                    if (bit == 0) s->cond = s->bittest_sense ? "cy" : "ncy";
                    else          s->cond = s->bittest_sense ? "z" : "nz";
                }
            } else if (s->kind == StmtKind::Intrinsic && !s->args.empty() && s->args[0] &&
                       s->args[0]->kind == ExprKind::Bit && s->args[0]->base &&
                       s->args[0]->base->kind == ExprKind::Reg && s->args[0]->base->name == "psw" &&
                       (s->args[0]->bit == 0 || s->args[0]->bit == 6)) {
                bool is_cy = (s->args[0]->bit == 0);
                std::string freg = is_cy ? "cy" : "z";
                if (s->name == "set_bit" || s->name == "clr_bit") {
                    uint32_t v = (s->name == "set_bit") ? 1u : 0u;
                    FlagDefPtr zf = nullptr, cyf = nullptr;
                    if (is_cy) {
                        cyf = std::make_shared<FlagDef>(FlagDef{FlagKind::CarryVal, Width::B, Expr::make_const(v, Width::B)});
                    } else {
                        zf = std::make_shared<FlagDef>(FlagDef{FlagKind::Cmp0, Width::B, Expr::make_const(v ? 0u : 1u, Width::B)});
                    }
                    auto asg = make_assign(s->ea, Expr::make_reg(freg, Width::B), Expr::make_const(v, Width::B), zf, cyf);
                    expanded.push_back(asg);
                    continue;
                } else if (s->name == "xor_bit") {
                    ExprPtr inv = Expr::make_bin("^", Expr::make_reg(freg, Width::B), Expr::make_const(1, Width::B), Width::B);
                    FlagDefPtr zf = nullptr, cyf = nullptr;
                    if (is_cy) cyf = std::make_shared<FlagDef>(FlagDef{FlagKind::CarryVal, Width::B, expr_clone(inv)});
                    auto asg = make_assign(s->ea, Expr::make_reg(freg, Width::B), inv, zf, cyf);
                    expanded.push_back(asg);
                    continue;
                }
            }
            if (s->kind == StmtKind::Assign) {
                s->src = rewrite_psw_flag_bits(s->src);
            } else if (s->kind == StmtKind::Ret) {
                s->val = rewrite_psw_flag_bits(s->val);
            }
            expanded.push_back(s);
        }
        b->stmts.swap(expanded);

        for (const auto &s : b->stmts) {
            if (s->kind == StmtKind::Compare || s->kind == StmtKind::Assign) {
                if (s->z_flag && s->z_flag->kind != FlagKind::Unknown) {
                    s->z_flag->origin_stmt_id = s->id;
                    z_defs[s->id] = s->z_flag;
                }
                if (s->cy_flag && s->cy_flag->kind != FlagKind::Unknown) {
                    s->cy_flag->origin_stmt_id = s->id;
                    cy_defs[s->id] = s->cy_flag;
                }
            }
        }
    }

    std::unordered_map<uint32_t, FlagState> block_out;
    std::unordered_map<uint32_t, std::vector<uint32_t>> preds;
    for (const auto &[bid, b] : func.blocks) {
        for (const auto &[how, tgt] : b->succ) {
            preds[tgt].push_back(b->start);
        }
    }

    std::unordered_set<uint64_t> cy_producers_needed;
    std::unordered_set<uint64_t> z_producers_needed;
    std::unordered_set<uint64_t> psw_sync_before_stmt;

    auto join_in_state = [&](uint32_t b_start) -> FlagState {
        FlagState in;
        if (b_start == func.entry) {
            in.z_uninit = true;
            in.cy_uninit = true;
        }
        auto pit = preds.find(b_start);
        if (pit == preds.end() || pit->second.empty()) {
            in.z_uninit = true;
            in.cy_uninit = true;
            return in;
        }
        bool any_visited = false;
        for (uint32_t p : pit->second) {
            auto oit = block_out.find(p);
            if (oit == block_out.end()) continue;
            any_visited = true;
            in.z_uninit = in.z_uninit || oit->second.z_uninit;
            in.cy_uninit = in.cy_uninit || oit->second.cy_uninit;
            in.z_origins.insert(oit->second.z_origins.begin(), oit->second.z_origins.end());
            in.cy_origins.insert(oit->second.cy_origins.begin(), oit->second.cy_origins.end());
        }
        if (!any_visited) {
            in.z_uninit = true;
            in.cy_uninit = true;
            return in;
        }
        if (!in.z_uninit && in.z_origins.size() == 1) {
            uint64_t zid = *in.z_origins.begin();
            if (auto it = z_defs.find(zid); it != z_defs.end()) in.z = it->second;
        }
        if (!in.cy_uninit && in.cy_origins.size() == 1) {
            uint64_t cid = *in.cy_origins.begin();
            if (auto it = cy_defs.find(cid); it != cy_defs.end()) in.cy = it->second;
        }
        return in;
    };

    auto clear_z = [](FlagState &st) {
        st.z = nullptr;
        st.z_origins.clear();
        st.z_uninit = true;
    };
    auto clear_cy = [](FlagState &st) {
        st.cy = nullptr;
        st.cy_origins.clear();
        st.cy_uninit = true;
    };

    auto scan = [&](const BlockPtr &b, FlagState cur, bool apply_to_branches) -> FlagState {
        for (const auto &s : b->stmts) {
            // Check incoming CY / ZF / whole-PSW read BEFORE this statement overwrites flags!
            if (apply_to_branches) {
                bool reads_cy = false;
                bool reads_z = false;
                bool reads_psw = false;
                if (s->kind == StmtKind::Assign) {
                    reads_cy = expr_reads_cy(s->src);
                    reads_z = expr_reads_z_or_psw6(s->src);
                    reads_psw = expr_reads_whole_psw(s->src);
                } else if (s->kind == StmtKind::Ret) {
                    reads_cy = expr_reads_cy(s->val);
                    reads_z = expr_reads_z_or_psw6(s->val);
                    reads_psw = expr_reads_whole_psw(s->val);
                } else if (s->kind == StmtKind::Intrinsic && s->name != "push") {
                    for (const auto &a : s->args) {
                        if (expr_reads_cy(a)) reads_cy = true;
                        if (expr_reads_z_or_psw6(a)) reads_z = true;
                        if (expr_reads_whole_psw(a)) reads_psw = true;
                    }
                }
                if (reads_psw) {
                    reads_cy = true;
                    reads_z = true;
                    if (!cur.cy_origins.empty() || !cur.z_origins.empty()) {
                        psw_sync_before_stmt.insert(s->id);
                    }
                }
                if (reads_cy && !cur.cy_origins.empty()) {
                    cy_producers_needed.insert(cur.cy_origins.begin(), cur.cy_origins.end());
                }
                if (reads_z && !cur.z_origins.empty()) {
                    z_producers_needed.insert(cur.z_origins.begin(), cur.z_origins.end());
                }
            }

            if (s->kind == StmtKind::Compare || s->kind == StmtKind::Assign) {
                if (s->z_flag) {
                    if (s->z_flag->kind == FlagKind::Unknown) {
                        clear_z(cur);
                    } else {
                        s->z_flag->origin_stmt_id = s->id;
                        cur.z = s->z_flag;
                        cur.z_origins = {s->id};
                        cur.z_uninit = false;
                    }
                }
                if (s->cy_flag) {
                    if (s->cy_flag->kind == FlagKind::Unknown) {
                        clear_cy(cur);
                    } else {
                        s->cy_flag->origin_stmt_id = s->id;
                        cur.cy = s->cy_flag;
                        cur.cy_origins = {s->id};
                        cur.cy_uninit = false;
                    }
                }
            } else if (s->kind == StmtKind::Branch) {
                if (!s->has_bittest && !s->cond.empty() && apply_to_branches) {
                    if (s->cond == "z" || s->cond == "nz") {
                        if (cur.z) {
                            s->z_flag = clone_flag(cur.z);
                        } else {
                            s->z_flag = nullptr;
                            z_producers_needed.insert(cur.z_origins.begin(), cur.z_origins.end());
                        }
                    } else if (s->cond == "cy" || s->cond == "ncy") {
                        if (cur.cy) {
                            s->cy_flag = clone_flag(cur.cy);
                        } else {
                            s->cy_flag = nullptr;
                            cy_producers_needed.insert(cur.cy_origins.begin(), cur.cy_origins.end());
                        }
                    } else {
                        if (cur.z) s->z_flag = clone_flag(cur.z);
                        else {
                            s->z_flag = nullptr;
                            z_producers_needed.insert(cur.z_origins.begin(), cur.z_origins.end());
                        }
                        if (cur.cy) s->cy_flag = clone_flag(cur.cy);
                        else {
                            s->cy_flag = nullptr;
                            cy_producers_needed.insert(cur.cy_origins.begin(), cur.cy_origins.end());
                        }
                    }
                }
                if (s->btclr_clear && s->bittest_expr && s->bittest_expr->kind == ExprKind::Bit &&
                    s->bittest_expr->base && s->bittest_expr->base->kind == ExprKind::Reg &&
                    s->bittest_expr->base->name == "psw") {
                    if (s->bittest_expr->bit == 0) {
                        if (apply_to_branches) {
                            cy_producers_needed.insert(cur.cy_origins.begin(), cur.cy_origins.end());
                            s->bittest_expr = Expr::make_bit(Expr::make_reg("cy", Width::B), 0);
                        }
                        clear_cy(cur);
                    } else if (s->bittest_expr->bit == 6) {
                        if (apply_to_branches) {
                            z_producers_needed.insert(cur.z_origins.begin(), cur.z_origins.end());
                            s->bittest_expr = Expr::make_bit(Expr::make_reg("z", Width::B), 0);
                        }
                        clear_z(cur);
                    }
                }
            } else if (s->kind == StmtKind::Call) {
                clear_z(cur);
                clear_cy(cur);
            } else if (s->kind == StmtKind::Intrinsic) {
                if (s->name == "pop" && !s->args.empty() &&
                    s->args[0]->kind == ExprKind::Reg && s->args[0]->name == "psw") {
                    clear_z(cur);
                    clear_cy(cur);
                } else if (s->name != "push" && s->name != "ei" && s->name != "di" &&
                           s->name != "sel" && s->name != "nop") {
                    clear_z(cur);
                    clear_cy(cur);
                }
            }
        }
        return cur;
    };

    auto order = func.ordered();
    for (int iter = 0; iter < 64; ++iter) {
        bool changed = false;
        for (const auto &b : order) {
            FlagState in = join_in_state(b->start);
            FlagState out = scan(b, in, false);
            auto it = block_out.find(b->start);
            if (it == block_out.end() || !it->second.same_dataflow(out)) {
                block_out[b->start] = std::move(out);
                changed = true;
            }
        }
        if (!changed) break;
    }

    // Materialize cloned FlagDef snapshots onto branches now that dataflow converged.
    for (const auto &b : order) {
        FlagState in = join_in_state(b->start);
        (void)scan(b, in, true);
    }

    // Materialize explicit `CY = <expr>;` / `ZF = <expr>;` statements without clobbering pre-state!
    {
        int cy_tmp_cnt = 0;
        for (const auto &b : order) {
            std::vector<StmtPtr> new_stmts;
            new_stmts.reserve(b->stmts.size());
            for (const auto &s : b->stmts) {
                bool is_dead_set_cy = (s->kind == StmtKind::Assign && s->dst &&
                                       s->dst->kind == ExprKind::Reg && s->dst->name == "cy" &&
                                       !cy_producers_needed.count(s->id));
                bool is_dead_set_z = (s->kind == StmtKind::Assign && s->dst &&
                                      s->dst->kind == ExprKind::Reg && s->dst->name == "z" &&
                                      !z_producers_needed.count(s->id));
                if (is_dead_set_cy || is_dead_set_z) {
                    continue;
                }

                if (psw_sync_before_stmt.count(s->id)) {
                    ExprPtr masked = Expr::make_bin("&", Expr::make_reg("psw", Width::B), Expr::make_const(0xBEu, Width::B), Width::B);
                    ExprPtr zbit = Expr::make_bin("<<", Expr::make_bin("&", Expr::make_reg("z", Width::B), Expr::make_const(1u, Width::B), Width::B), Expr::make_const(6u, Width::B), Width::B);
                    ExprPtr cbit = Expr::make_bin("&", Expr::make_reg("cy", Width::B), Expr::make_const(1u, Width::B), Width::B);
                    ExprPtr synced = Expr::make_bin("|", Expr::make_bin("|", masked, zbit, Width::B), cbit, Width::B);
                    new_stmts.push_back(make_assign(s->ea, Expr::make_reg("psw", Width::B), synced));
                }

                bool need_cy = cy_producers_needed.count(s->id) > 0 && s->cy_flag != nullptr;
                bool already_writes_cy = (s->kind == StmtKind::Assign && s->dst &&
                                          s->dst->kind == ExprKind::Reg && s->dst->name == "cy");
                StmtPtr post_cy_stmt;
                if (need_cy && !already_writes_cy) {
                    ExprPtr cy_val = materialize_cy_expr(*s->cy_flag);
                    bool s_reads_incoming_cy = (s->kind == StmtKind::Assign && expr_reads_cy(s->src));
                    if (s_reads_incoming_cy) {
                        ExprPtr tmp = Expr::make_var("_cy_next_" + std::to_string(cy_tmp_cnt++), Width::B);
                        new_stmts.push_back(make_assign(s->ea, tmp, cy_val));
                        post_cy_stmt = make_assign(s->ea, Expr::make_reg("cy"), expr_clone(tmp));
                    } else {
                        new_stmts.push_back(make_assign(s->ea, Expr::make_reg("cy"), cy_val));
                    }
                }

                bool need_z = z_producers_needed.count(s->id) > 0 && s->z_flag != nullptr;
                bool already_writes_z = (s->kind == StmtKind::Assign && s->dst &&
                                         s->dst->kind == ExprKind::Reg && s->dst->name == "z");
                StmtPtr post_z_stmt;
                if (need_z && !already_writes_z) {
                    ExprPtr zval = materialize_z_expr(*s->z_flag);
                    if (zval) {
                        if (s->z_flag->kind == FlagKind::Result) {
                            post_z_stmt = make_assign(s->ea, Expr::make_reg("z"), zval);
                        } else if (s->kind == StmtKind::Assign && expr_reads_z_or_psw6(s->src)) {
                            ExprPtr tmp = Expr::make_var("_z_next_" + std::to_string(cy_tmp_cnt++), Width::B);
                            new_stmts.push_back(make_assign(s->ea, tmp, zval));
                            post_z_stmt = make_assign(s->ea, Expr::make_reg("z"), expr_clone(tmp));
                        } else {
                            new_stmts.push_back(make_assign(s->ea, Expr::make_reg("z"), zval));
                        }
                    }
                }

                new_stmts.push_back(s);
                if (post_cy_stmt) new_stmts.push_back(std::move(post_cy_stmt));
                if (post_z_stmt) new_stmts.push_back(std::move(post_z_stmt));
            }
            b->stmts.swap(new_stmts);
        }
    }
}

std::unique_ptr<Function> build_func(
    const std::map<uint32_t, DecodedInsn> &insns,
    uint32_t entry,
    const std::set<uint32_t> &entry_set) {
    auto body = collect_body(insns, entry, entry_set);
    if (body.empty()) return nullptr;
    auto leaders = find_leaders(insns, body);
    leaders.insert(entry);

    auto f = std::make_unique<Function>();
    f->entry = entry;

    BlockPtr cur;
    for (uint32_t ea : body) {
        const auto &ins = insns.at(ea);
        if (leaders.count(ea) || !cur) {
            cur = std::make_shared<Block>();
            cur->start = ea;
            f->blocks[ea] = cur;
        }
        cur->insn_eas.push_back(ea);

        auto succ = cfg_succ(insns, ins);
        uint32_t nxt = ea + static_cast<uint32_t>(ins.size);
        bool closes_block = false;
        TermKind term = TermKind::Fall;
        std::vector<std::pair<std::string, uint32_t>> blk_succ;

        if (ins.sw.has_value()) {
            term = TermKind::Switch;
            blk_succ = std::move(succ);
            closes_block = true;
        } else if (ins.mnem == Mnem::Br && target_of(ins).has_value()) {
            term = TermKind::Goto;
            blk_succ = std::move(succ);
            closes_block = true;
        } else if (ins.mnem == Mnem::Br) {
            term = TermKind::Ret;
            closes_block = true;
        } else if (is_ret_mnem(ins.mnem) || ins.mnem == Mnem::Stop || ins.mnem == Mnem::Brk1) {
            term = TermKind::Ret;
            closes_block = true;
        } else if (is_skip_mnem(ins.mnem) || is_cond_branch_mnem(ins.mnem) || is_bit_branch_mnem(ins.mnem)) {
            term = TermKind::Branch;
            blk_succ = std::move(succ);
            closes_block = true;
        } else if (leaders.count(nxt) || !body.count(nxt)) {
            term = TermKind::Fall;
            if (body.count(nxt)) blk_succ.emplace_back("fall", nxt);
            closes_block = true;
        }
        if (closes_block) {
            cur->term = term;
            cur->succ = std::move(blk_succ);
            cur.reset();
        }
    }

    for (const auto &[bid, b] : f->blocks) {
        std::unordered_set<uint32_t> dispatch_eas;
        for (uint32_t ea : b->insn_eas) {
            const auto &ins = insns.at(ea);
            if (ins.sw.has_value()) {
                for (uint32_t d : ins.sw->dispatch_eas) dispatch_eas.insert(d);
            }
        }
        for (uint32_t ea : b->insn_eas) {
            const auto &ins = insns.at(ea);
            if (dispatch_eas.count(ea)) {
                if (ins.sw.has_value()) {
                    b->stmts.push_back(make_switch(
                        ins.ea, Expr::make_reg(ins.sw->idx_reg),
                        ins.sw->cases, ins.sw->default_ea, ins.sw->table_ea));
                }
                continue;
            }
            if ((ins.mnem == Mnem::Call || ins.mnem == Mnem::Callt || ins.mnem == Mnem::Brk)) {
                if (auto tgt = target_of(ins); tgt.has_value()) f->calls.insert(*tgt);
            }
            if (ins.sw.has_value()) {
                b->stmts.push_back(make_switch(
                    ins.ea, Expr::make_reg(ins.sw->idx_reg),
                    ins.sw->cases, ins.sw->default_ea, ins.sw->table_ea));
            } else if (is_skip_mnem(ins.mnem)) {
                b->stmts.push_back(make_skip_branch(insns, ins));
            } else {
                auto lifted = lift_insn(ins);
                b->stmts.insert(b->stmts.end(), lifted.begin(), lifted.end());
            }
        }
    }

    return f;
}

std::map<uint32_t, std::unique_ptr<Function>> build_functions(
    const std::map<uint32_t, DecodedInsn> &insns,
    const std::set<uint32_t> &calls,
    const std::vector<uint32_t> &extra_entries) {
    std::set<uint32_t> switch_targets;
    for (const auto &[ea, ins] : insns) {
        if (ins.sw.has_value()) {
            for (uint32_t t : ins.sw->targets) switch_targets.insert(t);
        }
    }

    std::set<uint32_t> entry_set;
    for (uint32_t c : calls) {
        if (insns.count(c)) entry_set.insert(c);
    }
    for (uint32_t e : extra_entries) {
        if (insns.count(e)) entry_set.insert(e);
    }
    for (uint32_t t : switch_targets) {
        if (!calls.count(t)) entry_set.erase(t);
    }

    std::map<uint32_t, std::unique_ptr<Function>> funcs;
    std::set<uint32_t> subsumed;
    for (uint32_t entry : entry_set) {
        if (subsumed.count(entry)) continue;
        auto fn = build_func(insns, entry, entry_set);
        if (fn) {
            for (const auto &[b_ea, _] : fn->blocks) {
                if (b_ea != entry && entry_set.count(b_ea)) subsumed.insert(b_ea);
            }
            funcs[entry] = std::move(fn);
        }
    }
    return funcs;
}

} // namespace rl78dec
