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
    if (e->kind == ExprKind::Bin) return expr_reads_cy(e->l) || expr_reads_cy(e->r);
    if (e->kind == ExprKind::Un) return expr_reads_cy(e->l);
    if (e->kind == ExprKind::Mem) return !e->has_static_addr && expr_reads_cy(e->addr);
    if (e->kind == ExprKind::Bit) return expr_reads_cy(e->base);
    if (e->kind == ExprKind::Intr) {
        for (const auto &a : e->args) if (expr_reads_cy(a)) return true;
    }
    return false;
}

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

void resolve_flags(Function &func) {
    struct FlagState {
        FlagDefPtr z;
        FlagDefPtr cy;
    };
    std::unordered_map<uint32_t, FlagState> block_out;
    std::unordered_map<uint32_t, std::vector<uint32_t>> preds;
    for (const auto &[bid, b] : func.blocks) {
        for (const auto &[how, tgt] : b->succ) {
            preds[tgt].push_back(b->start);
        }
    }

    std::unordered_set<uint64_t> cy_producers_needed;
    std::unordered_set<uint64_t> z_producers_needed;

    auto join_in_state = [&](uint32_t b_start, bool record_multi_needed) -> FlagState {
        FlagState in;
        auto pit = preds.find(b_start);
        if (pit == preds.end() || pit->second.empty()) return in;
        if (pit->second.size() == 1) {
            if (auto oit = block_out.find(pit->second[0]); oit != block_out.end()) {
                return oit->second;
            }
            return in;
        }
        // Multi-predecessor join: keep flag only if all predecessors share identical origin_stmt_id.
        bool z_init = false, z_same = true;
        FlagDefPtr z_first;
        bool cy_init = false, cy_same = true;
        FlagDefPtr cy_first;
        for (uint32_t p : pit->second) {
            auto oit = block_out.find(p);
            if (oit == block_out.end()) { z_same = false; cy_same = false; continue; }
            if (!z_init) { z_first = oit->second.z; z_init = true; }
            else if (!oit->second.z || !z_first || oit->second.z->origin_stmt_id != z_first->origin_stmt_id) z_same = false;
            if (!cy_init) { cy_first = oit->second.cy; cy_init = true; }
            else if (!oit->second.cy || !cy_first || oit->second.cy->origin_stmt_id != cy_first->origin_stmt_id) cy_same = false;
        }
        if (z_same && z_first && z_first->origin_stmt_id != 0) in.z = z_first;
        else if (record_multi_needed) {
            for (uint32_t p : pit->second) {
                auto oit = block_out.find(p);
                if (oit != block_out.end() && oit->second.z && oit->second.z->origin_stmt_id != 0) {
                    z_producers_needed.insert(oit->second.z->origin_stmt_id);
                }
            }
        }
        if (cy_same && cy_first && cy_first->origin_stmt_id != 0) in.cy = cy_first;
        else if (record_multi_needed) {
            for (uint32_t p : pit->second) {
                auto oit = block_out.find(p);
                if (oit != block_out.end() && oit->second.cy && oit->second.cy->origin_stmt_id != 0) {
                    cy_producers_needed.insert(oit->second.cy->origin_stmt_id);
                }
            }
        }
        return in;
    };

    auto scan = [&](const BlockPtr &b, FlagState cur, bool apply_to_branches) -> FlagState {
        for (const auto &s : b->stmts) {
            // Check incoming CY read BEFORE this statement overwrites CY!
            if (apply_to_branches && cur.cy && cur.cy->origin_stmt_id != 0) {
                bool reads = false;
                if (s->kind == StmtKind::Assign && expr_reads_cy(s->src)) reads = true;
                else if (s->kind == StmtKind::Ret && expr_reads_cy(s->val)) reads = true;
                else if (s->kind == StmtKind::Intrinsic) {
                    for (const auto &a : s->args) if (expr_reads_cy(a)) reads = true;
                }
                if (reads) cy_producers_needed.insert(cur.cy->origin_stmt_id);
            }

            if (s->kind == StmtKind::Compare) {
                if (s->z_flag)  { s->z_flag->origin_stmt_id = s->id; cur.z = s->z_flag; }
                if (s->cy_flag) { s->cy_flag->origin_stmt_id = s->id; cur.cy = s->cy_flag; }
            } else if (s->kind == StmtKind::Assign) {
                if (s->z_flag)  { s->z_flag->origin_stmt_id = s->id; cur.z = s->z_flag; }
                if (s->cy_flag) { s->cy_flag->origin_stmt_id = s->id; cur.cy = s->cy_flag; }
            } else if (s->kind == StmtKind::Branch) {
                if (!s->has_bittest && !s->cond.empty() && apply_to_branches) {
                    if (s->cond == "z" || s->cond == "nz") {
                        s->z_flag = clone_flag(cur.z);
                    } else if (s->cond == "cy" || s->cond == "ncy") {
                        s->cy_flag = clone_flag(cur.cy);
                    } else {
                        s->z_flag = clone_flag(cur.z);
                        s->cy_flag = clone_flag(cur.cy);
                    }
                }
                if (s->btclr_clear && s->bittest_expr && s->bittest_expr->kind == ExprKind::Bit &&
                    s->bittest_expr->base && s->bittest_expr->base->kind == ExprKind::Reg &&
                    s->bittest_expr->base->name == "psw") {
                    if (s->bittest_expr->bit == 0) cur.cy = nullptr;
                    else if (s->bittest_expr->bit == 6) cur.z = nullptr;
                }
            } else if (s->kind == StmtKind::Call) {
                cur.z = nullptr;
                cur.cy = nullptr;
            } else if (s->kind == StmtKind::Intrinsic) {
                if (s->name == "pop" && !s->args.empty() &&
                    s->args[0]->kind == ExprKind::Reg && s->args[0]->name == "psw") {
                    cur.z = nullptr;
                    cur.cy = nullptr;
                } else if (s->name != "push" && s->name != "ei" && s->name != "di" &&
                           s->name != "sel" && s->name != "nop") {
                    cur.z = nullptr;
                    cur.cy = nullptr;
                }
            }
        }
        return cur;
    };

    auto order = func.ordered();
    for (int iter = 0; iter < 6; ++iter) {
        bool changed = false;
        for (const auto &b : order) {
            FlagState in = join_in_state(b->start, false);
            FlagState out = scan(b, in, false);
            auto &prev = block_out[b->start];
            if (prev.z.get() != out.z.get() || prev.cy.get() != out.cy.get()) {
                prev = out;
                changed = true;
            }
        }
        if (!changed) break;
    }

    // Materialize cloned FlagDef snapshots onto branches now that dataflow converged.
    for (const auto &b : order) {
        FlagState in = join_in_state(b->start, true);
        (void)scan(b, in, true);
    }

    // Materialize explicit `CY = <expr>;` statements without clobbering incoming CY when s itself reads CY!
    if (!cy_producers_needed.empty() || !z_producers_needed.empty()) {
        int cy_tmp_cnt = 0;
        for (const auto &b : order) {
            std::vector<StmtPtr> new_stmts;
            new_stmts.reserve(b->stmts.size());
            for (const auto &s : b->stmts) {
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
                new_stmts.push_back(s);
                if (post_cy_stmt) new_stmts.push_back(std::move(post_cy_stmt));
                if (z_producers_needed.count(s->id) && s->z_flag) {
                    ExprPtr zval;
                    if (s->z_flag->kind == FlagKind::Cmp || s->z_flag->kind == FlagKind::Sub) {
                        zval = Expr::make_bin("==", wrap_u_cy(s->z_flag->a, s->z_flag->width), wrap_u_cy(s->z_flag->b, s->z_flag->width), Width::B);
                    } else if (s->z_flag->a) {
                        zval = Expr::make_bin("==", wrap_u_cy(s->z_flag->a, s->z_flag->width), Expr::make_const(0, s->z_flag->width), Width::B);
                    }
                    if (zval) new_stmts.push_back(make_assign(s->ea, Expr::make_reg("z"), zval));
                }
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
