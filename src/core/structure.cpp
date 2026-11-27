#include "rl78dec/structure.hpp"

#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace rl78dec {

namespace {

uint32_t width_mask(Width w) {
    switch (w) {
        case Width::B: return 0xFFu;
        case Width::W: return 0xFFFFu;
        case Width::A: return 0xFFFFFu;
        case Width::D: return 0xFFFFFFFFu;
    }
    return 0xFFu;
}

ExprPtr wrap_unsigned(const ExprPtr &e, Width w) {
    if (!e) return Expr::make_const(0, w);
    if (e->kind == ExprKind::Const) {
        return Expr::make_const(e->value & width_mask(w), w, e->name);
    }
    return Expr::make_un(w == Width::B ? "u8" : (w == Width::W ? "u16" : "u32"), e, w);
}

ExprPtr make_cmp_z(const FlagDef &f, bool eq_zero) {
    std::string eqop = eq_zero ? "==" : "!=";
    switch (f.kind) {
        case FlagKind::Cmp:
            return Expr::make_bin(eqop, wrap_unsigned(f.a, f.width), wrap_unsigned(f.b, f.width), Width::B);
        case FlagKind::Cmp0:
        case FlagKind::Result:
            return Expr::make_bin(eqop, wrap_unsigned(f.a, f.width), Expr::make_const(0, f.width), Width::B);
        case FlagKind::Sub:
            if (!f.c) {
                return Expr::make_bin(eqop, wrap_unsigned(f.a, f.width), wrap_unsigned(f.b, f.width), Width::B);
            } else {
                ExprPtr diff = Expr::make_bin("-",
                                              Expr::make_bin("-", wrap_unsigned(f.a, f.width), wrap_unsigned(f.b, f.width), f.width),
                                              wrap_unsigned(f.c, Width::B), f.width);
                return Expr::make_bin(eqop, wrap_unsigned(diff, f.width), Expr::make_const(0, f.width), Width::B);
            }
        case FlagKind::Add: {
            ExprPtr sum = Expr::make_bin("+", wrap_unsigned(f.a, f.width), wrap_unsigned(f.b, f.width), f.width);
            if (f.c) sum = Expr::make_bin("+", sum, wrap_unsigned(f.c, Width::B), f.width);
            return Expr::make_bin(eqop, wrap_unsigned(sum, f.width), Expr::make_const(0, f.width), Width::B);
        }
        case FlagKind::Movs:
            return Expr::make_bin(eqop, wrap_unsigned(f.b, Width::B), Expr::make_const(0, Width::B), Width::B);
        case FlagKind::Cmps:
            return Expr::make_bin(eqop, wrap_unsigned(f.a, Width::B), wrap_unsigned(f.b, Width::B), Width::B);
        default:
            return Expr::make_bin(eq_zero ? "!=" : "==", Expr::make_reg("ZF", Width::B), Expr::make_const(0, Width::B), Width::B);
    }
}

ExprPtr make_cmp_cy(const FlagDef &f, bool set) {
    switch (f.kind) {
        case FlagKind::Cmp:
            return Expr::make_bin(set ? "<" : ">=", wrap_unsigned(f.a, f.width), wrap_unsigned(f.b, f.width), Width::B);
        case FlagKind::Cmp0:
            return Expr::make_const(set ? 0u : 1u, Width::B);
        case FlagKind::Sub: {
            ExprPtr ua = Expr::make_un("u32", wrap_unsigned(f.a, f.width), Width::D);
            ExprPtr ub = Expr::make_un("u32", wrap_unsigned(f.b, f.width), Width::D);
            if (f.c) ub = Expr::make_bin("+", ub, Expr::make_un("u32", wrap_unsigned(f.c, Width::B), Width::D), Width::D);
            return Expr::make_bin(set ? "<" : ">=", ua, ub, Width::B);
        }
        case FlagKind::Add: {
            ExprPtr ua = Expr::make_un("u32", wrap_unsigned(f.a, f.width), Width::D);
            ExprPtr ub = Expr::make_un("u32", wrap_unsigned(f.b, f.width), Width::D);
            ExprPtr sum = Expr::make_bin("+", ua, ub, Width::D);
            if (f.c) sum = Expr::make_bin("+", sum, Expr::make_un("u32", wrap_unsigned(f.c, Width::B), Width::D), Width::D);
            return Expr::make_bin(set ? ">" : "<=", sum, Expr::make_const(width_mask(f.width), Width::D), Width::B);
        }
        case FlagKind::CarryVal:
            return Expr::make_bin(set ? "!=" : "==", f.a ? f.a : Expr::make_reg("CY", Width::B), Expr::make_const(0, Width::B), Width::B);
        case FlagKind::Movs: {
            ExprPtr za = Expr::make_bin("==", wrap_unsigned(f.a, Width::B), Expr::make_const(0, Width::B), Width::B);
            ExprPtr zb = Expr::make_bin("==", wrap_unsigned(f.b, Width::B), Expr::make_const(0, Width::B), Width::B);
            ExprPtr both = Expr::make_bin("||", za, zb, Width::B);
            return set ? both : negate_cond(both);
        }
        case FlagKind::Cmps: {
            ExprPtr neq = Expr::make_bin("!=", wrap_unsigned(f.a, Width::B), wrap_unsigned(f.b, Width::B), Width::B);
            ExprPtr c0  = Expr::make_bin("==", wrap_unsigned(f.c, Width::B), Expr::make_const(0, Width::B), Width::B);
            ExprPtr a0  = Expr::make_bin("==", wrap_unsigned(f.a, Width::B), Expr::make_const(0, Width::B), Width::B);
            ExprPtr or1 = Expr::make_bin("||", neq, Expr::make_bin("||", c0, a0, Width::B), Width::B);
            return set ? or1 : negate_cond(or1);
        }
        default:
            return Expr::make_bin(set ? "!=" : "==", Expr::make_reg("CY", Width::B), Expr::make_const(0, Width::B), Width::B);
    }
}

SNodePtr make_snode(SNodeKind k, uint32_t ea = 0) {
    auto n = std::make_shared<SNode>();
    n->kind = k;
    n->ea = ea;
    return n;
}

const StmtPtr find_term_stmt(const BlockPtr &b) {
    if (!b || b->stmts.empty()) return nullptr;
    return b->stmts.back();
}

} // namespace

ExprPtr cond_expr(const Stmt &branch) {
    if (branch.has_bittest) {
        ExprPtr e = branch.bittest_expr ? expr_clone(branch.bittest_expr) : Expr::make_const(1, Width::B);
        return branch.bittest_sense ? e : negate_cond(e);
    }
    if (branch.cond == "z")   return branch.z_flag ? make_cmp_z(*branch.z_flag, true)  : Expr::make_bin("!=", Expr::make_reg("ZF", Width::B), Expr::make_const(0, Width::B), Width::B);
    if (branch.cond == "nz")  return branch.z_flag ? make_cmp_z(*branch.z_flag, false) : Expr::make_bin("==", Expr::make_reg("ZF", Width::B), Expr::make_const(0, Width::B), Width::B);
    if (branch.cond == "cy")  return branch.cy_flag ? make_cmp_cy(*branch.cy_flag, true)  : Expr::make_bin("!=", Expr::make_reg("CY", Width::B), Expr::make_const(0, Width::B), Width::B);
    if (branch.cond == "ncy") return branch.cy_flag ? make_cmp_cy(*branch.cy_flag, false) : Expr::make_bin("==", Expr::make_reg("CY", Width::B), Expr::make_const(0, Width::B), Width::B);

    if (branch.cond == "h" || branch.cond == "nh") {
        bool higher = (branch.cond == "h");
        if (branch.z_flag && branch.cy_flag && branch.z_flag->kind == FlagKind::Cmp && branch.cy_flag->kind == FlagKind::Cmp) {
            return Expr::make_bin(higher ? ">" : "<=",
                                  wrap_unsigned(branch.z_flag->a, branch.z_flag->width),
                                  wrap_unsigned(branch.z_flag->b, branch.z_flag->width), Width::B);
        }
        if (branch.z_flag && branch.cy_flag && branch.z_flag->kind == FlagKind::Sub && !branch.z_flag->c && branch.cy_flag->kind == FlagKind::Sub && !branch.cy_flag->c) {
            return Expr::make_bin(higher ? ">" : "<=",
                                  wrap_unsigned(branch.z_flag->a, branch.z_flag->width),
                                  wrap_unsigned(branch.z_flag->b, branch.z_flag->width), Width::B);
        }
        ExprPtr zc = branch.z_flag ? make_cmp_z(*branch.z_flag, true) : Expr::make_bin("!=", Expr::make_reg("ZF", Width::B), Expr::make_const(0, Width::B), Width::B);
        ExprPtr cc = branch.cy_flag ? make_cmp_cy(*branch.cy_flag, true) : Expr::make_bin("!=", Expr::make_reg("CY", Width::B), Expr::make_const(0, Width::B), Width::B);
        ExprPtr nh = Expr::make_bin("||", zc, cc, Width::B);
        return higher ? negate_cond(nh) : nh;
    }

    return Expr::make_const(1, Width::B);
}

ExprPtr negate_cond(const ExprPtr &e) {
    if (!e) return Expr::make_const(0, Width::B);
    if (e->kind == ExprKind::Un && e->op == "!") return expr_clone(e->l);
    if (e->kind == ExprKind::Const) return Expr::make_const(e->value ? 0u : 1u, Width::B);
    if (e->kind == ExprKind::Bin) {
        if (e->op == "==") return Expr::make_bin("!=", e->l, e->r, e->width);
        if (e->op == "!=") return Expr::make_bin("==", e->l, e->r, e->width);
        if (e->op == "<")  return Expr::make_bin(">=", e->l, e->r, e->width);
        if (e->op == ">=") return Expr::make_bin("<",  e->l, e->r, e->width);
        if (e->op == ">")  return Expr::make_bin("<=", e->l, e->r, e->width);
        if (e->op == "<=") return Expr::make_bin(">",  e->l, e->r, e->width);
        if (e->op == "&&") return Expr::make_bin("||", negate_cond(e->l), negate_cond(e->r), Width::B);
        if (e->op == "||") return Expr::make_bin("&&", negate_cond(e->l), negate_cond(e->r), Width::B);
    }
    return Expr::make_un("!", e, Width::B);
}

std::vector<SNodePtr> structure(const Function &func, const FrameInfo *frame_info) {
    std::vector<SNodePtr> out;
    if (func.blocks.empty()) return out;

    auto order = func.ordered();
    std::unordered_map<uint32_t, std::vector<uint32_t>> preds;
    for (const auto &b : order) {
        for (const auto &[how, tgt] : b->succ) preds[tgt].push_back(b->start);
    }

    // Compute dominators using Cooper-Harvey-Kennedy iterative algorithm
    std::unordered_map<uint32_t, int> blk_idx;
    for (size_t i = 0; i < order.size(); ++i) blk_idx[order[i]->start] = static_cast<int>(i);
    int n = static_cast<int>(order.size());
    int entry_i = blk_idx.count(func.entry) ? blk_idx[func.entry] : 0;

    std::vector<int> idom(n, -1);
    idom[entry_i] = entry_i;
    auto intersect = [&](int b1, int b2) {
        while (b1 != b2) {
            while (b1 > b2) {
                if (idom[b1] < 0 || idom[b1] == b1) return entry_i;
                b1 = idom[b1];
            }
            while (b2 > b1) {
                if (idom[b2] < 0 || idom[b2] == b2) return entry_i;
                b2 = idom[b2];
            }
        }
        return b1;
    };
    for (int iter = 0; iter < 16; ++iter) {
        bool changed = false;
        for (int i = 0; i < n; ++i) {
            if (i == entry_i) continue;
            int new_idom = -1;
            for (uint32_t p_ea : preds[order[i]->start]) {
                int pi = blk_idx.count(p_ea) ? blk_idx[p_ea] : -1;
                if (pi >= 0 && idom[pi] != -1) {
                    new_idom = (new_idom == -1) ? pi : intersect(pi, new_idom);
                }
            }
            if (new_idom != -1 && idom[i] != new_idom) {
                idom[i] = new_idom;
                changed = true;
            }
        }
        if (!changed) break;
    }

    auto dominates = [&](int d, int u) -> bool {
        if (d < 0 || u < 0) return false;
        int cur = u;
        for (int k = 0; k <= n; ++k) {
            if (cur == d) return true;
            if (cur < 0 || idom[cur] < 0 || idom[cur] == cur) break;
            cur = idom[cur];
        }
        return false;
    };

    // Identify natural loop headers and bodies (backedges tail -> header where header dom tail)
    struct LoopInfo {
        uint32_t header = 0;
        std::set<uint32_t> body;
        std::set<uint32_t> backedge_tails;
    };
    std::map<uint32_t, LoopInfo> loops;
    for (const auto &b : order) {
        int bi = blk_idx[b->start];
        for (const auto &[how, tgt] : b->succ) {
            auto tit = blk_idx.find(tgt);
            if (tit == blk_idx.end()) continue;
            if (dominates(tit->second, bi)) {
                auto &lp = loops[tgt];
                lp.header = tgt;
                lp.backedge_tails.insert(b->start);
                lp.body.insert(tgt);
                std::vector<uint32_t> work = {b->start};
                while (!work.empty()) {
                    uint32_t x = work.back();
                    work.pop_back();
                    if (!lp.body.count(x)) {
                        lp.body.insert(x);
                        for (uint32_t p : preds[x]) work.push_back(p);
                    }
                }
            }
        }
    }

    std::unordered_set<uint32_t> emitted_blocks;
    std::unordered_set<uint32_t> referenced_labels;

    auto is_hidden = [&](const StmtPtr &s) {
        return s && frame_info && frame_info->hidden_stmts.count(s->id) > 0;
    };

    auto count_visible_stmts = [&](const BlockPtr &b) -> size_t {
        size_t cnt = 0;
        for (const auto &s : b->stmts) {
            if (s->kind != StmtKind::Nop && !is_hidden(s)) ++cnt;
        }
        return cnt;
    };

    auto emit_goto_or_jumpout = [&](uint32_t stmt_ea, uint32_t target_ea, std::vector<SNodePtr> &dst) {
        if (func.blocks.count(target_ea)) {
            auto g = make_snode(SNodeKind::Goto, stmt_ea);
            g->ea = target_ea;
            referenced_labels.insert(target_ea);
            dst.push_back(g);
        } else {
            auto st = make_snode(SNodeKind::Stmt, stmt_ea);
            st->stmt = make_intrinsic(stmt_ea, "goto", {Expr::make_const(target_ea, Width::A)}, "external");
            dst.push_back(st);
        }
    };

    auto emit_body_stmts = [&](const BlockPtr &b, std::vector<SNodePtr> &dst, bool skip_term) {
        size_t limit = b->stmts.size();
        if (skip_term && limit > 0) --limit;
        for (size_t i = 0; i < limit; ++i) {
            const auto &s = b->stmts[i];
            if (s->kind == StmtKind::Nop || is_hidden(s)) continue;
            if (s->kind == StmtKind::Ret) {
                auto r = make_snode(SNodeKind::Ret, s->ea);
                r->val = s->val;
                r->ret_kind = s->ret_kind;
                dst.push_back(r);
                continue;
            }
            if (s->kind == StmtKind::Goto) {
                emit_goto_or_jumpout(s->ea, s->goto_target, dst);
                continue;
            }
            auto st = make_snode(SNodeKind::Stmt, s->ea);
            st->stmt = s;
            dst.push_back(st);
        }
    };

    auto attach_btclr = [](const SNodePtr &node, const Stmt &br) {
        if (br.btclr_clear && br.bittest_expr && br.bittest_expr->kind == ExprKind::Bit) {
            node->btclr_clear = true;
            node->btclr_base = br.bittest_expr->base;
            node->btclr_bit = br.bittest_expr->bit;
        }
    };

    // Structured recursive block emitter with loop/branch structuring + label-goto safe fallback
    std::function<void(uint32_t, const std::set<uint32_t> &, std::optional<uint32_t>,
                       std::optional<uint32_t>, std::optional<uint32_t>, std::vector<SNodePtr> &)>
        emit_region = [&](uint32_t start_ea,
                          const std::set<uint32_t> &allowed,
                          std::optional<uint32_t> stop_ea,
                          std::optional<uint32_t> loop_hdr,
                          std::optional<uint32_t> loop_exit,
                          std::vector<SNodePtr> &dst) {
            std::optional<uint32_t> cur_opt = start_ea;
            while (cur_opt.has_value()) {
                uint32_t cur_ea = *cur_opt;
                if (stop_ea.has_value() && cur_ea == *stop_ea) return;
                if (loop_exit.has_value() && cur_ea == *loop_exit) {
                    dst.push_back(make_snode(SNodeKind::Break, cur_ea));
                    return;
                }
                if (loop_hdr.has_value() && cur_ea == *loop_hdr && emitted_blocks.count(cur_ea)) {
                    dst.push_back(make_snode(SNodeKind::Continue, cur_ea));
                    return;
                }
                if (!allowed.count(cur_ea) || !func.blocks.count(cur_ea) || emitted_blocks.count(cur_ea)) {
                    emit_goto_or_jumpout(cur_ea, cur_ea, dst);
                    return;
                }

                // Loop structuring when entering a loop header that we aren't already inside
                auto lit = loops.find(cur_ea);
                if (lit != loops.end() && (!loop_hdr.has_value() || *loop_hdr != cur_ea)) {
                    const LoopInfo &lp = lit->second;
                    std::optional<uint32_t> exit_ea;
                    for (uint32_t b_ea : lp.body) {
                        const auto &blk = func.blocks.at(b_ea);
                        for (const auto &[how, tgt] : blk->succ) {
                            if (!lp.body.count(tgt)) {
                                exit_ea = tgt;
                                break;
                            }
                        }
                        if (exit_ea.has_value()) break;
                    }

                    // Check simple while-at-top vs do-while loop (skip shorthand for BTCLR so bit clears strictly on taken edge)
                    const auto &hdr_blk = func.blocks.at(cur_ea);
                    auto term = find_term_stmt(hdr_blk);
                    if (hdr_blk->term == TermKind::Branch && term && term->kind == StmtKind::Branch &&
                        !term->btclr_clear && count_visible_stmts(hdr_blk) == 1 && exit_ea.has_value() &&
                        (term->branch_target == *exit_ea || term->fallthrough == *exit_ea)) {
                        // Header is pure condition check: while (cond) { body }
                        emitted_blocks.insert(cur_ea);
                        auto lbl = make_snode(SNodeKind::Label, cur_ea);
                        lbl->ea = cur_ea;
                        dst.push_back(lbl);
                        ExprPtr c = cond_expr(*term);
                        bool exit_on_taken = (term->branch_target == *exit_ea);
                        ExprPtr while_cond = exit_on_taken ? negate_cond(c) : c;
                        uint32_t body_start = exit_on_taken ? term->fallthrough : term->branch_target;

                        auto wnode = make_snode(SNodeKind::While, term->ea);
                        wnode->cond = while_cond;
                        wnode->dowhile = false;

                        if (lp.body.count(body_start) && body_start != cur_ea) {
                            emit_region(body_start, lp.body, std::nullopt, cur_ea, exit_ea, wnode->then_body);
                        }
                        dst.push_back(wnode);
                        cur_opt = exit_ea;
                        continue;
                    }

                    // General do-while / forever loop with break/continue
                    emitted_blocks.insert(cur_ea);
                    auto lbl = make_snode(SNodeKind::Label, cur_ea);
                    lbl->ea = cur_ea;
                    dst.push_back(lbl);
                    auto lnode = make_snode(SNodeKind::While, cur_ea);
                    lnode->dowhile = true;
                    lnode->cond = Expr::make_const(1, Width::B);

                    // Emit header body + branch inside do { ... }
                    emit_body_stmts(hdr_blk, lnode->then_body, hdr_blk->term != TermKind::Fall);
                    if (hdr_blk->term == TermKind::Branch && term && term->kind == StmtKind::Branch) {
                        ExprPtr c = cond_expr(*term);
                        if (!term->btclr_clear && term->branch_target == cur_ea && term->fallthrough != cur_ea &&
                            (!exit_ea.has_value() || term->fallthrough == *exit_ea)) {
                            // Classic single-block do { ... } while (cond);
                            lnode->cond = c;
                            dst.push_back(lnode);
                            cur_opt = term->fallthrough;
                            continue;
                        }
                        if (!term->btclr_clear && term->fallthrough == cur_ea && term->branch_target != cur_ea &&
                            (!exit_ea.has_value() || term->branch_target == *exit_ea)) {
                            lnode->cond = negate_cond(c);
                            dst.push_back(lnode);
                            cur_opt = term->branch_target;
                            continue;
                        }
                        // General multi-block loop header branch (always exact for BTCLR!)
                        if (!term->btclr_clear && lp.body.count(term->branch_target) && !lp.body.count(term->fallthrough)) {
                            auto bif = make_snode(SNodeKind::BreakIf, term->ea);
                            bif->cond = negate_cond(c);
                            lnode->then_body.push_back(bif);
                            if (term->branch_target != cur_ea) {
                                emit_region(term->branch_target, lp.body, std::nullopt, cur_ea, exit_ea, lnode->then_body);
                            }
                        } else if (lp.body.count(term->fallthrough) && !lp.body.count(term->branch_target)) {
                            auto bif = make_snode(SNodeKind::BreakIf, term->ea);
                            bif->cond = c;
                            attach_btclr(bif, *term);
                            lnode->then_body.push_back(bif);
                            if (term->fallthrough != cur_ea) {
                                emit_region(term->fallthrough, lp.body, std::nullopt, cur_ea, exit_ea, lnode->then_body);
                            }
                        } else {
                            auto ifn = make_snode(SNodeKind::If, term->ea);
                            ifn->cond = c;
                            attach_btclr(ifn, *term);
                            emit_region(term->branch_target, lp.body, std::nullopt, cur_ea, exit_ea, ifn->then_body);
                            emit_region(term->fallthrough, lp.body, std::nullopt, cur_ea, exit_ea, ifn->else_body);
                            lnode->then_body.push_back(ifn);
                        }
                    } else if (hdr_blk->term == TermKind::Fall || hdr_blk->term == TermKind::Goto) {
                        if (!hdr_blk->succ.empty()) {
                            uint32_t nxt = hdr_blk->succ[0].second;
                            if (nxt != cur_ea) emit_region(nxt, lp.body, std::nullopt, cur_ea, exit_ea, lnode->then_body);
                        }
                    }
                    dst.push_back(lnode);
                    if (exit_ea.has_value() && allowed.count(*exit_ea) && !emitted_blocks.count(*exit_ea)) {
                        cur_opt = exit_ea;
                        continue;
                    }
                    return;
                }

                // Regular non-loop block emission
                emitted_blocks.insert(cur_ea);
                auto lbl = make_snode(SNodeKind::Label, cur_ea);
                lbl->ea = cur_ea;
                dst.push_back(lbl);

                const auto &blk = func.blocks.at(cur_ea);
                if (blk->term == TermKind::Ret) {
                    emit_body_stmts(blk, dst, false);
                    return;
                }
                if (blk->term == TermKind::Goto) {
                    emit_body_stmts(blk, dst, true);
                    if (!blk->succ.empty()) {
                        cur_opt = blk->succ[0].second;
                        continue;
                    }
                    return;
                }
                if (blk->term == TermKind::Fall) {
                    emit_body_stmts(blk, dst, false);
                    if (!blk->succ.empty()) {
                        cur_opt = blk->succ[0].second;
                        continue;
                    }
                    return;
                }
                if (blk->term == TermKind::Switch) {
                    emit_body_stmts(blk, dst, true);
                    auto term = find_term_stmt(blk);
                    if (term && term->kind == StmtKind::Switch) {
                        auto sw = make_snode(SNodeKind::Switch, term->ea);
                        sw->switch_expr = term->expr;
                        std::map<uint32_t, std::vector<int64_t>> tgt_cases;
                        for (const auto &[cval, ctgt] : term->cases) {
                            if (ctgt.has_value()) tgt_cases[*ctgt].push_back(cval);
                        }
                        for (const auto &[ctgt, vals] : tgt_cases) {
                            SCase sc;
                            sc.vals = vals;
                            if (allowed.count(ctgt) && !emitted_blocks.count(ctgt)) {
                                emit_region(ctgt, allowed, stop_ea, loop_hdr, loop_exit, sc.body);
                            } else {
                                emit_goto_or_jumpout(ctgt, ctgt, sc.body);
                            }
                            sw->cases.push_back(std::move(sc));
                        }
                        if (term->default_ea.has_value()) {
                            sw->has_default = true;
                            if (allowed.count(*term->default_ea) && !emitted_blocks.count(*term->default_ea)) {
                                emit_region(*term->default_ea, allowed, stop_ea, loop_hdr, loop_exit, sw->default_body);
                            } else {
                                emit_goto_or_jumpout(*term->default_ea, *term->default_ea, sw->default_body);
                            }
                        }
                        dst.push_back(sw);
                    }
                    return;
                }
                if (blk->term == TermKind::Branch) {
                    emit_body_stmts(blk, dst, true);
                    auto term = find_term_stmt(blk);
                    if (!term || term->kind != StmtKind::Branch) return;
                    ExprPtr c = cond_expr(*term);
                    uint32_t t_ea = term->branch_target;
                    uint32_t f_ea = term->fallthrough;

                    // Immediate loop-exit branch inside a loop
                    if (loop_exit.has_value() && (t_ea == *loop_exit || f_ea == *loop_exit)) {
                        if (t_ea == *loop_exit) {
                            auto bif = make_snode(SNodeKind::BreakIf, term->ea);
                            attach_btclr(bif, *term);
                            bif->cond = c;
                            dst.push_back(bif);
                            cur_opt = f_ea;
                        } else if (term->btclr_clear) {
                            // Never invert BTCLR into BreakIf(!cond): clear on taken path, break on fallthrough
                            auto ifn = make_snode(SNodeKind::If, term->ea);
                            ifn->cond = c;
                            attach_btclr(ifn, *term);
                            ifn->else_body.push_back(make_snode(SNodeKind::Break, term->ea));
                            dst.push_back(ifn);
                            cur_opt = t_ea;
                        } else {
                            auto bif = make_snode(SNodeKind::BreakIf, term->ea);
                            bif->cond = negate_cond(c);
                            dst.push_back(bif);
                            cur_opt = t_ea;
                        }
                        continue;
                    }

                    // Find post-dominating merge block (simplest linear post-if continuation)
                    std::optional<uint32_t> merge_ea;
                    if (func.blocks.count(t_ea) && func.blocks.count(f_ea)) {
                        // Quick 1-step or 2-step diamond check
                        std::unordered_set<uint32_t> reach_t, reach_f;
                        auto collect_small = [&](uint32_t s_ea, std::unordered_set<uint32_t> &rset) {
                            std::vector<uint32_t> q = {s_ea};
                            for (int steps = 0; steps < 16 && !q.empty(); ++steps) {
                                uint32_t x = q.back(); q.pop_back();
                                if (!rset.insert(x).second || !func.blocks.count(x)) continue;
                                for (const auto &[h, nx] : func.blocks.at(x)->succ) q.push_back(nx);
                            }
                        };
                        collect_small(t_ea, reach_t);
                        collect_small(f_ea, reach_f);
                        if (reach_t.count(f_ea)) merge_ea = f_ea;
                        else if (reach_f.count(t_ea)) merge_ea = t_ea;
                        else {
                            uint32_t best = UINT32_MAX;
                            for (uint32_t x : reach_t) {
                                if (reach_f.count(x) && allowed.count(x) && x < best) best = x;
                            }
                            if (best != UINT32_MAX) merge_ea = best;
                        }
                    }

                    if (merge_ea.has_value() && *merge_ea == f_ea) {
                        // Simple `if (cond) { then_body }` followed by fallthrough
                        auto ifn = make_snode(SNodeKind::If, term->ea);
                        ifn->cond = c;
                        attach_btclr(ifn, *term);
                        emit_region(t_ea, allowed, f_ea, loop_hdr, loop_exit, ifn->then_body);
                        dst.push_back(ifn);
                        cur_opt = f_ea;
                        continue;
                    }
                    if (merge_ea.has_value() && *merge_ea == t_ea) {
                        if (term->btclr_clear) {
                            // Never invert BTCLR! Emit `if (cond) { bit &= ~mask; } else { else_body }` then merge at t_ea
                            auto ifn = make_snode(SNodeKind::If, term->ea);
                            ifn->cond = c;
                            attach_btclr(ifn, *term);
                            emit_region(f_ea, allowed, t_ea, loop_hdr, loop_exit, ifn->else_body);
                            dst.push_back(ifn);
                            cur_opt = t_ea;
                            continue;
                        }
                        // Inverted `if (!cond) { else_body }` followed by branch_target
                        auto ifn = make_snode(SNodeKind::If, term->ea);
                        ifn->cond = negate_cond(c);
                        emit_region(f_ea, allowed, t_ea, loop_hdr, loop_exit, ifn->then_body);
                        dst.push_back(ifn);
                        cur_opt = t_ea;
                        continue;
                    }

                    // Full if-then-else up to merge_ea (or function exit)
                    auto ifn = make_snode(SNodeKind::If, term->ea);
                    ifn->cond = c;
                    attach_btclr(ifn, *term);
                    emit_region(t_ea, allowed, merge_ea.has_value() ? merge_ea : stop_ea, loop_hdr, loop_exit, ifn->then_body);
                    emit_region(f_ea, allowed, merge_ea.has_value() ? merge_ea : stop_ea, loop_hdr, loop_exit, ifn->else_body);
                    dst.push_back(ifn);
                    if (merge_ea.has_value() && (!stop_ea.has_value() || *merge_ea != *stop_ea)) {
                        cur_opt = *merge_ea;
                        continue;
                    }
                    return;
                }
                return;
            }
        };

    std::set<uint32_t> all_blocks;
    for (const auto &b : order) all_blocks.insert(b->start);

    emit_region(func.entry, all_blocks, std::nullopt, std::nullopt, std::nullopt, out);

    // Emit any remaining reachable/unemitted blocks (e.g. jump tables / disjoint tails)
    for (const auto &b : order) {
        if (!emitted_blocks.count(b->start)) {
            emit_region(b->start, all_blocks, std::nullopt, std::nullopt, std::nullopt, out);
        }
    }

    // Prune unused SNodeKind::Label nodes so linear code stays clean
    std::function<void(std::vector<SNodePtr> &)> prune_labels = [&](std::vector<SNodePtr> &list) {
        std::vector<SNodePtr> kept;
        kept.reserve(list.size());
        for (auto &nnode : list) {
            if (nnode->kind == SNodeKind::Label && !referenced_labels.count(nnode->ea)) continue;
            prune_labels(nnode->then_body);
            prune_labels(nnode->else_body);
            for (auto &sc : nnode->cases) prune_labels(sc.body);
            prune_labels(nnode->default_body);
            kept.push_back(std::move(nnode));
        }
        list.swap(kept);
    };
    prune_labels(out);

    return out;
}

} // namespace rl78dec
