#include "rl78dec/spill.hpp"

#include <unordered_map>
#include <unordered_set>

namespace rl78dec {

namespace {

bool is_sp_add_const(const Stmt &s, int *out_val = nullptr) {
    if (s.kind != StmtKind::Assign || !s.dst || !s.src) return false;
    if (s.dst->kind != ExprKind::Reg || s.dst->name != "sp") return false;
    if (s.src->kind != ExprKind::Bin || s.src->op != "+") return false;
    if (!s.src->l || s.src->l->kind != ExprKind::Reg || s.src->l->name != "sp") return false;
    if (!s.src->r || s.src->r->kind != ExprKind::Const) return false;
    if (out_val) *out_val = static_cast<int>(s.src->r->value);
    return true;
}

std::pair<ExprPtr, std::vector<StmtPtr>> find_def_before(const std::vector<StmtPtr> &stmts,
                                                         size_t idx,
                                                         const std::string &reg_name) {
    auto [low_half, high_half] = pair_halves(reg_name);
    ExprPtr low_src, high_src;
    StmtPtr low_stmt, high_stmt;

    for (size_t j = idx; j > 0; --j) {
        const auto &s = stmts[j - 1];
        if (s->kind == StmtKind::Assign && s->dst && s->dst->kind == ExprKind::Reg) {
            if (s->dst->name == reg_name) {
                if (!low_src && !high_src) return {s->src, {s}};
                if (low_src && !high_src && s->src->kind == ExprKind::Const) {
                    high_src = Expr::make_const((s->src->value >> 8) & 0xFFu, Width::B);
                    high_stmt = s;
                    break;
                }
                if (high_src && !low_src && s->src->kind == ExprKind::Const) {
                    low_src = Expr::make_const(s->src->value & 0xFFu, Width::B);
                    low_stmt = s;
                    break;
                }
            }
            if (!low_half.empty() && s->dst->name == low_half && !low_src) {
                low_src = s->src;
                low_stmt = s;
            }
            if (!high_half.empty() && s->dst->name == high_half && !high_src) {
                high_src = s->src;
                high_stmt = s;
            }
            if (low_src && (high_src || high_half.empty())) break;
        } else if (s->kind == StmtKind::Call || s->kind == StmtKind::Ret ||
                   s->kind == StmtKind::Branch || s->kind == StmtKind::Goto) {
            break;
        }
    }

    if (low_src && high_src) {
        std::vector<StmtPtr> found;
        if (low_stmt) found.push_back(low_stmt);
        if (high_stmt) found.push_back(high_stmt);
        if (low_src->kind == ExprKind::Const && high_src->kind == ExprKind::Const) {
            uint32_t combined = ((high_src->value & 0xFFu) << 8) | (low_src->value & 0xFFu);
            return {Expr::make_const(combined, Width::W), found};
        }
        return {low_src, found};
    }
    if (low_src) return {low_src, {low_stmt}};
    if (high_src) return {high_src, {high_stmt}};
    return {nullptr, {}};
}

} // namespace

std::pair<int, StmtPtr> find_call_cleanup(const Function &func, const Block &b, size_t call_idx) {
    for (size_t k = call_idx + 1; k < b.stmts.size(); ++k) {
        int val = 0;
        if (is_sp_add_const(*b.stmts[k], &val)) return {val, b.stmts[k]};
        StmtKind sk = b.stmts[k]->kind;
        if (sk == StmtKind::Call || sk == StmtKind::Ret || sk == StmtKind::Branch || sk == StmtKind::Goto) {
            return {0, nullptr};
        }
    }
    if (b.succ.size() == 1 && b.succ[0].first == "fall") {
        auto sit = func.blocks.find(b.succ[0].second);
        if (sit != func.blocks.end()) {
            for (const auto &nxt : sit->second->stmts) {
                int val = 0;
                if (is_sp_add_const(*nxt, &val)) return {val, nxt};
                StmtKind sk = nxt->kind;
                if (sk == StmtKind::Call || sk == StmtKind::Ret || sk == StmtKind::Branch || sk == StmtKind::Goto) {
                    return {0, nullptr};
                }
            }
        }
    }
    return {0, nullptr};
}

void eliminate_spills(Function &func, FrameInfo &frame_info) {
    auto &hidden = frame_info.hidden_stmts;

    // Pass 1: Identify caller-pushed stack arguments cleaned up by addw sp, #N
    for (const auto &[bid, b] : func.blocks) {
        auto &stmts = b->stmts;
        for (size_t i = 0; i < stmts.size(); ++i) {
            if (stmts[i]->kind != StmtKind::Call) continue;
            auto [cleanup_bytes, cleanup_stmt] = find_call_cleanup(func, *b, i);
            if (cleanup_bytes > 0 && cleanup_stmt) {
                hidden.insert(cleanup_stmt->id);
                int expected_pushes = cleanup_bytes / 2;
                std::vector<ExprPtr> found_pushes;
                for (size_t j = i; j > 0 && static_cast<int>(found_pushes.size()) < expected_pushes; --j) {
                    const auto &prev = stmts[j - 1];
                    if (hidden.count(prev->id)) continue;
                    if (prev->kind == StmtKind::Intrinsic && prev->name == "push" && !prev->args.empty()) {
                        ExprPtr arg_val = prev->args[0];
                        if (arg_val->kind == ExprKind::Reg) {
                            auto [def_src, def_stmts] = find_def_before(stmts, j - 1, arg_val->name);
                            if (def_src) {
                                arg_val = def_src;
                                for (const auto &ds : def_stmts) hidden.insert(ds->id);
                            }
                        }
                        found_pushes.push_back(arg_val);
                        hidden.insert(prev->id);
                    } else if (prev->kind == StmtKind::Call || prev->kind == StmtKind::Ret ||
                               prev->kind == StmtKind::Branch || prev->kind == StmtKind::Goto) {
                        break;
                    }
                }
                for (const auto &pv : found_pushes) stmts[i]->args.push_back(pv);
            }
        }
    }

    // Pass 2: Simulate remaining pushes/pops as virtual spill variables (_sN)
    std::unordered_map<uint32_t, std::vector<ExprPtr>> in_stack;
    in_stack[func.entry] = frame_info.initial_spill_stack;
    int spill_cnt = 0;

    auto order = func.ordered();
    std::unordered_set<uint32_t> visited;
    std::vector<uint32_t> worklist;
    if (!order.empty()) worklist.push_back(order[0]->start);

    while (!worklist.empty()) {
        uint32_t b_ea = worklist.front();
        worklist.erase(worklist.begin());
        auto bit = func.blocks.find(b_ea);
        if (bit == func.blocks.end()) continue;
        visited.insert(b_ea);
        auto b = bit->second;

        std::vector<ExprPtr> stk = in_stack[b->start];
        std::vector<StmtPtr> new_stmts;
        new_stmts.reserve(b->stmts.size());

        for (const auto &s : b->stmts) {
            if (hidden.count(s->id)) {
                new_stmts.push_back(s);
                continue;
            }
            if (s->kind == StmtKind::Intrinsic && s->name == "push" && !s->args.empty()) {
                ExprPtr arg = s->args[0];
                auto var = Expr::make_var("_s" + std::to_string(spill_cnt++), arg->width);
                stk.push_back(var);
                new_stmts.push_back(make_assign(s->ea, var, arg));
            } else if (s->kind == StmtKind::Intrinsic && s->name == "pop" && !s->args.empty()) {
                if (!stk.empty()) {
                    ExprPtr var = stk.back();
                    stk.pop_back();
                    new_stmts.push_back(make_assign(s->ea, s->args[0], var));
                } else {
                    ExprPtr mem_sp = Expr::make_mem_addr(Expr::make_reg("sp"), s->args[0]->width);
                    new_stmts.push_back(make_assign(s->ea, s->args[0], mem_sp));
                    new_stmts.push_back(make_assign(
                        s->ea,
                        Expr::make_reg("sp"),
                        Expr::make_bin("+", Expr::make_reg("sp"), Expr::make_const(2, Width::W), Width::W)));
                }
            } else {
                int add_val = 0;
                if (is_sp_add_const(*s, &add_val)) {
                    int cleanup_words = add_val / 2;
                    for (int c = 0; c < cleanup_words && !stk.empty(); ++c) stk.pop_back();
                }
                new_stmts.push_back(s);
            }
        }
        b->stmts = std::move(new_stmts);

        for (const auto &[how, succ_ea] : b->succ) {
            if (!func.blocks.count(succ_ea)) continue;
            auto iit = in_stack.find(succ_ea);
            if (iit == in_stack.end()) {
                in_stack[succ_ea] = stk;
                if (!visited.count(succ_ea)) worklist.push_back(succ_ea);
            } else if (stk.size() < iit->second.size()) {
                iit->second = stk;
            }
        }
    }
}

} // namespace rl78dec
