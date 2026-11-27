#include "rl78dec/frame.hpp"

#include <algorithm>
#include <cstdio>
#include <functional>
#include <unordered_map>
#include <unordered_set>

namespace rl78dec {

namespace {

bool is_push_reg(const Stmt &s) {
    if (s.kind != StmtKind::Intrinsic || s.name != "push" || s.args.empty()) return false;
    if (s.args[0]->kind != ExprKind::Reg) return false;
    const std::string &rn = s.args[0]->name;
    return rn == "hl" || rn == "de" || rn == "bc" || rn == "ax" || rn == "psw";
}

bool is_pop_reg(const Stmt &s) {
    if (s.kind != StmtKind::Intrinsic || s.name != "pop" || s.args.empty()) return false;
    if (s.args[0]->kind != ExprKind::Reg) return false;
    const std::string &rn = s.args[0]->name;
    return rn == "hl" || rn == "de" || rn == "bc" || rn == "ax" || rn == "psw";
}

bool is_sub_sp(const Stmt &s, int *out_imm = nullptr) {
    if (s.kind != StmtKind::Assign || !s.dst || !s.src) return false;
    if (s.dst->kind != ExprKind::Reg || s.dst->name != "sp") return false;
    if (s.src->kind != ExprKind::Bin || s.src->op != "-") return false;
    if (!s.src->l || s.src->l->kind != ExprKind::Reg || s.src->l->name != "sp") return false;
    if (!s.src->r || s.src->r->kind != ExprKind::Const) return false;
    if (out_imm) *out_imm = static_cast<int>(s.src->r->value);
    return true;
}

bool is_add_sp(const Stmt &s) {
    if (s.kind != StmtKind::Assign || !s.dst || !s.src) return false;
    if (s.dst->kind != ExprKind::Reg || s.dst->name != "sp") return false;
    if (s.src->kind != ExprKind::Bin || s.src->op != "+") return false;
    if (!s.src->l || s.src->l->kind != ExprKind::Reg || s.src->l->name != "sp") return false;
    if (!s.src->r || s.src->r->kind != ExprKind::Const) return false;
    return true;
}

bool is_mov_hl_sp(const Stmt &s) {
    return s.kind == StmtKind::Assign && s.dst && s.src &&
           s.dst->kind == ExprKind::Reg && s.dst->name == "hl" &&
           s.src->kind == ExprKind::Reg && s.src->name == "sp";
}

bool is_mov_ax_sp(const Stmt &s) {
    return s.kind == StmtKind::Assign && s.dst && s.src &&
           s.dst->kind == ExprKind::Reg && s.dst->name == "ax" &&
           s.src->kind == ExprKind::Reg && s.src->name == "sp";
}

bool is_mov_hl_ax(const Stmt &s) {
    return s.kind == StmtKind::Assign && s.dst && s.src &&
           s.dst->kind == ExprKind::Reg && s.dst->name == "hl" &&
           s.src->kind == ExprKind::Reg && s.src->name == "ax";
}

AtomMask expr_used_ax_atoms(const ExprPtr &e) {
    if (!e) return 0;
    AtomMask m = 0;
    if (e->kind == ExprKind::Reg) return reg_atoms_named(e->name) & (atom::A | atom::X);
    if (e->kind == ExprKind::Bin) return expr_used_ax_atoms(e->l) | expr_used_ax_atoms(e->r);
    if (e->kind == ExprKind::Un) return expr_used_ax_atoms(e->l);
    if (e->kind == ExprKind::Bit) return expr_used_ax_atoms(e->base);
    if (e->kind == ExprKind::Mem && !e->has_static_addr) return expr_used_ax_atoms(e->addr);
    if (e->kind == ExprKind::Intr) {
        for (const auto &a : e->args) m |= expr_used_ax_atoms(a);
    }
    return m;
}

bool is_ax_dead_after_in_cfg(const Function &func, uint32_t start_bid, size_t after_idx, bool has_frame_or_push) {
    std::unordered_map<uint32_t, AtomMask> visited;
    std::function<bool(uint32_t, size_t, AtomMask)> dfs = [&](uint32_t bid, size_t start_k, AtomMask live_need) -> bool {
        if (live_need == 0) return true;
        auto bit = func.blocks.find(bid);
        if (bit == func.blocks.end()) return true;
        const Block &b = *bit->second;
        for (size_t k = start_k; k < b.stmts.size(); ++k) {
            const auto &st = b.stmts[k];
            AtomMask read_m = 0;
            if (st->kind == StmtKind::Assign) {
                read_m |= expr_used_ax_atoms(st->src);
                if (st->dst && st->dst->kind != ExprKind::Reg) read_m |= expr_used_ax_atoms(st->dst);
                if (read_m & live_need) return false;
                if (st->dst && st->dst->kind == ExprKind::Reg) {
                    live_need &= ~reg_atoms_named(st->dst->name);
                    if (live_need == 0) return true;
                }
            } else if (st->kind == StmtKind::Compare) {
                if (st->z_flag) read_m |= expr_used_ax_atoms(st->z_flag->a) | expr_used_ax_atoms(st->z_flag->b);
                if (st->cy_flag) read_m |= expr_used_ax_atoms(st->cy_flag->a) | expr_used_ax_atoms(st->cy_flag->b);
                if (read_m & live_need) return false;
            } else if (st->kind == StmtKind::Branch) {
                if (st->has_bittest) read_m |= expr_used_ax_atoms(st->bittest_expr);
                if (st->z_flag) read_m |= expr_used_ax_atoms(st->z_flag->a) | expr_used_ax_atoms(st->z_flag->b);
                if (st->cy_flag) read_m |= expr_used_ax_atoms(st->cy_flag->a) | expr_used_ax_atoms(st->cy_flag->b);
                if (read_m & live_need) return false;
            } else if (st->kind == StmtKind::Switch) {
                if (expr_used_ax_atoms(st->expr) & live_need) return false;
            } else if (st->kind == StmtKind::Swap) {
                read_m |= expr_used_ax_atoms(st->a) | expr_used_ax_atoms(st->b);
                if (read_m & live_need) return false;
            } else if (st->kind == StmtKind::Intrinsic) {
                if (st->name == "pop" && !st->args.empty() && st->args[0]->kind == ExprKind::Reg) {
                    live_need &= ~reg_atoms_named(st->args[0]->name);
                    if (live_need == 0) return true;
                } else {
                    for (const auto &a : st->args) read_m |= expr_used_ax_atoms(a);
                    if (read_m & live_need) return false;
                }
            } else if (st->kind == StmtKind::Call) {
                return false;
            } else if (st->kind == StmtKind::Ret) {
                return has_frame_or_push;
            }
        }
        for (const auto &[how, succ_ea] : b.succ) {
            AtomMask prev = visited[succ_ea];
            AtomMask next_need = live_need & ~prev;
            if (next_need == 0) continue;
            visited[succ_ea] = prev | next_need;
            if (!dfs(succ_ea, 0, next_need)) return false;
        }
        return true;
    };
    return dfs(start_bid, after_idx + 1, atom::A | atom::X);
}

struct PrologueScan {
    std::string fp_reg;
    int frame_size = 0;
    int fp_bias = 0;
    std::vector<std::string> saved_regs;
    std::vector<StmtPtr> stmts;
};

PrologueScan scan_block_prologue(const Function &func, const Block &b,
                                 const std::unordered_set<std::string> &popped_regs) {
    PrologueScan out;
    int cur_depth = 0;
    std::optional<int> ax_sp_depth;
    StmtPtr ax_sp_stmt;
    std::optional<int> fp_depth;
    AtomMask written_gprs = 0;
    bool seen_reg_setup = false;

    for (size_t idx = 0; idx < b.stmts.size(); ++idx) {
        const auto &s = b.stmts[idx];
        int sub_imm = 0;
        if (is_push_reg(*s)) {
            const std::string &rn = s->args[0]->name;
            if (!seen_reg_setup) {
                out.saved_regs.push_back(rn);
                out.stmts.push_back(s);
                cur_depth += 2;
            } else if ((rn == "hl" || rn == "de" || rn == "psw") &&
                       popped_regs.count(rn) &&
                       (reg_atoms_named(rn) & written_gprs) == 0 &&
                       std::find(out.saved_regs.begin(), out.saved_regs.end(), rn) == out.saved_regs.end()) {
                out.saved_regs.push_back(rn);
                out.stmts.push_back(s);
                cur_depth += 2;
            } else {
                break;
            }
        } else if (is_sub_sp(*s, &sub_imm)) {
            out.frame_size += sub_imm;
            out.stmts.push_back(s);
            cur_depth += sub_imm;
        } else if (is_mov_hl_sp(*s)) {
            out.fp_reg = "hl";
            fp_depth = cur_depth;
            out.stmts.push_back(s);
            break;
        } else if (is_mov_ax_sp(*s)) {
            ax_sp_depth = cur_depth;
            ax_sp_stmt = s;
            written_gprs |= (atom::A | atom::X);
            seen_reg_setup = true;
        } else if (is_mov_hl_ax(*s) && ax_sp_depth.has_value()) {
            out.fp_reg = "hl";
            fp_depth = *ax_sp_depth;
            bool has_fp_or_push = (!out.saved_regs.empty() || out.frame_size > 0);
            if (ax_sp_stmt && is_ax_dead_after_in_cfg(func, b.start, idx, has_fp_or_push)) {
                out.stmts.push_back(ax_sp_stmt);
            }
            out.stmts.push_back(s);
            break;
        } else if (s->kind == StmtKind::Assign && s->dst && s->src &&
                   s->dst->kind == ExprKind::Reg && s->src->kind == ExprKind::Reg &&
                   s->dst->name != "sp" && s->src->name != "sp") {
            AtomMask dm = reg_atoms_named(s->dst->name);
            written_gprs |= dm;
            if (dm & (atom::A | atom::X)) {
                ax_sp_depth = std::nullopt;
                ax_sp_stmt = nullptr;
            }
            seen_reg_setup = true;
        } else {
            break;
        }
    }
    int total_depth = out.frame_size + static_cast<int>(out.saved_regs.size()) * 2;
    if (out.fp_reg == "hl" && fp_depth.has_value()) {
        out.fp_bias = total_depth - *fp_depth;
    } else if (out.fp_reg.empty() && out.frame_size > 0) {
        out.fp_reg = "sp";
        out.fp_bias = 0;
    }
    return out;
}

std::vector<StmtPtr> scan_epilogues(const Function &func) {
    std::vector<StmtPtr> out;
    for (const auto &[bid, b] : func.blocks) {
        if (b->stmts.empty() || b->stmts.back()->kind != StmtKind::Ret) continue;
        bool has_add_sp = false;
        for (size_t idx = b->stmts.size() - 1; idx > 0; --idx) {
            const auto &s = b->stmts[idx - 1];
            if (is_pop_reg(*s)) {
                out.push_back(s);
            } else if (is_add_sp(*s)) {
                if (!has_add_sp) {
                    out.push_back(s);
                    has_add_sp = true;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }
    return out;
}

std::optional<int64_t> get_mem_disp(const ExprPtr &e, const std::string &fp_reg, int64_t bias = 0) {
    if (!e || e->kind != ExprKind::Mem || e->es || e->has_static_addr || !e->addr) return std::nullopt;
    if (e->addr->kind == ExprKind::Reg && e->addr->name == fp_reg) return bias;
    if (e->addr->kind == ExprKind::Bin && e->addr->op == "+" &&
        e->addr->l && e->addr->l->kind == ExprKind::Reg && e->addr->l->name == fp_reg &&
        e->addr->r && e->addr->r->kind == ExprKind::Const) {
        return static_cast<int64_t>(e->addr->r->value) + bias;
    }
    return std::nullopt;
}

bool expr_reads_disp(const ExprPtr &e, const std::string &fp_reg, int64_t fp_bias, int64_t target_disp) {
    if (!e) return false;
    if (auto d = get_mem_disp(e, fp_reg, fp_bias); d.has_value()) {
        if (*d >= target_disp && *d < target_disp + 2) return true;
    }
    if (fp_reg != "sp") {
        if (auto d2 = get_mem_disp(e, "sp", 0); d2.has_value()) {
            if (*d2 >= target_disp && *d2 < target_disp + 2) return true;
        }
    }
    switch (e->kind) {
        case ExprKind::Bin:
            return expr_reads_disp(e->l, fp_reg, fp_bias, target_disp) ||
                   expr_reads_disp(e->r, fp_reg, fp_bias, target_disp);
        case ExprKind::Un:
            return expr_reads_disp(e->l, fp_reg, fp_bias, target_disp);
        case ExprKind::Bit:
            return expr_reads_disp(e->base, fp_reg, fp_bias, target_disp);
        case ExprKind::Intr:
            for (const auto &a : e->args) if (expr_reads_disp(a, fp_reg, fp_bias, target_disp)) return true;
            return false;
        case ExprKind::Mem:
            return !e->has_static_addr && expr_reads_disp(e->addr, fp_reg, fp_bias, target_disp);
        default:
            return false;
    }
}

bool is_disp_read_before_write(const Function &func, const std::string &fp_reg, int64_t fp_bias, int64_t target_disp) {
    std::string eff_fp = fp_reg.empty() ? "sp" : fp_reg;
    int64_t eff_bias = fp_reg.empty() ? 0 : fp_bias;
    for (const auto &b : func.ordered()) {
        for (const auto &s : b->stmts) {
            if (s->kind == StmtKind::Assign) {
                if (expr_reads_disp(s->src, eff_fp, eff_bias, target_disp)) return true;
                if (auto d = get_mem_disp(s->dst, eff_fp, eff_bias); d.has_value()) {
                    if (*d >= target_disp && *d < target_disp + 2 && s->dst->width == Width::W) return false;
                }
                if (s->dst && s->dst->kind == ExprKind::Mem && !s->dst->has_static_addr &&
                    expr_reads_disp(s->dst->addr, eff_fp, eff_bias, target_disp)) {
                    return true;
                }
            } else if (s->kind == StmtKind::Compare) {
                if (s->z_flag && (expr_reads_disp(s->z_flag->a, eff_fp, eff_bias, target_disp) ||
                                  expr_reads_disp(s->z_flag->b, eff_fp, eff_bias, target_disp))) return true;
                if (s->cy_flag && (expr_reads_disp(s->cy_flag->a, eff_fp, eff_bias, target_disp) ||
                                   expr_reads_disp(s->cy_flag->b, eff_fp, eff_bias, target_disp))) return true;
            } else if (s->kind == StmtKind::Call) {
                for (const auto &a : s->args) if (expr_reads_disp(a, eff_fp, eff_bias, target_disp)) return true;
            } else if (s->kind == StmtKind::Ret) {
                if (expr_reads_disp(s->val, eff_fp, eff_bias, target_disp)) return true;
            } else if (s->kind == StmtKind::Branch) {
                if (s->has_bittest && expr_reads_disp(s->bittest_expr, eff_fp, eff_bias, target_disp)) return true;
                if (s->z_flag && (expr_reads_disp(s->z_flag->a, eff_fp, eff_bias, target_disp) ||
                                  expr_reads_disp(s->z_flag->b, eff_fp, eff_bias, target_disp))) return true;
                if (s->cy_flag && (expr_reads_disp(s->cy_flag->a, eff_fp, eff_bias, target_disp) ||
                                   expr_reads_disp(s->cy_flag->b, eff_fp, eff_bias, target_disp))) return true;
            } else if (s->kind == StmtKind::Switch) {
                if (expr_reads_disp(s->expr, eff_fp, eff_bias, target_disp)) return true;
            } else if (s->kind == StmtKind::Intrinsic) {
                for (const auto &a : s->args) if (expr_reads_disp(a, eff_fp, eff_bias, target_disp)) return true;
            }
        }
    }
    return false;
}

} // namespace

FrameInfo analyze_frame(Function &func, const IdaFrameInfo *ida_frame) {
    FrameInfo info;

    auto epilogue_stmts = scan_epilogues(func);
    std::unordered_set<std::string> popped_regs;
    for (const auto &s : epilogue_stmts) {
        if (is_pop_reg(*s)) popped_regs.insert(s->args[0]->name);
    }

    std::vector<StmtPtr> prologue_stmts;
    auto entry_it = func.blocks.find(func.entry);
    if (entry_it != func.blocks.end()) {
        PrologueScan ps = scan_block_prologue(func, *entry_it->second, popped_regs);
        if (ps.stmts.empty() && entry_it->second->succ.size() == 2) {
            uint32_t fall_ea = entry_it->second->succ[1].second;
            auto fit = func.blocks.find(fall_ea);
            if (fit != func.blocks.end()) ps = scan_block_prologue(func, *fit->second, popped_regs);
        }
        if (ps.fp_reg.empty()) {
            for (const auto &[bid, b] : func.blocks) {
                for (size_t i = 0; i < b->stmts.size(); ++i) {
                    if (is_mov_hl_sp(*b->stmts[i])) {
                        ps.fp_reg = "hl";
                        ps.stmts.push_back(b->stmts[i]);
                        int sub_imm = 0;
                        if (i > 0 && is_sub_sp(*b->stmts[i - 1], &sub_imm)) {
                            ps.frame_size += sub_imm;
                            ps.stmts.push_back(b->stmts[i - 1]);
                        }
                        break;
                    }
                }
                if (!ps.fp_reg.empty()) break;
            }
        }
        info.fp_reg = ps.fp_reg;
        info.frame_size = ps.frame_size;
        info.fp_bias = ps.fp_bias;
        info.saved_regs = ps.saved_regs;
        prologue_stmts = ps.stmts;
        if (!info.fp_reg.empty() || info.frame_size > 0 || !info.saved_regs.empty()) {
            info.has_frame = true;
        }
    }

    int total_pushed_bytes = static_cast<int>(info.saved_regs.size()) * 2;
    int arg_base = info.frame_size + total_pushed_bytes + 4;

    bool any_ret = false;
    bool all_isr = true;
    for (const auto &[bid, b] : func.blocks) {
        for (const auto &s : b->stmts) {
            if (s->kind == StmtKind::Ret) {
                any_ret = true;
                if (s->ret_kind != "reti" && s->ret_kind != "retb") all_isr = false;
            }
        }
    }
    info.is_isr = any_ret && all_isr;

    std::string eff_fp = info.fp_reg.empty() ? "sp" : info.fp_reg;
    int64_t eff_bias = info.fp_reg.empty() ? 0 : info.fp_bias;

    std::vector<std::string> true_saved;
    for (size_t i = 0; i < info.saved_regs.size(); ++i) {
        const std::string &r = info.saved_regs[i];
        int64_t disp = static_cast<int64_t>(info.frame_size) +
                       static_cast<int64_t>(info.saved_regs.size() - 1 - i) * 2;
        if (r == "hl" || r == "de" || r == "psw") {
            true_saved.push_back(r);
        } else if (info.is_isr && (r == "ax" || r == "bc") && popped_regs.count(r)) {
            true_saved.push_back(r);
        } else if (r == "ax") {
            if (is_disp_read_before_write(func, info.fp_reg, info.fp_bias, disp)) {
                bool lo_or_word_read = false;
                std::function<void(const ExprPtr &)> scan_lo = [&](const ExprPtr &e) {
                    if (!e || lo_or_word_read) return;
                    if (auto d = get_mem_disp(e, eff_fp, eff_bias); d.has_value() && *d == disp) {
                        lo_or_word_read = true;
                        return;
                    }
                    if (eff_fp != "sp") {
                        if (auto ds = get_mem_disp(e, "sp", 0); ds.has_value() && *ds == disp) {
                            lo_or_word_read = true;
                            return;
                        }
                    }
                    if (e->kind == ExprKind::Bin) { scan_lo(e->l); scan_lo(e->r); }
                    else if (e->kind == ExprKind::Un) { scan_lo(e->l); }
                    else if (e->kind == ExprKind::Bit) { scan_lo(e->base); }
                    else if (e->kind == ExprKind::Intr) { for (const auto &a : e->args) scan_lo(a); }
                    else if (e->kind == ExprKind::Mem && !e->has_static_addr) { scan_lo(e->addr); }
                };
                for (const auto &[bid2, b2] : func.blocks) {
                    for (const auto &s2 : b2->stmts) {
                        scan_lo(s2->dst); scan_lo(s2->src); scan_lo(s2->a); scan_lo(s2->b);
                        scan_lo(s2->val); scan_lo(s2->expr); scan_lo(s2->bittest_expr);
                        for (const auto &a2 : s2->args) scan_lo(a2);
                        if (s2->z_flag) { scan_lo(s2->z_flag->a); scan_lo(s2->z_flag->b); }
                        if (s2->cy_flag) { scan_lo(s2->cy_flag->a); scan_lo(s2->cy_flag->b); }
                    }
                }
                if (lo_or_word_read) {
                    if (std::find(info.homed_args.begin(), info.homed_args.end(), "ax") == info.homed_args.end()) {
                        info.homed_args.push_back("ax");
                    }
                    info.homed_slot_to_arg[disp] = "a0";
                    info.homed_word_slots[disp] = "a0";
                    auto sv = Expr::make_stack_var("a0", Width::W, disp, true);
                    info.args["a0"] = FrameInfo::VarDecl{sv, Width::W};
                    info.initial_spill_stack.push_back(sv);
                } else {
                    if (std::find(info.homed_args.begin(), info.homed_args.end(), "a") == info.homed_args.end()) {
                        info.homed_args.push_back("a");
                    }
                    info.homed_slot_to_arg[disp + 1] = "a0";
                    auto sv = Expr::make_stack_var("a0", Width::B, disp + 1, true);
                    info.args["a0"] = FrameInfo::VarDecl{sv, Width::B};
                    info.initial_spill_stack.push_back(
                        Expr::make_bin("<<", Expr::make_un("u16", sv, Width::W), Expr::make_const(8, Width::B), Width::W));
                }
            } else {
                info.initial_spill_stack.push_back(Expr::make_const(0, Width::W));
            }
        } else if (r == "bc") {
            if (is_disp_read_before_write(func, info.fp_reg, info.fp_bias, disp)) {
                if (std::find(info.homed_args.begin(), info.homed_args.end(), "bc") == info.homed_args.end()) {
                    info.homed_args.push_back("bc");
                }
                info.homed_slot_to_arg[disp] = "a1";
                info.homed_word_slots[disp] = "a1";
                auto sv = Expr::make_stack_var("a1", Width::W, disp, true);
                info.args["a1"] = FrameInfo::VarDecl{sv, Width::W};
                info.initial_spill_stack.push_back(sv);
            } else if (popped_regs.count(r) && info.homed_args.empty()) {
                true_saved.push_back(r);
            } else {
                info.initial_spill_stack.push_back(Expr::make_const(0, Width::W));
            }
        }
    }
    info.saved_regs = std::move(true_saved);
    info.arg_base = arg_base;
    info.prologue_pushes = info.saved_regs;

    std::unordered_set<std::string> hidden_pop_allowed(info.saved_regs.begin(), info.saved_regs.end());
    for (const auto &s : prologue_stmts) info.hidden_stmts.insert(s->id);
    for (const auto &s : epilogue_stmts) {
        if (is_pop_reg(*s)) {
            if (hidden_pop_allowed.count(s->args[0]->name)) {
                info.hidden_stmts.insert(s->id);
            }
        } else {
            info.hidden_stmts.insert(s->id);
        }
    }

    int frsize = info.frame_size;
    auto record_stack_var = [&](const ExprPtr &sv, Width w) {
        auto &map_ref = sv->is_arg ? info.args : info.locals;
        auto it = map_ref.find(sv->name);
        Width final_w = (w == Width::W || (it != map_ref.end() && it->second.width == Width::W))
                            ? Width::W
                            : Width::B;
        sv->width = final_w;
        map_ref[sv->name] = FrameInfo::VarDecl{sv, final_w};
    };

    auto resolve_rval_disp = [&](int64_t disp, Width w) -> ExprPtr {
        if (auto wit = info.homed_word_slots.find(disp); wit != info.homed_word_slots.end()) {
            auto sv = Expr::make_stack_var(wit->second, Width::W, disp, true);
            record_stack_var(sv, Width::W);
            if (w == Width::W) return sv;
            return Expr::make_bin("&", sv, Expr::make_const(0xFF, Width::B), Width::B);
        }
        if (w == Width::B) {
            if (auto hi_it = info.homed_word_slots.find(disp - 1); hi_it != info.homed_word_slots.end()) {
                auto sv = Expr::make_stack_var(hi_it->second, Width::W, disp - 1, true);
                record_stack_var(sv, Width::W);
                return Expr::make_bin("&",
                                      Expr::make_bin(">>", sv, Expr::make_const(8, Width::B), Width::W),
                                      Expr::make_const(0xFF, Width::B),
                                      Width::B);
            }
        }
        if (auto it = info.homed_slot_to_arg.find(disp); it != info.homed_slot_to_arg.end()) {
            auto sv = Expr::make_stack_var(it->second, w, disp, true);
            record_stack_var(sv, w);
            return sv;
        }
        char buf[32];
        if (disp >= arg_base) {
            std::snprintf(buf, sizeof(buf), "arg_%llX", static_cast<unsigned long long>(disp - arg_base));
            auto sv = Expr::make_stack_var(buf, w, disp, true);
            record_stack_var(sv, w);
            return sv;
        }
        if (disp < frsize) {
            std::snprintf(buf, sizeof(buf), "var_%llX", static_cast<unsigned long long>(frsize - disp));
            auto sv = Expr::make_stack_var(buf, w, disp, false);
            record_stack_var(sv, w);
            return sv;
        }
        std::snprintf(buf, sizeof(buf), "var_s%llX", static_cast<unsigned long long>(disp - frsize));
        auto sv = Expr::make_stack_var(buf, w, disp, false);
        record_stack_var(sv, w);
        return sv;
    };

    std::function<ExprPtr(const ExprPtr &, uint32_t, bool)> repl = [&](const ExprPtr &e, uint32_t ea, bool is_lval) -> ExprPtr {
        if (!e) return nullptr;
        if (e->kind == ExprKind::Mem && !e->es && !e->has_static_addr) {
            if (ida_frame && ida_frame->valid) {
                auto sit = ida_frame->stkvars_by_ea.find(ea);
                if (sit != ida_frame->stkvars_by_ea.end() && !sit->second.empty()) {
                    const IdaStkvarHit &hit = sit->second.begin()->second;
                    if (!is_lval && hit.size == 1) {
                        if (auto wit = info.homed_word_slots.find(hit.offset); wit != info.homed_word_slots.end()) {
                            auto sv = Expr::make_stack_var(wit->second, Width::W, hit.offset, true);
                            record_stack_var(sv, Width::W);
                            return Expr::make_bin("&", sv, Expr::make_const(0xFF, Width::B), Width::B);
                        }
                        if (auto hi_it = info.homed_word_slots.find(hit.offset - 1); hi_it != info.homed_word_slots.end()) {
                            auto sv = Expr::make_stack_var(hi_it->second, Width::W, hit.offset - 1, true);
                            record_stack_var(sv, Width::W);
                            return Expr::make_bin("&",
                                                  Expr::make_bin(">>", sv, Expr::make_const(8, Width::B), Width::W),
                                                  Expr::make_const(0xFF, Width::B),
                                                  Width::B);
                        }
                    }
                    std::string vname = hit.name;
                    bool is_arg = hit.is_arg;
                    if (auto hit_it = info.homed_slot_to_arg.find(hit.offset); hit_it != info.homed_slot_to_arg.end()) {
                        vname = hit_it->second;
                        is_arg = true;
                    }
                    Width w = (hit.size == 2 || info.homed_word_slots.count(hit.offset)) ? Width::W : Width::B;
                    auto v = Expr::make_stack_var(vname, w, hit.offset, is_arg);
                    record_stack_var(v, w);
                    return v;
                }
            }
            if (!info.fp_reg.empty()) {
                if (auto disp = get_mem_disp(e, info.fp_reg, info.fp_bias); disp.has_value()) {
                    if (!is_lval) return resolve_rval_disp(*disp, e->width);
                    if (auto wit = info.homed_word_slots.find(*disp); wit != info.homed_word_slots.end() && e->width == Width::W) {
                        auto sv = Expr::make_stack_var(wit->second, Width::W, *disp, true);
                        record_stack_var(sv, Width::W);
                        return sv;
                    }
                    if (!info.homed_word_slots.count(*disp) && !info.homed_word_slots.count(*disp - 1)) {
                        return resolve_rval_disp(*disp, e->width);
                    }
                }
            }
            if (info.fp_reg != "sp") {
                if (auto disp = get_mem_disp(e, "sp", 0); disp.has_value()) {
                    if (!is_lval) return resolve_rval_disp(*disp, e->width);
                    if (auto wit = info.homed_word_slots.find(*disp); wit != info.homed_word_slots.end() && e->width == Width::W) {
                        auto sv = Expr::make_stack_var(wit->second, Width::W, *disp, true);
                        record_stack_var(sv, Width::W);
                        return sv;
                    }
                    if (!info.homed_word_slots.count(*disp) && !info.homed_word_slots.count(*disp - 1)) {
                        return resolve_rval_disp(*disp, e->width);
                    }
                }
            }
            return Expr::make_mem_addr(repl(e->addr, ea, false), e->width, e->es, e->name, e->addr_is_linear);
        }
        switch (e->kind) {
            case ExprKind::Bin:
                return Expr::make_bin(e->op, repl(e->l, ea, false), repl(e->r, ea, false), e->width);
            case ExprKind::Un:
                return Expr::make_un(e->op, repl(e->l, ea, false), e->width);
            case ExprKind::Bit:
                return Expr::make_bit(repl(e->base, ea, false), e->bit);
            case ExprKind::Intr: {
                std::vector<ExprPtr> na;
                na.reserve(e->args.size());
                for (const auto &a : e->args) na.push_back(repl(a, ea, false));
                return Expr::make_intr(e->name, std::move(na), e->width);
            }
            default:
                return e;
        }
    };

    for (const auto &[bid, b] : func.blocks) {
        for (const auto &s : b->stmts) {
            if (s->kind == StmtKind::Assign) {
                s->src = repl(s->src, s->ea, false);
                // Handle byte-granular stores into a 16-bit homed word arg slot (`[fp+disp]` or `[fp+disp+1]`)
                bool handled_byte_lval = false;
                if (s->dst && s->dst->kind == ExprKind::Mem && !s->dst->es && !s->dst->has_static_addr &&
                    s->dst->width == Width::B) {
                    std::optional<int64_t> d_opt;
                    if (!info.fp_reg.empty()) d_opt = get_mem_disp(s->dst, info.fp_reg, info.fp_bias);
                    if (!d_opt.has_value() && info.fp_reg != "sp") d_opt = get_mem_disp(s->dst, "sp", 0);
                    if (d_opt.has_value()) {
                        if (auto lo_it = info.homed_word_slots.find(*d_opt); lo_it != info.homed_word_slots.end()) {
                            auto sv = Expr::make_stack_var(lo_it->second, Width::W, *d_opt, true);
                            record_stack_var(sv, Width::W);
                            s->dst = sv;
                            s->src = Expr::make_bin(
                                "|",
                                Expr::make_bin("&", expr_clone(sv), Expr::make_const(0xFF00u, Width::W), Width::W),
                                Expr::make_bin("&", Expr::make_un("u16", s->src, Width::W), Expr::make_const(0x00FFu, Width::W), Width::W),
                                Width::W);
                            handled_byte_lval = true;
                        } else if (auto hi_it = info.homed_word_slots.find(*d_opt - 1); hi_it != info.homed_word_slots.end()) {
                            auto sv = Expr::make_stack_var(hi_it->second, Width::W, *d_opt - 1, true);
                            record_stack_var(sv, Width::W);
                            s->dst = sv;
                            s->src = Expr::make_bin(
                                "|",
                                Expr::make_bin("&", expr_clone(sv), Expr::make_const(0x00FFu, Width::W), Width::W),
                                Expr::make_bin("<<", Expr::make_bin("&", Expr::make_un("u16", s->src, Width::W), Expr::make_const(0x00FFu, Width::W), Width::W), Expr::make_const(8, Width::B), Width::W),
                                Width::W);
                            handled_byte_lval = true;
                        }
                    }
                }
                if (!handled_byte_lval) {
                    s->dst = repl(s->dst, s->ea, true);
                }
                if (s->z_flag) {
                    s->z_flag->a = repl(s->z_flag->a, s->ea, false);
                    s->z_flag->b = repl(s->z_flag->b, s->ea, false);
                }
                if (s->cy_flag) {
                    s->cy_flag->a = repl(s->cy_flag->a, s->ea, false);
                    s->cy_flag->b = repl(s->cy_flag->b, s->ea, false);
                }
            } else if (s->kind == StmtKind::Compare) {
                if (s->z_flag) {
                    s->z_flag->a = repl(s->z_flag->a, s->ea, false);
                    s->z_flag->b = repl(s->z_flag->b, s->ea, false);
                }
                if (s->cy_flag) {
                    s->cy_flag->a = repl(s->cy_flag->a, s->ea, false);
                    s->cy_flag->b = repl(s->cy_flag->b, s->ea, false);
                }
            } else if (s->kind == StmtKind::Swap) {
                s->a = repl(s->a, s->ea, true);
                s->b = repl(s->b, s->ea, true);
            } else if (s->kind == StmtKind::Intrinsic) {
                for (auto &a : s->args) a = repl(a, s->ea, false);
            } else if (s->kind == StmtKind::Branch) {
                if (s->has_bittest) s->bittest_expr = repl(s->bittest_expr, s->ea, false);
            } else if (s->kind == StmtKind::Switch) {
                s->expr = repl(s->expr, s->ea, false);
            }
        }
    }

    std::function<void(const ExprPtr &)> sync_w = [&](const ExprPtr &e) {
        if (!e) return;
        if (e->kind == ExprKind::StackVar) {
            const auto &map_ref = e->is_arg ? info.args : info.locals;
            if (auto it = map_ref.find(e->name); it != map_ref.end() &&
                width_bytes(it->second.width) > width_bytes(e->width)) {
                e->width = it->second.width;
            }
            return;
        }
        if (e->kind == ExprKind::Bin) { sync_w(e->l); sync_w(e->r); }
        else if (e->kind == ExprKind::Un) { sync_w(e->l); }
        else if (e->kind == ExprKind::Bit) { sync_w(e->base); }
        else if (e->kind == ExprKind::Intr) { for (const auto &a : e->args) sync_w(a); }
        else if (e->kind == ExprKind::Mem && !e->has_static_addr) { sync_w(e->addr); }
    };
    for (const auto &[bid, b] : func.blocks) {
        for (const auto &s : b->stmts) {
            sync_w(s->dst); sync_w(s->src); sync_w(s->a); sync_w(s->b);
            sync_w(s->val); sync_w(s->expr); sync_w(s->bittest_expr);
            for (const auto &a : s->args) sync_w(a);
            if (s->z_flag) { sync_w(s->z_flag->a); sync_w(s->z_flag->b); }
            if (s->cy_flag) { sync_w(s->cy_flag->a); sync_w(s->cy_flag->b); }
        }
    }

    return info;
}

} // namespace rl78dec
