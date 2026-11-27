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

struct PrologueScan {
    std::string fp_reg;
    int frame_size = 0;
    std::vector<std::string> saved_regs;
    std::vector<StmtPtr> stmts;
};

PrologueScan scan_block_prologue(const Block &b) {
    PrologueScan out;
    for (const auto &s : b.stmts) {
        int sub_imm = 0;
        if (is_push_reg(*s)) {
            out.saved_regs.push_back(s->args[0]->name);
            out.stmts.push_back(s);
        } else if (is_sub_sp(*s, &sub_imm)) {
            out.frame_size += sub_imm;
            out.stmts.push_back(s);
        } else if (is_mov_hl_sp(*s)) {
            out.fp_reg = "hl";
            out.stmts.push_back(s);
            break;
        } else {
            break;
        }
    }
    if (out.fp_reg.empty() && out.frame_size > 0) {
        out.fp_reg = "sp";
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

std::optional<int64_t> get_mem_disp(const ExprPtr &e, const std::string &fp_reg) {
    if (!e || e->kind != ExprKind::Mem || e->es || e->has_static_addr || !e->addr) return std::nullopt;
    if (e->addr->kind == ExprKind::Reg && e->addr->name == fp_reg) return 0;
    if (e->addr->kind == ExprKind::Bin && e->addr->op == "+" &&
        e->addr->l && e->addr->l->kind == ExprKind::Reg && e->addr->l->name == fp_reg &&
        e->addr->r && e->addr->r->kind == ExprKind::Const) {
        return static_cast<int64_t>(e->addr->r->value);
    }
    return std::nullopt;
}

bool expr_reads_disp(const ExprPtr &e, const std::string &fp_reg, int64_t target_disp) {
    if (!e) return false;
    if (auto d = get_mem_disp(e, fp_reg); d.has_value()) {
        if (*d >= target_disp && *d < target_disp + 2) return true;
    }
    switch (e->kind) {
        case ExprKind::Bin:
            return expr_reads_disp(e->l, fp_reg, target_disp) || expr_reads_disp(e->r, fp_reg, target_disp);
        case ExprKind::Un:
            return expr_reads_disp(e->l, fp_reg, target_disp);
        case ExprKind::Bit:
            return expr_reads_disp(e->base, fp_reg, target_disp);
        case ExprKind::Intr:
            for (const auto &a : e->args) if (expr_reads_disp(a, fp_reg, target_disp)) return true;
            return false;
        case ExprKind::Mem:
            return !e->has_static_addr && expr_reads_disp(e->addr, fp_reg, target_disp);
        default:
            return false;
    }
}

bool is_disp_read_before_write(const Function &func, const std::string &fp_reg, int64_t target_disp) {
    if (fp_reg.empty()) return false;
    for (const auto &b : func.ordered()) {
        for (const auto &s : b->stmts) {
            if (s->kind == StmtKind::Assign) {
                if (expr_reads_disp(s->src, fp_reg, target_disp)) return true;
                if (auto d = get_mem_disp(s->dst, fp_reg); d.has_value()) {
                    if (*d >= target_disp && *d < target_disp + 2) return false;
                }
                if (s->dst && s->dst->kind == ExprKind::Mem && !s->dst->has_static_addr &&
                    expr_reads_disp(s->dst->addr, fp_reg, target_disp)) {
                    return true;
                }
            } else if (s->kind == StmtKind::Compare) {
                if (s->z_flag && (expr_reads_disp(s->z_flag->a, fp_reg, target_disp) ||
                                  expr_reads_disp(s->z_flag->b, fp_reg, target_disp))) return true;
                if (s->cy_flag && (expr_reads_disp(s->cy_flag->a, fp_reg, target_disp) ||
                                   expr_reads_disp(s->cy_flag->b, fp_reg, target_disp))) return true;
            } else if (s->kind == StmtKind::Call) {
                for (const auto &a : s->args) if (expr_reads_disp(a, fp_reg, target_disp)) return true;
            } else if (s->kind == StmtKind::Ret) {
                if (expr_reads_disp(s->val, fp_reg, target_disp)) return true;
            } else if (s->kind == StmtKind::Branch) {
                if (s->has_bittest && expr_reads_disp(s->bittest_expr, fp_reg, target_disp)) return true;
                if (s->z_flag && (expr_reads_disp(s->z_flag->a, fp_reg, target_disp) ||
                                  expr_reads_disp(s->z_flag->b, fp_reg, target_disp))) return true;
                if (s->cy_flag && (expr_reads_disp(s->cy_flag->a, fp_reg, target_disp) ||
                                   expr_reads_disp(s->cy_flag->b, fp_reg, target_disp))) return true;
            } else if (s->kind == StmtKind::Switch) {
                if (expr_reads_disp(s->expr, fp_reg, target_disp)) return true;
            } else if (s->kind == StmtKind::Intrinsic) {
                for (const auto &a : s->args) if (expr_reads_disp(a, fp_reg, target_disp)) return true;
            }
        }
    }
    return false;
}

} // namespace

FrameInfo analyze_frame(Function &func, const IdaFrameInfo *ida_frame) {
    FrameInfo info;

    std::vector<StmtPtr> prologue_stmts;
    auto entry_it = func.blocks.find(func.entry);
    if (entry_it != func.blocks.end()) {
        PrologueScan ps = scan_block_prologue(*entry_it->second);
        if (ps.stmts.empty() && entry_it->second->succ.size() == 2) {
            uint32_t fall_ea = entry_it->second->succ[1].second;
            auto fit = func.blocks.find(fall_ea);
            if (fit != func.blocks.end()) ps = scan_block_prologue(*fit->second);
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
        info.saved_regs = ps.saved_regs;
        prologue_stmts = ps.stmts;
        if (!info.fp_reg.empty() || info.frame_size > 0 || !info.saved_regs.empty()) {
            info.has_frame = true;
        }
    }

    auto epilogue_stmts = scan_epilogues(func);
    std::unordered_set<std::string> popped_regs;
    for (const auto &s : epilogue_stmts) {
        if (is_pop_reg(*s)) popped_regs.insert(s->args[0]->name);
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
            if (is_disp_read_before_write(func, info.fp_reg, disp)) {
                if (std::find(info.homed_args.begin(), info.homed_args.end(), "ax") == info.homed_args.end()) {
                    info.homed_args.push_back("ax");
                }
                info.homed_slot_to_arg[disp] = "a0";
            }
        } else if (r == "bc") {
            if (is_disp_read_before_write(func, info.fp_reg, disp)) {
                if (std::find(info.homed_args.begin(), info.homed_args.end(), "bc") == info.homed_args.end()) {
                    info.homed_args.push_back("bc");
                }
                info.homed_slot_to_arg[disp] = "a1";
            } else if (popped_regs.count(r) && info.homed_args.empty()) {
                true_saved.push_back(r);
            }
        }
    }
    info.saved_regs = std::move(true_saved);
    info.arg_base = arg_base;
    info.prologue_pushes = info.saved_regs;

    for (const auto &s : prologue_stmts) info.hidden_stmts.insert(s->id);
    for (const auto &s : epilogue_stmts) info.hidden_stmts.insert(s->id);

    int frsize = info.frame_size;
    auto resolve_disp = [&](int64_t disp, Width w) -> ExprPtr {
        if (auto it = info.homed_slot_to_arg.find(disp); it != info.homed_slot_to_arg.end()) {
            return Expr::make_stack_var(it->second, w, disp, true);
        }
        char buf[32];
        if (disp >= arg_base) {
            std::snprintf(buf, sizeof(buf), "arg_%llX", static_cast<unsigned long long>(disp - arg_base));
            return Expr::make_stack_var(buf, w, disp, true);
        }
        if (disp < frsize) {
            std::snprintf(buf, sizeof(buf), "var_%llX", static_cast<unsigned long long>(frsize - disp));
            return Expr::make_stack_var(buf, w, disp, false);
        }
        std::snprintf(buf, sizeof(buf), "var_s%llX", static_cast<unsigned long long>(disp - frsize));
        return Expr::make_stack_var(buf, w, disp, false);
    };

    auto record_stack_var = [&](const ExprPtr &sv, Width w) {
        auto &map_ref = sv->is_arg ? info.args : info.locals;
        auto it = map_ref.find(sv->name);
        Width final_w = (w == Width::W || (it != map_ref.end() && it->second.width == Width::W))
                            ? Width::W
                            : Width::B;
        sv->width = final_w;
        map_ref[sv->name] = FrameInfo::VarDecl{sv, final_w};
    };

    std::function<ExprPtr(const ExprPtr &, uint32_t)> repl = [&](const ExprPtr &e, uint32_t ea) -> ExprPtr {
        if (!e) return nullptr;
        if (e->kind == ExprKind::Mem && !e->es && !e->has_static_addr) {
            if (ida_frame && ida_frame->valid) {
                auto sit = ida_frame->stkvars_by_ea.find(ea);
                if (sit != ida_frame->stkvars_by_ea.end() && !sit->second.empty()) {
                    const IdaStkvarHit &hit = sit->second.begin()->second;
                    std::string vname = hit.name;
                    bool is_arg = hit.is_arg;
                    if (auto hit_it = info.homed_slot_to_arg.find(hit.offset); hit_it != info.homed_slot_to_arg.end()) {
                        vname = hit_it->second;
                        is_arg = true;
                    }
                    Width w = (hit.size == 2) ? Width::W : Width::B;
                    auto v = Expr::make_stack_var(vname, w, hit.offset, is_arg);
                    record_stack_var(v, w);
                    return v;
                }
            }
            if (!info.fp_reg.empty()) {
                if (auto disp = get_mem_disp(e, info.fp_reg); disp.has_value()) {
                    auto v = resolve_disp(*disp, e->width);
                    record_stack_var(v, e->width);
                    return v;
                }
            }
            if (info.fp_reg != "sp") {
                if (auto disp = get_mem_disp(e, "sp"); disp.has_value()) {
                    auto v = resolve_disp(*disp, e->width);
                    record_stack_var(v, e->width);
                    return v;
                }
            }
        }
        switch (e->kind) {
            case ExprKind::Bin:
                return Expr::make_bin(e->op, repl(e->l, ea), repl(e->r, ea), e->width);
            case ExprKind::Un:
                return Expr::make_un(e->op, repl(e->l, ea), e->width);
            case ExprKind::Bit:
                return Expr::make_bit(repl(e->base, ea), e->bit);
            case ExprKind::Intr: {
                std::vector<ExprPtr> na;
                na.reserve(e->args.size());
                for (const auto &a : e->args) na.push_back(repl(a, ea));
                return Expr::make_intr(e->name, std::move(na), e->width);
            }
            default:
                return e;
        }
    };

    for (const auto &[bid, b] : func.blocks) {
        for (const auto &s : b->stmts) {
            if (s->kind == StmtKind::Assign) {
                s->dst = repl(s->dst, s->ea);
                s->src = repl(s->src, s->ea);
                if (s->z_flag) {
                    s->z_flag->a = repl(s->z_flag->a, s->ea);
                    s->z_flag->b = repl(s->z_flag->b, s->ea);
                }
                if (s->cy_flag) {
                    s->cy_flag->a = repl(s->cy_flag->a, s->ea);
                    s->cy_flag->b = repl(s->cy_flag->b, s->ea);
                }
            } else if (s->kind == StmtKind::Compare) {
                if (s->z_flag) {
                    s->z_flag->a = repl(s->z_flag->a, s->ea);
                    s->z_flag->b = repl(s->z_flag->b, s->ea);
                }
                if (s->cy_flag) {
                    s->cy_flag->a = repl(s->cy_flag->a, s->ea);
                    s->cy_flag->b = repl(s->cy_flag->b, s->ea);
                }
            } else if (s->kind == StmtKind::Swap) {
                s->a = repl(s->a, s->ea);
                s->b = repl(s->b, s->ea);
            } else if (s->kind == StmtKind::Intrinsic) {
                for (auto &a : s->args) a = repl(a, s->ea);
            } else if (s->kind == StmtKind::Branch) {
                if (s->has_bittest) s->bittest_expr = repl(s->bittest_expr, s->ea);
            } else if (s->kind == StmtKind::Switch) {
                s->expr = repl(s->expr, s->ea);
            }
        }
    }

    return info;
}

} // namespace rl78dec
