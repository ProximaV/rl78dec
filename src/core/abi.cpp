#include "rl78dec/abi.hpp"

#include <algorithm>
#include <cctype>
#include <functional>
#include <unordered_map>
#include <unordered_set>

#include "rl78dec/spill.hpp"

namespace rl78dec {

namespace {

std::string trim(const std::string &s) {
    size_t i = 0, j = s.size();
    while (i < j && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    while (j > i && std::isspace(static_cast<unsigned char>(s[j - 1]))) --j;
    return s.substr(i, j - i);
}

std::string to_lower_copy(std::string s) {
    for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool str_contains(const std::string &h, const std::string &needle) {
    return h.find(needle) != std::string::npos;
}

ExprPtr consolidate_pair(const ExprPtr &a_off, const ExprPtr &a_seg) {
    if (a_off && a_off->kind == ExprKind::Const && a_seg && a_seg->kind == ExprKind::Const) {
        uint32_t lin = ((a_seg->value & 0xFFFFu) << 16) | (a_off->value & 0xFFFFu);
        return Expr::make_const(lin, Width::D);
    }
    if (a_seg && a_seg->kind == ExprKind::Const) {
        if (a_seg->value == 0) return a_off;
        return Expr::make_bin("|", Expr::make_const((a_seg->value & 0xFFFFu) << 16, Width::D), a_off, Width::D);
    }
    return Expr::make_bin("|", Expr::make_bin("<<", a_seg, Expr::make_const(16, Width::B), Width::D), a_off, Width::D);
}

AtomMask compute_liveness(const Function &func,
                          const std::unordered_set<uint64_t> &hidden,
                          const IDatabaseProvider *db) {
    std::unordered_map<uint32_t, AtomMask> b_gen, b_kill;

    std::function<void(const ExprPtr &, AtomMask &)> collect_uses = [&](const ExprPtr &e, AtomMask &used) {
        if (!e) return;
        switch (e->kind) {
            case ExprKind::Reg:  used |= reg_atoms_named(e->name); break;
            case ExprKind::Bin:  collect_uses(e->l, used); collect_uses(e->r, used); break;
            case ExprKind::Un:   collect_uses(e->l, used); break;
            case ExprKind::Bit:  collect_uses(e->base, used); break;
            case ExprKind::Mem:  if (!e->has_static_addr) collect_uses(e->addr, used); break;
            case ExprKind::Intr: for (const auto &a : e->args) collect_uses(a, used); break;
            default: break;
        }
    };

    for (const auto &[bid, b] : func.blocks) {
        AtomMask gen = 0, kill = 0;
        for (const auto &s : b->stmts) {
            if (hidden.count(s->id)) continue;
            AtomMask used = 0;
            if (s->kind == StmtKind::Assign) {
                collect_uses(s->src, used);
                if (s->dst->kind != ExprKind::Reg) collect_uses(s->dst, used);
            } else if (s->kind == StmtKind::Compare) {
                if (s->z_flag)  { collect_uses(s->z_flag->a, used); collect_uses(s->z_flag->b, used); }
                if (s->cy_flag) { collect_uses(s->cy_flag->a, used); collect_uses(s->cy_flag->b, used); }
            } else if (s->kind == StmtKind::Branch) {
                if (s->has_bittest) collect_uses(s->bittest_expr, used);
                if (s->z_flag)  { collect_uses(s->z_flag->a, used); collect_uses(s->z_flag->b, used); }
                if (s->cy_flag) { collect_uses(s->cy_flag->a, used); collect_uses(s->cy_flag->b, used); }
            } else if (s->kind == StmtKind::Swap) {
                collect_uses(s->a, used);
                collect_uses(s->b, used);
            } else if (s->kind == StmtKind::Ret) {
                collect_uses(s->val, used);
            } else if (s->kind == StmtKind::Switch) {
                collect_uses(s->expr, used);
            } else if (s->kind == StmtKind::Call) {
                collect_uses(s->expr, used);
                for (const auto &a : s->args) collect_uses(a, used);
                std::set<std::string> preserved;
                if (db && s->target.has_value()) preserved = db->get_callee_preserved_regs(*s->target);
                if (!preserved.count("ax")) kill |= reg_atoms(RegId::AX);
                if (!preserved.count("bc")) kill |= reg_atoms(RegId::BC);
                if (!preserved.count("de")) kill |= reg_atoms(RegId::DE);
                if (!preserved.count("hl")) kill |= reg_atoms(RegId::HL);
            } else if (s->kind == StmtKind::Intrinsic && s->name != "pop") {
                for (const auto &a : s->args) collect_uses(a, used);
            }

            gen |= (used & ~kill);

            if (s->kind == StmtKind::Assign && s->dst->kind == ExprKind::Reg) {
                kill |= reg_atoms_named(s->dst->name);
            } else if (s->kind == StmtKind::Intrinsic && s->name == "pop" &&
                       !s->args.empty() && s->args[0]->kind == ExprKind::Reg) {
                kill |= reg_atoms_named(s->args[0]->name);
            }
        }
        b_gen[bid] = gen;
        b_kill[bid] = kill;
    }

    std::unordered_map<uint32_t, AtomMask> live_in;
    auto order = func.ordered();
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto it = order.rbegin(); it != order.rend(); ++it) {
            const auto &b = *it;
            AtomMask out = 0;
            for (const auto &[how, succ] : b->succ) {
                auto lit = live_in.find(succ);
                if (lit != live_in.end()) out |= lit->second;
            }
            AtomMask nin = b_gen[b->start] | (out & ~b_kill[b->start]);
            if (nin != live_in[b->start]) {
                live_in[b->start] = nin;
                changed = true;
            }
        }
    }
    return live_in[func.entry];
}

void collect_expr_used_atoms(const ExprPtr &e, AtomMask &out) {
    if (!e) return;
    switch (e->kind) {
        case ExprKind::Reg: out |= reg_atoms_named(e->name); break;
        case ExprKind::Bin: collect_expr_used_atoms(e->l, out); collect_expr_used_atoms(e->r, out); break;
        case ExprKind::Un:  collect_expr_used_atoms(e->l, out); break;
        case ExprKind::Bit: collect_expr_used_atoms(e->base, out); break;
        case ExprKind::Mem: if (!e->has_static_addr) collect_expr_used_atoms(e->addr, out); break;
        case ExprKind::Intr: for (const auto &a : e->args) collect_expr_used_atoms(a, out); break;
        default: break;
    }
}

std::pair<std::string, ExprPtr> infer_return(Function &func, const std::unordered_set<uint64_t> &hidden) {
    struct RetCand {
        BlockPtr b;
        std::string ctype;
        ExprPtr cexpr;
        std::string creg;
    };
    std::vector<RetCand> exit_info;
    int ret_block_count = 0;

    std::unordered_map<uint32_t, std::vector<uint32_t>> preds;
    for (const auto &[bid, b] : func.blocks) {
        for (const auto &[how, tgt] : b->succ) preds[tgt].push_back(b->start);
    }

    struct ScanRes {
        std::string ctype = "void";
        ExprPtr cexpr;
        std::string creg;
        AtomMask clobbered = 0;
    };

    auto pick_from_assigned = [](const std::unordered_map<std::string, ExprPtr> &assigned,
                                 bool allow_const) -> ScanRes {
        auto pair_const_or_reg = [&](const char *pair_nm, const char *hi_nm, const char *lo_nm) -> ExprPtr {
            if (assigned.count(pair_nm)) {
                return (allow_const && assigned.at(pair_nm)->kind == ExprKind::Const)
                           ? assigned.at(pair_nm)
                           : Expr::make_reg(pair_nm);
            }
            if (assigned.count(hi_nm) && assigned.count(lo_nm)) {
                const auto &hi = assigned.at(hi_nm);
                const auto &lo = assigned.at(lo_nm);
                if (allow_const && hi->kind == ExprKind::Const && lo->kind == ExprKind::Const) {
                    uint32_t v = ((hi->value & 0xFFu) << 8) | (lo->value & 0xFFu);
                    return Expr::make_const(v, Width::W);
                }
                return Expr::make_reg(pair_nm);
            }
            return nullptr;
        };

        ScanRes r;
        ExprPtr bc_pair = pair_const_or_reg("bc", "b", "c");
        ExprPtr ax_pair = pair_const_or_reg("ax", "a", "x");
        ExprPtr de_pair = pair_const_or_reg("de", "d", "e");

        bool has_bc = (bc_pair != nullptr) || assigned.count("c");
        bool has_de = (de_pair != nullptr) || assigned.count("e");
        if (has_bc && has_de) {
            r.ctype = "uint32_t";
            r.creg = "de:bc";
            ExprPtr de_src = de_pair ? de_pair : assigned.at("e");
            ExprPtr bc_src = bc_pair ? bc_pair : assigned.at("c");
            if (allow_const && de_src->kind == ExprKind::Const && bc_src->kind == ExprKind::Const) {
                uint32_t val = ((de_src->value << 16) | bc_src->value) & 0xFFFFFFFFu;
                r.cexpr = Expr::make_const(val, Width::D);
            } else {
                ExprPtr de_part = (allow_const && de_src->kind == ExprKind::Const)
                                      ? de_src
                                      : Expr::make_reg(de_pair ? "de" : "e");
                ExprPtr bc_part = (allow_const && bc_src->kind == ExprKind::Const)
                                      ? bc_src
                                      : Expr::make_reg(bc_pair ? "bc" : "c");
                r.cexpr = consolidate_pair(bc_part, de_part);
            }
        } else if (bc_pair) {
            r.ctype = "uint16_t"; r.creg = "bc"; r.cexpr = bc_pair;
        } else if (ax_pair) {
            r.ctype = "uint16_t"; r.creg = "ax"; r.cexpr = ax_pair;
        } else if (de_pair) {
            r.ctype = "uint16_t"; r.creg = "de"; r.cexpr = de_pair;
        } else if (assigned.count("c")) {
            r.ctype = "uint8_t"; r.creg = "c";
            r.cexpr = (allow_const && assigned.at("c")->kind == ExprKind::Const) ? assigned.at("c") : Expr::make_reg("c");
        } else if (assigned.count("a")) {
            r.ctype = "uint8_t"; r.creg = "a";
            r.cexpr = (allow_const && assigned.at("a")->kind == ExprKind::Const) ? assigned.at("a") : Expr::make_reg("a");
        } else if (assigned.count("e")) {
            r.ctype = "uint8_t"; r.creg = "e";
            r.cexpr = (allow_const && assigned.at("e")->kind == ExprKind::Const) ? assigned.at("e") : Expr::make_reg("e");
        } else if (assigned.count("cy")) {
            r.ctype = "bool"; r.creg = "cy";
            r.cexpr = (allow_const && assigned.at("cy")->kind == ExprKind::Const) ? assigned.at("cy") : Expr::make_reg("cy");
        }
        return r;
    };

    auto scan_block_tail = [&](const Block &blk, size_t end_excl, AtomMask init_clobbered,
                               bool allow_const) -> ScanRes {
        std::unordered_map<std::string, ExprPtr> assigned;
        AtomMask popped_atoms = init_clobbered;
        AtomMask consumed_atoms = init_clobbered;
        AtomMask total_clobbered = init_clobbered;

        for (size_t idx = end_excl; idx > 0; --idx) {
            const auto &s = blk.stmts[idx - 1];
            if (s->kind == StmtKind::Intrinsic && s->name == "pop") {
                if (!s->args.empty() && s->args[0]->kind == ExprKind::Reg) {
                    AtomMask m = reg_atoms_named(s->args[0]->name);
                    popped_atoms |= m;
                    total_clobbered |= m;
                }
                continue;
            }
            if (hidden.count(s->id) || s->kind == StmtKind::Nop) continue;
            if (s->kind == StmtKind::Assign) {
                if (s->dst->kind == ExprKind::Mem || s->dst->kind == ExprKind::StackVar) {
                    collect_expr_used_atoms(s->src, consumed_atoms);
                    if (s->dst->kind == ExprKind::Mem) {
                        collect_expr_used_atoms(s->dst, consumed_atoms);
                    }
                    // If `optimize()` constant/copy-propagated a shuttle `a = val` / `ax = val`
                    // into this store (`Mem = val`), mark that shuttle register as consumed so a
                    // `void` function ending in `mov a, #0x77; mov !addr, a; ret` stays `void`,
                    // without blocking an earlier `movw bc, #3` return value!
                    if (s->src && (s->src->kind == ExprKind::Const || s->src->kind == ExprKind::Var ||
                                   s->src->kind == ExprKind::StackVar)) {
                        const char *shuttle = (s->dst->width == Width::W) ? "ax" : "a";
                        for (size_t prev_k = idx - 1; prev_k > 0; --prev_k) {
                            const auto &ps = blk.stmts[prev_k - 1];
                            if (hidden.count(ps->id)) continue;
                            if (ps->kind == StmtKind::Assign && ps->dst && ps->dst->kind == ExprKind::Reg) {
                                if (ps->dst->name == shuttle && expr_eq(ps->src, s->src)) {
                                    consumed_atoms |= reg_atoms_named(shuttle);
                                    break;
                                }
                                if (regs_overlap(ps->dst->name, shuttle)) break;
                            } else if (ps->kind == StmtKind::Call) {
                                break;
                            }
                        }
                    }
                    total_clobbered |= consumed_atoms;
                    continue;
                }
                if (s->dst->kind == ExprKind::Reg) {
                    const std::string &dn = s->dst->name;
                    AtomMask datoms = reg_atoms_named(dn);
                    bool is_spill_pop = (s->src && s->src->kind == ExprKind::Var && s->src->name.rfind("_s", 0) == 0);
                    total_clobbered |= datoms;
                    if (is_spill_pop) {
                        popped_atoms |= datoms;
                    } else if ((datoms & ~popped_atoms) == datoms && (datoms & ~consumed_atoms) == datoms) {
                        if (!assigned.count(dn)) assigned[dn] = s->src;
                    }
                }
                collect_expr_used_atoms(s->src, consumed_atoms);
            } else if (s->kind == StmtKind::Swap) {
                for (const auto &r : {s->a, s->b}) {
                    if (r && r->kind == ExprKind::Reg) {
                        AtomMask datoms = reg_atoms_named(r->name);
                        total_clobbered |= datoms;
                        if ((datoms & ~popped_atoms) == datoms && (datoms & ~consumed_atoms) == datoms &&
                            !assigned.count(r->name)) {
                            assigned[r->name] = r;
                        }
                    }
                }
            } else if (s->kind == StmtKind::Call || s->kind == StmtKind::Branch ||
                       s->kind == StmtKind::Goto || s->kind == StmtKind::Compare ||
                       s->kind == StmtKind::Intrinsic) {
                break;
            }
        }
        ScanRes res = pick_from_assigned(assigned, allow_const);
        res.clobbered = total_clobbered;
        return res;
    };

    std::unordered_set<uint32_t> matched_blocks;
    for (const auto &[bid, b] : func.blocks) {
        if (b->stmts.empty() || b->stmts.back()->kind != StmtKind::Ret) continue;
        ++ret_block_count;
        if (b->stmts.back()->ret_kind == "reti" || b->stmts.back()->ret_kind == "retb") continue;

        ScanRes direct = scan_block_tail(*b, b->stmts.size() - 1, 0, true);
        if (direct.ctype != "void") {
            exit_info.push_back({b, direct.ctype, direct.cexpr, direct.creg});
            matched_blocks.insert(b->start);
            continue;
        }

        // Shared epilogue block (e.g. `pop ax; movw tmp_buf0, ax; pop hl; ret` or multi-pred join):
        // compute all register atoms clobbered/used inside `b`, then inspect `b`'s predecessors!
        ScanRes ep_scan = scan_block_tail(*b, b->stmts.size() - 1, 0, false);
        auto pit = preds.find(b->start);
        if (pit != preds.end() && !pit->second.empty()) {
            std::vector<ScanRes> pred_cands;
            bool all_preds_ok = true;
            for (uint32_t p_ea : pit->second) {
                auto pbit = func.blocks.find(p_ea);
                if (pbit == func.blocks.end()) { all_preds_ok = false; break; }
                const Block &pb = *pbit->second;
                size_t p_end = pb.stmts.size();
                if (p_end > 0 && (pb.stmts.back()->kind == StmtKind::Goto ||
                                  pb.stmts.back()->kind == StmtKind::Branch)) {
                    --p_end;
                }
                ScanRes pr = scan_block_tail(pb, p_end, ep_scan.clobbered, true);
                if (pr.ctype == "void") { all_preds_ok = false; break; }
                pred_cands.push_back(std::move(pr));
            }
            if (all_preds_ok && !pred_cands.empty()) {
                bool all_bc_fam = true, any_c_only = false, all_bc_fit_u8 = true;
                bool all_ax_fam = true, any_a_only = false, all_ax_zero = true;
                for (const auto &pc : pred_cands) {
                    if (pc.creg != "bc" && pc.creg != "c") all_bc_fam = false;
                    if (pc.creg == "c") any_c_only = true;
                    if (pc.creg == "bc" && (!pc.cexpr || pc.cexpr->kind != ExprKind::Const || pc.cexpr->value > 0xFFu)) {
                        all_bc_fit_u8 = false;
                    }
                    if (pc.creg != "ax" && pc.creg != "a") all_ax_fam = false;
                    if (pc.creg == "a") any_a_only = true;
                    if (pc.creg == "ax" && (!pc.cexpr || pc.cexpr->kind != ExprKind::Const || pc.cexpr->value != 0u)) {
                        all_ax_zero = false;
                    }
                }
                std::string r0 = pred_cands[0].creg;
                std::string t0 = pred_cands[0].ctype;
                bool same = true;
                if (all_bc_fam && any_c_only) {
                    if (all_bc_fit_u8) { r0 = "c"; t0 = "uint8_t"; }
                    else               { r0 = "bc"; t0 = "uint16_t"; }
                } else if (all_ax_fam && any_a_only) {
                    if (all_ax_zero) { r0 = "a"; t0 = "uint8_t"; }
                    else             { r0 = "ax"; t0 = "uint16_t"; }
                } else {
                    for (const auto &pc : pred_cands) {
                        if (pc.creg != r0) { same = false; break; }
                    }
                }
                if (same) {
                    Width rw = (r0 == "de:bc") ? Width::D : ((r0 == "ax" || r0 == "bc" || r0 == "de") ? Width::W : Width::B);
                    ExprPtr ce = (r0 == "de:bc") ? consolidate_pair(Expr::make_reg("bc"), Expr::make_reg("de"))
                                                 : Expr::make_reg(r0, rw);
                    exit_info.push_back({b, t0, ce, r0});
                    matched_blocks.insert(b->start);
                }
            }
        }
    }

    // Harmonize compatible subregister/pair candidates without truncating genuine 16-bit returns!
    if (exit_info.size() > 1) {
        bool all_bc_family = true, any_c_byte = false, all_bc_fit_u8 = true;
        bool all_ax_family = true, any_a_byte = false, all_ax_zero = true;
        for (const auto &c : exit_info) {
            if (c.creg != "bc" && c.creg != "c") all_bc_family = false;
            if (c.creg == "c") any_c_byte = true;
            if (c.creg == "bc" && (!c.cexpr || c.cexpr->kind != ExprKind::Const || c.cexpr->value > 0xFFu)) {
                all_bc_fit_u8 = false;
            }
            if (c.creg != "ax" && c.creg != "a") all_ax_family = false;
            if (c.creg == "a") any_a_byte = true;
            if (c.creg == "ax" && (!c.cexpr || c.cexpr->kind != ExprKind::Const || c.cexpr->value != 0u)) {
                all_ax_zero = false;
            }
        }
        if (all_bc_family && any_c_byte) {
            if (all_bc_fit_u8) {
                for (auto &c : exit_info) {
                    if (c.creg == "bc") {
                        c.creg = "c";
                        c.ctype = "uint8_t";
                        c.cexpr = Expr::make_const(c.cexpr->value & 0xFFu, Width::B);
                    }
                }
            } else {
                for (auto &c : exit_info) {
                    if (c.creg == "c") {
                        c.creg = "bc";
                        c.ctype = "uint16_t";
                        c.cexpr = Expr::make_reg("bc", Width::W);
                    }
                }
            }
        } else if (all_ax_family && any_a_byte) {
            if (all_ax_zero) {
                for (auto &c : exit_info) {
                    if (c.creg == "ax") {
                        c.creg = "a";
                        c.ctype = "uint8_t";
                        c.cexpr = Expr::make_const(0, Width::B);
                    }
                }
            } else {
                for (auto &c : exit_info) {
                    if (c.creg == "a") {
                        c.creg = "ax";
                        c.ctype = "uint16_t";
                        c.cexpr = Expr::make_reg("ax", Width::W);
                    }
                }
            }
        }
    }

    if (!exit_info.empty() && static_cast<int>(exit_info.size()) < ret_block_count) {
        const std::string &t0 = exit_info[0].ctype;
        const std::string &r0 = exit_info[0].creg;
        bool cand_same = true;
        for (const auto &c : exit_info) {
            if (c.ctype != t0 || c.creg != r0) { cand_same = false; break; }
        }
        bool is_gpr_ret = (r0 == "a" || r0 == "ax" || r0 == "bc" || r0 == "c" ||
                           r0 == "de" || r0 == "e" || r0 == "de:bc");
        if (cand_same && is_gpr_ret) {
            AtomMask target_mask = (r0 == "de:bc") ? (reg_atoms(RegId::DE) | reg_atoms(RegId::BC))
                                                   : reg_atoms_named(r0);
            Width ret_w = (r0 == "de:bc") ? Width::D : ((r0 == "ax" || r0 == "bc" || r0 == "de") ? Width::W : Width::B);
            for (const auto &[bid, b] : func.blocks) {
                if (matched_blocks.count(b->start)) continue;
                if (b->stmts.empty() || b->stmts.back()->kind != StmtKind::Ret) continue;
                if (b->stmts.back()->ret_kind == "reti" || b->stmts.back()->ret_kind == "retb") continue;

                AtomMask popped_atoms = 0, written_atoms = 0;
                for (size_t idx = b->stmts.size() - 1; idx > 0; --idx) {
                    const auto &s = b->stmts[idx - 1];
                    if (s->kind == StmtKind::Intrinsic && s->name == "pop") {
                        if (!s->args.empty() && s->args[0]->kind == ExprKind::Reg) {
                            popped_atoms |= reg_atoms_named(s->args[0]->name);
                        }
                        continue;
                    }
                    if (hidden.count(s->id)) continue;
                    if (s->kind == StmtKind::Assign) {
                        if (s->dst->kind == ExprKind::Reg) {
                            AtomMask datoms = reg_atoms_named(s->dst->name);
                            written_atoms |= (datoms & ~popped_atoms);
                        }
                    } else if (s->kind == StmtKind::Swap) {
                        for (const auto &r : {s->a, s->b}) {
                            if (r && r->kind == ExprKind::Reg) {
                                AtomMask datoms = reg_atoms_named(r->name);
                                written_atoms |= (datoms & ~popped_atoms);
                            }
                        }
                    } else if (s->kind == StmtKind::Call || s->kind == StmtKind::Branch ||
                               s->kind == StmtKind::Goto || s->kind == StmtKind::Intrinsic) {
                        break;
                    }
                }
                if ((target_mask & written_atoms) == target_mask) {
                    ExprPtr ce = (r0 == "de:bc") ? consolidate_pair(Expr::make_reg("bc"), Expr::make_reg("de"))
                                                 : Expr::make_reg(r0, ret_w);
                    exit_info.push_back({b, t0, ce, r0});
                    matched_blocks.insert(b->start);
                }
            }
        }
    }

    if (ret_block_count > 0 && static_cast<int>(exit_info.size()) == ret_block_count) {
        const std::string &t0 = exit_info[0].ctype;
        const std::string &r0 = exit_info[0].creg;
        bool all_same = true;
        for (const auto &c : exit_info) {
            if (c.ctype != t0 || c.creg != r0) { all_same = false; break; }
        }
        if (all_same) {
            for (const auto &c : exit_info) {
                if (!c.b->stmts.empty() && c.b->stmts.back()->kind == StmtKind::Ret) {
                    c.b->stmts.back()->val = c.cexpr;
                }
            }
            return {t0, exit_info[0].cexpr};
        }
    }

    for (const auto &[bid, b] : func.blocks) {
        for (const auto &s : b->stmts) {
            if (s->kind == StmtKind::Ret) s->val.reset();
        }
    }
    return {"void", nullptr};
}

std::vector<StmtPtr> find_following_stmts(const Function &func, const Block &b, size_t idx,
                                          const std::unordered_set<uint64_t> &hidden) {
    std::vector<StmtPtr> res;
    for (size_t k = idx + 1; k < b.stmts.size(); ++k) {
        if (!hidden.count(b.stmts[k]->id)) res.push_back(b.stmts[k]);
    }
    const Block *cur = &b;
    std::unordered_set<uint32_t> visited{b.start};
    while (cur->succ.size() == 1 && cur->succ[0].first == "fall") {
        uint32_t succ_ea = cur->succ[0].second;
        if (!visited.insert(succ_ea).second) break;
        auto it = func.blocks.find(succ_ea);
        if (it == func.blocks.end()) break;
        cur = it->second.get();
        for (const auto &s : cur->stmts) {
            if (!hidden.count(s->id)) res.push_back(s);
        }
        if (res.size() >= 10) break;
    }
    return res;
}

std::pair<ExprPtr, StmtPtr> infer_call_return(const Function &func, const Block &b, size_t idx,
                                              const FrameInfo &fi, const IDatabaseProvider *db) {
    const auto &s_call = b.stmts[idx];
    if (db && s_call->target.has_value() && db->callee_returns_dword(*s_call->target)) {
        return {Expr::make_reg("de:bc", Width::D), nullptr};
    }

    auto stmts_after = find_following_stmts(func, b, idx, fi.hidden_stmts);
    AtomMask killed = 0, used_volatile = 0, used_after_first = 0;
    std::unordered_set<std::string> used_names;
    StmtPtr first_ret_assign;

    for (const auto &s : stmts_after) {
        std::unordered_set<std::string> cur_names;
        std::function<void(const ExprPtr &)> collect_names = [&](const ExprPtr &e) {
            if (!e) return;
            if (e->kind == ExprKind::Reg) cur_names.insert(e->name);
            else if (e->kind == ExprKind::Bin) { collect_names(e->l); collect_names(e->r); }
            else if (e->kind == ExprKind::Un)  { collect_names(e->l); }
            else if (e->kind == ExprKind::Bit) { collect_names(e->base); }
            else if (e->kind == ExprKind::Mem && !e->has_static_addr) collect_names(e->addr);
            else if (e->kind == ExprKind::Intr) for (const auto &a : e->args) collect_names(a);
        };

        if (s->kind == StmtKind::Assign) {
            collect_names(s->src);
            if (s->dst->kind != ExprKind::Reg) collect_names(s->dst);
        } else if (s->kind == StmtKind::Compare) {
            if (s->z_flag)  { collect_names(s->z_flag->a); collect_names(s->z_flag->b); }
            if (s->cy_flag) { collect_names(s->cy_flag->a); collect_names(s->cy_flag->b); }
        } else if (s->kind == StmtKind::Branch) {
            if (s->has_bittest) collect_names(s->bittest_expr);
            if (s->z_flag)  { collect_names(s->z_flag->a); collect_names(s->z_flag->b); }
            if (s->cy_flag) { collect_names(s->cy_flag->a); collect_names(s->cy_flag->b); }
            if (s->cond == "c" || s->cond == "nc") cur_names.insert("cy");
        } else if (s->kind == StmtKind::Ret && s->val) {
            collect_names(s->val);
        } else if (s->kind == StmtKind::Swap) {
            collect_names(s->a); collect_names(s->b);
        } else if (s->kind == StmtKind::Intrinsic && s->name != "pop") {
            for (const auto &a : s->args) collect_names(a);
        } else if (s->kind == StmtKind::Switch) {
            collect_names(s->expr);
        }

        bool had_first = (first_ret_assign != nullptr);
        bool stmt_used_ret = false;
        constexpr AtomMask kVolWithCy = atom::CALLER_SAVED | atom::CY;
        for (const auto &rname : cur_names) {
            if (rname == "psw") continue;
            AtomMask am = reg_atoms_named(rname);
            AtomMask live_bits = am & kVolWithCy & ~killed;
            if (live_bits != 0) {
                used_volatile |= live_bits;
                used_names.insert(rname);
                stmt_used_ret = true;
                if (had_first) used_after_first |= live_bits;
            }
        }
        if (stmt_used_ret && !first_ret_assign &&
            s->kind == StmtKind::Assign && s->src && s->src->kind == ExprKind::Reg) {
            first_ret_assign = s;
        }

        if (s->kind == StmtKind::Assign && s->dst->kind == ExprKind::Reg) {
            killed |= reg_atoms_named(s->dst->name);
        } else if (s->kind == StmtKind::Intrinsic && s->name == "pop" &&
                   !s->args.empty() && s->args[0]->kind == ExprKind::Reg) {
            killed |= reg_atoms_named(s->args[0]->name);
        } else if (s->kind == StmtKind::Call) {
            killed |= kVolWithCy;
        }

        bool has_de = (used_volatile & (atom::E | atom::D)) != 0;
        bool has_bc = (used_volatile & (atom::B | atom::C)) != 0;
        if (has_de && has_bc) break;
        if ((killed & atom::CALLER_SAVED) == atom::CALLER_SAVED) break;
    }

    bool has_de = (used_volatile & (atom::E | atom::D)) != 0;
    bool has_bc = (used_volatile & (atom::B | atom::C)) != 0;
    if (has_de && has_bc) return {Expr::make_reg("de:bc", Width::D), nullptr};

    std::string ret_reg;
    if ((used_names.count("bc") && !(killed & (atom::B | atom::C))) ||
        ((used_volatile & atom::B) && (used_volatile & atom::C))) ret_reg = "bc";
    else if (used_volatile & atom::C) ret_reg = "c";
    else if (used_volatile & atom::B) ret_reg = "bc";
    else if ((used_names.count("ax") && !(killed & (atom::A | atom::X))) ||
             ((used_volatile & atom::A) && (used_volatile & atom::X))) ret_reg = "ax";
    else if (used_volatile & atom::A) ret_reg = "a";
    else if (used_volatile & atom::X) ret_reg = "ax";
    else if ((used_names.count("de") && !(killed & (atom::D | atom::E))) ||
             ((used_volatile & atom::E) && (used_volatile & atom::D))) ret_reg = "de";
    else if (used_volatile & atom::E) ret_reg = "e";
    else if (used_volatile & atom::D) ret_reg = "de";
    else if (used_volatile & atom::CY) ret_reg = "cy";

    if (!ret_reg.empty()) {
        if (first_ret_assign && first_ret_assign->src->name == ret_reg) {
            bool dst_is_scratch = (first_ret_assign->dst->kind == ExprKind::Reg &&
                                   (reg_atoms_named(first_ret_assign->dst->name) & atom::SCRATCH) != 0);
            bool ret_used_later = (used_after_first & reg_atoms_named(ret_reg)) != 0;
            if (!dst_is_scratch && !ret_used_later) return {first_ret_assign->dst, first_ret_assign};
        }
        return {Expr::make_reg(ret_reg), nullptr};
    }
    return {nullptr, nullptr};
}

void recover_call_sites(Function &func, FrameInfo &fi, AtomMask live_atoms,
                        const std::vector<Param> &params, const IDatabaseProvider *db,
                        const std::unordered_map<uint32_t, FarParamSpecs> &local_far_specs) {
    auto lookup_far = [&](uint32_t target) -> std::optional<FarParamSpecs> {
        if (auto it = local_far_specs.find(target); it != local_far_specs.end()) return it->second;
        if (db) return db->get_callee_far_param_specs(target);
        return std::nullopt;
    };

    for (const auto &[bid, b] : func.blocks) {
        auto &stmts = b->stmts;
        for (size_t i = 0; i < stmts.size(); ++i) {
            auto &s = stmts[i];
            if (s->kind != StmtKind::Call) continue;

            ExprPtr ax_arg, bc_arg, de_arg, hl_arg;
            std::vector<uint64_t> ax_stmt_ids, bc_stmt_ids, de_stmt_ids, hl_stmt_ids;
            bool de_hide_ok = true, hl_hide_ok = true;
            AtomMask killed_since = 0;
            std::vector<StmtPtr> caller_pushes;

            for (size_t j = i; j > 0; --j) {
                const auto &prev = stmts[j - 1];
                if (fi.hidden_stmts.count(prev->id)) continue;
                if (prev->kind == StmtKind::Assign) {
                    if (prev->dst->kind == ExprKind::Reg) {
                        const std::string &dn = prev->dst->name;
                        AtomMask src_used = 0;
                        collect_expr_used_atoms(prev->src, src_used);
                        if ((dn == "ax" || dn == "a" || dn == "x") && !ax_arg) {
                            ax_arg = prev->src;
                            ax_stmt_ids.push_back(prev->id);
                        } else if ((dn == "bc" || dn == "c" || dn == "b") && !bc_arg) {
                            if (dn == "bc" || dn == "c") bc_arg = prev->src;
                            bc_stmt_ids.push_back(prev->id);
                        } else if ((dn == "de" || dn == "e" || dn == "d") && !de_arg) {
                            if ((src_used & killed_since) == 0) {
                                de_arg = prev->src;
                                de_stmt_ids.push_back(prev->id);
                            } else {
                                de_arg = Expr::make_reg(dn, prev->dst->width);
                                de_hide_ok = false;
                            }
                        } else if ((dn == "hl" || dn == "l" || dn == "h") && !hl_arg) {
                            if ((src_used & killed_since) == 0) {
                                hl_arg = prev->src;
                                hl_stmt_ids.push_back(prev->id);
                            } else {
                                hl_arg = Expr::make_reg(dn, prev->dst->width);
                                hl_hide_ok = false;
                            }
                        }
                        killed_since |= reg_atoms_named(dn);
                    } else {
                        break;
                    }
                } else if (prev->kind == StmtKind::Intrinsic && prev->name == "push") {
                    if (!prev->args.empty() && prev->args[0]->kind == ExprKind::Reg &&
                        prev->args[0]->name == "bc") {
                        size_t lim = (j - 1 >= 4) ? (j - 5) : 0;
                        for (size_t k = j - 1; k > lim; --k) {
                            const auto &ps = stmts[k - 1];
                            if (ps->kind == StmtKind::Assign && ps->dst->kind == ExprKind::Reg &&
                                (ps->dst->name == "c" || ps->dst->name == "bc")) {
                                if (ps->src->kind == ExprKind::Const) {
                                    prev->args[0] = Expr::make_const(ps->src->value, Width::B);
                                    fi.hidden_stmts.insert(ps->id);
                                    break;
                                }
                            } else if (ps->kind == StmtKind::Intrinsic && ps->name == "push") {
                                break;
                            }
                        }
                    }
                    caller_pushes.push_back(prev);
                } else {
                    break;
                }
            }

            auto [cleanup_bytes, cleanup_stmt] = find_call_cleanup(func, *b, i);
            if (cleanup_stmt) fi.hidden_stmts.insert(cleanup_stmt->id);

            std::optional<CalleeSigHint> sig_hint;
            if (db && s->target.has_value()) sig_hint = db->get_callee_sig(*s->target);

            if (!ax_arg && s->target.has_value() && db && !(sig_hint && sig_hint->valid)) {
                auto expects = db->callee_expects_ax(*s->target);
                if (expects.value_or(false)) {
                    bool caller_has_ax = (live_atoms & (atom::A | atom::X)) != 0 ||
                                         std::any_of(params.begin(), params.end(),
                                                     [](const Param &p) { return p.location == "ax" || p.location == "a"; });
                    if (!caller_has_ax) {
                        for (const auto &[bid2, blk2] : func.blocks) {
                            for (const auto &st : blk2->stmts) {
                                if (st->kind == StmtKind::Assign && st->dst->kind == ExprKind::Reg &&
                                    (st->dst->name == "ax" || st->dst->name == "a" || st->dst->name == "x")) {
                                    caller_has_ax = true;
                                    break;
                                }
                            }
                            if (caller_has_ax) break;
                        }
                    }
                    if (caller_has_ax) ax_arg = Expr::make_reg("ax");
                }
            }

            std::optional<FarParamSpecs> specs;
            if (s->target.has_value()) specs = lookup_far(*s->target);

            std::vector<ExprPtr> stack_raw = s->args;
            if (stack_raw.empty() && cleanup_bytes > 0 && !caller_pushes.empty()) {
                for (const auto &ps : caller_pushes) {
                    fi.hidden_stmts.insert(ps->id);
                    if (!ps->args.empty()) stack_raw.push_back(ps->args[0]);
                }
            }

            std::vector<ExprPtr> args;
            if (sig_hint && sig_hint->valid) {
                bool used_ax = false, used_bc = false, used_de = false, used_hl = false;
                size_t stack_idx = 0, p_idx = 0;
                for (const auto &hp : sig_hint->params) {
                    if (hp.location == "ax:bc") {
                        ExprPtr a0 = ax_arg ? ax_arg : Expr::make_reg("ax", Width::W);
                        ExprPtr a1 = bc_arg ? bc_arg : Expr::make_reg("bc", Width::W);
                        args.push_back(consolidate_pair(a0, a1));
                        used_ax = true;
                        used_bc = true;
                    } else if (hp.location == "ax" || hp.location == "a") {
                        Width pw = (hp.location == "a") ? Width::B : Width::W;
                        args.push_back(ax_arg ? ax_arg : Expr::make_reg(hp.location, pw));
                        used_ax = true;
                    } else if (hp.location == "bc" || hp.location == "c") {
                        Width pw = (hp.location == "c") ? Width::B : Width::W;
                        args.push_back(bc_arg ? bc_arg : Expr::make_reg(hp.location, pw));
                        used_bc = true;
                    } else if (hp.location == "de" || hp.location == "e" || hp.location == "d") {
                        Width pw = (hp.location == "e" || hp.location == "d") ? Width::B : Width::W;
                        args.push_back(de_arg ? de_arg : Expr::make_reg(hp.location, pw));
                        used_de = true;
                    } else if (hp.location == "hl" || hp.location == "l" || hp.location == "h") {
                        Width pw = (hp.location == "l" || hp.location == "h") ? Width::B : Width::W;
                        args.push_back(hl_arg ? hl_arg : Expr::make_reg(hp.location, pw));
                        used_hl = true;
                    } else {
                        bool is_far = (specs.has_value() && specs->far_stack_indices.count(static_cast<int>(stack_idx))) ||
                                      (hp.type_str == "uint32_t" || hp.type_str == "int32_t");
                        if (is_far && p_idx + 1 < stack_raw.size()) {
                            args.push_back(consolidate_pair(stack_raw[p_idx], stack_raw[p_idx + 1]));
                            p_idx += 2;
                        } else if (p_idx < stack_raw.size()) {
                            args.push_back(stack_raw[p_idx]);
                            ++p_idx;
                        } else {
                            Width pw = (hp.type_str == "uint8_t" || hp.type_str == "int8_t" || hp.type_str == "bool")
                                           ? Width::B
                                           : ((hp.type_str == "uint32_t" || hp.type_str == "int32_t") ? Width::D : Width::W);
                            args.push_back(Expr::make_const(0, pw));
                        }
                        ++stack_idx;
                    }
                }
                if (used_ax) for (uint64_t sid : ax_stmt_ids) fi.hidden_stmts.insert(sid);
                if (used_bc) for (uint64_t sid : bc_stmt_ids) fi.hidden_stmts.insert(sid);
                if (used_de && de_hide_ok) for (uint64_t sid : de_stmt_ids) fi.hidden_stmts.insert(sid);
                if (used_hl && hl_hide_ok) for (uint64_t sid : hl_stmt_ids) fi.hidden_stmts.insert(sid);
            } else {
                if (specs.has_value() && specs->has_far_reg && ax_arg && bc_arg) {
                    args.push_back(consolidate_pair(ax_arg, bc_arg));
                    for (uint64_t sid : ax_stmt_ids) fi.hidden_stmts.insert(sid);
                    for (uint64_t sid : bc_stmt_ids) fi.hidden_stmts.insert(sid);
                } else {
                    if (ax_arg) {
                        args.push_back(ax_arg);
                        for (uint64_t sid : ax_stmt_ids) fi.hidden_stmts.insert(sid);
                    }
                    if (bc_arg) {
                        args.push_back(bc_arg);
                        for (uint64_t sid : bc_stmt_ids) fi.hidden_stmts.insert(sid);
                    }
                }

                size_t stack_idx = 0, p_idx = 0;
                while (p_idx < stack_raw.size()) {
                    if (specs.has_value() && specs->far_stack_indices.count(static_cast<int>(stack_idx)) &&
                        p_idx + 1 < stack_raw.size()) {
                        args.push_back(consolidate_pair(stack_raw[p_idx], stack_raw[p_idx + 1]));
                        p_idx += 2;
                    } else {
                        args.push_back(stack_raw[p_idx]);
                        ++p_idx;
                    }
                    ++stack_idx;
                }
            }
            s->args = std::move(args);

            if (sig_hint && sig_hint->valid && sig_hint->ret_type == "void") {
                s->dst.reset();
            } else if (!s->dst) {
                auto [dst, fold_stmt] = infer_call_return(func, *b, i, fi, db);
                if (dst) {
                    s->dst = dst;
                    if (fold_stmt) fi.hidden_stmts.insert(fold_stmt->id);
                }
            }
        }
    }
}

} // namespace

std::string normalize_c_type(const std::string &raw) {
    std::string s = trim(raw);
    if (s.empty()) return "uint16_t";
    int ptr_depth = 0;
    while (!s.empty() && s.back() == '*') {
        ++ptr_depth;
        s.pop_back();
        s = trim(s);
    }
    // Split tokens, drop calling conventions and qualifiers
    std::vector<std::string> keep;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
        if (i >= s.size()) break;
        size_t j = i;
        while (j < s.size() && !std::isspace(static_cast<unsigned char>(s[j]))) ++j;
        std::string tok = s.substr(i, j - i);
        std::string ltok = to_lower_copy(tok);
        if (ltok != "__cdecl" && ltok != "__stdcall" && ltok != "__fastcall" &&
            ltok != "__thiscall" && ltok != "__usercall" && ltok != "__userpurge" &&
            ltok != "const" && ltok != "volatile") {
            keep.push_back(tok);
        }
        i = j;
    }
    std::string joined;
    for (size_t k = 0; k < keep.size(); ++k) {
        if (k > 0) joined += ' ';
        joined += keep[k];
    }
    std::string lj = to_lower_copy(joined);
    std::string base = joined;
    if (lj == "void") base = "void";
    else if (lj == "unsigned __int8" || lj == "unsigned char" || lj == "uchar" ||
             lj == "uint8" || lj == "uint8_t" || lj == "byte" || lj == "u8") base = "uint8_t";
    else if (lj == "signed __int8" || lj == "__int8" || lj == "char" || lj == "signed char" ||
             lj == "int8" || lj == "int8_t" || lj == "s8") base = "int8_t";
    else if (lj == "unsigned __int16" || lj == "unsigned short" || lj == "ushort" ||
             lj == "unsigned int" || lj == "unsigned" || lj == "uint16" ||
             lj == "uint16_t" || lj == "word" || lj == "u16") base = "uint16_t";
    else if (lj == "signed __int16" || lj == "__int16" || lj == "short" || lj == "signed short" ||
             lj == "int" || lj == "signed int" || lj == "signed" || lj == "int16" ||
             lj == "int16_t" || lj == "s16") base = "int16_t";
    else if (lj == "unsigned __int32" || lj == "unsigned long" || lj == "ulong" ||
             lj == "uint32" || lj == "uint32_t" || lj == "dword" || lj == "u32") base = "uint32_t";
    else if (lj == "signed __int32" || lj == "__int32" || lj == "long" || lj == "signed long" ||
             lj == "int32" || lj == "int32_t" || lj == "s32") base = "int32_t";
    else if (lj == "_bool1" || lj == "_bool" || lj == "bool") base = "bool";
    else if (base.empty()) base = "uint16_t";

    if (ptr_depth > 0) {
        return base + " " + std::string(static_cast<size_t>(ptr_depth), '*');
    }
    return base;
}

std::optional<ParsedProto> parse_prototype(const std::string &proto_str) {
    std::string s = trim(proto_str);
    while (!s.empty() && s.back() == ';') s.pop_back();
    size_t popen = s.find('(');
    size_t pclose = s.rfind(')');
    if (popen == std::string::npos || pclose == std::string::npos || pclose < popen) return std::nullopt;

    std::string header = trim(s.substr(0, popen));
    std::string param_str = trim(s.substr(popen + 1, pclose - popen - 1));

    auto split_ws = [](const std::string &txt) {
        std::vector<std::string> out;
        size_t i = 0;
        while (i < txt.size()) {
            while (i < txt.size() && std::isspace(static_cast<unsigned char>(txt[i]))) ++i;
            if (i >= txt.size()) break;
            size_t j = i;
            while (j < txt.size() && !std::isspace(static_cast<unsigned char>(txt[j]))) ++j;
            std::string tok = txt.substr(i, j - i);
            std::string ltok = to_lower_copy(tok);
            if (ltok != "__cdecl" && ltok != "__stdcall" && ltok != "__fastcall" &&
                ltok != "__thiscall" && ltok != "__usercall" && ltok != "__userpurge") {
                out.push_back(std::move(tok));
            }
            i = j;
        }
        return out;
    };

    auto hparts = split_ws(header);
    if (hparts.empty()) return std::nullopt;
    ParsedProto res;
    std::string last = hparts.back();
    size_t stars = 0;
    while (stars < last.size() && last[stars] == '*') ++stars;
    res.func_name = last.substr(stars);
    for (size_t i = 0; i + 1 < hparts.size(); ++i) {
        if (i > 0) res.ret_type += " ";
        res.ret_type += hparts[i];
    }
    if (stars > 0) res.ret_type += " " + std::string(stars, '*');
    res.ret_type = res.ret_type.empty() ? "void" : normalize_c_type(res.ret_type);

    if (!param_str.empty() && param_str != "void") {
        size_t start = 0;
        while (start <= param_str.size()) {
            size_t comma = param_str.find(',', start);
            std::string part = trim(comma == std::string::npos ? param_str.substr(start) : param_str.substr(start, comma - start));
            if (!part.empty()) {
                auto toks = split_ws(part);
                if (toks.size() == 1) {
                    res.params.emplace_back("", normalize_c_type(toks[0]));
                } else {
                    std::string blast = toks.back();
                    size_t pstars = 0;
                    while (pstars < blast.size() && blast[pstars] == '*') ++pstars;
                    std::string pname = blast.substr(pstars);
                    std::string ptype;
                    for (size_t i = 0; i + 1 < toks.size(); ++i) {
                        if (i > 0) ptype += " ";
                        ptype += toks[i];
                    }
                    if (pstars > 0) ptype += " " + std::string(pstars, '*');
                    res.params.emplace_back(pname, normalize_c_type(ptype));
                }
            }
            if (comma == std::string::npos) break;
            start = comma + 1;
        }
    }
    return res;
}

namespace {

bool is_8bit_ctype(const std::string &t) {
    return t == "uint8_t" || t == "int8_t" || t == "bool";
}

bool is_32bit_ctype(const std::string &t) {
    return t == "uint32_t" || t == "int32_t";
}

ExprPtr default_ret_expr_for(const std::string &ret_type) {
    if (ret_type == "bool") return Expr::make_reg("cy", Width::B);
    if (ret_type == "uint8_t" || ret_type == "int8_t") return Expr::make_reg("a", Width::B);
    if (is_32bit_ctype(ret_type)) return consolidate_pair(Expr::make_reg("bc"), Expr::make_reg("de"));
    return Expr::make_reg("ax", Width::W);
}

FunctionSig analyze_cc_impl(
    Function &func,
    FrameInfo &fi,
    const IDatabaseProvider *db,
    const std::string &user_proto,
    const CallerConsensus *caller_consensus,
    bool do_recover_calls) {
    AtomMask live_atoms = compute_liveness(func, fi.hidden_stmts, db);
    for (const auto &hr : fi.homed_args) live_atoms |= reg_atoms_named(hr);

    if (caller_consensus && caller_consensus->valid) {
        if (caller_consensus->has_ax) {
            bool expects = db ? db->callee_expects_ax(func.entry).value_or(true) : true;
            if (expects) live_atoms |= reg_atoms(RegId::AX);
        }
        if (caller_consensus->has_bc) live_atoms |= reg_atoms(RegId::BC);
    }

    std::unordered_map<uint32_t, FarParamSpecs> local_far_specs;

    if (!user_proto.empty()) {
        if (auto parsed = parse_prototype(user_proto); parsed.has_value()) {
            FunctionSig sig;
            sig.ret_type = parsed->ret_type;
            if (!parsed->func_name.empty()) func.name = parsed->func_name;
            sig.name = func.name;

            bool first_is_far = !parsed->params.empty() && is_32bit_ctype(parsed->params[0].second);
            size_t reg_slots = 0;
            if (parsed->params.size() >= 1) {
                std::string loc0 = first_is_far ? "ax:bc" : (is_8bit_ctype(parsed->params[0].second) ? "a" : "ax");
                sig.params.push_back(Param{parsed->params[0].first.empty() ? "a0" : parsed->params[0].first,
                                           parsed->params[0].second, loc0});
                reg_slots = 1;
            }
            if (!first_is_far && parsed->params.size() >= 2) {
                std::string loc1 = is_8bit_ctype(parsed->params[1].second) ? "c" : "bc";
                sig.params.push_back(Param{parsed->params[1].first.empty() ? "a1" : parsed->params[1].first,
                                           parsed->params[1].second, loc1});
                reg_slots = 2;
            }

            std::vector<std::pair<std::string, FrameInfo::VarDecl>> sargs(fi.args.begin(), fi.args.end());
            std::sort(sargs.begin(), sargs.end(), [](const auto &x, const auto &y) {
                return x.second.var->offset < y.second.var->offset;
            });
            size_t idx = 0;
            for (const auto &[nm, decl] : sargs) {
                if (nm == "a0" || nm == "a1") continue;
                size_t pidx = reg_slots + idx++;
                if (pidx < parsed->params.size()) {
                    const auto &[pn, pt] = parsed->params[pidx];
                    sig.params.push_back(Param{pn.empty() ? nm : pn, pt, "stack"});
                } else {
                    sig.params.push_back(Param{nm, decl.width == Width::W ? "uint16_t" : "uint8_t", "stack"});
                }
            }
            for (size_t pidx = reg_slots + idx; pidx < parsed->params.size(); ++pidx) {
                const auto &[pn, pt] = parsed->params[pidx];
                sig.params.push_back(Param{pn.empty() ? ("a" + std::to_string(pidx)) : pn, pt, "stack"});
            }

            if (sig.ret_type == "void") {
                for (const auto &[bid, b] : func.blocks) {
                    for (const auto &s : b->stmts) {
                        if (s->kind == StmtKind::Ret) s->val.reset();
                    }
                }
            } else {
                auto [inf_rt, inf_re] = infer_return(func, fi.hidden_stmts);
                ExprPtr fallback_ret = default_ret_expr_for(sig.ret_type);
                bool use_inf = (inf_re != nullptr) &&
                               ((is_8bit_ctype(sig.ret_type) && is_8bit_ctype(inf_rt)) ||
                                (is_32bit_ctype(sig.ret_type) && is_32bit_ctype(inf_rt)) ||
                                (!is_8bit_ctype(sig.ret_type) && !is_32bit_ctype(sig.ret_type) &&
                                 inf_rt != "void" && !is_8bit_ctype(inf_rt) && !is_32bit_ctype(inf_rt)));
                sig.ret_expr = use_inf ? inf_re : fallback_ret;
                for (const auto &[bid, b] : func.blocks) {
                    for (const auto &s : b->stmts) {
                        if (s->kind == StmtKind::Ret && s->ret_kind != "reti" && s->ret_kind != "retb") {
                            if (!s->val || !use_inf) s->val = sig.ret_expr;
                        }
                    }
                }
            }

            if (do_recover_calls) {
                recover_call_sites(func, fi, live_atoms, sig.params, db, local_far_specs);
            }
            return sig;
        }
    }

    bool has_ax = (live_atoms & (atom::A | atom::X)) != 0;
    bool has_bc = (live_atoms & (atom::B | atom::C)) != 0;

    std::optional<FarParamSpecs> callee_specs = db ? db->get_callee_far_param_specs(func.entry) : std::nullopt;
    bool is_far_reg = false;
    if (has_ax && has_bc) {
        if (callee_specs.has_value() && callee_specs->has_far_reg) {
            is_far_reg = true;
        } else if (fi.homed_slot_to_arg.count(0) && fi.homed_slot_to_arg.count(2)) {
            is_far_reg = true;
        }
    }

    std::vector<Param> params;
    if (is_far_reg) {
        params.push_back(Param{"a0", "uint32_t", "ax:bc"});
        if (fi.args.count("a0")) fi.args["a0"].width = Width::D;
        fi.args.erase("a1");
        for (const auto &[bid, b] : func.blocks) {
            for (const auto &st : b->stmts) {
                if (st->kind != StmtKind::Assign) continue;
                if ((st->src && st->src->kind == ExprKind::StackVar && st->src->name == "a1") ||
                    (st->src && st->src->kind == ExprKind::Reg && (st->src->name == "a1" || st->src->name == "c")) ||
                    (st->dst && st->dst->kind == ExprKind::Reg && st->dst->name == "es") ||
                    (st->dst && st->dst->kind == ExprKind::Mem && st->dst->has_static_addr &&
                     (st->dst->static_addr == 0xFFED4u || st->dst->static_addr == 0xFFED5u))) {
                    fi.hidden_stmts.insert(st->id);
                }
            }
        }
    } else {
        if (live_atoms & atom::X) params.push_back(Param{"a0", "uint16_t", "ax"});
        else if (live_atoms & atom::A) params.push_back(Param{"a0", "uint8_t", "a"});

        if (live_atoms & atom::B) params.push_back(Param{"a1", "uint16_t", "bc"});
        else if (live_atoms & atom::C) params.push_back(Param{"a1", "uint8_t", "c"});

        if (live_atoms & atom::D) params.push_back(Param{"a2", "uint16_t", "de"});
        else if (live_atoms & atom::E) params.push_back(Param{"a2", "uint8_t", "e"});

        if (live_atoms & atom::H) params.push_back(Param{"a3", "uint16_t", "hl"});
        else if (live_atoms & atom::L) params.push_back(Param{"a3", "uint8_t", "l"});
    }

    std::vector<std::pair<std::string, FrameInfo::VarDecl>> sargs;
    for (const auto &kv : fi.args) {
        if (kv.first != "a0" && kv.first != "a1" && kv.first != "a2" && kv.first != "a3") sargs.push_back(kv);
    }
    std::sort(sargs.begin(), sargs.end(), [](const auto &x, const auto &y) {
        return x.second.var->offset < y.second.var->offset;
    });

    std::set<int> far_stack_indices;
    int stack_idx = 0;
    for (size_t idx = 0; idx < sargs.size();) {
        const auto &[name1, decl1] = sargs[idx];
        bool is_far_stack = false;
        std::string name2;
        if (idx + 1 < sargs.size()) {
            name2 = sargs[idx + 1].first;
            std::string n1 = to_lower_copy(name1);
            std::string n2 = to_lower_copy(name2);
            if (n2 == "segment" || n2 == "seg" || n2 == "resp_segment" ||
                n2 == n1 + "_seg" || n2 == n1 + "_segment" ||
                ((str_contains(n1, "addr") || str_contains(n1, "address") || str_contains(n1, "table")) &&
                 (str_contains(n2, "seg") || str_contains(n2, "segment")))) {
                is_far_stack = true;
            }
        }
        if (is_far_stack) {
            params.push_back(Param{name1, "uint32_t", "stack"});
            far_stack_indices.insert(stack_idx);
            fi.args[name1].width = Width::D;
            fi.args.erase(name2);
            for (const auto &[bid, b] : func.blocks) {
                for (const auto &st : b->stmts) {
                    if (st->kind != StmtKind::Assign) continue;
                    if ((st->src && st->src->kind == ExprKind::StackVar && st->src->name == name2) ||
                        (st->dst && st->dst->kind == ExprKind::StackVar && st->dst->name == name2)) {
                        fi.hidden_stmts.insert(st->id);
                    }
                }
            }
            idx += 2;
        } else {
            params.push_back(Param{name1, decl1.width == Width::W ? "uint16_t" : "uint8_t", "stack"});
            idx += 1;
        }
        ++stack_idx;
    }

    local_far_specs[func.entry] = FarParamSpecs{is_far_reg, far_stack_indices};

    auto [ret_type, ret_expr] = infer_return(func, fi.hidden_stmts);
    if (do_recover_calls) {
        recover_call_sites(func, fi, live_atoms, params, db, local_far_specs);
    }

    FunctionSig sig;
    sig.name = func.name;
    sig.ret_type = ret_type;
    sig.ret_expr = ret_expr;
    sig.params = std::move(params);
    return sig;
}

} // namespace

FunctionSig infer_function_sig_only(
    Function &func,
    FrameInfo &frame_info,
    const IDatabaseProvider *db,
    const std::string &user_proto,
    const CallerConsensus *caller_consensus) {
    return analyze_cc_impl(func, frame_info, db, user_proto, caller_consensus, false);
}

FunctionSig analyze_calling_convention(
    Function &func,
    FrameInfo &frame_info,
    const IDatabaseProvider *db,
    const std::string &user_proto,
    const CallerConsensus *caller_consensus) {
    return analyze_cc_impl(func, frame_info, db, user_proto, caller_consensus, true);
}

} // namespace rl78dec
