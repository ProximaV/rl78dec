#include "rl78dec/lifter.hpp"

#include <unordered_set>

namespace rl78dec {

namespace {

Width op_width(const Operand &op) {
    return (op.width == Width::W) ? Width::W : Width::B;
}

} // namespace

ExprPtr operand_to_expr(const Operand &op) {
    switch (op.mode) {
        case OpMode::Reg:
            return Expr::make_reg(reg_name(op.reg));
        case OpMode::Imm:
            return Expr::make_const(op.value, op.width, op.name);
        case OpMode::Mem:
            return Expr::make_mem_abs(op.addr, op.width, op.es, op.name);
        case OpMode::Ind: {
            auto base = Expr::make_reg(reg_name(op.base_reg));
            ExprPtr addr = (op.disp == 0)
                ? base
                : Expr::make_bin("+", base, Expr::make_const(op.disp, Width::B), Width::W);
            return Expr::make_mem_addr(addr, op.width, op.es);
        }
        case OpMode::Idx16: {
            uint32_t disp = !op.es ? (0xF0000u | (op.disp & 0xFFFFu)) : op.disp;
            auto addr = Expr::make_bin("+", Expr::make_const(disp, Width::A),
                                       Expr::make_reg(reg_name(op.base_reg)), Width::A);
            return Expr::make_mem_addr(addr, op.width, op.es);
        }
        case OpMode::Hloff: {
            auto addr = Expr::make_bin("+", Expr::make_reg("hl"), Expr::make_reg(reg_name(op.base_reg)), Width::W);
            return Expr::make_mem_addr(addr, Width::B, op.es);
        }
        case OpMode::Bit: {
            ExprPtr base;
            if (op.bit_base == BitBase::Reg) {
                base = Expr::make_reg(reg_name(op.reg));
            } else if (op.bit_base == BitBase::Ind) {
                base = Expr::make_mem_addr(Expr::make_reg(reg_name(op.base_reg)), Width::B, op.es);
            } else {
                base = Expr::make_mem_abs(op.addr, Width::B, op.es);
            }
            return Expr::make_bit(base, op.bit);
        }
        case OpMode::Near:
        case OpMode::Far:
        case OpMode::Callt:
            return Expr::make_const(op.addr, Width::A, op.name);
        default:
            return Expr::make_const(0);
    }
}

std::vector<StmtPtr> lift_insn(const DecodedInsn &ins) {
    uint32_t ea = ins.ea;
    Mnem m = ins.mnem;
    auto e = [&](size_t i) -> ExprPtr {
        return i < ins.ops.size() ? operand_to_expr(ins.ops[i]) : Expr::make_const(0);
    };

    // --- Data movement ---
    if (m == Mnem::Mov || m == Mnem::Movw) {
        auto dst = e(0);
        auto src = e(1);
        FlagDefPtr zf = nullptr, cyf = nullptr;
        // Direct writes to PSW overwrite flags (e.g., MOV PSW, #byte)
        if (dst->kind == ExprKind::Reg && dst->name == "psw") {
            zf = std::make_shared<FlagDef>(FlagDef{FlagKind::Unknown, Width::B, nullptr, nullptr, nullptr});
            cyf = std::make_shared<FlagDef>(FlagDef{FlagKind::Unknown, Width::B, nullptr, nullptr, nullptr});
        }
        return {make_assign(ea, dst, src, zf, cyf)};
    }
    if (m == Mnem::Oneb || m == Mnem::Onew) {
        Width w = ins.ops.empty() ? Width::B : op_width(ins.ops[0]);
        return {make_assign(ea, e(0), Expr::make_const(1, w))};
    }
    if (m == Mnem::Clrb || m == Mnem::Clrw) {
        Width w = ins.ops.empty() ? Width::B : op_width(ins.ops[0]);
        return {make_assign(ea, e(0), Expr::make_const(0, w))};
    }
    if (m == Mnem::Xch || m == Mnem::Xchw) {
        return {make_swap(ea, e(0), e(1))};
    }
    if (m == Mnem::Movs) {
        // MOVS [HL+byte], X: dst <- X, Z <- (X == 0), CY <- (A == 0 || X == 0)
        auto dst = e(0);
        auto src = e(1);
        auto zf = std::make_shared<FlagDef>(FlagDef{FlagKind::Result, Width::B, expr_clone(src), nullptr, nullptr});
        auto cyf = std::make_shared<FlagDef>(FlagDef{FlagKind::Movs, Width::B, Expr::make_reg("a"), expr_clone(src), nullptr});
        return {make_assign(ea, dst, src, zf, cyf)};
    }

    // --- Arithmetic / Logic ---
    if (m == Mnem::Add || m == Mnem::Addc || m == Mnem::Sub || m == Mnem::Subc ||
        m == Mnem::And || m == Mnem::Or || m == Mnem::Xor ||
        m == Mnem::Addw || m == Mnem::Subw) {
        ExprPtr dst = e(0);
        ExprPtr src = e(1);
        bool is_word = (m == Mnem::Addw || m == Mnem::Subw);
        Width w = is_word ? Width::W : Width::B;
        bool is_sp = (dst->kind == ExprKind::Reg && dst->name == "sp");

        ExprPtr pre_dst = expr_clone(dst);
        ExprPtr rhs;
        FlagDefPtr zf = nullptr;
        FlagDefPtr cyf = nullptr;

        if (m == Mnem::Addc) {
            auto old_cy = Expr::make_reg("cy");
            rhs = Expr::make_bin("+", Expr::make_bin("+", pre_dst, src, w), expr_clone(old_cy), w);
            zf = std::make_shared<FlagDef>(FlagDef{FlagKind::Result, w, expr_clone(dst), nullptr, nullptr});
            cyf = std::make_shared<FlagDef>(FlagDef{FlagKind::Add, w, expr_clone(pre_dst), expr_clone(src), old_cy});
        } else if (m == Mnem::Subc) {
            auto old_cy = Expr::make_reg("cy");
            rhs = Expr::make_bin("-", Expr::make_bin("-", pre_dst, src, w), expr_clone(old_cy), w);
            zf = std::make_shared<FlagDef>(FlagDef{FlagKind::Result, w, expr_clone(dst), nullptr, nullptr});
            cyf = std::make_shared<FlagDef>(FlagDef{FlagKind::Sub, w, expr_clone(pre_dst), expr_clone(src), old_cy});
        } else if (m == Mnem::Add || m == Mnem::Addw) {
            rhs = Expr::make_bin("+", pre_dst, src, w);
            if (!is_sp) { // ADDW SP, #byte preserves all flags (78K0R p.1020)
                zf = std::make_shared<FlagDef>(FlagDef{FlagKind::Result, w, expr_clone(dst), nullptr, nullptr});
                cyf = std::make_shared<FlagDef>(FlagDef{FlagKind::Add, w, expr_clone(pre_dst), expr_clone(src), nullptr});
            }
        } else if (m == Mnem::Sub || m == Mnem::Subw) {
            rhs = Expr::make_bin("-", pre_dst, src, w);
            if (!is_sp) { // SUBW SP, #byte preserves all flags (78K0R p.1020)
                zf = std::make_shared<FlagDef>(FlagDef{FlagKind::Result, w, expr_clone(dst), nullptr, nullptr});
                cyf = std::make_shared<FlagDef>(FlagDef{FlagKind::Sub, w, expr_clone(pre_dst), expr_clone(src), nullptr});
            }
        } else {
            const char *op = (m == Mnem::And) ? "&" : (m == Mnem::Or) ? "|" : "^";
            rhs = Expr::make_bin(op, pre_dst, src, w);
            // AND/OR/XOR update Z only and preserve CY!
            zf = std::make_shared<FlagDef>(FlagDef{FlagKind::Result, w, expr_clone(dst), nullptr, nullptr});
        }
        return {make_assign(ea, dst, rhs, zf, cyf)};
    }

    if (m == Mnem::Cmp || m == Mnem::Cmpw) {
        Width w = (m == Mnem::Cmpw) ? Width::W : Width::B;
        auto a = e(0), b = e(1);
        auto zf = std::make_shared<FlagDef>(FlagDef{FlagKind::Cmp, w, a, b, nullptr});
        auto cyf = std::make_shared<FlagDef>(FlagDef{FlagKind::Cmp, w, expr_clone(a), expr_clone(b), nullptr});
        return {make_compare(ea, zf, cyf)};
    }
    if (m == Mnem::Cmps) {
        auto a = e(0), b = e(1);
        auto zf = std::make_shared<FlagDef>(FlagDef{FlagKind::Cmp, Width::B, a, b, nullptr});
        auto cyf = std::make_shared<FlagDef>(FlagDef{FlagKind::Cmps, Width::B, expr_clone(a), expr_clone(b), Expr::make_reg("a")});
        return {make_compare(ea, zf, cyf)};
    }
    if (m == Mnem::Cmp0) {
        auto a = e(0);
        auto zf = std::make_shared<FlagDef>(FlagDef{FlagKind::Cmp0, Width::B, a, Expr::make_const(0), nullptr});
        auto cyf = std::make_shared<FlagDef>(FlagDef{FlagKind::CarryVal, Width::B, Expr::make_const(0), nullptr, nullptr});
        return {make_compare(ea, zf, cyf)};
    }
    if (m == Mnem::Inc || m == Mnem::Incw || m == Mnem::Dec || m == Mnem::Decw) {
        ExprPtr dst = e(0);
        bool is_word = (m == Mnem::Incw || m == Mnem::Decw);
        Width w = is_word ? Width::W : Width::B;
        const char *op = (m == Mnem::Inc || m == Mnem::Incw) ? "+" : "-";
        ExprPtr rhs = Expr::make_bin(op, expr_clone(dst), Expr::make_const(1, w), w);
        // INC/DEC set Z only (preserve CY); INCW/DECW touch no flags!
        FlagDefPtr zf = is_word
            ? nullptr
            : std::make_shared<FlagDef>(FlagDef{FlagKind::Result, Width::B, expr_clone(dst), nullptr, nullptr});
        return {make_assign(ea, dst, rhs, zf, nullptr)};
    }
    if (m == Mnem::Mulu) {
        ExprPtr a16 = Expr::make_un("u16", Expr::make_reg("a"), Width::W);
        ExprPtr x16 = Expr::make_un("u16", Expr::make_reg("x"), Width::W);
        return {make_assign(ea, Expr::make_reg("ax"),
                            Expr::make_bin("*", a16, x16, Width::W))};
    }

    // RL78-S3 expanded multiply / divide / MAC instructions (R01US0015EJ0220 pp.91, 165-171)
    if (m == Mnem::Mulhu || m == Mnem::Mulh) {
        bool is_signed = (m == Mnem::Mulh);
        const char *cast_op = is_signed ? "i16" : "u16";
        ExprPtr prod = Expr::make_bin(
            "*",
            Expr::make_un(is_signed ? "i32" : "u32", Expr::make_un(cast_op, Expr::make_reg("ax"), Width::W), Width::D),
            Expr::make_un(is_signed ? "i32" : "u32", Expr::make_un(cast_op, Expr::make_reg("bc"), Width::W), Width::D),
            Width::D);
        auto tmp = Expr::make_var("_s3_mul_" + std::to_string(ea), Width::D);
        return {
            make_assign(ea, tmp, prod),
            make_assign(ea, Expr::make_reg("ax"), Expr::make_un("u16", expr_clone(tmp), Width::W)),
            make_assign(ea, Expr::make_reg("bc"),
                        Expr::make_un("u16", Expr::make_bin(">>", expr_clone(tmp), Expr::make_const(16, Width::B), Width::D), Width::W)),
        };
    }
    if (m == Mnem::Divhu) {
        auto n = Expr::make_var("_s3_dn_" + std::to_string(ea), Width::W);
        auto d = Expr::make_var("_s3_dd_" + std::to_string(ea), Width::W);
        ExprPtr is0 = Expr::make_bin("==", expr_clone(d), Expr::make_const(0, Width::W), Width::B);
        ExprPtr q = Expr::make_intr("__tern", {
            expr_clone(is0),
            Expr::make_const(0xFFFFu, Width::W),
            Expr::make_bin("/", Expr::make_un("u16", expr_clone(n), Width::W), Expr::make_un("u16", expr_clone(d), Width::W), Width::W)
        }, Width::W);
        ExprPtr r = Expr::make_intr("__tern", {
            is0,
            expr_clone(n),
            Expr::make_bin("%", Expr::make_un("u16", expr_clone(n), Width::W), Expr::make_un("u16", expr_clone(d), Width::W), Width::W)
        }, Width::W);
        return {
            make_assign(ea, n, Expr::make_reg("ax")),
            make_assign(ea, d, Expr::make_reg("de")),
            make_assign(ea, Expr::make_reg("ax"), q),
            make_assign(ea, Expr::make_reg("de"), r),
        };
    }
    if (m == Mnem::Divwu) {
        auto n = Expr::make_var("_s3_wn_" + std::to_string(ea), Width::D);
        auto d = Expr::make_var("_s3_wd_" + std::to_string(ea), Width::D);
        auto qv = Expr::make_var("_s3_wq_" + std::to_string(ea), Width::D);
        auto rv = Expr::make_var("_s3_wr_" + std::to_string(ea), Width::D);
        ExprPtr num = Expr::make_bin("|",
                                     Expr::make_bin("<<", Expr::make_un("u32", Expr::make_reg("bc"), Width::D), Expr::make_const(16, Width::B), Width::D),
                                     Expr::make_un("u32", Expr::make_reg("ax"), Width::D), Width::D);
        ExprPtr den = Expr::make_bin("|",
                                     Expr::make_bin("<<", Expr::make_un("u32", Expr::make_reg("hl"), Width::D), Expr::make_const(16, Width::B), Width::D),
                                     Expr::make_un("u32", Expr::make_reg("de"), Width::D), Width::D);
        ExprPtr is0 = Expr::make_bin("==", expr_clone(d), Expr::make_const(0, Width::D), Width::B);
        ExprPtr q = Expr::make_intr("__tern", {expr_clone(is0), Expr::make_const(0xFFFFFFFFu, Width::D), Expr::make_bin("/", expr_clone(n), expr_clone(d), Width::D)}, Width::D);
        ExprPtr r = Expr::make_intr("__tern", {is0, expr_clone(n), Expr::make_bin("%", expr_clone(n), expr_clone(d), Width::D)}, Width::D);
        return {
            make_assign(ea, n, num),
            make_assign(ea, d, den),
            make_assign(ea, qv, q),
            make_assign(ea, rv, r),
            make_assign(ea, Expr::make_reg("ax"), Expr::make_un("u16", expr_clone(qv), Width::W)),
            make_assign(ea, Expr::make_reg("bc"), Expr::make_un("u16", Expr::make_bin(">>", expr_clone(qv), Expr::make_const(16, Width::B), Width::D), Width::W)),
            make_assign(ea, Expr::make_reg("de"), Expr::make_un("u16", expr_clone(rv), Width::W)),
            make_assign(ea, Expr::make_reg("hl"), Expr::make_un("u16", Expr::make_bin(">>", expr_clone(rv), Expr::make_const(16, Width::B), Width::D), Width::W)),
        };
    }
    if (m == Mnem::Machu || m == Mnem::Mach) {
        bool is_signed = (m == Mnem::Mach);
        const char *cast_op = is_signed ? "i16" : "u16";
        ExprPtr prod = Expr::make_bin(
            "*",
            Expr::make_un(is_signed ? "i32" : "u32", Expr::make_un(cast_op, Expr::make_reg("ax"), Width::W), Width::D),
            Expr::make_un(is_signed ? "i32" : "u32", Expr::make_un(cast_op, Expr::make_reg("bc"), Width::W), Width::D),
            Width::D);
        ExprPtr macr = Expr::make_mem_abs(0xFFFF0u, Width::D, false, "MACR");
        return {make_assign(ea, macr, Expr::make_bin("+", expr_clone(macr), prod, Width::D))};
    }

    // --- Shifts / Rotates (update CY only, preserve Z) ---
    if (m == Mnem::Shl || m == Mnem::Shlw || m == Mnem::Shr || m == Mnem::Shrw || m == Mnem::Sar || m == Mnem::Sarw) {
        ExprPtr dst = e(0);
        ExprPtr cnt = e(1);
        bool is_word = (m == Mnem::Shlw || m == Mnem::Shrw || m == Mnem::Sarw);
        Width w = is_word ? Width::W : Width::B;
        uint32_t bits = is_word ? 16u : 8u;
        uint32_t k = (cnt->kind == ExprKind::Const) ? cnt->value : 1u;

        ExprPtr pre = expr_clone(dst);
        ExprPtr cy_expr;
        if (k == 0) {
            cy_expr = Expr::make_reg("cy");
        } else if (m == Mnem::Shl || m == Mnem::Shlw) {
            uint32_t sh = (k <= bits) ? (bits - k) : 0;
            cy_expr = Expr::make_bin("&", Expr::make_bin(">>", expr_clone(pre), Expr::make_const(sh, Width::B), w),
                                     Expr::make_const(1, Width::B), Width::B);
        } else {
            uint32_t sh = k - 1u;
            ExprPtr shifted = (sh == 0) ? expr_clone(pre)
                                        : Expr::make_bin(">>", expr_clone(pre), Expr::make_const(sh, Width::B), w);
            cy_expr = Expr::make_bin("&", shifted, Expr::make_const(1, Width::B), Width::B);
        }
        auto cyf = std::make_shared<FlagDef>(FlagDef{FlagKind::CarryVal, Width::B, cy_expr, nullptr, nullptr});

        ExprPtr upre = Expr::make_un(is_word ? "u16" : "u8", pre, w);
        ExprPtr rhs;
        if (m == Mnem::Shl || m == Mnem::Shlw) {
            rhs = Expr::make_un(is_word ? "u16" : "u8", Expr::make_bin("<<", upre, cnt, w), w);
        } else if (m == Mnem::Shr || m == Mnem::Shrw) {
            rhs = Expr::make_bin(">>", upre, cnt, w);
        } else {
            ExprPtr sp = Expr::make_un(is_word ? "i16" : "i8", pre, w);
            rhs = Expr::make_un(is_word ? "u16" : "u8", Expr::make_bin(">>", sp, cnt, w), w);
        }
        return {make_assign(ea, dst, rhs, nullptr, cyf)};
    }

    if (m == Mnem::Ror || m == Mnem::Rol || m == Mnem::Rorc || m == Mnem::Rolc || m == Mnem::Rolwc) {
        ExprPtr dst = e(0);
        bool is_word = (m == Mnem::Rolwc);
        Width w = is_word ? Width::W : Width::B;
        uint32_t top_bit = is_word ? 15u : 7u;
        ExprPtr pre = expr_clone(dst);
        bool from_lsb = (m == Mnem::Ror || m == Mnem::Rorc);
        ExprPtr new_cy = from_lsb
            ? Expr::make_bin("&", expr_clone(pre), Expr::make_const(1, Width::B), Width::B)
            : Expr::make_bin("&", Expr::make_bin(">>", expr_clone(pre), Expr::make_const(top_bit, Width::B), w),
                             Expr::make_const(1, Width::B), Width::B);
        auto cyf = std::make_shared<FlagDef>(FlagDef{FlagKind::CarryVal, Width::B, new_cy, nullptr, nullptr});

        ExprPtr upre = Expr::make_un(is_word ? "u16" : "u8", pre, w);
        ExprPtr cy_in = Expr::make_bin("&", Expr::make_reg("cy"), Expr::make_const(1, Width::B), Width::B);
        ExprPtr raw;
        if (m == Mnem::Ror) {
            raw = Expr::make_bin("|",
                                 Expr::make_bin(">>", upre, Expr::make_const(1, Width::B), w),
                                 Expr::make_bin("<<", expr_clone(upre), Expr::make_const(7, Width::B), w), w);
        } else if (m == Mnem::Rol) {
            raw = Expr::make_bin("|",
                                 Expr::make_bin("<<", upre, Expr::make_const(1, Width::B), w),
                                 Expr::make_bin(">>", expr_clone(upre), Expr::make_const(7, Width::B), w), w);
        } else if (m == Mnem::Rorc) {
            raw = Expr::make_bin("|",
                                 Expr::make_bin(">>", upre, Expr::make_const(1, Width::B), w),
                                 Expr::make_bin("<<", cy_in, Expr::make_const(7, Width::B), w), w);
        } else { // Rolc / Rolwc
            raw = Expr::make_bin("|",
                                 Expr::make_bin("<<", upre, Expr::make_const(1, Width::B), w),
                                 Expr::make_un(is_word ? "u16" : "u8", cy_in, w), w);
        }
        ExprPtr rhs = Expr::make_un(is_word ? "u16" : "u8", raw, w);
        return {make_assign(ea, dst, rhs, nullptr, cyf)};
    }

    // --- Bit Manipulation ---
    if (m == Mnem::Set1 || m == Mnem::Clr1 || m == Mnem::Not1) {
        ExprPtr tgt = e(0);
        if (tgt->kind == ExprKind::Reg && tgt->name == "cy") {
            ExprPtr val = (m == Mnem::Set1)
                ? Expr::make_const(1)
                : ((m == Mnem::Clr1) ? Expr::make_const(0) : Expr::make_un("!", expr_clone(tgt)));
            auto cyf = std::make_shared<FlagDef>(FlagDef{FlagKind::CarryVal, Width::B, expr_clone(val), nullptr, nullptr});
            return {make_assign(ea, tgt, val, nullptr, cyf)};
        }
        uint8_t bit = tgt->bit;
        ExprPtr base = tgt->base;
        uint32_t mask = 1u << bit;
        const char *op = (m == Mnem::Set1) ? "|" : (m == Mnem::Clr1) ? "&" : "^";
        ExprPtr rhs_mask = Expr::make_const((m == Mnem::Clr1) ? ((~mask) & 0xFFu) : mask);
        bool is_psw = (base->kind == ExprKind::Reg && base->name == "psw");
        FlagDefPtr zf = is_psw ? std::make_shared<FlagDef>(FlagDef{FlagKind::Unknown, Width::B, nullptr, nullptr, nullptr}) : nullptr;
        FlagDefPtr cyf = is_psw ? std::make_shared<FlagDef>(FlagDef{FlagKind::Unknown, Width::B, nullptr, nullptr, nullptr}) : nullptr;
        return {make_assign(ea, expr_clone(base), Expr::make_bin(op, base, rhs_mask, Width::B), zf, cyf)};
    }

    if (m == Mnem::Mov1 || m == Mnem::And1 || m == Mnem::Or1 || m == Mnem::Xor1) {
        ExprPtr dst = e(0), src = e(1);
        if (dst->kind == ExprKind::Reg && dst->name == "cy") {
            ExprPtr rhs = src;
            if (m != Mnem::Mov1) {
                const char *op = (m == Mnem::And1) ? "&" : (m == Mnem::Or1) ? "|" : "^";
                rhs = Expr::make_bin(op, expr_clone(dst), src, Width::B);
            }
            auto cyf = std::make_shared<FlagDef>(FlagDef{FlagKind::CarryVal, Width::B, expr_clone(rhs), nullptr, nullptr});
            return {make_assign(ea, dst, rhs, nullptr, cyf)};
        }
        // MOV1 bit, CY -> base = (base & ~(1 << bit)) | ((CY & 1) << bit) (preserves CY, native C!)
        uint8_t bit = dst->bit;
        ExprPtr base = dst->base;
        uint32_t clr_mask = (~(1u << bit)) & 0xFFu;
        ExprPtr cleared = Expr::make_bin("&", expr_clone(base), Expr::make_const(clr_mask), Width::B);
        ExprPtr cy_bit = Expr::make_bin("&", src, Expr::make_const(1), Width::B);
        ExprPtr shifted = (bit == 0) ? cy_bit : Expr::make_bin("<<", cy_bit, Expr::make_const(bit), Width::B);
        ExprPtr rhs = Expr::make_bin("|", cleared, shifted, Width::B);
        bool is_psw = (base->kind == ExprKind::Reg && base->name == "psw");
        FlagDefPtr zf = is_psw ? std::make_shared<FlagDef>(FlagDef{FlagKind::Unknown, Width::B, nullptr, nullptr, nullptr}) : nullptr;
        FlagDefPtr cyf = is_psw ? std::make_shared<FlagDef>(FlagDef{FlagKind::Unknown, Width::B, nullptr, nullptr, nullptr}) : nullptr;
        return {make_assign(ea, base, rhs, zf, cyf)};
    }

    // --- Control Flow ---
    if (m == Mnem::Br) {
        if (!ins.ops.empty() && (ins.ops[0].mode == OpMode::Near || ins.ops[0].mode == OpMode::Far)) {
            return {make_goto(ea, ins.ops[0].addr)};
        }
        return {make_intrinsic(ea, "goto", {e(0)}, "indirect")};
    }

    if (is_cond_branch_mnem(m)) {
        const char *cond = "z";
        switch (m) {
            case Mnem::Bc:  cond = "cy";  break;
            case Mnem::Bnc: cond = "ncy"; break;
            case Mnem::Bz:  cond = "z";   break;
            case Mnem::Bnz: cond = "nz";  break;
            case Mnem::Bh:  cond = "h";   break;
            case Mnem::Bnh: cond = "nh";  break;
            default: break;
        }
        uint32_t tgt = target_of(ins).value_or(ea + static_cast<uint32_t>(ins.size));
        return {make_branch(ea, cond, tgt, ea + static_cast<uint32_t>(ins.size))};
    }

    if (is_bit_branch_mnem(m)) {
        bool sense = (m != Mnem::Bf);
        bool btclr = (m == Mnem::Btclr);
        uint32_t tgt = target_of(ins).value_or(ea + static_cast<uint32_t>(ins.size));
        return {make_bittest_branch(ea, e(0), sense, tgt, ea + static_cast<uint32_t>(ins.size), btclr)};
    }

    if (m == Mnem::Call) {
        if (!ins.ops.empty() && (ins.ops[0].mode == OpMode::Near || ins.ops[0].mode == OpMode::Far)) {
            return {make_call(ea, ins.ops[0].addr, nullptr)};
        }
        return {make_call(ea, std::nullopt, e(0))};
    }
    if (m == Mnem::Callt) {
        if (!ins.ops.empty() && ins.ops[0].value != 0) {
            return {make_call(ea, ins.ops[0].value, nullptr)};
        }
        uint32_t vec_addr = !ins.ops.empty() ? ins.ops[0].addr : 0;
        return {make_call(ea, std::nullopt, Expr::make_mem_abs(vec_addr, Width::W))};
    }
    if (is_ret_mnem(m)) {
        return {make_ret(ea, mnem_name(m), nullptr)};
    }

    // --- Stack / CPU control ---
    if (m == Mnem::Push || m == Mnem::Pop) {
        return {make_intrinsic(ea, mnem_name(m), {e(0)})};
    }
    if (m == Mnem::Sel) {
        return {make_intrinsic(ea, "sel", {e(0)})};
    }
    if (m == Mnem::Brk) {
        if (ins.vector_target.has_value()) {
            return {make_intrinsic(ea, "brk", {Expr::make_const(*ins.vector_target, Width::A)}, "swi [0x007E]")};
        }
        return {make_intrinsic(ea, "brk", {}, "swi [0x007E]")};
    }
    if (m == Mnem::Nop) return {make_nop(ea)};
    if (m == Mnem::Ei || m == Mnem::Di || m == Mnem::Halt || m == Mnem::Stop || m == Mnem::Brk1) {
        return {make_intrinsic(ea, mnem_name(m), {})};
    }

    std::vector<ExprPtr> args;
    for (size_t i = 0; i < ins.ops.size(); ++i) args.push_back(e(i));
    return {make_intrinsic(ea, std::string("__rl78_unhandled_") + mnem_name(m), std::move(args), "unmodelled")};
}

} // namespace rl78dec
