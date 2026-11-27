#include "rl78dec/decoder.hpp"
#include "rl78dec/switch_table.hpp"

#include <unordered_set>

namespace rl78dec {

namespace {

constexpr Mnem kAlu8[9] = {
    Mnem::Add, Mnem::Addc, Mnem::Sub, Mnem::Subc,
    Mnem::Cmp, Mnem::And,  Mnem::Or,  Mnem::Xor, Mnem::Xch,
};

constexpr Mnem kMap71[16] = {
    Mnem::Set1, Mnem::Mov1, Mnem::Set1, Mnem::Clr1,
    Mnem::Mov1, Mnem::And1, Mnem::Or1,  Mnem::Xor1,
    Mnem::Clr1, Mnem::Mov1, Mnem::Set1, Mnem::Clr1,
    Mnem::Mov1, Mnem::And1, Mnem::Or1,  Mnem::Xor1,
};

struct Dec {
    const IDatabaseProvider &db;
    uint32_t ea = 0;
    uint32_t pos = 0;
    bool es = false;
    bool eof = false;
    DecodedInsn ins;

    Dec(const IDatabaseProvider &provider, uint32_t start_ea)
        : db(provider), ea(start_ea), pos(start_ea) {
        ins.ea = start_ea;
    }

    uint8_t u8() {
        uint8_t b = 0;
        if (!db.read_u8(pos, &b)) {
            eof = true;
            return 0;
        }
        ++pos;
        return b;
    }

    uint16_t u16() {
        uint16_t lo = u8();
        uint16_t hi = u8();
        return static_cast<uint16_t>(lo | (hi << 8));
    }

    int consumed() const { return static_cast<int>(pos - ea); }

    static Operand convert_special(Operand op) {
        if (op.mode == OpMode::Mem) {
            if (auto sr = special_reg(op.addr, op.width); sr.has_value()) {
                Operand r;
                r.mode = OpMode::Reg;
                r.reg = reg_from_name(*sr);
                r.width = reg_default_width(r.reg);
                return r;
            }
        } else if (op.mode == OpMode::Bit && op.bit_base == BitBase::Mem) {
            if (auto sr = special_reg(op.addr, Width::B); sr.has_value()) {
                Operand r;
                r.mode = OpMode::Bit;
                r.bit_base = BitBase::Reg;
                r.reg = reg_from_name(*sr);
                r.bit = op.bit;
                return r;
            }
        }
        return op;
    }

    void add(const Operand &op) { ins.ops.push_back(op); }

    void imm_val(uint32_t v) {
        Operand op;
        op.mode = OpMode::Imm;
        op.value = v;
        op.width = Width::B;
        add(op);
    }

    void imm8() {
        imm_val(u8());
    }

    void imm16() {
        Operand op;
        op.mode = OpMode::Imm;
        op.value = u16();
        op.width = Width::W;
        add(op);
    }

    void reg(RegId r) {
        Operand op;
        op.mode = OpMode::Reg;
        op.reg = r;
        op.width = reg_default_width(r);
        add(op);
    }

    void saddr(Width w = Width::B) {
        Operand op;
        op.mode = OpMode::Mem;
        op.addr = saddr_abs(u8());
        op.width = w;
        add(op);
    }

    void saddrp() { saddr(Width::W); }

    void sfr(Width w = Width::B) {
        Operand op;
        op.mode = OpMode::Mem;
        op.addr = sfr_abs(u8());
        op.width = w;
        add(convert_special(op));
    }

    void sfrp() { sfr(Width::W); }

    void r_bit(RegId r, uint8_t bit) {
        Operand op;
        op.mode = OpMode::Bit;
        op.bit_base = BitBase::Reg;
        op.reg = r;
        op.bit = bit;
        add(op);
    }

    void saddr_bit(uint8_t bit) {
        Operand op;
        op.mode = OpMode::Bit;
        op.bit_base = BitBase::Mem;
        op.addr = saddr_abs(u8());
        op.bit = bit;
        add(op);
    }

    void sfr_bit(uint8_t bit) {
        Operand op;
        op.mode = OpMode::Bit;
        op.bit_base = BitBase::Mem;
        op.addr = sfr_abs(u8());
        op.bit = bit;
        add(convert_special(op));
    }

    void r_ind(RegId base, Width w = Width::B) {
        Operand op;
        op.mode = OpMode::Ind;
        op.base_reg = base;
        op.disp = 0;
        op.width = w;
        op.es = es;
        add(op);
    }

    void r_ind_bit(RegId base, uint8_t bit) {
        Operand op;
        op.mode = OpMode::Bit;
        op.bit_base = BitBase::Ind;
        op.base_reg = base;
        op.bit = bit;
        op.es = es;
        add(op);
    }

    void r_off_imm8(RegId base, Width w = Width::B) {
        Operand op;
        op.mode = OpMode::Ind;
        op.base_reg = base;
        op.disp = u8();
        op.width = w;
        op.es = es;
        add(op);
    }

    void r_off_imm16(RegId base, Width w = Width::B) {
        Operand op;
        op.mode = OpMode::Idx16;
        op.base_reg = base;
        op.disp = u16();
        op.width = w;
        op.es = es;
        add(op);
    }

    void hl_off_reg(RegId idx) {
        Operand op;
        op.mode = OpMode::Hloff;
        op.base_reg = idx;
        op.width = Width::B;
        op.es = es;
        add(op);
    }

    void addr_rel() {
        int8_t disp = static_cast<int8_t>(u8());
        uint32_t tgt = static_cast<uint32_t>(static_cast<int32_t>(ea) + consumed() + disp) & 0xFFFFFu;
        Operand op;
        op.mode = OpMode::Near;
        op.addr = tgt;
        op.width = Width::A;
        add(op);
    }

    void addr16_rel() {
        int16_t disp = static_cast<int16_t>(u16());
        uint32_t tgt = static_cast<uint32_t>(static_cast<int32_t>(ea) + consumed() + disp) & 0xFFFFFu;
        Operand op;
        op.mode = OpMode::Near;
        op.addr = tgt;
        op.width = Width::A;
        add(op);
    }

    void addr16_abs() {
        Operand op;
        op.mode = OpMode::Near;
        op.addr = u16();
        op.width = Width::A;
        add(op);
    }

    void addr16_abs_d(Width w = Width::B) {
        uint32_t addr = u16();
        if (!es) addr += (0xFu << 16);
        Operand op;
        op.mode = OpMode::Mem;
        op.addr = addr;
        op.width = w;
        op.es = es;
        add(convert_special(op));
    }

    void addr16_abs_d16() { addr16_abs_d(Width::W); }

    void addr16_abs_bit(uint8_t bit) {
        uint32_t addr = u16();
        if (!es) addr += (0xFu << 16);
        Operand op;
        op.mode = OpMode::Bit;
        op.bit_base = BitBase::Mem;
        op.addr = addr;
        op.bit = bit;
        op.es = es;
        add(convert_special(op));
    }

    void addr20_abs() {
        uint32_t addr = u16();
        addr |= static_cast<uint32_t>(u8()) << 16;
        Operand op;
        op.mode = OpMode::Far;
        op.addr = addr;
        op.width = Width::A;
        add(op);
    }

    std::optional<uint32_t> read_vector16(uint32_t vec_addr) const {
        uint16_t tgt = 0;
        if (db.read_u16_le(vec_addr, &tgt) && tgt > 0 && tgt != 0xFFFFu) {
            return static_cast<uint32_t>(tgt);
        }
        return std::nullopt;
    }

    void callt(uint32_t addr) {
        Operand op;
        op.mode = OpMode::Callt;
        op.addr = addr;
        op.value = read_vector16(addr).value_or(0);
        op.width = Width::W;
        add(op);
    }

    std::optional<DecodedInsn> finish(Mnem m) {
        if (eof) return std::nullopt;
        ins.mnem = m;
        ins.es = es;
        ins.size = consumed();
        ins.raw.resize(static_cast<size_t>(ins.size));
        if (ins.size > 0) {
            db.read_bytes(ea, ins.raw.data(), ins.raw.size());
        }
        return std::move(ins);
    }
};

std::optional<DecodedInsn> decode_map31(Dec &d) {
    uint8_t code = d.u8();
    if (d.eof) return std::nullopt;
    uint8_t lo = code & 0xFu;
    uint8_t hi = (code >> 4) & 0xFu;
    if (lo <= 5) {
        static constexpr Mnem kBt[6] = {Mnem::Btclr, Mnem::Btclr, Mnem::Bt, Mnem::Bt, Mnem::Bf, Mnem::Bf};
        Mnem mnem = kBt[lo];
        uint8_t bit = hi & 7u;
        uint8_t sel = code & 0x81u;
        if (sel == 0x00)      d.saddr_bit(bit);
        else if (sel == 0x01) d.r_bit(RegId::A, bit);
        else if (sel == 0x80) d.sfr_bit(bit);
        else                  d.r_ind_bit(RegId::HL, bit);
        d.addr_rel();
        return d.finish(mnem);
    }
    if (lo >= 7 && lo <= 0xB && hi >= 1 && hi <= 7) {
        static constexpr Mnem kSh[5] = {Mnem::Shl, Mnem::Shl, Mnem::Shl, Mnem::Shr, Mnem::Sar};
        Mnem mnem = kSh[lo - 7];
        if (mnem == Mnem::Shl) {
            static constexpr RegId kReg[3] = {RegId::C, RegId::B, RegId::A};
            d.reg(kReg[lo - 7]);
        } else {
            d.reg(RegId::A);
        }
        d.imm_val(hi);
        return d.finish(mnem);
    }
    if (lo >= 0xC && hi >= 1) {
        static constexpr Mnem kShw[4] = {Mnem::Shlw, Mnem::Shlw, Mnem::Shrw, Mnem::Sarw};
        Mnem mnem = kShw[lo - 0xC];
        if (mnem == Mnem::Shlw) {
            d.reg((lo == 0xC) ? RegId::BC : RegId::AX);
        } else {
            d.reg(RegId::AX);
        }
        d.imm_val(hi);
        return d.finish(mnem);
    }
    return std::nullopt;
}

std::optional<DecodedInsn> decode_map61(Dec &d) {
    uint8_t code = d.u8();
    if (d.eof) return std::nullopt;
    uint8_t lo = code & 0xFu;
    uint8_t hi = (code >> 4) & 0xFu;

    if (hi <= 7 && lo <= 7) {
        d.reg(R8_LUT[lo]);
        d.reg(RegId::A);
        return d.finish(kAlu8[hi]);
    }
    if ((hi <= 7 && lo == 8) || (hi <= 8 && lo >= 0xA)) {
        d.reg(RegId::A);
        d.reg(R8_LUT[lo & 7u]);
        return d.finish(kAlu8[hi]);
    }
    if (hi >= 8 && lo >= 4 && lo <= 7) {
        uint32_t addr = 0x80u | ((lo & 3u) << 4) | ((hi & 7u) << 1);
        d.callt(addr);
        return d.finish(Mnem::Callt);
    }

    switch (code) {
        case 0x09: d.reg(RegId::AX); d.r_off_imm8(RegId::HL, Width::W); return d.finish(Mnem::Addw);
        case 0x29: d.reg(RegId::AX); d.r_off_imm8(RegId::HL, Width::W); return d.finish(Mnem::Subw);
        case 0x49: d.reg(RegId::AX); d.r_off_imm8(RegId::HL, Width::W); return d.finish(Mnem::Cmpw);
        case 0x59: d.r_off_imm8(RegId::HL); return d.finish(Mnem::Inc);
        case 0x69: d.r_off_imm8(RegId::HL); return d.finish(Mnem::Dec);
        case 0x79: d.r_off_imm8(RegId::HL, Width::W); return d.finish(Mnem::Incw);
        case 0x89: d.r_off_imm8(RegId::HL, Width::W); return d.finish(Mnem::Decw);
        case 0xC3: d.addr_rel(); return d.finish(Mnem::Bh);
        case 0xD3: d.addr_rel(); return d.finish(Mnem::Bnh);
        case 0xE3: return d.finish(Mnem::Skh);
        case 0xF3: return d.finish(Mnem::Sknh);
        case 0xA8: d.reg(RegId::A); d.saddr(); return d.finish(Mnem::Xch);
        case 0xB8: d.reg(RegId::ES); d.saddr(); return d.finish(Mnem::Mov);
        case 0xA9: d.reg(RegId::A); d.hl_off_reg(RegId::C); return d.finish(Mnem::Xch);
        case 0xB9: d.reg(RegId::A); d.hl_off_reg(RegId::B); return d.finish(Mnem::Xch);
        case 0xAA: d.reg(RegId::A); d.addr16_abs_d(); return d.finish(Mnem::Xch);
        case 0xAB: d.reg(RegId::A); d.sfr(); return d.finish(Mnem::Xch);
        case 0xAC: d.reg(RegId::A); d.r_ind(RegId::HL); return d.finish(Mnem::Xch);
        case 0xAD: d.reg(RegId::A); d.r_off_imm8(RegId::HL); return d.finish(Mnem::Xch);
        case 0xAE: d.reg(RegId::A); d.r_ind(RegId::DE); return d.finish(Mnem::Xch);
        case 0xAF: d.reg(RegId::A); d.r_off_imm8(RegId::DE); return d.finish(Mnem::Xch);
        case 0xC8: return d.finish(Mnem::Skc);
        case 0xD8: return d.finish(Mnem::Sknc);
        case 0xE8: return d.finish(Mnem::Skz);
        case 0xF8: return d.finish(Mnem::Sknz);
        case 0xC9: d.reg(RegId::A); d.hl_off_reg(RegId::B); return d.finish(Mnem::Mov);
        case 0xD9: d.hl_off_reg(RegId::B); d.reg(RegId::A); return d.finish(Mnem::Mov);
        case 0xE9: d.reg(RegId::A); d.hl_off_reg(RegId::C); return d.finish(Mnem::Mov);
        case 0xF9: d.hl_off_reg(RegId::C); d.reg(RegId::A); return d.finish(Mnem::Mov);
        case 0xCB: d.reg(RegId::AX); return d.finish(Mnem::Br);
        case 0xDB: d.reg(RegId::A); d.imm_val(1); return d.finish(Mnem::Ror);
        case 0xEB: d.reg(RegId::A); d.imm_val(1); return d.finish(Mnem::Rol);
        case 0xFB: d.reg(RegId::A); d.imm_val(1); return d.finish(Mnem::Rorc);
        case 0xCC: d.ins.vector_target = d.read_vector16(BRK_VECTOR); return d.finish(Mnem::Brk);
        case 0xDC: d.reg(RegId::A); d.imm_val(1); return d.finish(Mnem::Rolc);
        case 0xEC: return d.finish(Mnem::Retb);
        case 0xFC: return d.finish(Mnem::Reti);
        case 0xCD: d.reg(RegId::PSW); return d.finish(Mnem::Pop);
        case 0xDD: d.reg(RegId::PSW); return d.finish(Mnem::Push);
        case 0xED: return d.finish(Mnem::Halt);
        case 0xFD: return d.finish(Mnem::Stop);
        case 0xCE: d.r_off_imm8(RegId::HL); d.reg(RegId::X); return d.finish(Mnem::Movs);
        case 0xDE: d.reg(RegId::X); d.r_off_imm8(RegId::HL); return d.finish(Mnem::Cmps);
        case 0xEE: d.reg(RegId::AX); d.imm_val(1); return d.finish(Mnem::Rolwc);
        case 0xFE: d.reg(RegId::BC); d.imm_val(1); return d.finish(Mnem::Rolwc);
        default: break;
    }

    if (lo == 0 && (code == 0x80 || code == 0x90 || code == 0xA0 || code == 0xB0 ||
                    code == 0xC0 || code == 0xD0 || code == 0xE0 || code == 0xF0)) {
        d.reg(RegId::A);
        d.hl_off_reg(RegId::B);
        return d.finish(kAlu8[hi & 7u]);
    }
    if (lo == 2 && (code == 0x82 || code == 0x92 || code == 0xA2 || code == 0xB2 ||
                    code == 0xC2 || code == 0xD2 || code == 0xE2 || code == 0xF2)) {
        d.reg(RegId::A);
        d.hl_off_reg(RegId::C);
        return d.finish(kAlu8[hi & 7u]);
    }
    if (lo == 0xA && (code == 0xCA || code == 0xDA || code == 0xEA || code == 0xFA)) {
        d.reg(R16_LUT[hi & 3u]);
        return d.finish(Mnem::Call);
    }
    if (lo == 0xF && (code == 0xCF || code == 0xDF || code == 0xEF || code == 0xFF)) {
        d.reg(RB_LUT[hi & 3u]);
        return d.finish(Mnem::Sel);
    }
    return std::nullopt;
}

std::optional<DecodedInsn> decode_map71(Dec &d) {
    uint8_t code = d.u8();
    if (d.eof) return std::nullopt;
    uint8_t lo = code & 0xFu;
    uint8_t hi = (code >> 4) & 0xFu;

    if (hi >= 8 && lo == 0) {
        if (hi == 8) { d.reg(RegId::CY); return d.finish(Mnem::Set1); }
        if (hi == 0xC) { d.reg(RegId::CY); return d.finish(Mnem::Not1); }
        return std::nullopt;
    }
    if (hi >= 8 && lo == 8) {
        if (hi == 8) { d.reg(RegId::CY); return d.finish(Mnem::Clr1); }
        return std::nullopt;
    }

    Mnem mnem = kMap71[lo];
    uint8_t bit = hi & 7u;
    uint8_t sel = code & 0x8Fu;

    switch (sel) {
        case 0x01: d.saddr_bit(bit); d.reg(RegId::CY); break;
        case 0x81: d.r_ind_bit(RegId::HL, bit); d.reg(RegId::CY); break;
        case 0x02:
        case 0x03: d.saddr_bit(bit); break;
        case 0x82:
        case 0x83: d.r_ind_bit(RegId::HL, bit); break;
        case 0x04: case 0x05: case 0x06: case 0x07:
            d.reg(RegId::CY); d.saddr_bit(bit); break;
        case 0x84: case 0x85: case 0x86: case 0x87:
            d.reg(RegId::CY); d.r_ind_bit(RegId::HL, bit); break;
        case 0x00:
        case 0x08: d.addr16_abs_bit(bit); break;
        case 0x09: d.sfr_bit(bit); d.reg(RegId::CY); break;
        case 0x89: d.r_bit(RegId::A, bit); d.reg(RegId::CY); break;
        case 0x0A:
        case 0x0B: {
            uint8_t sfr_byte = d.u8();
            if (bit == 7 && sfr_byte == 0xFAu) {
                return d.finish(lo == 0x0Au ? Mnem::Ei : Mnem::Di);
            }
            Operand op;
            op.mode = OpMode::Bit;
            op.bit_base = BitBase::Mem;
            op.addr = sfr_abs(sfr_byte);
            op.bit = bit;
            d.add(Dec::convert_special(op));
            break;
        }
        case 0x8A:
        case 0x8B: d.r_bit(RegId::A, bit); break;
        case 0x0C: case 0x0D: case 0x0E: case 0x0F:
            d.reg(RegId::CY); d.sfr_bit(bit); break;
        case 0x8C: case 0x8D: case 0x8E: case 0x8F:
            d.reg(RegId::CY); d.r_bit(RegId::A, bit); break;
        default:
            return std::nullopt;
    }
    return d.finish(mnem);
}

std::optional<DecodedInsn> decode_main(Dec &d, uint8_t code) {
    uint8_t lo = code & 0xFu;
    uint8_t hi = (code >> 4) & 0xFu;

    if (lo >= 0xA && hi <= 7) {
        Mnem mnem = kAlu8[hi];
        if (lo == 0xA) d.saddr();
        else           d.reg(RegId::A);

        if (lo == 0xA || lo == 0xC)      d.imm8();
        else if (lo == 0xB)              d.saddr();
        else if (lo == 0xD)              d.r_ind(RegId::HL);
        else if (lo == 0xE)              d.r_off_imm8(RegId::HL);
        else if (lo == 0xF)              d.addr16_abs_d();
        return d.finish(mnem);
    }

    if (code == 0x31) return decode_map31(d);
    if (code == 0x61) return decode_map61(d);
    if (code == 0x71) return decode_map71(d);

    if (code >= 0x50 && code <= 0x57) { d.reg(R8_LUT[lo]); d.imm8(); return d.finish(Mnem::Mov); }
    if (code == 0x60 || (code >= 0x62 && code <= 0x67)) { d.reg(RegId::A); d.reg(R8_LUT[lo]); return d.finish(Mnem::Mov); }
    if (code == 0x70 || (code >= 0x72 && code <= 0x77)) { d.reg(R8_LUT[lo]); d.reg(RegId::A); return d.finish(Mnem::Mov); }
    if (code >= 0x80 && code <= 0x87) { d.reg(R8_LUT[lo]); return d.finish(Mnem::Inc); }
    if (code >= 0x90 && code <= 0x97) { d.reg(R8_LUT[lo]); return d.finish(Mnem::Dec); }
    if (code >= 0xD0 && code <= 0xD3) { d.reg(R8_LUT[lo]); return d.finish(Mnem::Cmp0); }
    if (code >= 0xE0 && code <= 0xE3) { d.reg(R8_LUT[lo]); return d.finish(Mnem::Oneb); }
    if (code >= 0xF0 && code <= 0xF3) { d.reg(R8_LUT[lo]); return d.finish(Mnem::Clrb); }
    if (code == 0xC0 || code == 0xC2 || code == 0xC4 || code == 0xC6) { d.reg(R16_LUT[lo >> 1]); return d.finish(Mnem::Pop); }
    if (code == 0xC1 || code == 0xC3 || code == 0xC5 || code == 0xC7) { d.reg(R16_LUT[lo >> 1]); return d.finish(Mnem::Push); }
    if (code == 0xE6 || code == 0xE7) { d.reg(R16_LUT[lo & 1u]); return d.finish(Mnem::Onew); }
    if (code == 0xF6 || code == 0xF7) { d.reg(R16_LUT[lo & 1u]); return d.finish(Mnem::Clrw); }

    switch (code) {
        case 0x00: return d.finish(Mnem::Nop);
        case 0x01: d.reg(RegId::AX); d.reg(RegId::AX); return d.finish(Mnem::Addw);
        case 0x02: d.reg(RegId::AX); d.addr16_abs_d16(); return d.finish(Mnem::Addw);
        case 0x03: d.reg(RegId::AX); d.reg(RegId::BC); return d.finish(Mnem::Addw);
        case 0x04: d.reg(RegId::AX); d.imm16(); return d.finish(Mnem::Addw);
        case 0x05: d.reg(RegId::AX); d.reg(RegId::DE); return d.finish(Mnem::Addw);
        case 0x06: d.reg(RegId::AX); d.saddrp(); return d.finish(Mnem::Addw);
        case 0x07: d.reg(RegId::AX); d.reg(RegId::HL); return d.finish(Mnem::Addw);
        case 0x08: d.reg(RegId::A); d.reg(RegId::X); return d.finish(Mnem::Xch);
        case 0x09: d.reg(RegId::A); d.r_off_imm16(RegId::B); return d.finish(Mnem::Mov);
        case 0x10: d.reg(RegId::SP); d.imm8(); return d.finish(Mnem::Addw);
        case 0x12: d.reg(RegId::BC); d.reg(RegId::AX); return d.finish(Mnem::Movw);
        case 0x13: d.reg(RegId::AX); d.reg(RegId::BC); return d.finish(Mnem::Movw);
        case 0x14: d.reg(RegId::DE); d.reg(RegId::AX); return d.finish(Mnem::Movw);
        case 0x15: d.reg(RegId::AX); d.reg(RegId::DE); return d.finish(Mnem::Movw);
        case 0x16: d.reg(RegId::HL); d.reg(RegId::AX); return d.finish(Mnem::Movw);
        case 0x17: d.reg(RegId::AX); d.reg(RegId::HL); return d.finish(Mnem::Movw);
        case 0x18: d.r_off_imm16(RegId::B); d.reg(RegId::A); return d.finish(Mnem::Mov);
        case 0x19: d.r_off_imm16(RegId::B); d.imm8(); return d.finish(Mnem::Mov);
        case 0x20: d.reg(RegId::SP); d.imm8(); return d.finish(Mnem::Subw);
        case 0x22: d.reg(RegId::AX); d.addr16_abs_d16(); return d.finish(Mnem::Subw);
        case 0x23: d.reg(RegId::AX); d.reg(RegId::BC); return d.finish(Mnem::Subw);
        case 0x24: d.reg(RegId::AX); d.imm16(); return d.finish(Mnem::Subw);
        case 0x25: d.reg(RegId::AX); d.reg(RegId::DE); return d.finish(Mnem::Subw);
        case 0x26: d.reg(RegId::AX); d.saddrp(); return d.finish(Mnem::Subw);
        case 0x27: d.reg(RegId::AX); d.reg(RegId::HL); return d.finish(Mnem::Subw);
        case 0x28: d.r_off_imm16(RegId::C); d.reg(RegId::A); return d.finish(Mnem::Mov);
        case 0x29: d.reg(RegId::A); d.r_off_imm16(RegId::C); return d.finish(Mnem::Mov);
        case 0x30: d.reg(RegId::AX); d.imm16(); return d.finish(Mnem::Movw);
        case 0x32: d.reg(RegId::BC); d.imm16(); return d.finish(Mnem::Movw);
        case 0x33: d.reg(RegId::AX); d.reg(RegId::BC); return d.finish(Mnem::Xchw);
        case 0x34: d.reg(RegId::DE); d.imm16(); return d.finish(Mnem::Movw);
        case 0x35: d.reg(RegId::AX); d.reg(RegId::DE); return d.finish(Mnem::Xchw);
        case 0x36: d.reg(RegId::HL); d.imm16(); return d.finish(Mnem::Movw);
        case 0x37: d.reg(RegId::AX); d.reg(RegId::HL); return d.finish(Mnem::Xchw);
        case 0x38: d.r_off_imm16(RegId::C); d.imm8(); return d.finish(Mnem::Mov);
        case 0x39: d.r_off_imm16(RegId::BC); d.imm8(); return d.finish(Mnem::Mov);
        case 0x40: d.addr16_abs_d(); d.imm8(); return d.finish(Mnem::Cmp);
        case 0x41: d.reg(RegId::ES); d.imm8(); return d.finish(Mnem::Mov);
        case 0x42: d.reg(RegId::AX); d.addr16_abs_d16(); return d.finish(Mnem::Cmpw);
        case 0x43: d.reg(RegId::AX); d.reg(RegId::BC); return d.finish(Mnem::Cmpw);
        case 0x44: d.reg(RegId::AX); d.imm16(); return d.finish(Mnem::Cmpw);
        case 0x45: d.reg(RegId::AX); d.reg(RegId::DE); return d.finish(Mnem::Cmpw);
        case 0x46: d.reg(RegId::AX); d.saddrp(); return d.finish(Mnem::Cmpw);
        case 0x47: d.reg(RegId::AX); d.reg(RegId::HL); return d.finish(Mnem::Cmpw);
        case 0x48: d.r_off_imm16(RegId::BC); d.reg(RegId::A); return d.finish(Mnem::Mov);
        case 0x49: d.reg(RegId::A); d.r_off_imm16(RegId::BC); return d.finish(Mnem::Mov);
        case 0x58: d.r_off_imm16(RegId::B, Width::W); d.reg(RegId::AX); return d.finish(Mnem::Movw);
        case 0x59: d.reg(RegId::AX); d.r_off_imm16(RegId::B, Width::W); return d.finish(Mnem::Movw);
        case 0x68: d.r_off_imm16(RegId::C, Width::W); d.reg(RegId::AX); return d.finish(Mnem::Movw);
        case 0x69: d.reg(RegId::AX); d.r_off_imm16(RegId::C, Width::W); return d.finish(Mnem::Movw);
        case 0x78: d.r_off_imm16(RegId::BC, Width::W); d.reg(RegId::AX); return d.finish(Mnem::Movw);
        case 0x79: d.reg(RegId::AX); d.r_off_imm16(RegId::BC, Width::W); return d.finish(Mnem::Movw);
        case 0x88: d.reg(RegId::A); d.r_off_imm8(RegId::SP); return d.finish(Mnem::Mov);
        case 0x89: d.reg(RegId::A); d.r_ind(RegId::DE); return d.finish(Mnem::Mov);
        case 0x8A: d.reg(RegId::A); d.r_off_imm8(RegId::DE); return d.finish(Mnem::Mov);
        case 0x8B: d.reg(RegId::A); d.r_ind(RegId::HL); return d.finish(Mnem::Mov);
        case 0x8C: d.reg(RegId::A); d.r_off_imm8(RegId::HL); return d.finish(Mnem::Mov);
        case 0x8D: d.reg(RegId::A); d.saddr(); return d.finish(Mnem::Mov);
        case 0x8E: d.reg(RegId::A); d.sfr(); return d.finish(Mnem::Mov);
        case 0x8F: d.reg(RegId::A); d.addr16_abs_d(); return d.finish(Mnem::Mov);
        case 0x98: d.r_off_imm8(RegId::SP); d.reg(RegId::A); return d.finish(Mnem::Mov);
        case 0x99: d.r_ind(RegId::DE); d.reg(RegId::A); return d.finish(Mnem::Mov);
        case 0x9A: d.r_off_imm8(RegId::DE); d.reg(RegId::A); return d.finish(Mnem::Mov);
        case 0x9B: d.r_ind(RegId::HL); d.reg(RegId::A); return d.finish(Mnem::Mov);
        case 0x9C: d.r_off_imm8(RegId::HL); d.reg(RegId::A); return d.finish(Mnem::Mov);
        case 0x9D: d.saddr(); d.reg(RegId::A); return d.finish(Mnem::Mov);
        case 0x9E: d.sfr(); d.reg(RegId::A); return d.finish(Mnem::Mov);
        case 0x9F: d.addr16_abs_d(); d.reg(RegId::A); return d.finish(Mnem::Mov);
        case 0xA0: d.addr16_abs_d(); return d.finish(Mnem::Inc);
        case 0xB0: d.addr16_abs_d(); return d.finish(Mnem::Dec);
        case 0xA1: d.reg(RegId::AX); return d.finish(Mnem::Incw);
        case 0xB1: d.reg(RegId::AX); return d.finish(Mnem::Decw);
        case 0xA2: d.addr16_abs_d16(); return d.finish(Mnem::Incw);
        case 0xB2: d.addr16_abs_d16(); return d.finish(Mnem::Decw);
        case 0xA3: d.reg(RegId::BC); return d.finish(Mnem::Incw);
        case 0xB3: d.reg(RegId::BC); return d.finish(Mnem::Decw);
        case 0xA4: d.saddr(); return d.finish(Mnem::Inc);
        case 0xB4: d.saddr(); return d.finish(Mnem::Dec);
        case 0xA5: d.reg(RegId::DE); return d.finish(Mnem::Incw);
        case 0xB5: d.reg(RegId::DE); return d.finish(Mnem::Decw);
        case 0xA6: d.saddrp(); return d.finish(Mnem::Incw);
        case 0xB6: d.saddrp(); return d.finish(Mnem::Decw);
        case 0xA7: d.reg(RegId::HL); return d.finish(Mnem::Incw);
        case 0xB7: d.reg(RegId::HL); return d.finish(Mnem::Decw);
        case 0xA8: d.reg(RegId::AX); d.r_off_imm8(RegId::SP, Width::W); return d.finish(Mnem::Movw);
        case 0xB8: d.r_off_imm8(RegId::SP, Width::W); d.reg(RegId::AX); return d.finish(Mnem::Movw);
        case 0xA9: d.reg(RegId::AX); d.r_ind(RegId::DE, Width::W); return d.finish(Mnem::Movw);
        case 0xB9: d.r_ind(RegId::DE, Width::W); d.reg(RegId::AX); return d.finish(Mnem::Movw);
        case 0xAA: d.reg(RegId::AX); d.r_off_imm8(RegId::DE, Width::W); return d.finish(Mnem::Movw);
        case 0xBA: d.r_off_imm8(RegId::DE, Width::W); d.reg(RegId::AX); return d.finish(Mnem::Movw);
        case 0xAB: d.reg(RegId::AX); d.r_ind(RegId::HL, Width::W); return d.finish(Mnem::Movw);
        case 0xBB: d.r_ind(RegId::HL, Width::W); d.reg(RegId::AX); return d.finish(Mnem::Movw);
        case 0xAC: d.reg(RegId::AX); d.r_off_imm8(RegId::HL, Width::W); return d.finish(Mnem::Movw);
        case 0xBC: d.r_off_imm8(RegId::HL, Width::W); d.reg(RegId::AX); return d.finish(Mnem::Movw);
        case 0xAD: d.reg(RegId::AX); d.saddrp(); return d.finish(Mnem::Movw);
        case 0xBD: d.saddrp(); d.reg(RegId::AX); return d.finish(Mnem::Movw);
        case 0xAE: d.reg(RegId::AX); d.sfrp(); return d.finish(Mnem::Movw);
        case 0xBE: d.sfrp(); d.reg(RegId::AX); return d.finish(Mnem::Movw);
        case 0xAF: d.reg(RegId::AX); d.addr16_abs_d16(); return d.finish(Mnem::Movw);
        case 0xBF: d.addr16_abs_d16(); d.reg(RegId::AX); return d.finish(Mnem::Movw);
        case 0xC8: d.r_off_imm8(RegId::SP); d.imm8(); return d.finish(Mnem::Mov);
        case 0xC9: d.saddrp(); d.imm16(); return d.finish(Mnem::Movw);
        case 0xCA: d.r_off_imm8(RegId::DE); d.imm8(); return d.finish(Mnem::Mov);
        case 0xCB: d.sfrp(); d.imm16(); return d.finish(Mnem::Movw);
        case 0xCC: d.r_off_imm8(RegId::HL); d.imm8(); return d.finish(Mnem::Mov);
        case 0xCD: d.saddr(); d.imm8(); return d.finish(Mnem::Mov);
        case 0xCE: {
            uint8_t b1 = d.u8();
            uint8_t b2 = d.u8();
            if (d.eof) return std::nullopt;
            if (b1 == 0xFB) {
                switch (b2) {
                    case 0x01: return d.finish(Mnem::Mulhu);
                    case 0x02: return d.finish(Mnem::Mulh);
                    case 0x03: return d.finish(Mnem::Divhu);
                    case 0x05: return d.finish(Mnem::Machu);
                    case 0x06: return d.finish(Mnem::Mach);
                    case 0x0B: return d.finish(Mnem::Divwu);
                    default: break;
                }
            }
            Operand op;
            op.mode = OpMode::Mem;
            op.addr = sfr_abs(b1);
            op.width = Width::B;
            d.add(Dec::convert_special(op));
            d.imm_val(b2);
            return d.finish(Mnem::Mov);
        }
        case 0xCF: d.addr16_abs_d(); d.imm8(); return d.finish(Mnem::Mov);
        case 0xD4: d.saddr(); return d.finish(Mnem::Cmp0);
        case 0xD5: d.addr16_abs_d(); return d.finish(Mnem::Cmp0);
        case 0xD6: d.reg(RegId::X); return d.finish(Mnem::Mulu);
        case 0xD7: return d.finish(Mnem::Ret);
        case 0xD8: d.reg(RegId::X); d.saddr(); return d.finish(Mnem::Mov);
        case 0xE8: d.reg(RegId::B); d.saddr(); return d.finish(Mnem::Mov);
        case 0xF8: d.reg(RegId::C); d.saddr(); return d.finish(Mnem::Mov);
        case 0xD9: d.reg(RegId::X); d.addr16_abs_d(); return d.finish(Mnem::Mov);
        case 0xE9: d.reg(RegId::B); d.addr16_abs_d(); return d.finish(Mnem::Mov);
        case 0xF9: d.reg(RegId::C); d.addr16_abs_d(); return d.finish(Mnem::Mov);
        case 0xDA: d.reg(RegId::BC); d.saddrp(); return d.finish(Mnem::Movw);
        case 0xEA: d.reg(RegId::DE); d.saddrp(); return d.finish(Mnem::Movw);
        case 0xFA: d.reg(RegId::HL); d.saddrp(); return d.finish(Mnem::Movw);
        case 0xDB: d.reg(RegId::BC); d.addr16_abs_d16(); return d.finish(Mnem::Movw);
        case 0xEB: d.reg(RegId::DE); d.addr16_abs_d16(); return d.finish(Mnem::Movw);
        case 0xFB: d.reg(RegId::HL); d.addr16_abs_d16(); return d.finish(Mnem::Movw);
        case 0xDC: d.addr_rel(); return d.finish(Mnem::Bc);
        case 0xDD: d.addr_rel(); return d.finish(Mnem::Bz);
        case 0xDE: d.addr_rel(); return d.finish(Mnem::Bnc);
        case 0xDF: d.addr_rel(); return d.finish(Mnem::Bnz);
        case 0xEC: d.addr20_abs(); return d.finish(Mnem::Br);
        case 0xED: d.addr16_abs(); return d.finish(Mnem::Br);
        case 0xEE: d.addr16_rel(); return d.finish(Mnem::Br);
        case 0xEF: d.addr_rel(); return d.finish(Mnem::Br);
        case 0xE4: d.saddr(); return d.finish(Mnem::Oneb);
        case 0xE5: d.addr16_abs_d(); return d.finish(Mnem::Oneb);
        case 0xF4: d.saddr(); return d.finish(Mnem::Clrb);
        case 0xF5: d.addr16_abs_d(); return d.finish(Mnem::Clrb);
        case 0xFC: d.addr20_abs(); return d.finish(Mnem::Call);
        case 0xFD: d.addr16_abs(); return d.finish(Mnem::Call);
        case 0xFE: d.addr16_rel(); return d.finish(Mnem::Call);
        case 0xFF: return d.finish(Mnem::Brk1);
        default:   return std::nullopt;
    }
}

} // namespace

std::optional<DecodedInsn> decode_one(const IDatabaseProvider &db, uint32_t ea) {
    if (!db.is_loaded(ea)) return std::nullopt;
    Dec d(db, ea);
    uint8_t code = d.u8();
    if (d.eof) return std::nullopt;
    if (code == 0x11) {
        d.es = true;
        code = d.u8();
        if (d.eof) return std::nullopt;
    }
    auto res = decode_main(d, code);
    if (!res.has_value()) return std::nullopt;
    if (res->es) {
        bool applied = false;
        for (const auto &op : res->ops) {
            if (op.es) { applied = true; break; }
        }
        if (!applied) return std::nullopt;
    }
    return res;
}

std::optional<uint32_t> target_of(const DecodedInsn &ins) {
    if (ins.mnem == Mnem::Callt) {
        if (!ins.ops.empty() && ins.ops[0].mode == OpMode::Callt && ins.ops[0].value != 0) {
            return ins.ops[0].value;
        }
        return std::nullopt;
    }
    if (ins.mnem == Mnem::Brk) return ins.vector_target;
    if (ins.ops.empty()) return std::nullopt;
    const Operand &op = is_bit_branch_mnem(ins.mnem) ? ins.ops.back() : ins.ops.front();
    if (op.mode == OpMode::Near || op.mode == OpMode::Far) return op.addr;
    return std::nullopt;
}

std::vector<std::pair<std::string, uint32_t>> insn_succs(const IDatabaseProvider &db, const DecodedInsn &ins) {
    if (ins.sw.has_value()) {
        std::vector<std::pair<std::string, uint32_t>> out;
        for (uint32_t t : ins.sw->targets) out.emplace_back("switch", t);
        return out;
    }
    std::vector<std::pair<std::string, uint32_t>> out;
    auto tgt = target_of(ins);
    if (is_skip_mnem(ins.mnem)) {
        out.emplace_back("fall", ins.ea + static_cast<uint32_t>(ins.size));
        auto nxt = decode_one(db, ins.ea + static_cast<uint32_t>(ins.size));
        if (nxt.has_value() && nxt->size > 0) {
            out.emplace_back("jump", ins.ea + static_cast<uint32_t>(ins.size + nxt->size));
        }
        return out;
    }
    if (ins.mnem == Mnem::Br) {
        if (tgt.has_value()) out.emplace_back("jump", *tgt);
    } else if (is_ret_mnem(ins.mnem) || ins.mnem == Mnem::Brk1 || ins.mnem == Mnem::Stop) {
        // no fallthrough
    } else if (is_cond_branch_mnem(ins.mnem) || is_bit_branch_mnem(ins.mnem)) {
        if (tgt.has_value()) out.emplace_back("jump", *tgt);
        out.emplace_back("fall", ins.ea + static_cast<uint32_t>(ins.size));
    } else if (ins.mnem == Mnem::Call || ins.mnem == Mnem::Callt || ins.mnem == Mnem::Brk) {
        if (tgt.has_value()) out.emplace_back("call", *tgt);
        out.emplace_back("fall", ins.ea + static_cast<uint32_t>(ins.size));
    } else {
        out.emplace_back("fall", ins.ea + static_cast<uint32_t>(ins.size));
    }
    return out;
}

DecodedProgram decode_recursive(const IDatabaseProvider &db, const std::vector<uint32_t> &entries) {
    DecodedProgram prog;
    std::unordered_set<uint32_t> seen;
    std::vector<uint32_t> work;
    for (uint32_t e : entries) {
        if (db.is_loaded(e)) work.push_back(e);
    }
    while (!work.empty()) {
        uint32_t ea = work.back();
        work.pop_back();
        if (!seen.insert(ea).second || !db.is_loaded(ea)) continue;
        auto ins = decode_one(db, ea);
        if (!ins.has_value() || ins->size <= 0) continue;
        prog.insns[ea] = *ins;
        DecodedInsn &stored = prog.insns[ea];
        if (stored.mnem == Mnem::Br && !stored.ops.empty() &&
            stored.ops[0].mode == OpMode::Reg && stored.ops[0].reg == RegId::AX) {
            if (auto sw = detect_switch(db, prog.insns, stored); sw.has_value()) {
                stored.sw = *sw;
            }
        }
        for (const auto &[how, tgt] : insn_succs(db, stored)) {
            if (how == "call") prog.calls.insert(tgt);
            work.push_back(tgt);
        }
    }
    return prog;
}

} // namespace rl78dec
