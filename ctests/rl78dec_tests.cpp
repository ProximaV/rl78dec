#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>
#ifdef _WIN32
#include <process.h>
#endif

#include "rl78dec/database.hpp"
#include "rl78dec/decoder.hpp"
#include "rl78dec/pipeline.hpp"

namespace fs = std::filesystem;

namespace {

int g_pass = 0;
int g_fail = 0;
std::vector<std::string> g_failures;

void fail_msg(const std::string &test_name, const std::string &msg) {
    ++g_fail;
    g_failures.push_back(test_name + ": " + msg);
    std::fprintf(stderr, "[FAIL] %s: %s\n", test_name.c_str(), msg.c_str());
}

void pass_msg(const std::string &test_name) {
    ++g_pass;
    std::printf("[PASS] %s\n", test_name.c_str());
}

#define CHECK(cond, msg)                                                        \
    do {                                                                        \
        if (!(cond)) {                                                          \
            fail_msg(kTestName, std::string(msg) + " (" #cond ")");             \
            return;                                                             \
        }                                                                       \
    } while (0)

// ---------------------------------------------------------------------------
// Independent RL78 / 78K0R Reference Machine (from 78K0R Kx3-L & RL78 manuals)
// ---------------------------------------------------------------------------
struct Rl78RefMachine {
    std::array<uint8_t, 0x100000> mem{};
    uint32_t pc = 0;
    uint16_t sp = 0xFE00;
    uint8_t psw = 0x06; // IE=0, Z=0, RBS1=0, AC=0, RBS0=0, ISP=11, CY=0
    uint8_t cs = 0;
    uint8_t es = 0x0F;
    bool halted = false;
    bool stopped = false;

    static constexpr uint8_t PSW_CY = 0x01;
    static constexpr uint8_t PSW_AC = 0x10;
    static constexpr uint8_t PSW_Z  = 0x40;
    static constexpr uint8_t PSW_IE = 0x80;

    void reset(uint32_t entry_pc = 0x0100, uint16_t init_sp = 0xFE00) {
        mem.fill(0);
        pc = entry_pc;
        sp = init_sp;
        psw = 0x06;
        cs = 0;
        es = 0x0F;
        halted = false;
        stopped = false;
        // Write sentinel return address 0xFFFFF on stack so RET stops execution
        push_ret20(0x0FFFFFu);
    }

    int bank() const { return ((psw >> 4) & 0x2) | ((psw >> 3) & 0x1); }
    void set_bank(int b) {
        psw = static_cast<uint8_t>((psw & ~0x28u) | ((b & 2) ? 0x20u : 0u) | ((b & 1) ? 0x08u : 0u));
    }
    bool z() const { return (psw & PSW_Z) != 0; }
    bool cy() const { return (psw & PSW_CY) != 0; }
    bool ie() const { return (psw & PSW_IE) != 0; }
    void set_z(bool v) { psw = v ? (psw | PSW_Z) : (psw & ~PSW_Z); }
    void set_cy(bool v) { psw = v ? (psw | PSW_CY) : (psw & ~PSW_CY); }
    void set_ie(bool v) { psw = v ? (psw | PSW_IE) : (psw & ~PSW_IE); }

    uint32_t gpr_addr(int r8) const { return 0xFFEF8u - 8u * static_cast<uint32_t>(bank()) + static_cast<uint32_t>(r8); }
    uint8_t r8(int idx) const { return mem[gpr_addr(idx)]; }
    void set_r8(int idx, uint8_t v) { mem[gpr_addr(idx)] = v; }
    uint16_t r16(int pair) const {
        uint32_t a = gpr_addr(pair * 2);
        return static_cast<uint16_t>(mem[a] | (mem[a + 1] << 8));
    }
    void set_r16(int pair, uint16_t v) {
        uint32_t a = gpr_addr(pair * 2);
        mem[a] = static_cast<uint8_t>(v & 0xFFu);
        mem[a + 1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
    }
    uint8_t A() const { return r8(1); }
    uint8_t X() const { return r8(0); }
    uint16_t AX() const { return r16(0); }
    uint16_t BC() const { return r16(1); }
    uint16_t DE() const { return r16(2); }
    uint16_t HL() const { return r16(3); }
    void set_A(uint8_t v) { set_r8(1, v); }
    void set_X(uint8_t v) { set_r8(0, v); }
    void set_AX(uint16_t v) { set_r16(0, v); }
    void set_BC(uint16_t v) { set_r16(1, v); }
    void set_DE(uint16_t v) { set_r16(2, v); }
    void set_HL(uint16_t v) { set_r16(3, v); }

    void load_bytes(uint32_t ea, const std::vector<uint8_t> &bytes) {
        for (size_t i = 0; i < bytes.size(); ++i) mem[(ea + i) & 0xFFFFFu] = bytes[i];
    }

    uint8_t rd8(uint32_t lin) const {
        lin &= 0xFFFFFu;
        if (lin == 0xFFFF8u) return static_cast<uint8_t>(sp & 0xFFu);
        if (lin == 0xFFFF9u) return static_cast<uint8_t>((sp >> 8) & 0xFFu);
        if (lin == 0xFFFFAu) return psw;
        if (lin == 0xFFFFCu) return cs;
        if (lin == 0xFFFFDu) return es;
        return mem[lin];
    }
    void wr8(uint32_t lin, uint8_t v) {
        lin &= 0xFFFFFu;
        if (lin == 0xFFFF8u) { sp = static_cast<uint16_t>((sp & 0xFF00u) | v); return; }
        if (lin == 0xFFFF9u) { sp = static_cast<uint16_t>((sp & 0x00FFu) | (static_cast<uint16_t>(v) << 8)); return; }
        if (lin == 0xFFFFAu) { psw = v; return; }
        if (lin == 0xFFFFCu) { cs = v & 0x0Fu; return; }
        if (lin == 0xFFFFDu) { es = v & 0x0Fu; return; }
        mem[lin] = v;
    }
    uint16_t rd16(uint32_t lin) const {
        return static_cast<uint16_t>(rd8(lin) | (static_cast<uint16_t>(rd8(lin + 1)) << 8));
    }
    void wr16(uint32_t lin, uint16_t v) {
        wr8(lin, static_cast<uint8_t>(v & 0xFFu));
        wr8(lin + 1, static_cast<uint8_t>((v >> 8) & 0xFFu));
    }

    uint32_t seg_addr(uint16_t off, bool has_es) const {
        uint32_t seg = has_es ? (es & 0xFu) : 0xFu;
        return (seg << 16) | off;
    }
    static uint32_t saddr(uint8_t rel) {
        return (rel < 0x20u) ? (0xFFF00u + rel) : (0xFFE00u + rel);
    }
    static uint32_t sfr(uint8_t rel) { return 0xFFF00u + rel; }

    void push16(uint16_t v) {
        sp = static_cast<uint16_t>(sp - 2);
        wr16(0xF0000u | sp, v);
    }
    uint16_t pop16() {
        uint16_t v = rd16(0xF0000u | sp);
        sp = static_cast<uint16_t>(sp + 2);
        return v;
    }
    void push_ret20(uint32_t ret_pc) {
        sp = static_cast<uint16_t>(sp - 4);
        wr8(0xF0000u | sp, static_cast<uint8_t>(ret_pc & 0xFFu));
        wr8(0xF0000u | static_cast<uint16_t>(sp + 1), static_cast<uint8_t>((ret_pc >> 8) & 0xFFu));
        wr8(0xF0000u | static_cast<uint16_t>(sp + 2), static_cast<uint8_t>((ret_pc >> 16) & 0x0Fu));
        wr8(0xF0000u | static_cast<uint16_t>(sp + 3), 0);
    }
    uint32_t pop_ret20() {
        uint32_t r = rd8(0xF0000u | sp) |
                     (static_cast<uint32_t>(rd8(0xF0000u | static_cast<uint16_t>(sp + 1))) << 8) |
                     (static_cast<uint32_t>(rd8(0xF0000u | static_cast<uint16_t>(sp + 2)) & 0x0Fu) << 16);
        sp = static_cast<uint16_t>(sp + 4);
        return r;
    }

    uint8_t fetch8() {
        uint8_t b = mem[pc & 0xFFFFFu];
        pc = (pc + 1) & 0xFFFFFu;
        return b;
    }
    uint16_t fetch16() {
        uint16_t lo = fetch8();
        uint16_t hi = fetch8();
        return static_cast<uint16_t>(lo | (hi << 8));
    }

    int insn_size_at(uint32_t ea) const {
        rl78dec::MemoryDatabaseProvider tmp(0x100000, 0);
        // Only copy a small window around ea
        std::vector<uint8_t> win(8, 0);
        for (size_t i = 0; i < 8; ++i) win[i] = mem[(ea + i) & 0xFFFFFu];
        rl78dec::MemoryDatabaseProvider wdb(win, ea);
        auto dec = rl78dec::decode_one(wdb, ea);
        return dec.has_value() ? dec->size : 1;
    }

    uint8_t alu8(int op, uint8_t dst, uint8_t src, bool write_back, bool &wb) {
        wb = write_back;
        uint16_t res = 0;
        switch (op) {
            case 0: // ADD
                res = static_cast<uint16_t>(dst) + src;
                set_z((res & 0xFFu) == 0);
                set_cy(res > 0xFFu);
                return static_cast<uint8_t>(res);
            case 1: // ADDC
                res = static_cast<uint16_t>(dst) + src + (cy() ? 1u : 0u);
                set_z((res & 0xFFu) == 0);
                set_cy(res > 0xFFu);
                return static_cast<uint8_t>(res);
            case 2: // SUB
                res = static_cast<uint16_t>(dst) - src;
                set_z((res & 0xFFu) == 0);
                set_cy(dst < src);
                return static_cast<uint8_t>(res);
            case 3: { // SUBC
                uint16_t sub_amt = static_cast<uint16_t>(src) + (cy() ? 1u : 0u);
                res = static_cast<uint16_t>(dst) - sub_amt;
                set_z((res & 0xFFu) == 0);
                set_cy(static_cast<uint16_t>(dst) < sub_amt);
                return static_cast<uint8_t>(res);
            }
            case 4: // CMP
                wb = false;
                res = static_cast<uint16_t>(dst) - src;
                set_z((res & 0xFFu) == 0);
                set_cy(dst < src);
                return dst;
            case 5: // AND (Z only!)
                res = dst & src;
                set_z((res & 0xFFu) == 0);
                return static_cast<uint8_t>(res);
            case 6: // OR (Z only!)
                res = dst | src;
                set_z((res & 0xFFu) == 0);
                return static_cast<uint8_t>(res);
            case 7: // XOR (Z only!)
                res = dst ^ src;
                set_z((res & 0xFFu) == 0);
                return static_cast<uint8_t>(res);
            default:
                return dst;
        }
    }

    bool step() {
        if (pc == 0x0FFFFFu || halted || stopped) return false;
        bool has_es = false;
        uint8_t code = fetch8();
        if (code == 0x11) {
            has_es = true;
            code = fetch8();
        }
        uint8_t lo = code & 0xFu;
        uint8_t hi = (code >> 4) & 0xFu;

        if (lo >= 0xA && hi <= 7) {
            uint8_t dst_addr_rel = 0;
            uint8_t dst_val = 0;
            if (lo == 0xA) { dst_addr_rel = fetch8(); dst_val = rd8(saddr(dst_addr_rel)); }
            else { dst_val = A(); }

            uint8_t src_val = 0;
            if (lo == 0xA || lo == 0xC) src_val = fetch8();
            else if (lo == 0xB) src_val = rd8(saddr(fetch8()));
            else if (lo == 0xD) src_val = rd8(seg_addr(HL(), has_es));
            else if (lo == 0xE) src_val = rd8(seg_addr(static_cast<uint16_t>(HL() + fetch8()), has_es));
            else if (lo == 0xF) src_val = rd8(seg_addr(fetch16(), has_es));

            bool wb = false;
            uint8_t res = alu8(hi, dst_val, src_val, true, wb);
            if (wb) {
                if (lo == 0xA) wr8(saddr(dst_addr_rel), res);
                else set_A(res);
            }
            return true;
        }

        if (code == 0x31) {
            uint8_t c2 = fetch8();
            uint8_t l2 = c2 & 0xFu, h2 = (c2 >> 4) & 0xFu;
            if (l2 <= 5) {
                uint8_t bit = h2 & 7u;
                uint8_t sel = c2 & 0x81u;
                uint32_t maddr = 0;
                uint8_t val = 0;
                if (sel == 0x00) { maddr = saddr(fetch8()); val = rd8(maddr); }
                else if (sel == 0x01) { val = A(); }
                else if (sel == 0x80) { maddr = sfr(fetch8()); val = rd8(maddr); }
                else { maddr = seg_addr(HL(), has_es); val = rd8(maddr); }
                int8_t rel = static_cast<int8_t>(fetch8());
                bool bset = ((val >> bit) & 1u) != 0;
                bool take = (l2 <= 3) ? bset : !bset;
                if (l2 <= 1 && bset) {
                    uint8_t nv = static_cast<uint8_t>(val & ~(1u << bit));
                    if (sel == 0x01) set_A(nv);
                    else wr8(maddr, nv);
                }
                if (take) pc = static_cast<uint32_t>(static_cast<int32_t>(pc) + rel) & 0xFFFFFu;
                return true;
            }
            if (l2 >= 7 && l2 <= 0xB && h2 >= 1 && h2 <= 7) {
                int cnt = h2;
                if (l2 <= 9) {
                    int r = (l2 == 7) ? 2 : ((l2 == 8) ? 3 : 1);
                    uint8_t v = r8(r);
                    set_cy(((v >> (8 - cnt)) & 1u) != 0);
                    set_r8(r, static_cast<uint8_t>(v << cnt));
                } else if (l2 == 0xA) {
                    uint8_t v = A();
                    set_cy(((v >> (cnt - 1)) & 1u) != 0);
                    set_A(static_cast<uint8_t>(v >> cnt));
                } else {
                    int8_t sv = static_cast<int8_t>(A());
                    set_cy(((static_cast<uint8_t>(sv) >> (cnt - 1)) & 1u) != 0);
                    set_A(static_cast<uint8_t>(sv >> cnt));
                }
                return true;
            }
            if (l2 >= 0xC && h2 >= 1) {
                int cnt = h2;
                if (l2 <= 0xD) {
                    int p = (l2 == 0xC) ? 1 : 0;
                    uint16_t v = r16(p);
                    set_cy(((v >> (16 - cnt)) & 1u) != 0);
                    set_r16(p, static_cast<uint16_t>(v << cnt));
                } else if (l2 == 0xE) {
                    uint16_t v = AX();
                    set_cy(((v >> (cnt - 1)) & 1u) != 0);
                    set_AX(static_cast<uint16_t>(v >> cnt));
                } else {
                    int16_t sv = static_cast<int16_t>(AX());
                    set_cy(((static_cast<uint16_t>(sv) >> (cnt - 1)) & 1u) != 0);
                    set_AX(static_cast<uint16_t>(sv >> cnt));
                }
                return true;
            }
            return false;
        }

        if (code == 0x61) {
            uint8_t c2 = fetch8();
            uint8_t l2 = c2 & 0xFu, h2 = (c2 >> 4) & 0xFu;
            if (h2 <= 7 && l2 <= 7) {
                bool wb = false;
                uint8_t res = alu8(h2, r8(l2), A(), true, wb);
                if (wb) set_r8(l2, res);
                return true;
            }
            if ((h2 <= 7 && l2 == 8) || (h2 <= 8 && l2 >= 0xA)) {
                if (h2 == 8) {
                    uint8_t t = A();
                    set_A(r8(l2 & 7));
                    set_r8(l2 & 7, t);
                    return true;
                }
                bool wb = false;
                uint8_t res = alu8(h2, A(), r8(l2 & 7), true, wb);
                if (wb) set_A(res);
                return true;
            }
            if (c2 == 0x80 || c2 == 0x90 || c2 == 0xA0 || c2 == 0xB0 ||
                c2 == 0xC0 || c2 == 0xD0 || c2 == 0xE0 || c2 == 0xF0) {
                uint8_t m = rd8(seg_addr(static_cast<uint16_t>(HL() + r8(3)), has_es));
                bool wb = false;
                uint8_t res = alu8(h2 & 7, A(), m, true, wb);
                if (wb) set_A(res);
                return true;
            }
            if (c2 == 0x82 || c2 == 0x92 || c2 == 0xA2 || c2 == 0xB2 ||
                c2 == 0xC2 || c2 == 0xD2 || c2 == 0xE2 || c2 == 0xF2) {
                uint8_t m = rd8(seg_addr(static_cast<uint16_t>(HL() + r8(2)), has_es));
                bool wb = false;
                uint8_t res = alu8(h2 & 7, A(), m, true, wb);
                if (wb) set_A(res);
                return true;
            }
            switch (c2) {
                case 0x09: { uint32_t a = seg_addr(static_cast<uint16_t>(HL() + fetch8()), has_es); uint32_t sum = AX() + rd16(a); set_AX(sum & 0xFFFFu); set_z(AX() == 0); set_cy(sum > 0xFFFFu); return true; }
                case 0x29: { uint32_t a = seg_addr(static_cast<uint16_t>(HL() + fetch8()), has_es); uint16_t v = rd16(a); set_cy(AX() < v); set_AX(AX() - v); set_z(AX() == 0); return true; }
                case 0x49: { uint32_t a = seg_addr(static_cast<uint16_t>(HL() + fetch8()), has_es); uint16_t v = rd16(a); set_cy(AX() < v); set_z(AX() == v); return true; }
                case 0x59: { uint32_t a = seg_addr(static_cast<uint16_t>(HL() + fetch8()), has_es); uint8_t v = rd8(a) + 1; wr8(a, v); set_z(v == 0); return true; }
                case 0x69: { uint32_t a = seg_addr(static_cast<uint16_t>(HL() + fetch8()), has_es); uint8_t v = rd8(a) - 1; wr8(a, v); set_z(v == 0); return true; }
                case 0xC3: { int8_t rel = static_cast<int8_t>(fetch8()); if (!z() && !cy()) pc = (pc + rel) & 0xFFFFFu; return true; }
                case 0xD3: { int8_t rel = static_cast<int8_t>(fetch8()); if (z() || cy()) pc = (pc + rel) & 0xFFFFFu; return true; }
                case 0xE3: { if (!z() && !cy()) pc = (pc + insn_size_at(pc)) & 0xFFFFFu; return true; }
                case 0xF3: { if (z() || cy()) pc = (pc + insn_size_at(pc)) & 0xFFFFFu; return true; }
                case 0xC8: { if (cy()) pc = (pc + insn_size_at(pc)) & 0xFFFFFu; return true; }
                case 0xD8: { if (!cy()) pc = (pc + insn_size_at(pc)) & 0xFFFFFu; return true; }
                case 0xE8: { if (z()) pc = (pc + insn_size_at(pc)) & 0xFFFFFu; return true; }
                case 0xF8: { if (!z()) pc = (pc + insn_size_at(pc)) & 0xFFFFFu; return true; }
                case 0xC9: set_A(rd8(seg_addr(static_cast<uint16_t>(HL() + r8(3)), has_es))); return true;
                case 0xD9: wr8(seg_addr(static_cast<uint16_t>(HL() + r8(3)), has_es), A()); return true;
                case 0xE9: set_A(rd8(seg_addr(static_cast<uint16_t>(HL() + r8(2)), has_es))); return true;
                case 0xF9: wr8(seg_addr(static_cast<uint16_t>(HL() + r8(2)), has_es), A()); return true;
                case 0xCB: pc = AX(); return true;
                case 0xDB: { uint8_t a = A(); bool c = (a & 1) != 0; set_cy(c); set_A((a >> 1) | (c ? 0x80u : 0u)); return true; }
                case 0xEB: { uint8_t a = A(); bool c = (a & 0x80) != 0; set_cy(c); set_A(static_cast<uint8_t>((a << 1) | (c ? 1u : 0u))); return true; }
                case 0xFB: { uint8_t a = A(); bool oc = cy(); set_cy((a & 1) != 0); set_A(static_cast<uint8_t>((a >> 1) | (oc ? 0x80u : 0u))); return true; }
                case 0xDC: { uint8_t a = A(); bool oc = cy(); set_cy((a & 0x80) != 0); set_A(static_cast<uint8_t>((a << 1) | (oc ? 1u : 0u))); return true; }
                case 0xEE: { uint16_t v = AX(); bool oc = cy(); set_cy((v & 0x8000u) != 0); set_AX(static_cast<uint16_t>((v << 1) | (oc ? 1u : 0u))); return true; }
                case 0xFE: { uint16_t v = BC(); bool oc = cy(); set_cy((v & 0x8000u) != 0); set_BC(static_cast<uint16_t>((v << 1) | (oc ? 1u : 0u))); return true; }
                case 0xCE: {
                    uint32_t a = seg_addr(static_cast<uint16_t>(HL() + fetch8()), has_es);
                    uint8_t xv = X();
                    wr8(a, xv);
                    set_z(xv == 0);
                    set_cy(A() == 0 || xv == 0);
                    return true;
                }
                case 0xDE: {
                    uint32_t a = seg_addr(static_cast<uint16_t>(HL() + fetch8()), has_es);
                    uint8_t mv = rd8(a);
                    uint8_t xv = X();
                    set_z(xv == mv);
                    set_cy(xv != mv || A() == 0 || xv == 0);
                    return true;
                }
                case 0xCD: psw = static_cast<uint8_t>(pop16() >> 8); return true;
                case 0xDD: push16(static_cast<uint16_t>(psw) << 8); return true;
                case 0xCF: set_bank(0); return true;
                case 0xDF: set_bank(1); return true;
                case 0xEF: set_bank(2); return true;
                case 0xFF: set_bank(3); return true;
                case 0xCA: case 0xDA: case 0xEA: case 0xFA: {
                    uint16_t t = r16(h2 & 3);
                    push_ret20(pc);
                    pc = t;
                    return true;
                }
                default: return false;
            }
        }

        if (code == 0x71) {
            uint8_t c2 = fetch8();
            uint8_t l2 = c2 & 0xFu, h2 = (c2 >> 4) & 0xFu;
            if (c2 == 0x80) { set_cy(true); return true; }
            if (c2 == 0x88) { set_cy(false); return true; }
            if (c2 == 0xC0) { set_cy(!cy()); return true; }
            uint8_t bit = h2 & 7u;
            uint8_t sel = c2 & 0x8Fu;
            uint32_t addr = 0;
            bool is_a = false;
            if ((sel & 0x0Fu) == 0x00 || (sel & 0x0Fu) == 0x08) addr = seg_addr(fetch16(), has_es);
            else if ((sel & 0x80u) == 0 && (sel & 0x0Fu) >= 1 && (sel & 0x0Fu) <= 7) addr = saddr(fetch8());
            else if ((sel & 0x80u) != 0 && (sel & 0x0Fu) >= 1 && (sel & 0x0Fu) <= 7) addr = seg_addr(HL(), has_es);
            else if ((sel & 0x80u) == 0 && (sel & 0x0Fu) >= 9) {
                uint8_t sfr_r = fetch8();
                if (bit == 7 && sfr_r == 0xFAu && (l2 == 0x0A || l2 == 0x0B)) {
                    set_ie(l2 == 0x0A);
                    return true;
                }
                addr = sfr(sfr_r);
            } else {
                is_a = true;
            }
            uint8_t v = is_a ? A() : rd8(addr);
            bool bval = ((v >> bit) & 1u) != 0;
            switch (l2) {
                case 0: case 2: case 0xA: // SET1
                    v = static_cast<uint8_t>(v | (1u << bit));
                    if (is_a) set_A(v); else wr8(addr, v);
                    return true;
                case 3: case 8: case 0xB: // CLR1
                    v = static_cast<uint8_t>(v & ~(1u << bit));
                    if (is_a) set_A(v); else wr8(addr, v);
                    return true;
                case 1: case 9: // MOV1 bit, CY
                    v = cy() ? static_cast<uint8_t>(v | (1u << bit)) : static_cast<uint8_t>(v & ~(1u << bit));
                    if (is_a) set_A(v); else wr8(addr, v);
                    return true;
                case 4: case 0xC: set_cy(bval); return true;
                case 5: case 0xD: set_cy(cy() && bval); return true;
                case 6: case 0xE: set_cy(cy() || bval); return true;
                case 7: case 0xF: set_cy(cy() != bval); return true;
                default: return false;
            }
        }

        if (code >= 0x50 && code <= 0x57) { set_r8(lo, fetch8()); return true; }
        if (code == 0x60 || (code >= 0x62 && code <= 0x67)) { set_A(r8(lo)); return true; }
        if (code == 0x70 || (code >= 0x72 && code <= 0x77)) { set_r8(lo, A()); return true; }
        if (code >= 0x80 && code <= 0x87) { uint8_t v = static_cast<uint8_t>(r8(lo) + 1); set_r8(lo, v); set_z(v == 0); return true; }
        if (code >= 0x90 && code <= 0x97) { uint8_t v = static_cast<uint8_t>(r8(lo) - 1); set_r8(lo, v); set_z(v == 0); return true; }
        if (code >= 0xD0 && code <= 0xD3) { set_z(r8(lo) == 0); set_cy(false); return true; }
        if (code >= 0xE0 && code <= 0xE3) { set_r8(lo, 1); return true; }
        if (code >= 0xF0 && code <= 0xF3) { set_r8(lo, 0); return true; }
        if (code == 0xC0 || code == 0xC2 || code == 0xC4 || code == 0xC6) { set_r16(lo >> 1, pop16()); return true; }
        if (code == 0xC1 || code == 0xC3 || code == 0xC5 || code == 0xC7) { push16(r16(lo >> 1)); return true; }
        if (code == 0xE6 || code == 0xE7) { set_r16(lo & 1u, 1); return true; }
        if (code == 0xF6 || code == 0xF7) { set_r16(lo & 1u, 0); return true; }

        switch (code) {
            case 0x00: return true;
            case 0x01: { uint32_t s = AX() + AX(); set_AX(s & 0xFFFFu); set_z(AX() == 0); set_cy(s > 0xFFFFu); return true; }
            case 0x03: { uint32_t s = AX() + BC(); set_AX(s & 0xFFFFu); set_z(AX() == 0); set_cy(s > 0xFFFFu); return true; }
            case 0x04: { uint32_t s = AX() + fetch16(); set_AX(s & 0xFFFFu); set_z(AX() == 0); set_cy(s > 0xFFFFu); return true; }
            case 0x05: { uint32_t s = AX() + DE(); set_AX(s & 0xFFFFu); set_z(AX() == 0); set_cy(s > 0xFFFFu); return true; }
            case 0x07: { uint32_t s = AX() + HL(); set_AX(s & 0xFFFFu); set_z(AX() == 0); set_cy(s > 0xFFFFu); return true; }
            case 0x08: { uint8_t t = A(); set_A(X()); set_X(t); return true; }
            case 0x09: { uint16_t w = fetch16(); set_A(rd8(seg_addr(static_cast<uint16_t>(w + r8(3)), has_es))); return true; }
            case 0x10: sp = static_cast<uint16_t>(sp + fetch8()); return true;
            case 0x12: set_BC(AX()); return true;
            case 0x13: set_AX(BC()); return true;
            case 0x14: set_DE(AX()); return true;
            case 0x15: set_AX(DE()); return true;
            case 0x16: set_HL(AX()); return true;
            case 0x17: set_AX(HL()); return true;
            case 0x18: { uint16_t w = fetch16(); wr8(seg_addr(static_cast<uint16_t>(w + r8(3)), has_es), A()); return true; }
            case 0x20: sp = static_cast<uint16_t>(sp - fetch8()); return true;
            case 0x23: { uint16_t v = BC(); set_cy(AX() < v); set_AX(AX() - v); set_z(AX() == 0); return true; }
            case 0x24: { uint16_t v = fetch16(); set_cy(AX() < v); set_AX(AX() - v); set_z(AX() == 0); return true; }
            case 0x28: { uint16_t w = fetch16(); wr8(seg_addr(static_cast<uint16_t>(w + r8(2)), has_es), A()); return true; }
            case 0x29: { uint16_t w = fetch16(); set_A(rd8(seg_addr(static_cast<uint16_t>(w + r8(2)), has_es))); return true; }
            case 0x30: set_AX(fetch16()); return true;
            case 0x32: set_BC(fetch16()); return true;
            case 0x33: { uint16_t t = AX(); set_AX(BC()); set_BC(t); return true; }
            case 0x34: set_DE(fetch16()); return true;
            case 0x36: set_HL(fetch16()); return true;
            case 0x41: es = fetch8() & 0xFu; return true;
            case 0x43: { uint16_t v = BC(); set_cy(AX() < v); set_z(AX() == v); return true; }
            case 0x44: { uint16_t v = fetch16(); set_cy(AX() < v); set_z(AX() == v); return true; }
            case 0x58: { uint16_t w = fetch16(); wr16(seg_addr(static_cast<uint16_t>(w + r8(3)), has_es), AX()); return true; }
            case 0x59: { uint16_t w = fetch16(); set_AX(rd16(seg_addr(static_cast<uint16_t>(w + r8(3)), has_es))); return true; }
            case 0x88: set_A(rd8(0xF0000u | static_cast<uint16_t>(sp + fetch8()))); return true;
            case 0x89: set_A(rd8(seg_addr(DE(), has_es))); return true;
            case 0x8A: set_A(rd8(seg_addr(static_cast<uint16_t>(DE() + fetch8()), has_es))); return true;
            case 0x8B: set_A(rd8(seg_addr(HL(), has_es))); return true;
            case 0x8C: set_A(rd8(seg_addr(static_cast<uint16_t>(HL() + fetch8()), has_es))); return true;
            case 0x8D: set_A(rd8(saddr(fetch8()))); return true;
            case 0x8E: set_A(rd8(sfr(fetch8()))); return true;
            case 0x8F: set_A(rd8(seg_addr(fetch16(), has_es))); return true;
            case 0x98: wr8(0xF0000u | static_cast<uint16_t>(sp + fetch8()), A()); return true;
            case 0x99: wr8(seg_addr(DE(), has_es), A()); return true;
            case 0x9A: wr8(seg_addr(static_cast<uint16_t>(DE() + fetch8()), has_es), A()); return true;
            case 0x9B: wr8(seg_addr(HL(), has_es), A()); return true;
            case 0x9C: wr8(seg_addr(static_cast<uint16_t>(HL() + fetch8()), has_es), A()); return true;
            case 0x9D: wr8(saddr(fetch8()), A()); return true;
            case 0x9E: wr8(sfr(fetch8()), A()); return true;
            case 0x9F: wr8(seg_addr(fetch16(), has_es), A()); return true;
            case 0xA4: { uint32_t a = saddr(fetch8()); uint8_t v = rd8(a) + 1; wr8(a, v); set_z(v == 0); return true; }
            case 0xB4: { uint32_t a = saddr(fetch8()); uint8_t v = rd8(a) - 1; wr8(a, v); set_z(v == 0); return true; }
            case 0xA1: set_AX(AX() + 1); return true;
            case 0xB1: set_AX(AX() - 1); return true;
            case 0xA8: set_AX(rd16(0xF0000u | static_cast<uint16_t>(sp + fetch8()))); return true;
            case 0xAB: set_AX(rd16(seg_addr(HL(), has_es))); return true;
            case 0xB8: wr16(0xF0000u | static_cast<uint16_t>(sp + fetch8()), AX()); return true;
            case 0xAD: set_AX(rd16(saddr(fetch8()))); return true;
            case 0xBD: wr16(saddr(fetch8()), AX()); return true;
            case 0xAE: set_AX(rd16(sfr(fetch8()))); return true;
            case 0xBE: wr16(sfr(fetch8()), AX()); return true;
            case 0xAF: set_AX(rd16(seg_addr(fetch16(), has_es))); return true;
            case 0xBF: wr16(seg_addr(fetch16(), has_es), AX()); return true;
            case 0xCC: { uint8_t d = fetch8(); uint8_t imm = fetch8(); wr8(seg_addr(static_cast<uint16_t>(HL() + d), has_es), imm); return true; }
            case 0xCA: { uint8_t d = fetch8(); uint8_t imm = fetch8(); wr8(seg_addr(static_cast<uint16_t>(DE() + d), has_es), imm); return true; }
            case 0xCD: { uint32_t a = saddr(fetch8()); wr8(a, fetch8()); return true; }
            case 0xCE: {
                uint8_t s = fetch8(), imm = fetch8();
                if (s == 0xFB) {
                    if (imm == 0x01) { // MULHU
                        uint32_t p = static_cast<uint32_t>(AX()) * static_cast<uint32_t>(BC());
                        set_AX(static_cast<uint16_t>(p & 0xFFFFu));
                        set_BC(static_cast<uint16_t>((p >> 16) & 0xFFFFu));
                        return true;
                    }
                    if (imm == 0x02) { // MULH (signed)
                        int32_t p = static_cast<int32_t>(static_cast<int16_t>(AX())) *
                                    static_cast<int32_t>(static_cast<int16_t>(BC()));
                        uint32_t u = static_cast<uint32_t>(p);
                        set_AX(static_cast<uint16_t>(u & 0xFFFFu));
                        set_BC(static_cast<uint16_t>((u >> 16) & 0xFFFFu));
                        return true;
                    }
                    if (imm == 0x03) { // DIVHU
                        if (DE() == 0) { set_DE(AX()); set_AX(0xFFFFu); }
                        else { uint16_t q = AX() / DE(); uint16_t rem = AX() % DE(); set_AX(q); set_DE(rem); }
                        return true;
                    }
                    if (imm == 0x05 || imm == 0x06) { // MACHU / MACH
                        uint32_t cur_macr = static_cast<uint32_t>(rd16(0xFFFF0u)) |
                                            (static_cast<uint32_t>(rd16(0xFFFF2u)) << 16);
                        uint64_t next_macr = 0;
                        if (imm == 0x05) {
                            uint64_t prod = static_cast<uint64_t>(AX()) * static_cast<uint64_t>(BC());
                            next_macr = static_cast<uint64_t>(cur_macr) + prod;
                            set_cy(next_macr > 0xFFFFFFFFULL);
                        } else {
                            int64_t prod = static_cast<int64_t>(static_cast<int16_t>(AX())) *
                                           static_cast<int64_t>(static_cast<int16_t>(BC()));
                            int64_t sum = static_cast<int64_t>(static_cast<int32_t>(cur_macr)) + prod;
                            set_cy(sum > 0x7FFFFFFFLL || sum < -0x80000000LL);
                            next_macr = static_cast<uint64_t>(sum);
                        }
                        wr16(0xFFFF0u, static_cast<uint16_t>(next_macr & 0xFFFFu));
                        wr16(0xFFFF2u, static_cast<uint16_t>((next_macr >> 16) & 0xFFFFu));
                        return true;
                    }
                    if (imm == 0x0B) { // DIVWU
                        uint32_t num = (static_cast<uint32_t>(BC()) << 16) | AX();
                        uint32_t den = (static_cast<uint32_t>(HL()) << 16) | DE();
                        if (den == 0) {
                            set_DE(static_cast<uint16_t>(num & 0xFFFFu));
                            set_HL(static_cast<uint16_t>((num >> 16) & 0xFFFFu));
                            set_AX(0xFFFFu);
                            set_BC(0xFFFFu);
                        } else {
                            uint32_t q = num / den;
                            uint32_t rem = num % den;
                            set_AX(static_cast<uint16_t>(q & 0xFFFFu));
                            set_BC(static_cast<uint16_t>((q >> 16) & 0xFFFFu));
                            set_DE(static_cast<uint16_t>(rem & 0xFFFFu));
                            set_HL(static_cast<uint16_t>((rem >> 16) & 0xFFFFu));
                        }
                        return true;
                    }
                }
                wr8(sfr(s), imm);
                return true;
            }
            case 0xCF: { uint32_t a = seg_addr(fetch16(), has_es); wr8(a, fetch8()); return true; }
            case 0xD4: set_z(rd8(saddr(fetch8())) == 0); set_cy(false); return true;
            case 0xD5: set_z(rd8(seg_addr(fetch16(), has_es)) == 0); set_cy(false); return true;
            case 0xD6: set_AX(static_cast<uint16_t>(A()) * static_cast<uint16_t>(X())); return true;
            case 0xD7: pc = pop_ret20(); return true;
            case 0xD8: set_X(rd8(saddr(fetch8()))); return true;
            case 0xE8: set_r8(3, rd8(saddr(fetch8()))); return true;
            case 0xF8: set_r8(2, rd8(saddr(fetch8()))); return true;
            case 0xDC: { int8_t rel = static_cast<int8_t>(fetch8()); if (cy()) pc = (pc + rel) & 0xFFFFFu; return true; }
            case 0xDD: { int8_t rel = static_cast<int8_t>(fetch8()); if (z()) pc = (pc + rel) & 0xFFFFFu; return true; }
            case 0xDE: { int8_t rel = static_cast<int8_t>(fetch8()); if (!cy()) pc = (pc + rel) & 0xFFFFFu; return true; }
            case 0xDF: { int8_t rel = static_cast<int8_t>(fetch8()); if (!z()) pc = (pc + rel) & 0xFFFFFu; return true; }
            case 0xEF: { int8_t rel = static_cast<int8_t>(fetch8()); pc = (pc + rel) & 0xFFFFFu; return true; }
            case 0xED: pc = fetch16(); return true;
            case 0xFD: { uint16_t t = fetch16(); push_ret20(pc); pc = t; return true; }
            case 0xFE: { int16_t rel = static_cast<int16_t>(fetch16()); push_ret20(pc); pc = static_cast<uint32_t>(static_cast<int32_t>(pc) + rel) & 0xFFFFFu; return true; }
            default: return false;
        }
    }

    int run(int max_steps = 10000) {
        int steps = 0;
        while (steps < max_steps && pc != 0x0FFFFFu) {
            if (!step()) break;
            ++steps;
        }
        return steps;
    }
};

// ---------------------------------------------------------------------------
// MSVC C-Compiler & Differential Execution Oracle Helpers
// ---------------------------------------------------------------------------
fs::path find_vcvars64() {
    const char *pf86 = std::getenv("ProgramFiles(x86)");
    fs::path base = pf86 ? fs::path(pf86) : fs::path("C:/Program Files (x86)");
    fs::path vswhere = base / "Microsoft Visual Studio" / "Installer" / "vswhere.exe";
    if (fs::exists(vswhere)) {
        fs::path tmp = fs::temp_directory_path() / "rl78dec_vswhere_out.txt";
        fs::path bat = fs::temp_directory_path() / "rl78dec_vswhere.bat";
        {
            std::ofstream ofs(bat);
            ofs << "@echo off\r\n\"" << vswhere.string() << "\" -latest -products * -property installationPath > \"" << tmp.string() << "\"\r\n";
        }
        if (std::system(("\"" + bat.string() + "\"").c_str()) == 0) {
            std::ifstream ifs(tmp);
            std::string line;
            if (std::getline(ifs, line)) {
                while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
                fs::path cand = fs::path(line) / "VC" / "Auxiliary" / "Build" / "vcvars64.bat";
                if (fs::exists(cand)) return cand;
            }
        }
    }
    for (const char *yr : {"18", "2026", "2022"}) {
        for (const char *ed : {"Professional", "Enterprise", "Community", "BuildTools"}) {
            fs::path cand = fs::path("C:/Program Files/Microsoft Visual Studio") / yr / ed / "VC" / "Auxiliary" / "Build" / "vcvars64.bat";
            if (fs::exists(cand)) return cand;
        }
    }
    return {};
}

fs::path find_prelude_h() {
    std::vector<fs::path> cands = {
        fs::current_path() / ".agents" / "skills" / "decompiler-qa-audit" / "resources" / "rl78dec_audit_prelude.h",
        fs::current_path().parent_path() / ".agents" / "skills" / "decompiler-qa-audit" / "resources" / "rl78dec_audit_prelude.h",
    };
    for (const auto &c : cands) {
        if (fs::exists(c)) return fs::canonical(c);
    }
    return {};
}

static std::string pid_suffix() {
#ifdef _WIN32
    return std::to_string(_getpid());
#else
    return "0";
#endif
}

bool compile_check_c_src(const std::string &c_src, std::string *out_diag = nullptr) {
    static fs::path vcvars = find_vcvars64();
    static fs::path prelude = find_prelude_h();
    if (vcvars.empty() || prelude.empty()) {
        if (out_diag) *out_diag = "vcvars64.bat or rl78dec_audit_prelude.h not found";
        return false;
    }
    fs::path dir = fs::temp_directory_path() / ("rl78dec_test_c_oracle_" + pid_suffix());
    fs::create_directories(dir);
    fs::path cfile = dir / "check.c";
    fs::path bat = dir / "check.bat";
    fs::path log = dir / "check.log";
    {
        std::ofstream ofs(cfile);
        ofs << "#include \"" << prelude.generic_string() << "\"\n\n" << c_src << "\n";
    }
    {
        std::ofstream ofs(bat);
        ofs << "@echo off\r\n"
            << "call \"" << vcvars.string() << "\" >nul 2>&1\r\n"
            << "if errorlevel 1 exit /b 1\r\n"
            << "cl.exe /nologo /Zs /W3 /TC \"" << cfile.string() << "\" > \"" << log.string() << "\" 2>&1\r\n";
    }
    int rc = std::system(("\"" + bat.string() + "\"").c_str());
    if (out_diag) {
        std::ifstream ifs(log);
        std::ostringstream ss;
        ss << ifs.rdbuf();
        *out_diag = ss.str();
    }
    return rc == 0;
}

// Redirect physical 20-bit RL78 bus pointer dereferences *(uintN_t *)(addr_expr) onto g_rl78_mem[]
// ONLY for host execution of differential tests (syntax check still runs on raw unmodified C output!).
std::string adapt_rl78_ptrs_for_host_exec(const std::string &src) {
    std::string out = src;
    struct Pat { const char *pfx; const char *ctype; };
    const Pat pats[] = {
        {"*(uint8_t *)(", "uint8_t"},
        {"*(uint16_t *)(", "uint16_t"},
        {"*(uint32_t *)(", "uint32_t"},
    };
    bool changed = true;
    while (changed) {
        changed = false;
        for (const Pat &pat : pats) {
            size_t plen = std::strlen(pat.pfx);
            size_t pos = 0;
            while ((pos = out.find(pat.pfx, pos)) != std::string::npos) {
                size_t start_inner = pos + plen;
                int depth = 1;
                size_t j = start_inner;
                while (j < out.size() && depth > 0) {
                    if (out[j] == '(') ++depth;
                    else if (out[j] == ')') --depth;
                    ++j;
                }
                if (depth != 0) break;
                size_t end_inner = j - 1;
                std::string inner = out.substr(start_inner, end_inner - start_inner);
                // Keep real C global/local casts like *(uint16_t *)((uint8_t *)&sym + off) or *(uint16_t *)((uint8_t *)arr + off) untouched!
                if (inner.find(")&") != std::string::npos || inner.rfind("(uint8_t *)", 0) == 0) {
                    pos = start_inner;
                    continue;
                }
                std::string adapted_inner = adapt_rl78_ptrs_for_host_exec(inner);
                std::string repl = "(*(" + std::string(pat.ctype) + " *)&g_rl78_mem[(uint32_t)(" +
                                   adapted_inner + ") & 0xFFFFFu])";
                out.replace(pos, j - pos, repl);
                changed = true;
                break;
            }
            if (changed) break;
        }
    }
    return out;
}

bool compile_and_run_c_exe(const std::string &c_tu, std::string &out_stdout, std::string &out_err) {
    static fs::path vcvars = find_vcvars64();
    static fs::path prelude = find_prelude_h();
    if (vcvars.empty() || prelude.empty()) {
        out_err = "vcvars64.bat or rl78dec_audit_prelude.h not found";
        return false;
    }
    std::string host_tu = adapt_rl78_ptrs_for_host_exec(c_tu);
    fs::path dir = fs::temp_directory_path() / ("rl78dec_diff_exec_" + pid_suffix());
    fs::create_directories(dir);
    fs::path cfile = dir / "diff_driver.c";
    fs::path objfile = dir / "diff_driver.obj";
    fs::path exefile = dir / "diff_driver.exe";
    fs::path bat = dir / "build_run.bat";
    fs::path build_log = dir / "build.log";
    fs::path run_log = dir / "run.log";
    {
        std::ofstream ofs(cfile);
        ofs << "#include <stdio.h>\n"
            << "#include <string.h>\n"
            << "#include \"" << prelude.generic_string() << "\"\n\n"
            << "uint8_t g_rl78_mem[0x100000];\n"
            << "uint8_t CY = 0, ZF = 0, HF = 0, es = 0x0F, cs = 0, psw = 0;\n"
            << "void ei(void) {}\nvoid di(void) {}\nvoid halt(void) {}\nvoid stop(void) {}\n"
            << "void brk(void) {}\nvoid brk1(void) {}\nvoid sel(int rb) { (void)rb; }\n"
            << "void movs(uint32_t dst, uint8_t val) { RL78_MEM8(dst) = val; }\n"
            << "void JUMPOUT(uint32_t ea) { (void)ea; }\n\n"
            << host_tu << "\n";
    }
    {
        std::ofstream ofs(bat);
        ofs << "@echo off\r\n"
            << "call \"" << vcvars.string() << "\" >nul 2>&1\r\n"
            << "if errorlevel 1 exit /b 1\r\n"
            << "cl.exe /nologo /W3 /TC \"" << cfile.string() << "\" /Fo\"" << objfile.string()
            << "\" /Fe\"" << exefile.string() << "\" > \"" << build_log.string() << "\" 2>&1\r\n"
            << "if errorlevel 1 exit /b 2\r\n"
            << "\"" << exefile.string() << "\" > \"" << run_log.string() << "\" 2>&1\r\n";
    }
    int rc = std::system(("\"" + bat.string() + "\"").c_str());
    {
        std::ifstream ifs(build_log);
        std::ostringstream ss;
        ss << ifs.rdbuf();
        out_err = ss.str();
    }
    if (rc != 0) return false;
    {
        std::ifstream ifs(run_log);
        std::ostringstream ss;
        ss << ifs.rdbuf();
        out_stdout = ss.str();
    }
    return true;
}

rl78dec::DecompileResult decompile_bytes(const std::vector<uint8_t> &bytes,
                                         uint32_t ea = 0x0100,
                                         const std::string &name = "",
                                         const std::string &proto = "",
                                         std::optional<int> bank = 0) {
    rl78dec::MemoryDatabaseProvider db(0x10000, 0);
    db.write_bytes(ea, bytes);
    if (!name.empty()) db.add_func_entry(ea, name);
    rl78dec::DecompileOptions opts;
    opts.verify_ir = true;
    opts.default_bank = bank;
    if (!proto.empty()) opts.user_data.set_func_proto(proto);
    return rl78dec::decompile_function(db, ea, opts);
}

// ===========================================================================
// TIER 1 & TIER 4 UNIT TESTS (Raw Machine Bytes -> Full Pipeline + verify_ir)
// ===========================================================================

void test_ei_di_vs_psw7() {
    const std::string kTestName = "test_ei_di_vs_psw7";
    // 71 7A FA = EI; 71 7B FA = DI; 71 0A FA = SET1 PSW.0 (CY); D7 = RET
    auto res = decompile_bytes({0x71, 0x7A, 0xFA, 0x71, 0x7B, 0xFA, 0x71, 0x0A, 0xFA, 0xD7});
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed or IR problems");
    CHECK(res.c_text.find("ei();") != std::string::npos, "Missing ei()");
    CHECK(res.c_text.find("di();") != std::string::npos, "Missing di()");
    CHECK(res.c_text.find("psw |= 0x80") == std::string::npos, "EI must not emit psw |= 0x80");
    CHECK(res.c_text.find("psw &= 0x7F") == std::string::npos, "DI must not emit psw &= 0x7F");
    std::string diag;
    CHECK(compile_check_c_src(res.c_text, &diag), "cl.exe /Zs failed:\n" + diag);
    pass_msg(kTestName);
}

void test_es_prefix_and_code_seg0() {
    const std::string kTestName = "test_es_prefix_and_code_seg0";
    // 41 02       : mov es, #2
    // 11 8F 00 10 : mov a, ES:!0x1000  -> mem8[0x21000]
    // 9F 00 20    : mov !0x2000, a     -> mem8[0xF2000] (no ES prefix, must use 0xF0000!)
    // FD 00 03    : call !0x0300       -> sub_300 (NOT 0xF0300!)
    // D7          : ret
    rl78dec::MemoryDatabaseProvider db(0x10000, 0);
    db.write_bytes(0x0100, {0x41, 0x02, 0x11, 0x8F, 0x00, 0x10, 0x9F, 0x00, 0x20, 0xFD, 0x00, 0x03, 0xD7});
    db.write_bytes(0x0300, {0xD7}); // sub_300: ret
    rl78dec::DecompileOptions opts;
    opts.verify_ir = true;
    auto res = rl78dec::decompile_function(db, 0x0100, opts);
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    CHECK(res.c_text.find("0x21000") != std::string::npos, "ES:!0x1000 must fold to 0x21000");
    CHECK(res.c_text.find("0xF2000") != std::string::npos, "Non-ES !0x2000 must map to 0xF2000");
    CHECK(res.c_text.find("sub_300(") != std::string::npos, "CALL !0x0300 must target segment 0 (sub_300)");
    std::string diag;
    CHECK(compile_check_c_src("void sub_300(void);\n" + res.c_text, &diag), "cl.exe /Zs failed:\n" + diag);
    pass_msg(kTestName);
}

void test_saddr_wraparound_and_sel_rb_bank() {
    const std::string kTestName = "test_saddr_wraparound_and_sel_rb_bank";
    // 51 11          : mov a, #0x11      (bank 0 A)
    // 61 DF          : sel rb1           (switches to bank 1, must NOT fold bank 0 A!)
    // 9D 20          : mov saddr_20, a   (0xFFE20; saddr <0x20 -> 0xFFF00, >=0x20 -> 0xFFE00)
    // 8D 10          : mov a, saddr_10   (0xFFF10 = TXD0!)
    // 9D F8          : mov saddr_F8, a   (0xFFEF8 = bank 0 X, inactive in bank 1 -> must stay mem8!)
    // D7             : ret
    auto res = decompile_bytes({0x51, 0x11, 0x61, 0xDF, 0x9D, 0x20, 0x8D, 0x10, 0x9D, 0xF8, 0xD7});
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    CHECK(res.c_text.find("0xFFE20") != std::string::npos, "saddr 0x20 must map to 0xFFE20");
    CHECK(res.c_text.find("0xFFF10") != std::string::npos || res.c_text.find("TXD0") != std::string::npos,
          "saddr 0x10 must map to 0xFFF10 (TXD0)");
    CHECK(res.c_text.find("0xFFEF8") != std::string::npos,
          "0xFFEF8 in RB1 must NOT alias active RB1 X");
    CHECK(res.c_text.find("mem8[0xFFE20] = 0x11") == std::string::npos &&
          res.c_text.find("0xFFE20) = 0x11") == std::string::npos,
          "SEL RB1 must invalidate cached RB0 constant A=0x11");
    std::string diag;
    CHECK(compile_check_c_src(res.c_text, &diag), "cl.exe /Zs failed:\n" + diag);
    pass_msg(kTestName);
}

void test_skip_target_variable_length() {
    const std::string kTestName = "test_skip_target_variable_length";
    // 0x0100: cmp a, #5       ; 4C 05       (2 bytes)
    // 0x0102: skc             ; 61 C8       (2 bytes) -> skips next 4-byte insn at 0x0104!
    // 0x0104: mov !0x1000, #1 ; CF 00 10 01 (4 bytes)
    // 0x0108: ret             ; D7
    auto res = decompile_bytes({0x4C, 0x05, 0x61, 0xC8, 0xCF, 0x00, 0x10, 0x01, 0xD7});
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    auto dec = rl78dec::decode_one(
        [&]() {
            rl78dec::MemoryDatabaseProvider db(0x10000, 0);
            db.write_bytes(0x0100, {0x4C, 0x05, 0x61, 0xC8, 0xCF, 0x00, 0x10, 0x01, 0xD7});
            return db;
        }(), 0x0102);
    CHECK(dec.has_value() && dec->mnem == rl78dec::Mnem::Skc, "Expected SKC");
    CHECK(res.c_text.find("0xF1000") != std::string::npos, "Skipped 4-byte insn missing");
    std::string diag;
    CHECK(compile_check_c_src(res.c_text, &diag), "cl.exe /Zs failed:\n" + diag);
    pass_msg(kTestName);
}

void test_rl78_s3_mulhu_divhu_not_misdecoded_as_reserve() {
    const std::string kTestName = "test_rl78_s3_mulhu_divhu_not_misdecoded_as_reserve";
    // [B7] CE FB 01 = MULHU (RL78-S3), CE FB 03 = DIVHU (RL78-S3)
    // Buggy decoder decodes CE FB 01 as `mov RESERVE, #1`!
    auto res = decompile_bytes({0xCE, 0xFB, 0x01, 0xCE, 0xFB, 0x03, 0xD7});
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    CHECK(res.c_text.find("RESERVE =") == std::string::npos && res.c_text.find("0xFFFFB") == std::string::npos,
          "RL78-S3 MULHU/DIVHU (CE FB 01/03) misdecoded as write to RESERVE (0xFFFFB)!");
    pass_msg(kTestName);
}

void test_hidden_prologue_epilogue_and_call_setup_omitted() {
    const std::string kTestName = "test_hidden_prologue_epilogue_and_call_setup_omitted";
    // [B1] Standard RL78 prologue/epilogue + call with register & stack args:
    // push hl          ; C7
    // subw sp, #4      ; 20 04
    // movw hl, sp      ; 16  (Wait: 16 is movw hl, ax; movw ax, sp = AE F8; movw hl, ax = 16)
    // movw ax, #0x1234 ; 30 34 12
    // push ax          ; C1
    // movw ax, #0x0007 ; 30 07 00
    // call !0x0300     ; FD 00 03
    // addw sp, #2      ; 10 02
    // addw sp, #4      ; 10 04
    // pop hl           ; C6
    // ret              ; D7
    rl78dec::MemoryDatabaseProvider db(0x10000, 0);
    db.write_bytes(0x0100, {
        0xC7, 0x20, 0x04, 0xAE, 0xF8, 0x16,
        0x30, 0x34, 0x12, 0xC1,
        0x30, 0x07, 0x00, 0xFD, 0x00, 0x03,
        0x10, 0x02, 0x10, 0x04, 0xC6, 0xD7
    });
    db.write_bytes(0x0300, {0xD7});
    rl78dec::DecompileOptions opts;
    opts.verify_ir = true;
    auto res = rl78dec::decompile_function(db, 0x0100, opts);
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    CHECK(res.c_text.find("push(") == std::string::npos, "Hidden push() leaked into C output!");
    CHECK(res.c_text.find("pop(") == std::string::npos, "Hidden pop() leaked into C output!");
    CHECK(res.c_text.find("sp =") == std::string::npos, "Hidden sp adjustment leaked into C output!");
    CHECK(res.c_text.find("ax =") == std::string::npos, "Hidden call setup reg `ax =` leaked into C output!");
    std::string diag;
    CHECK(compile_check_c_src("void sub_300(uint16_t a0, uint16_t a1);\n" + res.c_text, &diag),
          "cl.exe /Zs failed:\n" + diag);
    pass_msg(kTestName);
}

void test_c_ident_sanitization() {
    const std::string kTestName = "test_c_ident_sanitization";
    // [B6] Function named `clear_P4.0` (seen in DOL-1001-VTE-1001-00703030.i64 @ 0x3A8BD!)
    // 71 0B 04 : clr1 P4.0
    // D7       : ret
    auto res = decompile_bytes({0x71, 0x0B, 0x04, 0xD7}, 0x0100, "clear_P4.0");
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    std::string diag;
    CHECK(compile_check_c_src(res.c_text, &diag),
          "Unsanitized C identifier `clear_P4.0` failed cl.exe /Zs:\n" + diag);
    pass_msg(kTestName);
}

void test_branch_flag_folds_es_and_const() {
    const std::string kTestName = "test_branch_flag_folds_es_and_const";
    // [B3] mov es, #0x0F; cmp0 ES:!0x2000; bnz +3; mov a, #1; ret; mov a, #2; ret
    auto res = decompile_bytes({
        0x41, 0x0F,
        0x11, 0xD5, 0x00, 0x20,
        0xDF, 0x03,
        0x51, 0x01, 0xD7,
        0x51, 0x02, 0xD7
    });
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    CHECK(res.c_text.find("es_mem8") == std::string::npos,
          "Branch flag failed to fold constant ES=0x0F into mem8[0xF2000]!");
    CHECK(res.c_text.find("0xF2000") != std::string::npos, "Expected folded 0xF2000 in branch");
    std::string diag;
    CHECK(compile_check_c_src(res.c_text, &diag), "cl.exe /Zs failed:\n" + diag);
    pass_msg(kTestName);
}

void test_btclr_inverted_if_with_else_retains_clear() {
    const std::string kTestName = "test_btclr_inverted_if_with_else_retains_clear";
    // [B5] Test BTCLR saddr_20.3 with inverted iflag + non-empty else branch:
    // 0x0100: btclr saddr_20.3, 0x0107 ; 31 30 20 03
    // 0x0104: mov a, #1                ; 51 01
    // 0x0106: ret                      ; D7
    // 0x0107: mov a, #2                ; 51 02
    // 0x0109: ret                      ; D7
    rl78dec::MemoryDatabaseProvider db(0x10000, 0);
    db.write_bytes(0x0100, {0x31, 0x30, 0x20, 0x03, 0x51, 0x01, 0xD7, 0x51, 0x02, 0xD7});
    rl78dec::DecompileOptions opts;
    opts.verify_ir = true;
    opts.user_data.toggle_iflag(0x0100);
    auto res = rl78dec::decompile_function(db, 0x0100, opts);
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    CHECK(res.c_text.find("0xF7") != std::string::npos,
          "Inverted BTCLR with non-empty else dropped the `&= 0xF7` bit clear!");
    std::string diag;
    CHECK(compile_check_c_src(res.c_text, &diag), "cl.exe /Zs failed:\n" + diag);
    pass_msg(kTestName);
}

// ===========================================================================
// TIER 3 — DIFFERENTIAL SEMANTIC EXECUTION (Rl78RefMachine vs Compiled C)
// ===========================================================================
struct DiffCase {
    std::string name;
    std::vector<uint8_t> code;
    std::string proto;
    std::string c_code;
    std::string c_harness_calls; // C statements calling the decompiled function & printing "CASE <tag>: ..."
    std::vector<std::string> expected_lines;
};

static std::string hex8(uint8_t v) { char b[8]; std::snprintf(b, sizeof(b), "%02X", v); return b; }
static std::string hex16(uint16_t v) { char b[16]; std::snprintf(b, sizeof(b), "%04X", v); return b; }

void run_differential_suite() {
    const std::string kTestName = "differential_semantic_suite";
    std::vector<DiffCase> cases;

    // D1: Subregister preservation & partial 8-bit write on 16-bit AX web + user_proto return
    // [B11] [B12]
    // func_d1(uint16_t a0): mov a, #0x55; ret  -> returns (0x55 << 8) | (a0 & 0xFF)
    {
        DiffCase dc;
        dc.name = "d1_subreg_partial_write_ax";
        dc.code = {0x51, 0x55, 0xD7}; // mov a, #0x55; ret
        dc.proto = "uint16_t d1_subreg(uint16_t a0)";
        rl78dec::MemoryDatabaseProvider db(0x10000, 0);
        db.write_bytes(0x0100, dc.code);
        db.add_func_entry(0x0100, "d1_subreg");
        rl78dec::DecompileOptions opts;
        opts.verify_ir = true;
        opts.user_data.set_func_proto(dc.proto);
        auto res = rl78dec::decompile_function(db, 0x0100, opts);
        if (!res.ok || !res.ir_func || !res.ir_func->problems.empty()) {
            fail_msg(dc.name, "decompile failed");
        } else {
            dc.c_code = res.c_text;
            std::ostringstream cs;
            for (uint16_t ax_in : {uint16_t(0x0000), uint16_t(0x1234), uint16_t(0xFFFF), uint16_t(0x807F)}) {
                auto mp = std::make_unique<Rl78RefMachine>(); auto &m = *mp;
                m.reset(0x0100);
                m.load_bytes(0x0100, dc.code);
                m.set_AX(ax_in);
                m.run();
                dc.expected_lines.push_back("d1:" + hex16(ax_in) + "=" + hex16(m.AX()));
                cs << "    printf(\"d1:" << hex16(ax_in) << "=%04X\\n\", (unsigned)d1_subreg(0x" << hex16(ax_in) << "));\n";
            }
            dc.c_harness_calls = cs.str();
            cases.push_back(std::move(dc));
        }
    }

    // D2: uint8_t param (A live) + write X + return AX (16-bit) [B12]
    {
        DiffCase dc;
        dc.name = "d2_u8_param_to_u16_ret";
        // mov b, a; mov x, #0x34; mov a, b; ret -> AX = (a_in << 8) | 0x34
        dc.code = {0x73, 0x50, 0x34, 0x63, 0xD7};
        dc.proto = "uint16_t d2_u8_to_u16(uint16_t a0)";
        rl78dec::MemoryDatabaseProvider db(0x10000, 0);
        db.write_bytes(0x0100, dc.code);
        db.add_func_entry(0x0100, "d2_u8_to_u16");
        rl78dec::DecompileOptions opts;
        opts.verify_ir = true;
        opts.user_data.set_func_proto(dc.proto);
        auto res = rl78dec::decompile_function(db, 0x0100, opts);
        if (!res.ok || !res.ir_func || !res.ir_func->problems.empty()) {
            fail_msg(dc.name, "decompile failed");
        } else {
            dc.c_code = res.c_text;
            std::ostringstream cs;
            for (uint16_t ax_in : {uint16_t(0x0000), uint16_t(0x1200), uint16_t(0xFFAA), uint16_t(0x8001)}) {
                auto mp = std::make_unique<Rl78RefMachine>(); auto &m = *mp;
                m.reset(0x0100);
                m.load_bytes(0x0100, dc.code);
                m.set_AX(ax_in);
                m.run();
                dc.expected_lines.push_back("d2:" + hex16(ax_in) + "=" + hex16(m.AX()));
                cs << "    printf(\"d2:" << hex16(ax_in) << "=%04X\\n\", (unsigned)d2_u8_to_u16(0x" << hex16(ax_in) << "));\n";
            }
            dc.c_harness_calls = cs.str();
            cases.push_back(std::move(dc));
        }
    }

    // D3: Independent Z vs CY flag separation:
    //   1) cmp a, #0x80; inc b; bc taken   (INC touches Z only, preserves CY from CMP!)
    //   2) sub a, b; shl c, 1; bz taken    (SHL touches CY only, preserves Z from SUB!)
    //   3) cmp0 a; bc taken                (CMP0 clears CY=0!)
    //   4) cmp a, b; bh taken              (BH: !(Z|CY), i.e., a > b unsigned)
    {
        DiffCase dc;
        dc.name = "d3_z_cy_flag_separation";
        // Args: a0 = AX (A = high byte, X = low byte), a1 = BC (B = high byte, C = low byte)
        // 0x0100: cmp a, #0x80    ; 4C 80
        // 0x0102: inc b           ; 83
        // 0x0103: bc +4 -> 0x0109 ; DC 04
        // 0x0105: mov x, #0x10    ; 50 10
        // 0x0107: br +2 -> 0x010B ; EF 02
        // 0x0109: mov x, #0x20    ; 50 20
        // 0x010B: sub a, b        ; 61 2B
        // 0x010D: shl c, 1        ; 31 17
        // 0x010F: bz +3 -> 0x0114 ; DD 03
        // 0x0111: or x, #0x01     ; 5C/6C? Wait: or a, #N is 6C! Use mov a, x; or a, #1; mov x, a?
        // Simpler: just add 1/2 to x using `inc x` (80) or `mov a, x; ...`:
        // Actually: 0x010F: bz +2 (0x0113); inc x (80); inc x (80);
        // 0x0113: cmp0 a (D1); bc +2 (DC 02); or_x: mov a, x (60); ret (D7)
        // Wait: let's encode cleanly:
        // 0100: 4C 80       cmp a, #0x80
        // 0102: 83          inc b          (Z = (B+1==0), CY preserved!)
        // 0103: DC 04       bc 0109
        // 0105: 50 10       mov x, #0x10
        // 0107: EF 02       br 010B
        // 0109: 50 20       mov x, #0x20
        // 010B: 61 2B       sub a, b       (Z = (a==b), CY = (a<b))
        // 010D: 31 17       shl c, 1       (CY = c>>7, Z preserved!)
        // 010F: DD 03       bz 0114
        // 0111: 80          inc x          (x += 1 if not bz)
        // 0112: EF 02       br 0116
        // 0114: 80          inc x
        // 0115: 80          inc x          (x += 2 if bz)
        // 0116: D1          cmp0 a         (CY = 0!)
        // 0117: DC 02       bc 011B        (never taken!)
        // 0119: EF 02       br 011D
        // 011B: 50 FF       mov x, #0xFF
        // 011D: 60          mov a, x
        // 011E: D7          ret            (returns A = x)
        dc.code = {
            0x4C, 0x80, 0x83, 0xDC, 0x04, 0x50, 0x10, 0xEF, 0x02, 0x50, 0x20,
            0x61, 0x2B, 0x31, 0x17, 0xDD, 0x03, 0x80, 0xEF, 0x02, 0x80, 0x80,
            0xD1, 0xDC, 0x02, 0xEF, 0x02, 0x50, 0xFF, 0x60, 0xD7
        };
        dc.proto = "uint8_t d3_flags(uint16_t a0, uint16_t a1)";
        rl78dec::MemoryDatabaseProvider db(0x10000, 0);
        db.write_bytes(0x0100, dc.code);
        db.add_func_entry(0x0100, "d3_flags");
        rl78dec::DecompileOptions opts;
        opts.verify_ir = true;
        opts.user_data.set_func_proto(dc.proto);
        auto res = rl78dec::decompile_function(db, 0x0100, opts);
        if (!res.ok || !res.ir_func || !res.ir_func->problems.empty()) {
            fail_msg(dc.name, "decompile failed");
        } else {
            dc.c_code = res.c_text;
            std::ostringstream cs;
            uint16_t ax_vecs[] = {0x0000, 0x7F00, 0x8000, 0xFF00, 0x0500};
            uint16_t bc_vecs[] = {0xFF00, 0x7E80, 0x7F80, 0xFE01, 0x0480};
            for (int i = 0; i < 5; ++i) {
                auto mp = std::make_unique<Rl78RefMachine>(); auto &m = *mp;
                m.reset(0x0100);
                m.load_bytes(0x0100, dc.code);
                m.set_AX(ax_vecs[i]);
                m.set_BC(bc_vecs[i]);
                m.run();
                dc.expected_lines.push_back("d3:" + std::to_string(i) + "=" + hex8(m.A()));
                cs << "    printf(\"d3:" << i << "=%02X\\n\", (unsigned)d3_flags(0x" << hex16(ax_vecs[i])
                   << ", 0x" << hex16(bc_vecs[i]) << "));\n";
            }
            dc.c_harness_calls = cs.str();
            cases.push_back(std::move(dc));
        }
    }

    // D4: BTCLR saddr.bit taken vs fallthrough (bit cleared ONLY on taken path!)
    {
        DiffCase dc;
        dc.name = "d4_btclr_taken_vs_fallthrough";
        // Input: mem[0xFFE20] = saddr_20
        // 0100: 31 30 20 03  btclr saddr_20.3, 0107
        // 0104: 51 00        mov a, #0
        // 0106: D7           ret
        // 0107: 51 01        mov a, #1
        // 0109: D7           ret
        dc.code = {0x31, 0x30, 0x20, 0x03, 0x51, 0x00, 0xD7, 0x51, 0x01, 0xD7};
        dc.proto = "uint8_t d4_btclr(void)";
        rl78dec::MemoryDatabaseProvider db(0x10000, 0);
        db.write_bytes(0x0100, dc.code);
        db.add_func_entry(0x0100, "d4_btclr");
        rl78dec::DecompileOptions opts;
        opts.verify_ir = true;
        opts.user_data.set_func_proto(dc.proto);
        auto res = rl78dec::decompile_function(db, 0x0100, opts);
        if (!res.ok || !res.ir_func || !res.ir_func->problems.empty()) {
            fail_msg(dc.name, "decompile failed");
        } else {
            dc.c_code = res.c_text;
            std::ostringstream cs;
            for (uint8_t init_v : {uint8_t(0x00), uint8_t(0x08), uint8_t(0xFF), uint8_t(0xF7)}) {
                auto mp = std::make_unique<Rl78RefMachine>(); auto &m = *mp;
                m.reset(0x0100);
                m.load_bytes(0x0100, dc.code);
                m.wr8(0xFFE20u, init_v);
                m.run();
                dc.expected_lines.push_back("d4:" + hex8(init_v) + "=" + hex8(m.A()) + ":" + hex8(m.rd8(0xFFE20u)));
                cs << "    RL78_MEM8(0xFFE20) = 0x" << hex8(init_v) << ";\n"
                   << "    { uint8_t r = d4_btclr(); printf(\"d4:" << hex8(init_v)
                   << "=%02X:%02X\\n\", (unsigned)r, (unsigned)RL78_MEM8(0xFFE20)); }\n";
            }
            dc.c_harness_calls = cs.str();
            cases.push_back(std::move(dc));
        }
    }

    // D5: MOVS [HL+off], X and CMPS X, [HL+off] CY/Z flags
    {
        DiffCase dc;
        dc.name = "d5_movs_cmps_flags";
        // Inputs: a0 = AX (A=hi, X=lo), mem[0xFFE30] = target byte
        // HL = 0xFE2E -> [HL+2] = 0xFFE30
        // 0100: 36 2E FE    movw hl, #0xFE2E
        // 0103: 61 CE 02    movs [hl+2], x   ; Z=(X==0), CY=(A==0 || X==0)
        // 0106: DC 04       bc 010C
        // 0108: 52 10       mov c, #0x10
        // 010A: EF 02       br 010E
        // 010C: 52 20       mov c, #0x20
        // 010E: 61 DE 02    cmps x, [hl+2]   ; Z=(X==mem), CY=(X!=mem || A==0 || X==0)
        // 0111: DC 02       bc 0115
        // 0113: 82          inc c            ; +1 if !CY
        // 0114: D7          ret              ; (returns c? wait: mov a, c; ret)
        // Let's end with mov a, c; ret at 0115:
        dc.code = {
            0x36, 0x2E, 0xFE,
            0x61, 0xCE, 0x02,
            0xDC, 0x04,
            0x52, 0x10,
            0xEF, 0x02,
            0x52, 0x20,
            0x61, 0xDE, 0x02,
            0xDC, 0x01,
            0x82,
            0x62, 0xD7
        };
        dc.proto = "uint8_t d5_movs_cmps(uint16_t a0)";
        rl78dec::MemoryDatabaseProvider db(0x10000, 0);
        db.write_bytes(0x0100, dc.code);
        db.add_func_entry(0x0100, "d5_movs_cmps");
        rl78dec::DecompileOptions opts;
        opts.verify_ir = true;
        opts.user_data.set_func_proto(dc.proto);
        auto res = rl78dec::decompile_function(db, 0x0100, opts);
        if (!res.ok || !res.ir_func || !res.ir_func->problems.empty()) {
            fail_msg(dc.name, "decompile failed");
        } else {
            dc.c_code = res.c_text;
            std::ostringstream cs;
            for (uint16_t ax_in : {uint16_t(0x0000), uint16_t(0x0005), uint16_t(0x0500), uint16_t(0x0505)}) {
                auto mp = std::make_unique<Rl78RefMachine>(); auto &m = *mp;
                m.reset(0x0100);
                m.load_bytes(0x0100, dc.code);
                m.set_AX(ax_in);
                m.run();
                dc.expected_lines.push_back("d5:" + hex16(ax_in) + "=" + hex8(m.A()) + ":" + hex8(m.rd8(0xFFE30u)));
                cs << "    RL78_MEM8(0xFFE30) = 0;\n"
                   << "    { uint8_t r = d5_movs_cmps(0x" << hex16(ax_in) << "); printf(\"d5:" << hex16(ax_in)
                   << "=%02X:%02X\\n\", (unsigned)r, (unsigned)RL78_MEM8(0xFFE30)); }\n";
            }
            dc.c_harness_calls = cs.str();
            cases.push_back(std::move(dc));
        }
    }

    // D6: Chained ADDC / SUBC / ROLC / ROLWC [B10]
    {
        DiffCase dc;
        dc.name = "d6_chained_addc_rolc";
        // 16-bit addition AX + BC using 8-bit ADD/ADDC + carry out:
        // a0 = AX, a1 = BC -> returns AX + BC, and stores carry in mem8[0xFFE21]
        // 0100: 60          mov a, x
        // 0101: 61 0A       add a, c     ; x + c -> CY0
        // 0103: 70          mov x, a
        // 0104: 61 8B       xch a, b? No: 61 8B is xch a, b; use: mov a, x; wait: save A:
        // Wait: 8-bit high byte of AX is A! If we clobbered A, we lost high byte of AX!
        // Let's do:
        // 0100: 61 8D       xch a, d     ; save original A in D (preserves CY) -> wait, or pass in saddr!
        // Even simpler: compute (X + C) + (B + CY0) + carry:
        // 0100: 60          mov a, x     ; a = X
        // 0101: 61 0A       add a, c     ; a = X + C, CY = carry0
        // 0103: 70          mov x, a     ; X = low byte
        // 0104: 63          mov a, b     ; a = B (MOV preserves CY!)
        // 0105: 1C 10       addc a, #0x10; a = B + 0x10 + CY0, CY = carry1  [ADDC #1!]
        // 0107: 73          mov b, a     ; B = mid byte
        // 0108: 51 00       mov a, #0    ; a = 0 (MOV preserves CY!)
        // 010A: 1C 00       addc a, #0   ; a = CY1  [ADDC #2!]
        // 010C: 9D 21       mov saddr_21, a
        // 010E: 63          mov a, b     ; A = mid byte, X = low byte
        // 010F: D7          ret
        dc.code = {
            0x60, 0x61, 0x0A, 0x70,
            0x63, 0x1C, 0x10, 0x73,
            0x51, 0x00, 0x1C, 0x00, 0x9D, 0x21,
            0x63, 0xD7
        };
        dc.proto = "uint16_t d6_addc_chain(uint16_t a0, uint16_t a1)";
        rl78dec::MemoryDatabaseProvider db(0x10000, 0);
        db.write_bytes(0x0100, dc.code);
        db.add_func_entry(0x0100, "d6_addc_chain");
        rl78dec::DecompileOptions opts;
        opts.verify_ir = true;
        opts.user_data.set_func_proto(dc.proto);
        auto res = rl78dec::decompile_function(db, 0x0100, opts);
        if (!res.ok || !res.ir_func || !res.ir_func->problems.empty()) {
            fail_msg(dc.name, "decompile failed");
        } else {
            dc.c_code = res.c_text;
            std::ostringstream cs;
            uint16_t ax_v[] = {0x00FF, 0x0001, 0x0080, 0x00FF};
            uint16_t bc_v[] = {0xEF01, 0xF0FE, 0xEF80, 0xFF01};
            for (int i = 0; i < 4; ++i) {
                auto mp = std::make_unique<Rl78RefMachine>(); auto &m = *mp;
                m.reset(0x0100);
                m.load_bytes(0x0100, dc.code);
                m.set_AX(ax_v[i]);
                m.set_BC(bc_v[i]);
                m.run();
                dc.expected_lines.push_back("d6:" + std::to_string(i) + "=" + hex16(m.AX()) + ":" + hex8(m.rd8(0xFFE21u)));
                cs << "    RL78_MEM8(0xFFE21) = 0;\n"
                   << "    { uint16_t r = d6_addc_chain(0x" << hex16(ax_v[i]) << ", 0x" << hex16(bc_v[i])
                   << "); printf(\"d6:" << i << "=%04X:%02X\\n\", (unsigned)r, (unsigned)RL78_MEM8(0xFFE21)); }\n";
            }
            dc.c_harness_calls = cs.str();
            cases.push_back(std::move(dc));
        }
    }

    // D7: Dynamic non-ES `[HL]` pointer dereference -> MUST access 0xF0000 | a0 [B2]
    {
        DiffCase dc;
        dc.name = "d7_dynamic_hl_ram_mirror";
        // a0 = AX -> movw hl, ax; mov a, [hl]; ret
        dc.code = {0x16, 0x8B, 0xD7};
        dc.proto = "uint8_t d7_read_hl(uint16_t a0)";
        rl78dec::MemoryDatabaseProvider db(0x10000, 0);
        db.write_bytes(0x0100, dc.code);
        db.add_func_entry(0x0100, "d7_read_hl");
        rl78dec::DecompileOptions opts;
        opts.verify_ir = true;
        opts.user_data.set_func_proto(dc.proto);
        auto res = rl78dec::decompile_function(db, 0x0100, opts);
        if (!res.ok || !res.ir_func || !res.ir_func->problems.empty()) {
            fail_msg(dc.name, "decompile failed");
        } else {
            dc.c_code = res.c_text;
            std::ostringstream cs;
            uint16_t ptrs[] = {0xFE40, 0x1234};
            for (uint16_t p : ptrs) {
                auto mp = std::make_unique<Rl78RefMachine>(); auto &m = *mp;
                m.reset(0x0100);
                m.load_bytes(0x0100, dc.code);
                m.wr8(0xF0000u | p, static_cast<uint8_t>((p ^ 0xA5u) & 0xFFu));
                m.wr8(p, 0x11u); // Distinct value at 0x0xxxx to catch missing 0xF0000!
                m.set_AX(p);
                m.run();
                dc.expected_lines.push_back("d7:" + hex16(p) + "=" + hex8(m.A()));
                cs << "    RL78_MEM8(0x" << std::hex << (0xF0000u | p) << ") = 0x" << hex8((p ^ 0xA5u) & 0xFFu) << ";\n"
                   << "    RL78_MEM8(0x" << std::hex << p << ") = 0x11;\n" << std::dec
                   << "    printf(\"d7:" << hex16(p) << "=%02X\\n\", (unsigned)d7_read_hl(0x" << hex16(p) << "));\n";
            }
            dc.c_harness_calls = cs.str();
            cases.push_back(std::move(dc));
        }
    }

    // D8: Pre-value clobber on Compare + flag-preserving MOV [B4]
    {
        DiffCase dc;
        dc.name = "d8_compare_prevalue_clobber";
        // cmp saddr_20, #5 ; 4A 20 05
        // mov saddr_20, #0 ; CD 20 00   (preserves Z and CY!)
        // bc +3            ; DC 03
        // mov a, #0x11     ; 51 11
        // ret              ; D7
        // mov a, #0x22     ; 51 22
        // ret              ; D7
        dc.code = {0x4A, 0x20, 0x05, 0xCD, 0x20, 0x00, 0xDC, 0x03, 0x51, 0x11, 0xD7, 0x51, 0x22, 0xD7};
        dc.proto = "uint8_t d8_cmp_mov(void)";
        auto res = decompile_bytes(dc.code, 0x0100, "d8_cmp_mov", dc.proto);
        if (!res.ok || !res.ir_func || !res.ir_func->problems.empty()) {
            fail_msg(dc.name, "decompile failed");
        } else {
            dc.c_code = res.c_text;
            std::ostringstream cs;
            for (uint8_t iv : {uint8_t(0), uint8_t(4), uint8_t(5), uint8_t(10)}) {
                auto mp = std::make_unique<Rl78RefMachine>(); auto &m = *mp;
                m.reset(0x0100);
                m.load_bytes(0x0100, dc.code);
                m.wr8(0xFFE20u, iv);
                m.run();
                dc.expected_lines.push_back("d8:" + hex8(iv) + "=" + hex8(m.A()));
                cs << "    RL78_MEM8(0xFFE20) = 0x" << hex8(iv) << ";\n"
                   << "    printf(\"d8:" << hex8(iv) << "=%02X\\n\", (unsigned)d8_cmp_mov());\n";
            }
            dc.c_harness_calls = cs.str();
            cases.push_back(std::move(dc));
        }
    }

    // D9: SAR / SARW / ROLC / RORC / MULU / BH / BNH
    {
        DiffCase dc;
        dc.name = "d9_sar_mulu_bh";
        // a0 = AX (A, X), a1 = BC (B, C)
        // sarw ax, 4        ; 31 4F
        // xchw ax, bc       ; 33    (BC = sarw(AX, 4), AX = orig BC)
        // cmpw ax, #0x1000  ; 44 00 10
        // bh +2             ; 61 C3 02  (if orig BC > 0x1000)
        // addw ax, #1       ; 04 01 00
        // addw ax, bc       ; 03
        // ret               ; D7
        dc.code = {0x31, 0x4F, 0x33, 0x44, 0x00, 0x10, 0x61, 0xC3, 0x03, 0x04, 0x01, 0x00, 0x03, 0xD7};
        // Note: 0x0106: 61 C3 03 skips 3 bytes (04 01 00 -> lands at 0x010C: 03 D7)
        dc.proto = "uint16_t d9_sarw_bh(uint16_t a0, uint16_t a1)";
        auto res = decompile_bytes(dc.code, 0x0100, "d9_sarw_bh", dc.proto);
        if (!res.ok || !res.ir_func || !res.ir_func->problems.empty()) {
            fail_msg(dc.name, "decompile failed");
        } else {
            dc.c_code = res.c_text;
            std::ostringstream cs;
            uint16_t ax_v[] = {0xA28C, 0x7FFF, 0x8000, 0x0000};
            uint16_t bc_v[] = {0x0FFF, 0x1000, 0x1001, 0xFFFF};
            for (int i = 0; i < 4; ++i) {
                auto mp = std::make_unique<Rl78RefMachine>(); auto &m = *mp;
                m.reset(0x0100);
                m.load_bytes(0x0100, dc.code);
                m.set_AX(ax_v[i]);
                m.set_BC(bc_v[i]);
                m.run();
                dc.expected_lines.push_back("d9:" + std::to_string(i) + "=" + hex16(m.AX()));
                cs << "    printf(\"d9:" << i << "=%04X\\n\", (unsigned)d9_sarw_bh(0x" << hex16(ax_v[i])
                   << ", 0x" << hex16(bc_v[i]) << "));\n";
            }
            dc.c_harness_calls = cs.str();
            cases.push_back(std::move(dc));
        }
    }

    // D10: Loop + nested if/else + switch table structuring (multi-block differential!)
    {
        DiffCase dc;
        dc.name = "d10_loop_and_switch_structuring";
        // Sum 1..N (N = a0 & 0xFF, in C):
        // 0100: 60          mov a, x      ; a = N
        // 0101: 72          mov c, a      ; c = N
        // 0102: 30 00 00    movw ax, #0   ; sum = 0
        // 0105: D2          cmp0 c        ; while (c != 0)
        // 0106: DD 07       bz 010F
        // 0108: 03          addw ax, bc? Wait: B is uninit! Clear B first:
        // Fix: 0100: 60 (mov a,x), 72 (mov c,a), F3 (clrb b), 30 00 00 (movw ax,#0)
        // 0106: D2 (cmp0 c), DD 04 (bz 010C), 03 (addw ax, bc), 92 (dec c), EF F9 (br 0106)
        // 010D: D7 (ret)  -- wait: 0107: DD 04 -> 0109+4 = 010D; 010B: EF F9 -> 010D-7 = 0106
        dc.code = {0x60, 0x72, 0xF3, 0x30, 0x00, 0x00, 0xD2, 0xDD, 0x04, 0x03, 0x92, 0xEF, 0xF9, 0xD7};
        dc.proto = "uint16_t d10_sum_loop(uint16_t a0)";
        auto res = decompile_bytes(dc.code, 0x0100, "d10_sum_loop", dc.proto);
        if (!res.ok || !res.ir_func || !res.ir_func->problems.empty()) {
            fail_msg(dc.name, "decompile failed");
        } else {
            dc.c_code = res.c_text;
            if (res.c_text.find("while") == std::string::npos && res.c_text.find("do") == std::string::npos) {
                fail_msg(dc.name, "Expected structured loop (while/do)");
            }
            std::ostringstream cs;
            for (uint16_t n : {uint16_t(0), uint16_t(1), uint16_t(5), uint16_t(10)}) {
                auto mp = std::make_unique<Rl78RefMachine>(); auto &m = *mp;
                m.reset(0x0100);
                m.load_bytes(0x0100, dc.code);
                m.set_AX(n);
                m.run();
                dc.expected_lines.push_back("d10:" + hex16(n) + "=" + hex16(m.AX()));
                cs << "    printf(\"d10:" << hex16(n) << "=%04X\\n\", (unsigned)d10_sum_loop(0x" << hex16(n) << "));\n";
            }
            dc.c_harness_calls = cs.str();
            cases.push_back(std::move(dc));
        }
    }

    // D11: Switch table structuring (`shlw ax, 1; addw ax, #tbl; br ax` -> `switch`)
    {
        DiffCase dc;
        dc.name = "d11_switch_table";
        // 0x0100: clrb a         ; F1
        // 0x0101: shlw ax, 1     ; 31 1D
        // 0x0103: addw ax, #0x0130 ; 04 30 01
        // 0x0106: movw hl, ax    ; 16
        // 0x0107: movw ax, [hl]  ; AB
        // 0x0108: br ax          ; 61 CB -> wait: br ax jumps directly to [tbl + idx*2] or tbl itself!
        // Note: switch_table.cpp checks `shlw ax, 1; addw ax, #tbl; ... br ax`
        // Let's also test direct jump table `br ax` where tbl contains branch insns (4-byte entries) OR 2-byte address table!
        // Let's use 4-byte branch table at 0x0110 (shlw ax, 2; addw ax, #0x0110; br ax):
        // 0x0100: clrb a         ; F1
        // 0x0101: shlw ax, 2     ; 31 2D
        // 0x0103: addw ax, #0x0110 ; 04 10 01
        // 0x0106: br ax          ; 61 CB
        // 0x0110: br !0x0120; nop ; ED 20 01 00
        // 0x0114: br !0x0124; nop ; ED 24 01 00
        // 0x0118: br !0x0128; nop ; ED 28 01 00
        // 0x0120: movw ax, #0xAA; ret -> 30 AA 00 D7
        // 0x0124: movw ax, #0xBB; ret -> 30 BB 00 D7
        // 0x0128: movw ax, #0xCC; ret -> 30 CC 00 D7
        // Wait: switch_table.cpp reads targets as u16/u32 addresses from table_ea!
        // Let's use 2-byte address table at 0x0110 with `shlw ax, 1; addw ax, #0x0110; movw hl, ax; movw ax, [hl]; br ax`:
        rl78dec::MemoryDatabaseProvider db(0x100000, 0);
        db.write_bytes(0x0100, {0xF1, 0x31, 0x1D, 0x04, 0x10, 0x01, 0x16, 0xAB, 0x61, 0xCB});
        db.write_u16_le(0x0110, 0x0120);
        db.write_u16_le(0x0112, 0x0124);
        db.write_u16_le(0x0114, 0x0128);
        db.write_u16_le(0xF0110, 0x0120);
        db.write_u16_le(0xF0112, 0x0124);
        db.write_u16_le(0xF0114, 0x0128);
        db.write_bytes(0x0120, {0x30, 0xAA, 0x00, 0xD7});
        db.write_bytes(0x0124, {0x30, 0xBB, 0x00, 0xD7});
        db.write_bytes(0x0128, {0x30, 0xCC, 0x00, 0xD7});
        db.add_func_entry(0x0100, "d11_switch");
        rl78dec::DecompileOptions opts;
        opts.verify_ir = true;
        opts.user_data.set_func_proto("uint16_t d11_switch(uint16_t a0)");
        auto res = rl78dec::decompile_function(db, 0x0100, opts);
        if (!res.ok || !res.ir_func || !res.ir_func->problems.empty()) {
            fail_msg(dc.name, "decompile failed");
        } else if (res.c_text.find("switch (") == std::string::npos) {
            fail_msg(dc.name, "Expected structured `switch (`");
        } else {
            // Also verify cit_switch node exists in cfunc_t ctree with 3 cases
            bool found_cit_switch = false;
            size_t sw_cases = 0;
            auto find_sw = [&](auto &self, const rl78dec::cinsn_t *ins) -> void {
                if (!ins || found_cit_switch) return;
                if (ins->op == rl78dec::cit_switch) {
                    found_cit_switch = true;
                    sw_cases = ins->cswitch.cases.size();
                    return;
                }
                if (ins->op == rl78dec::cit_block) {
                    for (const auto *st : ins->cblock.statements) self(self, st);
                } else if (ins->op == rl78dec::cit_if) {
                    self(self, ins->cif.ithen);
                    self(self, ins->cif.ielse);
                } else if (ins->op == rl78dec::cit_while || ins->op == rl78dec::cit_do || ins->op == rl78dec::cit_for) {
                    self(self, ins->cloop.body);
                }
            };
            if (res.cfunc) find_sw(find_sw, res.cfunc->body);
            if (!found_cit_switch || sw_cases != 3) {
                fail_msg(dc.name, "cfunc_t missing cit_switch with 3 cases");
            }
            dc.c_code = res.c_text;
            std::ostringstream cs;
            for (uint16_t sel : {uint16_t(0), uint16_t(1), uint16_t(2)}) {
                auto mp = std::make_unique<Rl78RefMachine>(); auto &m = *mp;
                m.reset(0x0100);
                m.load_bytes(0x0100, {0xF1, 0x31, 0x1D, 0x04, 0x10, 0x01, 0x16, 0xAB, 0x61, 0xCB});
                m.wr16(0x0110, 0x0120);
                m.wr16(0x0112, 0x0124);
                m.wr16(0x0114, 0x0128);
                m.wr16(0xF0110, 0x0120);
                m.wr16(0xF0112, 0x0124);
                m.wr16(0xF0114, 0x0128);
                m.load_bytes(0x0120, {0x30, 0xAA, 0x00, 0xD7});
                m.load_bytes(0x0124, {0x30, 0xBB, 0x00, 0xD7});
                m.load_bytes(0x0128, {0x30, 0xCC, 0x00, 0xD7});
                m.set_AX(sel);
                m.run();
                dc.expected_lines.push_back("d11:" + hex16(sel) + "=" + hex16(m.AX()));
                cs << "    printf(\"d11:" << hex16(sel) << "=%04X\\n\", (unsigned)d11_switch(0x" << hex16(sel) << "));\n";
            }
            dc.c_harness_calls = cs.str();
            cases.push_back(std::move(dc));
        }
    }

    // D12: Without user_proto: dynamic [HL] + flags + return value (tests auto ABI + [HL] 0xF0000)
    {
        DiffCase dc;
        dc.name = "d12_auto_abi_hl_mirror";
        // movw hl, ax; mov a, [hl]; add a, #1; ret  (returns uint8_t)
        dc.code = {0x16, 0x8B, 0x0C, 0x01, 0xD7};
        auto res = decompile_bytes(dc.code, 0x0100, "d12_auto_hl");
        if (!res.ok || !res.ir_func || !res.ir_func->problems.empty()) {
            fail_msg(dc.name, "decompile failed");
        } else {
            dc.c_code = res.c_text;
            std::ostringstream cs;
            for (uint16_t p : {uint16_t(0xFE50), uint16_t(0x2000)}) {
                auto mp = std::make_unique<Rl78RefMachine>(); auto &m = *mp;
                m.reset(0x0100);
                m.load_bytes(0x0100, dc.code);
                m.wr8(0xF0000u | p, 0x7Eu);
                m.wr8(p, 0x22u);
                m.set_AX(p);
                m.run();
                dc.expected_lines.push_back("d12:" + hex16(p) + "=" + hex8(m.A()));
                cs << "    RL78_MEM8(0x" << std::hex << (0xF0000u | p) << ") = 0x7E;\n"
                   << "    RL78_MEM8(0x" << std::hex << p << ") = 0x22;\n" << std::dec
                   << "    printf(\"d12:" << hex16(p) << "=%02X\\n\", (unsigned)d12_auto_hl(0x" << hex16(p) << "));\n";
            }
            dc.c_harness_calls = cs.str();
            cases.push_back(std::move(dc));
        }
    }

    // D13: Chained ROLWC BC, 1 / ROLWC AX, 1 (32-bit rotate through carry)
    {
        DiffCase dc;
        dc.name = "d13_rolwc_chain";
        // a0 = AX, a1 = BC -> set1 cy (71 80), rolwc ax, 1 (61 EE), rolwc bc, 1 (61 FE), addw ax, bc (03), ret (D7)
        dc.code = {0x71, 0x80, 0x61, 0xEE, 0x61, 0xFE, 0x03, 0xD7};
        dc.proto = "uint16_t d13_rolwc(uint16_t a0, uint16_t a1)";
        auto res = decompile_bytes(dc.code, 0x0100, "d13_rolwc", dc.proto);
        if (!res.ok || !res.ir_func || !res.ir_func->problems.empty()) {
            fail_msg(dc.name, "decompile failed");
        } else {
            dc.c_code = res.c_text;
            std::ostringstream cs;
            uint16_t ax_v[] = {0x8000, 0x7FFF, 0x0001, 0xFFFF};
            uint16_t bc_v[] = {0x0000, 0x1234, 0x8000, 0x0001};
            for (int i = 0; i < 4; ++i) {
                auto mp = std::make_unique<Rl78RefMachine>(); auto &m = *mp;
                m.reset(0x0100);
                m.load_bytes(0x0100, dc.code);
                m.set_AX(ax_v[i]);
                m.set_BC(bc_v[i]);
                m.run();
                dc.expected_lines.push_back("d13:" + std::to_string(i) + "=" + hex16(m.AX()));
                cs << "    printf(\"d13:" << i << "=%04X\\n\", (unsigned)d13_rolwc(0x" << hex16(ax_v[i])
                   << ", 0x" << hex16(bc_v[i]) << "));\n";
            }
            dc.c_harness_calls = cs.str();
            cases.push_back(std::move(dc));
        }
    }

    // D14: RL78-S3 MULH (signed 16x16->32) + DIVHU (with divide-by-zero 0xFFFF semantics)
    {
        DiffCase dc;
        dc.name = "d14_rl78_s3_mulh_divhu";
        // CE FB 02 (mulh), 15 (movw ax, de? no: 14=movw de,ax, wait high word is BC -> move BC to DE via 13 14? Wait:)
        // Better: 13 (movw ax,bc)?? No, CE FB 02 puts low16 in AX and high16 in BC.
        // Let's save AX->HL (16), movw ax,bc (13), movw de,ax (14), movw ax,hl (17), divhu (CE FB 03), addw ax,de (05), ret (D7)
        dc.code = {0xCE, 0xFB, 0x02, 0x16, 0x13, 0x14, 0x17, 0xCE, 0xFB, 0x03, 0x05, 0xD7};
        dc.proto = "uint16_t d14_mulh_divhu(uint16_t a0, uint16_t a1)";
        auto res = decompile_bytes(dc.code, 0x0100, "d14_mulh_divhu", dc.proto);
        if (!res.ok || !res.ir_func || !res.ir_func->problems.empty()) {
            fail_msg(dc.name, "decompile failed");
        } else {
            dc.c_code = res.c_text;
            std::ostringstream cs;
            uint16_t a0v[] = {0xC000, 0xFFFE, 0x0100, 0x8081};
            uint16_t a1v[] = {0x1000, 0x0003, 0x0000, 0x0001};
            for (int i = 0; i < 4; ++i) {
                auto mp = std::make_unique<Rl78RefMachine>(); auto &m = *mp;
                m.reset(0x0100);
                m.load_bytes(0x0100, dc.code);
                m.set_AX(a0v[i]);
                m.set_BC(a1v[i]);
                m.run();
                dc.expected_lines.push_back("d14:" + std::to_string(i) + "=" + hex16(m.AX()));
                cs << "    printf(\"d14:" << i << "=%04X\\n\", (unsigned)d14_mulh_divhu(0x"
                   << hex16(a0v[i]) << ", 0x" << hex16(a1v[i]) << "));\n";
            }
            dc.c_harness_calls = cs.str();
            cases.push_back(std::move(dc));
        }
    }

    // D15: RL78-S3 MACHU (MACR 0xFFFF0) + DIVWU (32/32 including /0 -> 0xFFFFFFFF)
    {
        DiffCase dc;
        dc.name = "d15_rl78_s3_divwu_machu";
        // movw de,ax (14); movw ax,#0 (30 00 00); movw macrl,ax (BE F0); movw macrh,ax (BE F2);
        // movw ax,de (15); machu (CE FB 05); movw ax,bc (13); movw de,ax (14); movw hl,#0 (36 00 00);
        // movw ax,macrh (AE F2); movw bc,ax (12); movw ax,macrl (AE F0);
        // divwu (CE FB 0B); addw ax,bc (03); addw ax,de (05); ret (D7)
        dc.code = {
            0x14, 0x30, 0x00, 0x00, 0xBE, 0xF0, 0xBE, 0xF2,
            0x15, 0xCE, 0xFB, 0x05, 0x13, 0x14, 0x36, 0x00, 0x00,
            0xAE, 0xF2, 0x12, 0xAE, 0xF0,
            0xCE, 0xFB, 0x0B, 0x03, 0x05, 0xD7
        };
        dc.proto = "uint16_t d15_divwu_machu(uint16_t a0, uint16_t a1)";
        auto res = decompile_bytes(dc.code, 0x0100, "d15_divwu_machu", dc.proto);
        if (!res.ok || !res.ir_func || !res.ir_func->problems.empty()) {
            fail_msg(dc.name, "decompile failed");
        } else {
            dc.c_code = res.c_text;
            std::ostringstream cs;
            uint16_t a0v[] = {0xC000, 0x1234, 0xFFFF};
            uint16_t a1v[] = {0x1000, 0x0000, 0x0002};
            for (int i = 0; i < 3; ++i) {
                auto mp = std::make_unique<Rl78RefMachine>(); auto &m = *mp;
                m.reset(0x0100);
                m.load_bytes(0x0100, dc.code);
                m.set_AX(a0v[i]);
                m.set_BC(a1v[i]);
                m.run();
                dc.expected_lines.push_back("d15:" + std::to_string(i) + "=" + hex16(m.AX()));
                cs << "    printf(\"d15:" << i << "=%04X\\n\", (unsigned)d15_divwu_machu(0x"
                   << hex16(a0v[i]) << ", 0x" << hex16(a1v[i]) << "));\n";
            }
            dc.c_harness_calls = cs.str();
            cases.push_back(std::move(dc));
        }
    }

    // D16: Multi-predecessor CY join into ADDC + uint8_t param + local X high/low split
    {
        DiffCase dc;
        dc.name = "d16_multi_pred_cy_join_and_u8_hi_split";
        // cmp a,#10 (4C 0A); bc +4 (DC 04); add a,#0x10 (0C 10); br +2 (EF 02); set1 cy (71 80);
        // addc a,#0 (1C 00); mov x,#5 (50 05); movw bc,ax (12); movw ax,bc (13); ret (D7)
        dc.code = {0x4C, 0x0A, 0xDC, 0x04, 0x0C, 0x10, 0xEF, 0x02, 0x71, 0x80, 0x1C, 0x00, 0x50, 0x05, 0x12, 0x13, 0xD7};
        dc.proto = "uint16_t d16_join(uint8_t a0)";
        auto res = decompile_bytes(dc.code, 0x0100, "d16_join", dc.proto);
        if (!res.ok || !res.ir_func || !res.ir_func->problems.empty()) {
            fail_msg(dc.name, "decompile failed");
        } else {
            dc.c_code = res.c_text;
            std::ostringstream cs;
            for (uint8_t inp : {uint8_t(5), uint8_t(10), uint8_t(0xF5)}) {
                auto mp = std::make_unique<Rl78RefMachine>(); auto &m = *mp;
                m.reset(0x0100);
                m.load_bytes(0x0100, dc.code);
                m.set_A(inp);
                m.run();
                dc.expected_lines.push_back("d16:" + hex8(inp) + "=" + hex16(m.AX()));
                cs << "    printf(\"d16:" << hex8(inp) << "=%04X\\n\", (unsigned)d16_join(0x" << hex8(inp) << "));\n";
            }
            dc.c_harness_calls = cs.str();
            cases.push_back(std::move(dc));
        }
    }

    // Compile & execute each differential case individually so one buggy case doesn't mask others!
    for (const auto &dc : cases) {
        if (dc.c_code.find("es_mem8") != std::string::npos || dc.c_code.find("mem8") != std::string::npos) {
            fail_msg(dc.name, "Memory reference intrinsic (mem8/es_mem8) leaked into native C output!\n" + dc.c_code);
            continue;
        }
        std::string zs_diag;
        if (!compile_check_c_src(dc.c_code, &zs_diag)) {
            fail_msg(dc.name, "Raw unmodified C failed cl.exe /Zs:\n" + zs_diag + "\n--- C code ---\n" + dc.c_code);
            continue;
        }
        std::string tu = dc.c_code + "\nint main(void) {\n" + dc.c_harness_calls + "    return 0;\n}\n";
        std::string stdout_s, err_s;
        if (!compile_and_run_c_exe(tu, stdout_s, err_s)) {
            fail_msg(dc.name, "cl.exe compile/run failed:\n" + err_s + "\n--- C code ---\n" + dc.c_code);
            continue;
        }
        std::vector<std::string> got;
        std::istringstream iss(stdout_s);
        std::string ln;
        while (std::getline(iss, ln)) {
            while (!ln.empty() && (ln.back() == '\r' || ln.back() == '\n')) ln.pop_back();
            if (!ln.empty()) got.push_back(ln);
        }
        if (got != dc.expected_lines) {
            std::ostringstream msg;
            msg << "Semantic mismatch vs Rl78RefMachine!\n" << dc.c_code << "\nExpected vs Got:\n";
            size_t n = std::max(dc.expected_lines.size(), got.size());
            for (size_t i = 0; i < n; ++i) {
                msg << "  exp=" << (i < dc.expected_lines.size() ? dc.expected_lines[i] : "<missing>")
                    << "  got=" << (i < got.size() ? got[i] : "<missing>") << "\n";
            }
            fail_msg(dc.name, msg.str());
        } else {
            pass_msg(dc.name);
        }
    }
}

// ===========================================================================
// ADDITIONAL TIER 1 MULTI-BLOCK STRUCTURING TESTS
// ===========================================================================
void test_nested_if_else_and_loop_break_continue() {
    const std::string kTestName = "test_nested_if_else_and_loop_break_continue";
    // Nested if/else + loop with break & continue:
    // 0100: 30 00 00    movw ax, #0
    // 0103: 52 05       mov c, #5
    // 0105: D2          cmp0 c
    // 0106: DD 0D       bz 0115
    // 0108: 62          mov a, c
    // 0109: 4C 03       cmp a, #3
    // 010B: DD 06       bz 0113     (continue: dec c; br 0105)
    // 010D: 4C 01       cmp a, #1
    // 010F: DD 04       bz 0115     (break)
    // 0111: 80          inc x
    // 0112: 92          dec c
    // 0113: EF F0       br 0105
    // 0115: 60          mov a, x
    // 0116: D7          ret
    auto res = decompile_bytes({
        0x30, 0x00, 0x00,
        0x52, 0x05,
        0xD2,
        0xDD, 0x0B,
        0x62,
        0x4C, 0x03,
        0xDD, 0x05,
        0x4C, 0x01,
        0xDD, 0x03,
        0x80,
        0x92,
        0xEF, 0xF0,
        0x60, 0xD7
    });
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    CHECK(res.c_text.find("while") != std::string::npos || res.c_text.find("do") != std::string::npos,
          "Expected loop structuring");
    std::string diag;
    CHECK(compile_check_c_src(res.c_text, &diag), "cl.exe /Zs failed:\n" + diag);
    pass_msg(kTestName);
}

void test_mulu_and_callt_and_brk() {
    const std::string kTestName = "test_mulu_and_callt_and_brk";
    // 51 0C 50 0A D6 (mulu x: 12 * 10 = 120) + callt [0080] (61 84) + ret (D7)
    rl78dec::MemoryDatabaseProvider db(0x10000, 0);
    db.write_u16_le(0x0080, 0x0300);
    db.write_bytes(0x0100, {0x51, 0x0C, 0x50, 0x0A, 0xD6, 0x61, 0x84, 0xD7});
    db.write_bytes(0x0300, {0xD7});
    rl78dec::DecompileOptions opts;
    opts.verify_ir = true;
    auto res = rl78dec::decompile_function(db, 0x0100, opts);
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    CHECK(res.c_text.find("sub_300(") != std::string::npos, "CALLT [0080] must resolve vector 0x0300");
    std::string diag;
    CHECK(compile_check_c_src("void sub_300(uint16_t a0);\n" + res.c_text, &diag), "cl.exe /Zs failed:\n" + diag);
    pass_msg(kTestName);
}

void test_word_bc_indexed_and_es_movw() {
    const std::string kTestName = "test_word_bc_indexed_and_es_movw";
    // 41 03          : mov es, #3
    // 11 59 00 20    : movw ax, ES:0x2000[b]
    // 58 00 30       : movw 0x3000[b], ax (no ES -> 0xF3000!)
    // D7             : ret
    auto res = decompile_bytes({0x41, 0x03, 0x11, 0x59, 0x00, 0x20, 0x58, 0x00, 0x30, 0xD7});
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    CHECK(res.c_text.find("es_mem8") == std::string::npos && res.c_text.find("mem8") == std::string::npos,
          "Expected native C pointer dereferences instead of mem8/es_mem8");
    CHECK(res.c_text.find("0x32000") != std::string::npos, "ES:0x2000[b] must fold ES=3 to 0x32000");
    CHECK(res.c_text.find("0xF3000") != std::string::npos, "Non-ES 0x3000[b] must map to 0xF3000");
    std::string diag;
    CHECK(compile_check_c_src(res.c_text, &diag), "cl.exe /Zs failed:\n" + diag);
    pass_msg(kTestName);
}

void test_itron_rdyq_remove_es_0f_and_native_c_compliance() {
    const std::string kTestName = "test_itron_rdyq_remove_es_0f_and_native_c_compliance";
    // Exact machine bytes of syscon-1.01.bin.i64:
    //   itron_rdyq_remove @ 0x6F44..0x6F8B
    //   itron_queue_remove @ 0x6F8C..0x6FB5
    const std::vector<uint8_t> rdyq_bytes = {
        0xF6, 0x11, 0x29, 0xE5, 0xB3, 0x08, 0x04, 0xD2, 0xB2, 0x14, 0xC3, 0xFE, 0x3A, 0x00,
        0xC2, 0xC3, 0xD1, 0xDF, 0x21, 0x11, 0x29, 0xE5, 0xB3, 0x75, 0x53, 0x01, 0x2C, 0x08,
        0xDE, 0x02, 0xF3, 0x65, 0x52, 0x01, 0xD1, 0xDD, 0x05, 0x31, 0x17, 0x91, 0xDF, 0xFB,
        0x11, 0x09, 0xCE, 0xB2, 0x61, 0x7A, 0x11, 0x18, 0xCE, 0xB2, 0x11, 0x8F, 0xCA, 0xB2,
        0xC2, 0x61, 0x4A, 0xDF, 0x0A, 0x11, 0x8F, 0xC9, 0xB2, 0x5C, 0xF7, 0x11, 0x9F, 0xC9,
        0xB2, 0xD7
    };
    const std::vector<uint8_t> q_bytes = {
        0x11, 0x29, 0x15, 0xB4, 0x61, 0x4A, 0xDD, 0x1C, 0x70, 0x11, 0x89, 0x61, 0x4A, 0xDF,
        0x03, 0x60, 0x11, 0x99, 0x11, 0x29, 0x21, 0xB4, 0x61, 0x8A, 0x08, 0x11, 0x28, 0x15,
        0xB4, 0x61, 0x8A, 0x11, 0x28, 0x21, 0xB4, 0xD7, 0x11, 0xCA, 0x00, 0xFF, 0xF1, 0xD7
    };

    rl78dec::MemoryDatabaseProvider db(0x100000, 0);
    db.write_bytes(0x6F44, rdyq_bytes);
    db.write_bytes(0x6F8C, q_bytes);
    db.add_func_entry(0x6F44, "itron_rdyq_remove");
    db.add_func_entry(0x6F8C, "itron_queue_remove");
    db.set_default_es(0x0F);
    db.set_caller_consensus(0x6F8C, {true, true, true});

    db.set_symbol_info(0xFB3E5, {"byte_FB3E5", 0xFB3E5, 0, 1, false, false, ""});
    db.set_symbol_info(0xFB2CE, {"word_FB2CE", 0xFB2CE, 0, 2, false, false, ""});
    db.set_symbol_info(0xFB2CA, {"word_FB2CA", 0xFB2CA, 0, 2, false, false, ""});
    db.set_symbol_info(0xFB2C8, {"word_FB2C8", 0xFB2C8, 0, 2, false, false, ""});
    db.set_symbol_info(0xFB415, {"byte_FB415", 0xFB415, 0, 1, false, false, ""});
    db.set_symbol_info(0xFB421, {"byte_FB421", 0xFB421, 0, 1, false, false, ""});

    rl78dec::DecompileOptions opts;
    opts.verify_ir = true;
    auto res_q = rl78dec::decompile_function(db, 0x6F8C, opts);
    CHECK(res_q.ok && res_q.ir_func && res_q.ir_func->problems.empty(), "itron_queue_remove decompile failed");
    CHECK(res_q.c_text.find("es_mem8") == std::string::npos && res_q.c_text.find("mem8") == std::string::npos,
          "mem8/es_mem8 leaked in itron_queue_remove:\n" + res_q.c_text);
    CHECK(res_q.c_text.find("uint8_t itron_queue_remove(uint16_t a0, uint16_t a1, uint16_t a2)") != std::string::npos,
          "Expected multi-exit uint8_t return + DE a2 param on itron_queue_remove:\n" + res_q.c_text);
    CHECK(res_q.c_text.find("byte_FB415[") != std::string::npos && res_q.c_text.find("byte_FB421[") != std::string::npos,
          "Expected native byte_FB415/byte_FB421 array indexing in itron_queue_remove:\n" + res_q.c_text);
    CHECK(res_q.c_text.find("return 0;") != std::string::npos,
          "Expected `return 0;` in empty branch of itron_queue_remove:\n" + res_q.c_text);

    // Populate callee prototype on DB (mirroring IDA interprocedural cache) before decompiling caller
    db.set_func_proto(0x6F8C, "uint8_t itron_queue_remove(uint16_t a0, uint16_t a1)");
    auto res_r = rl78dec::decompile_function(db, 0x6F44, opts);
    CHECK(res_r.ok && res_r.ir_func && res_r.ir_func->problems.empty(), "itron_rdyq_remove decompile failed");

    CHECK(res_r.c_text.find("es_mem8") == std::string::npos, "es_mem8 leaked in itron_rdyq_remove:\n" + res_r.c_text);
    CHECK(res_r.c_text.find("mem8") == std::string::npos, "mem8 leaked in itron_rdyq_remove:\n" + res_r.c_text);

    CHECK(res_r.c_text.find("byte_FB3E5[") != std::string::npos,
          "Expected native C symbol array access byte_FB3E5[...] in:\n" + res_r.c_text);
    CHECK(res_r.c_text.find("word_FB2CE") != std::string::npos, "Missing word_FB2CE in:\n" + res_r.c_text);
    CHECK(res_r.c_text.find("word_FB2CA") != std::string::npos, "Missing word_FB2CA in:\n" + res_r.c_text);
    CHECK(res_r.c_text.find("word_FB2C8") != std::string::npos, "Missing word_FB2C8 in:\n" + res_r.c_text);
    CHECK(res_r.c_text.find("= itron_queue_remove(") != std::string::npos,
          "Expected itron_rdyq_remove to capture uint8_t return of itron_queue_remove(...):\n" + res_r.c_text);
    CHECK(res_r.cfunc && res_r.cfunc->sym_eas.count("byte_FB3E5") && res_r.cfunc->sym_eas["byte_FB3E5"] == 0xFB3E5,
          "sym_eas missing byte_FB3E5 -> 0xFB3E5");

    std::string decls =
        "extern uint8_t byte_FB3E5[];\n"
        "extern uint16_t word_FB2CE;\n"
        "extern uint16_t word_FB2CA;\n"
        "extern uint16_t word_FB2C8;\n"
        "extern uint8_t byte_FB415[];\n"
        "extern uint8_t byte_FB421[];\n\n";
    std::string comb_c = decls + res_q.c_text + "\n";
    std::string diag;
    CHECK(compile_check_c_src(comb_c, &diag), "Raw unmodified itron_queue_remove C failed cl.exe /Zs:\n" + diag + "\n" + comb_c);
    std::string r_c = decls + "uint8_t itron_queue_remove(uint16_t a0, uint16_t a1);\n\n" + res_r.c_text;
    CHECK(compile_check_c_src(r_c, &diag), "Raw unmodified itron_rdyq_remove C failed cl.exe /Zs:\n" + diag + "\n" + r_c);

    // Differential semantic execution vs Rl78RefMachine across bitmasks [0..15], queue states & cur_tid
    std::ostringstream cs;
    std::vector<std::string> expected;
    struct Vec { uint8_t tid; uint8_t prio; uint8_t cur_tid; bool solo; };
    std::vector<Vec> vecs = {
        {2, 3, 2, true},    // low byte bitmap, queue becomes empty, cur_tid matches -> clears word_FB2C8+1 bit 3
        {4, 11, 1, true},   // high byte bitmap (>=8), queue becomes empty, cur_tid != tid
        {3, 5, 3, false},   // 2-element queue, non-empty after unlink -> bitmap NOT cleared!
    };
    for (size_t vi = 0; vi < vecs.size(); ++vi) {
        const auto &v = vecs[vi];
        auto setup_ref = [&](Rl78RefMachine &m) {
            m.reset(0x6F44);
            m.load_bytes(0x6F44, rdyq_bytes);
            m.load_bytes(0x6F8C, q_bytes);
            m.es = 0x0F;
            m.set_BC(v.tid);
            m.wr8(0xFB3E5u + v.tid, v.prio);
            m.wr16(0xFB2CEu, 0xAAAAu);
            m.wr8(0xFB2CAu, v.cur_tid);
            m.wr8(0xFB2C9u, 0xFFu);
            uint32_t qhead = 0xFB2D2u + v.prio;
            if (v.solo) {
                m.wr8(qhead, v.tid);
                m.wr8(0xFB415u + v.tid, v.tid);
                m.wr8(0xFB421u + v.tid, v.tid);
            } else {
                uint8_t other = static_cast<uint8_t>(v.tid + 1);
                m.wr8(qhead, v.tid);
                m.wr8(0xFB415u + v.tid, other);
                m.wr8(0xFB421u + v.tid, other);
                m.wr8(0xFB415u + other, v.tid);
                m.wr8(0xFB421u + other, v.tid);
            }
        };
        auto mp = std::make_unique<Rl78RefMachine>();
        setup_ref(*mp);
        mp->run();
        char ebuf[128];
        std::snprintf(ebuf, sizeof(ebuf), "itron:%zu=%04X:%02X:%02X:%02X",
                      vi, (unsigned)mp->rd16(0xFB2CEu), (unsigned)mp->rd8(0xFB2C9u),
                      (unsigned)mp->rd8(0xFB2D2u + v.prio),
                      (unsigned)mp->rd8(0xFB415u + (v.solo ? v.tid : v.tid + 1)));
        expected.push_back(ebuf);

        cs << "    memset(g_rl78_mem, 0, sizeof(g_rl78_mem));\n"
           << "    byte_FB3E5[" << (int)v.tid << "] = " << (int)v.prio << ";\n"
           << "    word_FB2CE = 0xAAAAu;\n"
           << "    word_FB2CA = " << (int)v.cur_tid << ";\n"
           << "    word_FB2C8 = 0xFF00u;\n"
           << "    g_rl78_mem[0xFB2D2u + " << (int)v.prio << "] = " << (int)v.tid << ";\n";
        if (v.solo) {
            cs << "    byte_FB415[" << (int)v.tid << "] = " << (int)v.tid << ";\n"
               << "    byte_FB421[" << (int)v.tid << "] = " << (int)v.tid << ";\n";
        } else {
            int other = v.tid + 1;
            cs << "    byte_FB415[" << (int)v.tid << "] = " << other << ";\n"
               << "    byte_FB421[" << (int)v.tid << "] = " << other << ";\n"
               << "    byte_FB415[" << other << "] = " << (int)v.tid << ";\n"
               << "    byte_FB421[" << other << "] = " << (int)v.tid << ";\n";
        }
        cs << "    itron_rdyq_remove(" << (int)v.tid << ");\n"
           << "    printf(\"itron:" << vi << "=%04X:%02X:%02X:%02X\\n\", "
           << "(unsigned)word_FB2CE, (unsigned)*((uint8_t *)&word_FB2C8 + 1), "
           << "(unsigned)g_rl78_mem[0xFB2D2u + " << (int)v.prio << "], "
           << "(unsigned)byte_FB415[" << (v.solo ? (int)v.tid : (int)(v.tid + 1)) << "]);\n";
    }

    std::string storage =
        "uint8_t byte_FB3E5[64];\n"
        "uint16_t word_FB2CE;\n"
        "uint16_t word_FB2CA;\n"
        "uint16_t word_FB2C8;\n"
        "uint8_t byte_FB415[64];\n"
        "uint8_t byte_FB421[64];\n"
        "static uint8_t itron_queue_remove(uint16_t qhead, uint16_t tid16) {\n"
        "    uint8_t tid = (uint8_t)tid16;\n"
        "    uint8_t next = byte_FB415[tid];\n"
        "    if (next == tid) {\n"
        "        RL78_MEM8(0xF0000u | qhead) = 0xFF;\n"
        "        return 0;\n"
        "    }\n"
        "    if (RL78_MEM8(0xF0000u | qhead) == tid) {\n"
        "        RL78_MEM8(0xF0000u | qhead) = next;\n"
        "    }\n"
        "    uint8_t prev = byte_FB421[tid];\n"
        "    byte_FB415[prev] = next;\n"
        "    byte_FB421[next] = prev;\n"
        "    return prev;\n"
        "}\n\n";
    std::string tu = storage + res_r.c_text + "\nint main(void) {\n" + cs.str() + "    return 0;\n}\n";
    std::string stdout_s, err_s;
    CHECK(compile_and_run_c_exe(tu, stdout_s, err_s), "cl.exe compile/run failed:\n" + err_s + "\n" + tu);

    std::vector<std::string> got;
    std::istringstream iss(stdout_s);
    std::string ln;
    while (std::getline(iss, ln)) {
        while (!ln.empty() && (ln.back() == '\r' || ln.back() == '\n')) ln.pop_back();
        if (!ln.empty()) got.push_back(ln);
    }
    if (got != expected) {
        std::ostringstream d;
        d << "Differential mismatch on itron_rdyq_remove!\nExpected:\n";
        for (const auto &s : expected) d << "  " << s << "\n";
        d << "Got:\n";
        for (const auto &s : got) d << "  " << s << "\n";
        CHECK(false, d.str());
    }
    pass_msg(kTestName);
}

void test_dynamic_es_not_falsely_folded_differential() {
    const std::string kTestName = "test_dynamic_es_not_falsely_folded_differential";
    // Even if DB says ES=0x0F at function entry, `mov es, a` makes ES dynamic!
    // 0100: 9E FD     mov es, a
    // 0102: 14        movw de, ax   (Wait: pass ptr in BC=a1, seg in A=a0: movw de, bc? Use movw ax, bc (13); movw de, ax (14)!)
    // Actually: a0 = AX (A=seg, X=dummy), a1 = BC (ptr16):
    // 0100: 9E FD     mov ES, a
    // 0102: 13        movw ax, bc
    // 0103: 14        movw de, ax
    // 0104: 11 89     mov a, es:[de]
    // 0106: D7        ret
    const std::vector<uint8_t> code = {0x9E, 0xFD, 0x13, 0x14, 0x11, 0x89, 0xD7};
    rl78dec::MemoryDatabaseProvider db(0x10000, 0);
    db.write_bytes(0x0100, code);
    db.add_func_entry(0x0100, "dyn_es_read");
    db.set_default_es(0x0F);

    rl78dec::DecompileOptions opts;
    opts.verify_ir = true;
    opts.user_data.set_func_proto("uint8_t dyn_es_read(uint16_t a0, uint16_t a1)");
    auto res = rl78dec::decompile_function(db, 0x0100, opts);
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    CHECK(res.c_text.find("es_mem8") == std::string::npos && res.c_text.find("mem8") == std::string::npos,
          "mem8/es_mem8 leaked:\n" + res.c_text);
    CHECK(res.c_text.find("0xF0123") == std::string::npos &&
              res.c_text.find("(es & 0xFu)") != std::string::npos,
          "Dynamic `mov es, a` was falsely folded to entry ES=0x0F!\n" + res.c_text);

    std::string diag;
    CHECK(compile_check_c_src(res.c_text, &diag), "cl.exe /Zs failed:\n" + diag);

    std::vector<std::string> expected;
    std::ostringstream cs;
    for (uint8_t seg : {uint8_t(0), uint8_t(1), uint8_t(2), uint8_t(0xF)}) {
        auto mp = std::make_unique<Rl78RefMachine>();
        mp->reset(0x0100);
        mp->load_bytes(0x0100, code);
        mp->wr8(0x00123u, 0x10);
        mp->wr8(0x10123u, 0x20);
        mp->wr8(0x20123u, 0x30);
        mp->wr8(0xF0123u, 0x40);
        mp->set_AX(static_cast<uint16_t>(seg) << 8);
        mp->set_BC(0x0123u);
        mp->run();
        expected.push_back("seg:" + hex8(seg) + "=" + hex8(mp->A()));
        cs << "    RL78_MEM8(0x00123) = 0x10; RL78_MEM8(0x10123) = 0x20; "
           << "RL78_MEM8(0x20123) = 0x30; RL78_MEM8(0xF0123) = 0x40;\n"
           << "    printf(\"seg:" << hex8(seg) << "=%02X\\n\", (unsigned)dyn_es_read(0x"
           << hex16(static_cast<uint16_t>(seg) << 8) << ", 0x0123));\n";
    }
    std::string stdout_s, err_s;
    std::string tu = res.c_text + "\nint main(void) {\n" + cs.str() + "    return 0;\n}\n";
    CHECK(compile_and_run_c_exe(tu, stdout_s, err_s), "Differential exec failed:\n" + err_s);
    std::vector<std::string> got;
    std::istringstream iss(stdout_s);
    std::string ln;
    while (std::getline(iss, ln)) {
        while (!ln.empty() && (ln.back() == '\r' || ln.back() == '\n')) ln.pop_back();
        if (!ln.empty()) got.push_back(ln);
    }
    CHECK(got == expected, "Dynamic ES differential mismatch!");
    pass_msg(kTestName);
}

void test_struct_pointer_and_callee_es_clobber() {
    const std::string kTestName = "test_struct_pointer_and_callee_es_clobber";
    // Part A: Struct pointer inference & arrow dereference without es_mem8
    {
        rl78dec::MemoryDatabaseProvider db(0x10000, 0);
        db.add_udt({"kermit_cmd0", {{0, 2, "id"}, {2, 2, "auth"}, {4, 4, "func"}}});
        db.set_symbol_info(0x2A0E, {"kermit_cmd_tableR", 0x2A0E, 0, 8, false, false, "kermit_cmd0"});
        db.write_bytes(0x0100, {
            0x04, 0x0E, 0x2A, // addw ax, #0x2A0E
            0x14,             // movw de, ax
            0x41, 0x00,       // mov es, #0
            0x11, 0xA9,       // movw ax, es:[de]     (->id)
            0x12,             // movw bc, ax
            0x11, 0x8A, 0x02, // mov a, es:[de+2]     (->auth)
            0x73,             // mov b, a
            0x60,             // mov a, c
            0x0B,             // add a, b
            0x13,             // movw ax, bc
            0x03,             // addw ax, bc          (uses ->id and ->auth)
            0x12,             // movw bc, ax
            0x11, 0xAA, 0x04, // movw ax, es:[de+4]   (->func)
            0x03,             // addw ax, bc          (uses ->func too)
            0xD7              // ret
        });
        db.add_func_entry(0x0100, "read_cmd");
        rl78dec::DecompileOptions opts;
        opts.verify_ir = true;
        auto res = rl78dec::decompile_function(db, 0x0100, opts);
        CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Struct decompile failed");
        CHECK(res.c_text.find("es_mem8") == std::string::npos && res.c_text.find("mem8") == std::string::npos,
              "Struct access leaked mem8/es_mem8:\n" + res.c_text);
        CHECK(res.c_text.find("kermit_cmd0 *") != std::string::npos, "Missing struct pointer type:\n" + res.c_text);
        CHECK(res.c_text.find("->id") != std::string::npos, "Missing ->id:\n" + res.c_text);
        CHECK(res.c_text.find("->auth") != std::string::npos, "Missing ->auth:\n" + res.c_text);
        CHECK(res.c_text.find("->func") != std::string::npos, "Missing ->func:\n" + res.c_text);
        std::string diag;
        std::string hdr =
            "typedef struct kermit_cmd0 {\n"
            "    uint16_t id;\n"
            "    uint16_t auth;\n"
            "    uint32_t func;\n"
            "} kermit_cmd0;\n"
            "extern kermit_cmd0 kermit_cmd_tableR;\n\n";
        CHECK(compile_check_c_src(hdr + res.c_text, &diag), "Struct pointer cl.exe /Zs failed:\n" + diag);
    }
    // Part B: Callee that dynamically clobbers ES invalidates ES across CALL, while clean callee preserves ES
    {
        rl78dec::MemoryDatabaseProvider db(0x10000, 0);
        db.set_default_es(0x0F);
        db.set_symbol_name(0xFB100, "g_ok");
        db.write_bytes(0x0300, {0xD7});                   // clean_callee: ret (preserves ES=0xF)
        db.write_bytes(0x0400, {0x9E, 0xFD, 0xD7});       // dirty_callee: mov es, a; ret (clobbers ES)
        db.write_bytes(0x0100, {
            0xFD, 0x00, 0x03,       // call clean_callee
            0x11, 0x8F, 0x00, 0xB1, // mov a, es:!0xB100 -> must fold to g_ok (0xFB100)!
            0xFD, 0x00, 0x04,       // call dirty_callee
            0x11, 0x8F, 0x00, 0xB2, // mov a, es:!0xB200 -> MUST keep runtime `es`!
            0xD7
        });
        db.add_func_entry(0x0100, "caller_fn");
        db.add_func_entry(0x0300, "clean_callee");
        db.add_func_entry(0x0400, "dirty_callee");
        db.set_func_proto(0x0300, "void clean_callee(void)");
        db.set_func_proto(0x0400, "void dirty_callee(uint8_t a0)");
        rl78dec::DecompileOptions opts;
        opts.verify_ir = true;
        auto res = rl78dec::decompile_function(db, 0x0100, opts);
        CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Caller decompile failed");
        CHECK(res.c_text.find("g_ok") != std::string::npos,
              "ES=0xF was NOT preserved across clean_callee!\n" + res.c_text);
        CHECK(res.c_text.find("(es & 0xFu) << 16") != std::string::npos,
              "ES was falsely assumed constant across ES-clobbering dirty_callee!\n" + res.c_text);
        std::string diag;
        CHECK(compile_check_c_src("extern uint8_t g_ok;\nvoid clean_callee(void);\nvoid dirty_callee(uint8_t a0);\n" + res.c_text, &diag),
              "cl.exe /Zs failed:\n" + diag);
    }
    pass_msg(kTestName);
}

void test_de_hl_register_param_and_itron_queue_linked() {
    const std::string kTestName = "test_de_hl_register_param_and_itron_queue_linked";
    // Real syscon-1.01.bin.i64 machine bytes without hand-written C stub or manual callee proto!
    // itron_queue_remove @ 0x6F8C takes qhead in DE and tid in C!
    const std::vector<uint8_t> rdyq_bytes = {
        0xF6, 0x11, 0x29, 0xE5, 0xB3, 0x08, 0x04, 0xD2, 0xB2, 0x14, 0xC3, 0xFE, 0x3A, 0x00,
        0xC2, 0xC3, 0xD1, 0xDF, 0x21, 0x11, 0x29, 0xE5, 0xB3, 0x75, 0x53, 0x01, 0x2C, 0x08,
        0xDE, 0x02, 0xF3, 0x65, 0x52, 0x01, 0xD1, 0xDD, 0x05, 0x31, 0x17, 0x91, 0xDF, 0xFB,
        0x11, 0x09, 0xCE, 0xB2, 0x61, 0x7A, 0x11, 0x18, 0xCE, 0xB2, 0x11, 0x8F, 0xCA, 0xB2,
        0xC2, 0x61, 0x4A, 0xDF, 0x0A, 0x11, 0x8F, 0xC9, 0xB2, 0x5C, 0xF7, 0x11, 0x9F, 0xC9,
        0xB2, 0xD7
    };
    const std::vector<uint8_t> q_bytes = {
        0x11, 0x29, 0x15, 0xB4, 0x61, 0x4A, 0xDD, 0x1C, 0x70, 0x11, 0x89, 0x61, 0x4A, 0xDF,
        0x03, 0x60, 0x11, 0x99, 0x11, 0x29, 0x21, 0xB4, 0x61, 0x8A, 0x08, 0x11, 0x28, 0x15,
        0xB4, 0x61, 0x8A, 0x11, 0x28, 0x21, 0xB4, 0xD7, 0x11, 0xCA, 0x00, 0xFF, 0xF1, 0xD7
    };

    rl78dec::MemoryDatabaseProvider db(0x100000, 0);
    db.write_bytes(0x6F44, rdyq_bytes);
    db.write_bytes(0x6F8C, q_bytes);
    db.add_func_entry(0x6F44, "itron_rdyq_remove");
    db.add_func_entry(0x6F8C, "itron_queue_remove");
    db.set_default_es(0x0F);
    db.set_symbol_info(0xFB3E5, {"byte_FB3E5", 0xFB3E5, 0, 1, false, false, ""});
    db.set_symbol_info(0xFB2CE, {"word_FB2CE", 0xFB2CE, 0, 2, false, false, ""});
    db.set_symbol_info(0xFB2CA, {"word_FB2CA", 0xFB2CA, 0, 2, false, false, ""});
    db.set_symbol_info(0xFB2C8, {"word_FB2C8", 0xFB2C8, 0, 2, false, false, ""});
    db.set_symbol_info(0xFB415, {"byte_FB415", 0xFB415, 0, 1, false, false, ""});
    db.set_symbol_info(0xFB421, {"byte_FB421", 0xFB421, 0, 1, false, false, ""});

    // Decompile whole image WITHOUT manual callee prototype so ABI & call-site recovery must match DE+C!
    rl78dec::DecompileOptions opts;
    opts.verify_ir = true;
    auto img = rl78dec::decompile_image(db, {0x6F44, 0x6F8C}, opts);
    CHECK(img.errors.empty(), "decompile_image errors");
    const auto &res_q = img.funcs.at(0x6F8C);
    const auto &res_r = img.funcs.at(0x6F44);
    CHECK(res_q.ok && res_r.ok, "Functions failed to decompile");
    CHECK(res_q.c_text.find("es_mem8") == std::string::npos && res_q.c_text.find("mem8") == std::string::npos,
          "mem8/es_mem8 leaked in itron_queue_remove");
    CHECK(res_q.cfunc && res_q.cfunc->arg_names.size() >= 2,
          "itron_queue_remove must recover both DE and C/BC parameters, got:\n" + res_q.c_text);

    // Link REAL decompiled itron_queue_remove + itron_rdyq_remove and execute differentially vs Rl78RefMachine!
    std::string decls =
        "uint8_t byte_FB3E5[64];\n"
        "uint16_t word_FB2CE;\n"
        "uint16_t word_FB2CA;\n"
        "uint16_t word_FB2C8;\n"
        "uint8_t byte_FB415[64];\n"
        "uint8_t byte_FB421[64];\n" +
        res_q.cfunc->signature_line + ";\n\n";

    std::ostringstream cs;
    std::vector<std::string> expected;
    struct Vec { uint8_t tid; uint8_t prio; uint8_t cur_tid; bool solo; };
    std::vector<Vec> vecs = {
        {2, 3, 2, true},
        {4, 11, 1, true},
        {3, 5, 3, false},
    };
    for (size_t vi = 0; vi < vecs.size(); ++vi) {
        const auto &v = vecs[vi];
        auto mp = std::make_unique<Rl78RefMachine>();
        mp->reset(0x6F44);
        mp->load_bytes(0x6F44, rdyq_bytes);
        mp->load_bytes(0x6F8C, q_bytes);
        mp->es = 0x0F;
        mp->set_BC(v.tid);
        mp->wr8(0xFB3E5u + v.tid, v.prio);
        mp->wr16(0xFB2CEu, 0xAAAAu);
        mp->wr8(0xFB2CAu, v.cur_tid);
        mp->wr8(0xFB2C9u, 0xFFu);
        uint32_t qhead = 0xFB2D2u + v.prio;
        if (v.solo) {
            mp->wr8(qhead, v.tid);
            mp->wr8(0xFB415u + v.tid, v.tid);
            mp->wr8(0xFB421u + v.tid, v.tid);
        } else {
            uint8_t other = static_cast<uint8_t>(v.tid + 1);
            mp->wr8(qhead, v.tid);
            mp->wr8(0xFB415u + v.tid, other);
            mp->wr8(0xFB421u + v.tid, other);
            mp->wr8(0xFB415u + other, v.tid);
            mp->wr8(0xFB421u + other, v.tid);
        }
        mp->run();
        char ebuf[128];
        std::snprintf(ebuf, sizeof(ebuf), "linked:%zu=%04X:%02X:%02X:%02X",
                      vi, (unsigned)mp->rd16(0xFB2CEu), (unsigned)mp->rd8(0xFB2C9u),
                      (unsigned)mp->rd8(0xFB2D2u + v.prio),
                      (unsigned)mp->rd8(0xFB415u + (v.solo ? v.tid : v.tid + 1)));
        expected.push_back(ebuf);

        cs << "    memset(g_rl78_mem, 0, sizeof(g_rl78_mem));\n"
           << "    byte_FB3E5[" << (int)v.tid << "] = " << (int)v.prio << ";\n"
           << "    word_FB2CE = 0xAAAAu;\n"
           << "    word_FB2CA = " << (int)v.cur_tid << ";\n"
           << "    word_FB2C8 = 0xFF00u;\n"
           << "    g_rl78_mem[0xFB2D2u + " << (int)v.prio << "] = " << (int)v.tid << ";\n";
        if (v.solo) {
            cs << "    byte_FB415[" << (int)v.tid << "] = " << (int)v.tid << ";\n"
               << "    byte_FB421[" << (int)v.tid << "] = " << (int)v.tid << ";\n";
        } else {
            int other = v.tid + 1;
            cs << "    byte_FB415[" << (int)v.tid << "] = " << other << ";\n"
               << "    byte_FB421[" << (int)v.tid << "] = " << other << ";\n"
               << "    byte_FB415[" << other << "] = " << (int)v.tid << ";\n"
               << "    byte_FB421[" << other << "] = " << (int)v.tid << ";\n";
        }
        cs << "    itron_rdyq_remove(" << (int)v.tid << ");\n"
           << "    printf(\"linked:" << vi << "=%04X:%02X:%02X:%02X\\n\", "
           << "(unsigned)word_FB2CE, (unsigned)*((uint8_t *)&word_FB2C8 + 1), "
           << "(unsigned)g_rl78_mem[0xFB2D2u + " << (int)v.prio << "], "
           << "(unsigned)byte_FB415[" << (v.solo ? (int)v.tid : (int)(v.tid + 1)) << "]);\n";
    }
    std::string tu = decls + res_q.c_text + "\n\n" + res_r.c_text + "\n\nint main(void) {\n" + cs.str() + "    return 0;\n}\n";
    std::string stdout_s, err_s;
    CHECK(compile_and_run_c_exe(tu, stdout_s, err_s), "Linked itron cl.exe compile/run failed:\n" + err_s + "\n" + tu);
    std::vector<std::string> got;
    std::istringstream iss(stdout_s);
    std::string ln;
    while (std::getline(iss, ln)) {
        while (!ln.empty() && (ln.back() == '\r' || ln.back() == '\n')) ln.pop_back();
        if (!ln.empty()) got.push_back(ln);
    }
    if (got != expected) {
        std::ostringstream d;
        d << "Linked itron_queue_remove + itron_rdyq_remove differential mismatch!\n"
          << res_q.c_text << "\n" << res_r.c_text << "\nExpected vs Got:\n";
        for (size_t i = 0; i < std::max(expected.size(), got.size()); ++i) {
            d << "  exp=" << (i < expected.size() ? expected[i] : "<missing>")
              << "  got=" << (i < got.size() ? got[i] : "<missing>") << "\n";
        }
        CHECK(false, d.str());
    }
    pass_msg(kTestName);
}

void test_array_of_structs_byte_index_native_c() {
    const std::string kTestName = "test_array_of_structs_byte_index_native_c";
    // Global array of structs at 0x2A00 (is_array=true AND struct_name="cmd_entry"):
    // build_listing_with_decls emits `extern cmd_entry g_cmds[];`, so byte-indexed accesses
    // `mov a, es:0x2A00[b]` and `movw ax, es:0x2A00[b]` MUST cast `(uint8_t *)g_cmds` rather than
    // emitting `g_cmds[idx]` (invalid C struct-to-uint8_t conversion) or `&g_cmds[idx]` (wrong stride!).
    rl78dec::MemoryDatabaseProvider db(0x10000, 0);
    db.add_udt({"cmd_entry", {{0, 2, "id"}, {2, 2, "flags"}}});
    db.set_symbol_info(0x2A00, {"g_cmds", 0x2A00, 0, 12, true, false, "cmd_entry"});
    // 0100: 41 00         mov es, #0
    // 0102: 11 09 00 2A   mov a, es:0x2A00[b]
    // 0106: 70            mov x, a
    // 0107: 11 59 00 2A   movw ax, es:0x2A00[b]
    // 010B: 61 08         add a, x
    // 010D: D7            ret
    const std::vector<uint8_t> code = {0x41, 0x00, 0x11, 0x09, 0x00, 0x2A, 0x70, 0x11, 0x59, 0x00, 0x2A, 0x61, 0x08, 0xD7};
    db.write_bytes(0x0100, code);
    db.add_func_entry(0x0100, "read_cmd_byte");
    db.set_func_proto(0x0100, "uint16_t read_cmd_byte(uint16_t a0, uint16_t a1)");

    rl78dec::DecompileOptions opts;
    opts.verify_ir = true;
    auto img = rl78dec::decompile_image(db, {0x0100}, opts);
    CHECK(img.errors.empty() && img.funcs.at(0x0100).ok, "Decompile failed");
    std::string listing = img.listing_text;
    std::string diag;
    CHECK(compile_check_c_src(listing, &diag),
          "Array-of-structs byte-indexed C failed cl.exe /Zs:\n" + diag + "\n" + listing);

    // Also differentially verify stride (idx=4 -> second element's .id!)
    std::ostringstream cs;
    std::vector<std::string> expected;
    for (uint8_t b_idx : {uint8_t(0), uint8_t(4), uint8_t(8)}) {
        auto mp = std::make_unique<Rl78RefMachine>();
        mp->reset(0x0100);
        mp->load_bytes(0x0100, code);
        mp->wr16(0x2A00, 0x1122); mp->wr16(0x2A02, 0x3344);
        mp->wr16(0x2A04, 0x5566); mp->wr16(0x2A06, 0x7788);
        mp->wr16(0x2A08, 0x99AA); mp->wr16(0x2A0A, 0xBBCC);
        mp->set_BC(static_cast<uint16_t>(b_idx) << 8);
        mp->run();
        expected.push_back("cmd:" + hex8(b_idx) + "=" + hex16(mp->AX()));
        cs << "    printf(\"cmd:" << hex8(b_idx) << "=%04X\\n\", (unsigned)read_cmd_byte(0, 0x"
           << hex16(static_cast<uint16_t>(b_idx) << 8) << "));\n";
    }
    // Replace extern decl with concrete definition for execution
    std::string exec_src = listing;
    size_t ext_pos = exec_src.find("extern cmd_entry g_cmds[];");
    CHECK(ext_pos != std::string::npos, "Missing extern cmd_entry g_cmds[] in listing:\n" + listing);
    exec_src.replace(ext_pos, std::strlen("extern cmd_entry g_cmds[];"),
                     "cmd_entry g_cmds[3] = {{0x1122, 0x3344}, {0x5566, 0x7788}, {0x99AA, 0xBBCC}};");
    std::string tu = exec_src + "\nint main(void) {\n" + cs.str() + "    return 0;\n}\n";
    std::string stdout_s, err_s;
    CHECK(compile_and_run_c_exe(tu, stdout_s, err_s), "cl.exe run failed:\n" + err_s);
    std::vector<std::string> got;
    std::istringstream iss(stdout_s);
    std::string ln;
    while (std::getline(iss, ln)) {
        while (!ln.empty() && (ln.back() == '\r' || ln.back() == '\n')) ln.pop_back();
        if (!ln.empty()) got.push_back(ln);
    }
    CHECK(got == expected, "Array-of-structs byte-index stride mismatch!\n" + listing);
    pass_msg(kTestName);
}

void test_multi_block_es_with_const_hl_folds_to_symbol() {
    const std::string kTestName = "test_multi_block_es_with_const_hl_folds_to_symbol";
    // Block 0: mov es, #0; cmp a, #0; bz B2;
    // Block 1: nop; br B2
    // Block 2 (2 preds, both ES=0): movw hl, #0x2A0E; mov a, es:[hl]; ret
    // ES=0 must propagate across the join AND (u16)0x2A0E must fold to static 0x02A0E -> `g_rom_byte`!
    rl78dec::MemoryDatabaseProvider db(0x10000, 0);
    db.set_default_es(0x0F);
    db.set_symbol_info(0x02A0E, {"g_rom_byte", 0x02A0E, 0, 1, false, true, ""});
    const std::vector<uint8_t> code = {
        0x41, 0x00,       // 0100: mov es, #0
        0x4C, 0x00,       // 0102: cmp a, #0
        0xDD, 0x03,       // 0104: bz 0109
        0x00,             // 0106: nop
        0xEF, 0x00,       // 0107: br 0109
        0x36, 0x0E, 0x2A, // 0109: movw hl, #0x2A0E
        0x11, 0x8B,       // 010C: mov a, es:[hl]
        0xD7              // 010E: ret
    };
    db.write_bytes(0x0100, code);
    db.add_func_entry(0x0100, "read_rom_join");
    rl78dec::DecompileOptions opts;
    opts.verify_ir = true;
    auto res = rl78dec::decompile_function(db, 0x0100, opts);
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    CHECK(res.c_text.find("g_rom_byte") != std::string::npos,
          "Multi-block ES=0 + const HL failed to resolve g_rom_byte (0x02A0E):\n" + res.c_text);
    CHECK(res.c_text.find("(uint16_t)") == std::string::npos,
          "Unfolded (uint16_t)(0x2A0E) remained in static ES:[HL]:\n" + res.c_text);
    std::string diag;
    CHECK(compile_check_c_src("extern uint8_t g_rom_byte;\n" + res.c_text, &diag), "cl.exe /Zs failed:\n" + diag);
    pass_msg(kTestName);
}

void test_multi_block_es_0f_with_const_hl() {
    const std::string kTestName = "test_multi_block_es_0f_with_const_hl";
    // B0: mov es, #0x0F; movw hl, #0xB2E6; cmp a, #0; bz B2;
    // B1: mov a, #0; ret
    // B2 (single pred B0): mov a, es:[hl]; ret  -> MUST resolve 0xFB2E6 (`g_ram_byte`), NOT 0x0B2E6!
    rl78dec::MemoryDatabaseProvider db(0x10000, 0);
    db.set_symbol_info(0xFB2E6, {"g_ram_byte", 0xFB2E6, 0, 1, false, true, ""});
    const std::vector<uint8_t> code = {
        0x41, 0x0F,       // 0100: mov es, #0x0F
        0x36, 0xE6, 0xB2, // 0102: movw hl, #0xB2E6
        0x4C, 0x00,       // 0105: cmp a, #0
        0xDD, 0x03,       // 0107: bz 010C
        0x51, 0x00,       // 0109: mov a, #0
        0xD7,             // 010B: ret
        0x11, 0x8B,       // 010C: mov a, es:[hl]
        0xD7              // 010E: ret
    };
    db.write_bytes(0x0100, code);
    db.add_func_entry(0x0100, "read_ram_branch");
    rl78dec::DecompileOptions opts;
    opts.verify_ir = true;
    auto res = rl78dec::decompile_function(db, 0x0100, opts);
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    CHECK(res.c_text.find("g_ram_byte") != std::string::npos,
          "ES=0x0F + cross-block HL=0xB2E6 failed to resolve g_ram_byte (0xFB2E6):\n" + res.c_text);
    std::string diag;
    CHECK(compile_check_c_src("extern uint8_t g_ram_byte;\n" + res.c_text, &diag), "cl.exe /Zs failed:\n" + diag);
    pass_msg(kTestName);
}

void test_process_conf_shared_epilogue_returns_and_no_flag_noise() {
    const std::string kTestName = "test_process_conf_shared_epilogue_returns_and_no_flag_noise";

    // Part A: Exact real DOL-1001-VTE-1001-00703030.i64 `process_CONF` (0xA714..0xA863) machine bytes
    // + `sub_3444C` (0x3444C) + `sub_225B` (0x225B) + `sub_21A2` (0x21A2)
    {
        const std::vector<uint8_t> conf_bytes = {
            0xC7, 0xC1, 0x20, 0x12, 0xFB, 0xF8, 0xFF, 0xC7, 0x17, 0x04, 0x0E, 0x00, 0x16, 0xF7, 0x41, 0x00,
            0x11, 0x49, 0x6E, 0x32, 0x9B, 0xA3, 0xA7, 0x51, 0x04, 0x61, 0x4A, 0xDF, 0xF3, 0xC6, 0xF6, 0xBC,
            0x06, 0xBC, 0x08, 0x8C, 0x12, 0x4C, 0x02, 0xDC, 0x04, 0xE7, 0xEE, 0x1E, 0x01, 0x8C, 0x12, 0x31,
            0x29, 0xF0, 0x41, 0x00, 0x11, 0x02, 0x6A, 0x32, 0xC1, 0x11, 0x8F, 0x6C, 0x32, 0x9D, 0xD4, 0xC0,
            0xBC, 0x0A, 0x8D, 0xD4, 0x9C, 0x0C, 0x30, 0x04, 0x00, 0xC1, 0x17, 0x04, 0x0E, 0x00, 0x52, 0x0F,
            0xC3, 0xC1, 0xAC, 0x0A, 0x14, 0x8C, 0x0C, 0x9D, 0xD4, 0x15, 0xF8, 0xD4, 0xF3, 0xFC, 0x4C, 0x44,
            0x03, 0x10, 0x06, 0xF6, 0x43, 0xDD, 0x05, 0xE7, 0xA3, 0xEE, 0xDF, 0x00, 0xAC, 0x0A, 0x14, 0x8C,
            0x0C, 0x9E, 0xFD, 0x11, 0xAA, 0x06, 0x44, 0xF0, 0x03, 0xDD, 0x06, 0x32, 0x03, 0x00, 0xEE, 0xCA,
            0x00, 0xAC, 0x0A, 0x14, 0x8C, 0x0C, 0x9E, 0xFD, 0x11, 0xAA, 0x08, 0x44, 0xFF, 0xFF, 0xDF, 0x06,
            0x32, 0x04, 0x00, 0xEE, 0xB5, 0x00, 0xAC, 0x0A, 0x14, 0x8C, 0x0C, 0x9E, 0xFD, 0x11, 0xAA, 0x0A,
            0x44, 0xFF, 0xFF, 0xDF, 0x06, 0x32, 0x05, 0x00, 0xEE, 0xA0, 0x00, 0xAC, 0x0A, 0x14, 0x8C, 0x0C,
            0x9E, 0xFD, 0x11, 0xAA, 0x04, 0x24, 0x50, 0x50, 0xDD, 0x0B, 0x24, 0x0A, 0x0A, 0xDD, 0x06, 0x32,
            0x06, 0x00, 0xEE, 0x86, 0x00, 0xAC, 0x0A, 0x14, 0x8C, 0x0C, 0x9E, 0xFD, 0x11, 0xAA, 0x0A, 0xE7,
            0x43, 0xDD, 0x77, 0xAC, 0x0A, 0x04, 0x10, 0x00, 0xBB, 0x8C, 0x0C, 0x9C, 0x02, 0xF6, 0xBC, 0x04,
            0xAC, 0x04, 0x44, 0xF0, 0x03, 0xDE, 0x2E, 0xAB, 0x14, 0x8C, 0x02, 0x9E, 0xFD, 0x11, 0x89, 0x9D,
            0xDC, 0xF4, 0xDD, 0xF6, 0xBD, 0xDE, 0xAC, 0x06, 0xBD, 0xD8, 0xAC, 0x08, 0xBD, 0xDA, 0xAD, 0xDE,
            0xFD, 0x5B, 0x22, 0xAD, 0xDA, 0xBC, 0x08, 0xAD, 0xD8, 0xBC, 0x06, 0xAC, 0x04, 0xA1, 0xBC, 0x04,
            0xAB, 0xA1, 0xBB, 0xEF, 0xCB, 0xAC, 0x06, 0xBD, 0xD8, 0xAC, 0x08, 0xBD, 0xDA, 0xFD, 0xA2, 0x21,
            0xAD, 0xDA, 0xBC, 0x08, 0xAD, 0xD8, 0xBC, 0x06, 0xAC, 0x0A, 0x14, 0x8C, 0x0C, 0x9D, 0xD6, 0x61,
            0xB8, 0xD6, 0x11, 0xAA, 0x0E, 0x61, 0x49, 0x08, 0xDF, 0x09, 0x61, 0xB8, 0xD6, 0x11, 0xAA, 0x0C,
            0x61, 0x49, 0x06, 0xDD, 0x05, 0x32, 0x07, 0x00, 0xEF, 0x01, 0xF7, 0x10, 0x14, 0xC6, 0xD7,
        };
        const std::vector<uint8_t> sub_3444C_bytes = {
            0x14, 0xAE, 0xF8, 0xC7, 0x16, 0xAD, 0xD8, 0xC1, 0xAC, 0x08, 0xBD, 0xD8,
            0x8C, 0x06, 0x73, 0xAC, 0x04, 0x16, 0xA2, 0xD8, 0xB2, 0xD8, 0xF6, 0x4C, // wait: real bytes of sub_3444C tail:
        };
        (void)sub_3444C_bytes;

        rl78dec::MemoryDatabaseProvider db(0x40000, 0);
        db.write_bytes(0x0A714, conf_bytes);
        // sub_3444C shared-epilogue BC return (clrw bc / movw bc, ax -> pop ax; movw tmp_buf0, ax; pop hl; ret)
        db.write_bytes(0x3444C, {
            0x14, 0xAE, 0xF8, 0xC7, 0x16, 0xAD, 0xD8, 0xC1,
            0x4C, 0x00, 0xDD, 0x05, 0x32, 0x01, 0x00, 0xEF, 0x01, 0xF7,
            0xC0, 0xBD, 0xD8, 0xC6, 0xD7
        });
        db.write_bytes(0x0225B, {0xD7});
        db.write_bytes(0x021A2, {0xD7});
        db.add_func_entry(0x0A714, "process_CONF");
        db.add_func_entry(0x3444C, "sub_3444C");
        db.add_func_entry(0x0225B, "sub_225B");
        db.add_func_entry(0x021A2, "sub_21A2");

        rl78dec::DecompileOptions opts;
        opts.verify_ir = true;
        auto img = rl78dec::decompile_image(db, {0x0A714, 0x3444C, 0x0225B, 0x021A2}, opts);
        CHECK(img.errors.empty(), "decompile_image failed on process_CONF");
        const auto &res = img.funcs.at(0x0A714);
        CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "process_CONF IR verification failed");
        CHECK(res.c_text.find("uint16_t process_CONF(") != std::string::npos,
              "process_CONF must return uint16_t (BC), got:\n" + res.c_text);
        for (int rc = 0; rc <= 7; ++rc) {
            std::string needle = "return " + std::to_string(rc) + ";";
            CHECK(res.c_text.find(needle) != std::string::npos,
                  "process_CONF missing `" + needle + "` in:\n" + res.c_text);
        }
        CHECK(res.c_text.find("CY =") == std::string::npos,
              "Unnecessary `CY =` leaked into process_CONF:\n" + res.c_text);
        CHECK(res.c_text.find("ZF =") == std::string::npos,
              "Unnecessary `ZF =` leaked into process_CONF:\n" + res.c_text);
        CHECK(res.c_text.find("es_mem8") == std::string::npos && res.c_text.find("mem8") == std::string::npos,
              "mem8/es_mem8 leaked into process_CONF:\n" + res.c_text);
        CHECK(res.cfunc && res.cfunc->lvars.size() <= 18,
              "Excessive temporary variables remained in process_CONF:\n" + res.c_text);

        std::string diag;
        CHECK(compile_check_c_src(img.listing_text, &diag),
              "process_CONF listing failed cl.exe /Zs /W3 /TC:\n" + diag + "\n" + img.listing_text);
    }

    // Part B: Differential semantic execution vs Rl78RefMachine across all shared-epilogue BC return paths
    // (1, 3, 4, 5, 6, 0-early, 7-hi-mismatch, 7-lo-mismatch, 0-crc-match) with zero manual prototype!
    {
        // Memory layout at 0xF2000 (header struct):
        //   0xF2000 (+0): magic16  (must be 0x5050 or 0x5A5A, else return 6)
        //   0xF2002 (+2): len16    (must be 0x03F0, else return 3)
        //   0xF2004 (+4): field8   (must != 0xFFFF, else return 4)
        //   0xF2006 (+6): mode16   (must != 0xFFFF, else return 5; if == 1, early return 0)
        //   0xF2008 (+8): crc_lo   (compared against [hl+0] = 0x1234)
        //   0xF200A (+A): crc_hi   (compared against [hl+2] = 0x5678, else return 7; if both match return 0)
        // Entry arg: A = slot (if A >= 2, return 1)
        const std::vector<uint8_t> code = {
            0xC7,                   // 0100: push hl
            0xC1,                   // 0101: push ax
            0x20, 0x04,             // 0102: subw sp, #4
            0xAE, 0xF8,             // 0104: movw ax, sp
            0x16,                   // 0106: movw hl, ax
            0x30, 0x34, 0x12,       // 0107: movw ax, #0x1234
            0xB8, 0x00,             // 010A: movw [sp+0], ax
            0x30, 0x78, 0x56,       // 010C: movw ax, #0x5678
            0xB8, 0x02,             // 010F: movw [sp+2], ax
            0x8C, 0x05,             // 0111: mov a, [hl+5]   (homed A from push ax at sp+4: X=+4, A=+5!)
            0x4C, 0x02,             // 0113: cmp a, #2
            0xDC, 0x04,             // 0115: bc 011B
            0xE7,                   // 0117: onew bc         (return 1)
            0xED, 0x6F, 0x01,       // 0118: br !0x016F
            0xAF, 0x02, 0x20,       // 011B: movw ax, !0x2002
            0x44, 0xF0, 0x03,       // 011E: cmpw ax, #0x03F0
            0xDD, 0x06,             // 0121: bz 0129
            0x32, 0x03, 0x00,       // 0123: movw bc, #3     (return 3)
            0xED, 0x6F, 0x01,       // 0126: br !0x016F
            0xAF, 0x04, 0x20,       // 0129: movw ax, !0x2004
            0x44, 0xFF, 0xFF,       // 012C: cmpw ax, #0xFFFF
            0xDF, 0x06,             // 012F: bnz 0137
            0x32, 0x04, 0x00,       // 0131: movw bc, #4     (return 4)
            0xED, 0x6F, 0x01,       // 0134: br !0x016F
            0xAF, 0x06, 0x20,       // 0137: movw ax, !0x2006
            0x44, 0xFF, 0xFF,       // 013A: cmpw ax, #0xFFFF
            0xDF, 0x06,             // 013D: bnz 0145
            0x32, 0x05, 0x00,       // 013F: movw bc, #5     (return 5)
            0xED, 0x6F, 0x01,       // 0142: br !0x016F
            0xAF, 0x00, 0x20,       // 0145: movw ax, !0x2000
            0x24, 0x50, 0x50,       // 0148: subw ax, #0x5050
            0xDD, 0x0B,             // 014B: bz 0158
            0x24, 0x0A, 0x0A,       // 014D: subw ax, #0x0A0A
            0xDD, 0x06,             // 0150: bz 0158
            0x32, 0x06, 0x00,       // 0152: movw bc, #6     (return 6)
            0xED, 0x6F, 0x01,       // 0155: br !0x016F
            0xAF, 0x06, 0x20,       // 0158: movw ax, !0x2006
            0xE7,                   // 015B: onew bc
            0x43,                   // 015C: cmpw ax, bc
            0xDD, 0x0F,             // 015D: bz 016E         (early return 0)
            0xAF, 0x0A, 0x20,       // 015F: movw ax, !0x200A
            0x61, 0x49, 0x02,       // 0162: cmpw ax, [hl+2]
            0xDF, 0x06,             // 0165: bnz 016D        (short-circuit to bz 016E!)
            0xAF, 0x08, 0x20,       // 0167: movw ax, !0x2008
            0x61, 0x49, 0x00,       // 016A: cmpw ax, [hl+0]
            0xDD, 0x05,             // 016D: bz 0174? Wait: 016D+2=016F; we want bz 016E!
        };
        (void)code;
        // Exact branch offsets around 0x0158..0x0174:
        // 0158: AF 06 20       movw ax, !0x2006
        // 015B: E7             onew bc
        // 015C: 43             cmpw ax, bc
        // 015D: DD 14          bz 0173          (015F + 0x14 = 0x0173: clrw bc)
        // 015F: AF 0A 20       movw ax, !0x200A
        // 0162: 61 49 02       cmpw ax, [hl+2]
        // 0165: DF 06          bnz 016D         (0167 + 0x06 = 0x016D: bz 0173)
        // 0167: AF 08 20       movw ax, !0x2008
        // 016A: 61 49 00       cmpw ax, [hl+0]
        // 016D: DD 04          bz 0173          (016F + 0x04 = 0x0173: clrw bc)
        // 016F: 32 07 00       movw bc, #7
        // 0172: EF 01          br 0175          (0174 + 0x01 = 0x0175: epilogue)
        // 0174? Wait: 016F + 3 = 0172; EF 01 is 2 bytes (0172..0174), 0174 + 1 = 0175!
        // So 0x0174 is `F7` (clrw bc), and 0x0175 is `10 06 C6 D7` (addw sp, #6; pop hl; ret)!
        // Recheck targets:
        //   015D: DD 15 -> 015F + 0x15 = 0x0174 (clrw bc)
        //   016D: DD 05 -> 016F + 0x05 = 0x0174 (clrw bc)
        //   All early `br !epilogue`: ED 75 01 (jumps to 0x0175)!
        const std::vector<uint8_t> vcode = {
            0xC7, 0xC1, 0x20, 0x04, 0xAE, 0xF8, 0x16,
            0x30, 0x34, 0x12, 0xB8, 0x00,
            0x30, 0x78, 0x56, 0xB8, 0x02,
            0x8C, 0x05, 0x4C, 0x02, 0xDC, 0x04, 0xE7, 0xED, 0x75, 0x01,
            0xAF, 0x02, 0x20, 0x44, 0xF0, 0x03, 0xDD, 0x06, 0x32, 0x03, 0x00, 0xED, 0x75, 0x01,
            0xAF, 0x04, 0x20, 0x44, 0xFF, 0xFF, 0xDF, 0x06, 0x32, 0x04, 0x00, 0xED, 0x75, 0x01,
            0xAF, 0x06, 0x20, 0x44, 0xFF, 0xFF, 0xDF, 0x06, 0x32, 0x05, 0x00, 0xED, 0x75, 0x01,
            0xAF, 0x00, 0x20, 0x24, 0x50, 0x50, 0xDD, 0x0B, 0x24, 0x0A, 0x0A, 0xDD, 0x06, 0x32, 0x06, 0x00, 0xED, 0x75, 0x01,
            0xAF, 0x06, 0x20, 0xE7, 0x43, 0xDD, 0x15,
            0xAF, 0x0A, 0x20, 0x61, 0x49, 0x02, 0xDF, 0x06,
            0xAF, 0x08, 0x20, 0x61, 0x49, 0x00,
            0xDD, 0x05,
            0x32, 0x07, 0x00, 0xEF, 0x01,
            0xF7,
            0x10, 0x06, 0xC6, 0xD7
        };

        auto res = decompile_bytes(vcode, 0x0100, "validate_conf");
        CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "validate_conf decompile failed");
        CHECK(res.c_text.find("uint16_t validate_conf(") != std::string::npos,
              "Expected auto-inferred uint16_t return on validate_conf:\n" + res.c_text);
        CHECK(res.c_text.find("CY =") == std::string::npos && res.c_text.find("ZF =") == std::string::npos,
              "CY/ZF noise leaked in validate_conf:\n" + res.c_text);
        std::string diag;
        CHECK(compile_check_c_src(res.c_text, &diag), "validate_conf cl.exe /Zs failed:\n" + diag + "\n" + res.c_text);

        struct HdrVec {
            uint8_t slot;
            uint16_t magic, len, f8, mode, crc_lo, crc_hi;
        };
        std::vector<HdrVec> vecs = {
            {2, 0x5050, 0x03F0, 0x0001, 0x0002, 0x1234, 0x5678}, // slot >= 2 -> 1
            {0, 0x5050, 0x0100, 0x0001, 0x0002, 0x1234, 0x5678}, // len != 0x3F0 -> 3
            {1, 0x5050, 0x03F0, 0xFFFF, 0x0002, 0x1234, 0x5678}, // f8 == 0xFFFF -> 4
            {0, 0x5050, 0x03F0, 0x0001, 0xFFFF, 0x1234, 0x5678}, // mode == 0xFFFF -> 5
            {0, 0x1111, 0x03F0, 0x0001, 0x0002, 0x1234, 0x5678}, // bad magic -> 6
            {0, 0x5050, 0x03F0, 0x0001, 0x0001, 0x9999, 0x9999}, // mode == 1 -> early 0
            {1, 0x5A5A, 0x03F0, 0x0001, 0x0002, 0x1234, 0x9999}, // crc_hi mismatch -> 7
            {1, 0x5A5A, 0x03F0, 0x0001, 0x0002, 0x9999, 0x5678}, // crc_lo mismatch -> 7
            {1, 0x5A5A, 0x03F0, 0x0001, 0x0002, 0x1234, 0x5678}, // full match -> 0
        };
        std::vector<std::string> expected;
        std::ostringstream cs;
        for (size_t i = 0; i < vecs.size(); ++i) {
            const auto &v = vecs[i];
            auto mp = std::make_unique<Rl78RefMachine>();
            mp->reset(0x0100);
            mp->load_bytes(0x0100, vcode);
            mp->set_AX(static_cast<uint16_t>(v.slot) << 8);
            mp->wr16(0xF2000, v.magic);
            mp->wr16(0xF2002, v.len);
            mp->wr16(0xF2004, v.f8);
            mp->wr16(0xF2006, v.mode);
            mp->wr16(0xF2008, v.crc_lo);
            mp->wr16(0xF200A, v.crc_hi);
            mp->run();
            expected.push_back("vconf:" + std::to_string(i) + "=" + hex16(mp->BC()));

            cs << "    RL78_MEM16(0xF2000) = 0x" << hex16(v.magic) << ";\n"
               << "    RL78_MEM16(0xF2002) = 0x" << hex16(v.len) << ";\n"
               << "    RL78_MEM16(0xF2004) = 0x" << hex16(v.f8) << ";\n"
               << "    RL78_MEM16(0xF2006) = 0x" << hex16(v.mode) << ";\n"
               << "    RL78_MEM16(0xF2008) = 0x" << hex16(v.crc_lo) << ";\n"
               << "    RL78_MEM16(0xF200A) = 0x" << hex16(v.crc_hi) << ";\n"
               << "    printf(\"vconf:" << i << "=%04X\\n\", (unsigned)validate_conf("
               << static_cast<unsigned>(v.slot) << "u));\n";
        }
        std::string tu = res.c_text + "\nint main(void) {\n" + cs.str() + "    return 0;\n}\n";
        std::string stdout_s, err_s;
        CHECK(compile_and_run_c_exe(tu, stdout_s, err_s), "validate_conf cl.exe run failed:\n" + err_s + "\n" + tu);
        std::vector<std::string> got;
        std::istringstream iss(stdout_s);
        std::string ln;
        while (std::getline(iss, ln)) {
            while (!ln.empty() && (ln.back() == '\r' || ln.back() == '\n')) ln.pop_back();
            if (!ln.empty()) got.push_back(ln);
        }
        if (got != expected) {
            std::ostringstream d;
            d << "Differential mismatch on validate_conf!\n" << res.c_text << "\nExpected vs Got:\n";
            for (size_t i = 0; i < std::max(expected.size(), got.size()); ++i) {
                d << "  exp=" << (i < expected.size() ? expected[i] : "<missing>")
                  << "  got=" << (i < got.size() ? got[i] : "<missing>") << "\n";
            }
            CHECK(false, d.str());
        }
    }
    pass_msg(kTestName);
}

void test_adv_guard_clause_stop_ea_nonpure_epilogue() {
    const std::string kTestName = "test_adv_guard_clause_stop_ea_nonpure_epilogue";
    // Outer if (A == 0) merges with else arm at non-pure Ret epilogue E (0x0124: writes !0x2000 = 0x99; ret).
    // Inside then-arm: if (X < 5) { bc = 0x0011; br E; } else { !0x2002 = 0x1111; bc = (!0x2004 == 9 ? 0x0044 : 0x0022); ret; }
    // Tests guard-clause flattening when taken arm targets stop_ea (E).
    const std::vector<uint8_t> code = {
        0x4C, 0x00,             // 0100: cmp a, #0
        0xDF, 0x1D,             // 0102: bnz 0121
        0x60,                   // 0104: mov a, x
        0x4C, 0x05,             // 0105: cmp a, #5
        0x32, 0x11, 0x00,       // 0107: movw bc, #0x0011
        0xDC, 0x18,             // 010A: bc 0124 (E)
        0x30, 0x11, 0x11,       // 010C: movw ax, #0x1111
        0xBF, 0x02, 0x20,       // 010F: movw !0x2002, ax
        0x8F, 0x04, 0x20,       // 0112: mov a, !0x2004
        0x4C, 0x09,             // 0115: cmp a, #9
        0xDD, 0x04,             // 0117: bz 011D
        0x32, 0x22, 0x00,       // 0119: movw bc, #0x0022
        0xD7,                   // 011C: ret
        0x32, 0x44, 0x00,       // 011D: movw bc, #0x0044
        0xD7,                   // 0120: ret
        0x32, 0x33, 0x00,       // 0121: movw bc, #0x0033 (else arm falls into E)
        0x51, 0x99,             // 0124: mov a, #0x99 (E)
        0x9F, 0x00, 0x20,       // 0126: mov !0x2000, a
        0xD7,                   // 0129: ret
    };
    auto res = decompile_bytes(code, 0x0100, "guard_stop_ea");
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    std::string diag;
    CHECK(compile_check_c_src(res.c_text, &diag), "cl.exe /Zs failed:\n" + diag + "\n" + res.c_text);

    struct Vec { uint8_t a, x, m4; };
    std::vector<Vec> vecs = {{0, 2, 0}, {0, 7, 1}, {0, 7, 9}, {1, 2, 0}};
    std::vector<std::string> expected;
    std::ostringstream cs;
    for (size_t i = 0; i < vecs.size(); ++i) {
        const auto &v = vecs[i];
        auto mp = std::make_unique<Rl78RefMachine>();
        mp->reset(0x0100);
        mp->load_bytes(0x0100, code);
        mp->set_AX(static_cast<uint16_t>((static_cast<uint16_t>(v.a) << 8) | v.x));
        mp->wr8(0xF2004, v.m4);
        mp->run();
        std::ostringstream exp;
        exp << "gse:" << i << "=" << hex16(mp->BC()) << ":" << hex8(mp->rd8(0xF2000)) << ":" << hex16(mp->rd16(0xF2002));
        expected.push_back(exp.str());

        uint16_t ax = static_cast<uint16_t>((static_cast<uint16_t>(v.a) << 8) | v.x);
        cs << "    RL78_MEM8(0xF2000) = 0; RL78_MEM16(0xF2002) = 0; RL78_MEM8(0xF2004) = " << (unsigned)v.m4 << ";\n"
           << "    { uint16_t r = (uint16_t)guard_stop_ea(0x" << hex16(ax) << ");\n"
           << "      printf(\"gse:" << i << "=%04X:%02X:%04X\\n\", (unsigned)r, (unsigned)RL78_MEM8(0xF2000), (unsigned)RL78_MEM16(0xF2002)); }\n";
    }
    std::string tu = res.c_text + "\nint main(void) {\n" + cs.str() + "    return 0;\n}\n";
    std::string stdout_s, err_s;
    CHECK(compile_and_run_c_exe(tu, stdout_s, err_s), "cl.exe run failed:\n" + err_s + "\n" + tu);
    std::vector<std::string> got;
    std::istringstream iss(stdout_s);
    std::string ln;
    while (std::getline(iss, ln)) {
        while (!ln.empty() && (ln.back() == '\r' || ln.back() == '\n')) ln.pop_back();
        if (!ln.empty()) got.push_back(ln);
    }
    CHECK(got == expected, "Differential mismatch in " + kTestName + ":\n" + res.c_text + "\n" + stdout_s);
    pass_msg(kTestName);
}

void test_adv_psw_bittest_and_read_after_cmp() {
    const std::string kTestName = "test_adv_psw_bittest_and_read_after_cmp";
    // cmp a, #5; bt psw.0, taken (31 82 FA 03) -> clrb a / oneb a; ret
    const std::vector<uint8_t> code = {
        0x4C, 0x05,             // 0100: cmp a, #5
        0x31, 0x82, 0xFA, 0x03, // 0102: bt sfr(PSW).0, 0109
        0xF1,                   // 0106: clrb a
        0xEF, 0x01,             // 0107: br 010A
        0xE1,                   // 0109: oneb a
        0xD7,                   // 010A: ret
    };
    auto res = decompile_bytes(code, 0x0100, "psw_bt_cy");
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    std::string diag;
    CHECK(compile_check_c_src(res.c_text, &diag), "cl.exe /Zs failed:\n" + diag + "\n" + res.c_text);

    std::vector<uint8_t> inputs = {0, 4, 5, 6, 0xFF};
    std::vector<std::string> expected;
    std::ostringstream cs;
    for (size_t i = 0; i < inputs.size(); ++i) {
        auto mp = std::make_unique<Rl78RefMachine>();
        mp->reset(0x0100);
        mp->load_bytes(0x0100, code);
        mp->set_AX(static_cast<uint16_t>(inputs[i]) << 8);
        mp->run();
        expected.push_back("pswbt:" + std::to_string(i) + "=" + hex8(mp->A()));
        cs << "    printf(\"pswbt:" << i << "=%02X\\n\", (unsigned)(uint8_t)psw_bt_cy(" << (unsigned)inputs[i] << "u));\n";
    }
    std::string tu = res.c_text + "\nint main(void) {\n" + cs.str() + "    return 0;\n}\n";
    std::string stdout_s, err_s;
    CHECK(compile_and_run_c_exe(tu, stdout_s, err_s), "cl.exe run failed:\n" + err_s + "\n" + tu);
    std::vector<std::string> got;
    std::istringstream iss(stdout_s);
    std::string ln;
    while (std::getline(iss, ln)) {
        while (!ln.empty() && (ln.back() == '\r' || ln.back() == '\n')) ln.pop_back();
        if (!ln.empty()) got.push_back(ln);
    }
    CHECK(got == expected, "Differential mismatch in " + kTestName + ":\n" + res.c_text + "\n" + stdout_s);
    pass_msg(kTestName);
}

void test_adv_bc_vs_c_return_truncation() {
    const std::string kTestName = "test_adv_bc_vs_c_return_truncation";
    // Path 1 returns full 16-bit BC = 0x1234; Path 2 writes B=0 and C=0x56 via 8-bit movs.
    // Must infer uint16_t return, NEVER truncate 0x1234 to uint8_t (0x34)!
    const std::vector<uint8_t> code = {
        0xD1,                   // 0100: cmp0 a
        0xDD, 0x04,             // 0101: bz 0107
        0x32, 0x34, 0x12,       // 0103: movw bc, #0x1234
        0xD7,                   // 0106: ret
        0xF3,                   // 0107: clrb b
        0x52, 0x56,             // 0108: mov c, #0x56
        0xD7,                   // 010A: ret
    };
    auto res = decompile_bytes(code, 0x0100, "bc_or_c_ret");
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    std::string diag;
    CHECK(compile_check_c_src(res.c_text, &diag), "cl.exe /Zs failed:\n" + diag + "\n" + res.c_text);

    std::vector<uint8_t> inputs = {0, 1, 0xFF};
    std::vector<std::string> expected;
    std::ostringstream cs;
    for (size_t i = 0; i < inputs.size(); ++i) {
        auto mp = std::make_unique<Rl78RefMachine>();
        mp->reset(0x0100);
        mp->load_bytes(0x0100, code);
        mp->set_AX(static_cast<uint16_t>(inputs[i]) << 8);
        mp->run();
        expected.push_back("bcc:" + std::to_string(i) + "=" + hex16(mp->BC()));
        cs << "    printf(\"bcc:" << i << "=%04X\\n\", (unsigned)(uint16_t)bc_or_c_ret(" << (unsigned)inputs[i] << "u));\n";
    }
    std::string tu = res.c_text + "\nint main(void) {\n" + cs.str() + "    return 0;\n}\n";
    std::string stdout_s, err_s;
    CHECK(compile_and_run_c_exe(tu, stdout_s, err_s), "cl.exe run failed:\n" + err_s + "\n" + tu);
    std::vector<std::string> got;
    std::istringstream iss(stdout_s);
    std::string ln;
    while (std::getline(iss, ln)) {
        while (!ln.empty() && (ln.back() == '\r' || ln.back() == '\n')) ln.pop_back();
        if (!ln.empty()) got.push_back(ln);
    }
    CHECK(got == expected, "Differential mismatch in " + kTestName + ":\n" + res.c_text + "\n" + stdout_s);
    pass_msg(kTestName);
}

void test_adv_shared_epilogue_with_mem_store_and_multi_z_join() {
    const std::string kTestName = "test_adv_shared_epilogue_with_mem_store_and_multi_z_join";
    // Shared non-pure epilogue (`pop hl; ret` with extra mem store in one arm AFTER setting bc = 3)
    // plus multi-pred Z join where arm1 uses `sub a, x` and arm2 uses `cmp a, #5`.
    const std::vector<uint8_t> code = {
        0xC7,                   // 0100: push hl
        0xC1,                   // 0101: push ax
        0xAE, 0xF8,             // 0102: movw ax, sp
        0x16,                   // 0104: movw hl, ax
        0x8C, 0x01,             // 0105: mov a, [hl+1]  (A param)
        0x4C, 0x02,             // 0107: cmp a, #2
        0xDC, 0x08,             // 0109: bc 0113
        0x32, 0x03, 0x00,       // 010B: movw bc, #3
        0x51, 0x77,             // 010E: mov a, #0x77
        0x9F, 0x00, 0x20,       // 0110: mov !0x2000, a  (mem store AFTER setting BC!)
        0xEF, 0x0A,             // 0113? Wait: let's jump to 011D (epilogue): 0115 + 0x08 = 0x011D!
        // Let's re-index from 0113 cleanly below!
    };
    (void)code;
    const std::vector<uint8_t> fcode = {
        0xC7,                   // 0100: push hl
        0xC1,                   // 0101: push ax
        0xAE, 0xF8,             // 0102: movw ax, sp
        0x16,                   // 0104: movw hl, ax
        0x8C, 0x01,             // 0105: mov a, [hl+1]   (A)
        0x4C, 0x02,             // 0107: cmp a, #2
        0xDC, 0x0A,             // 0109: bc 0115         (010B + 0x0A = 0x0115)
        0x32, 0x03, 0x00,       // 010B: movw bc, #3
        0x51, 0x77,             // 010E: mov a, #0x77
        0x9F, 0x00, 0x20,       // 0110: mov !0x2000, a  (mem store after setting BC!)
        0xEF, 0x0D,             // 0113: br 0122         (0115 + 0x0D = 0x0122)
        0x8C, 0x00,             // 0115: mov a, [hl+0]   (X)
        0x4C, 0x05,             // 0117: cmp a, #5
        0xDD, 0x05,             // 0119: bz 0120         (011B + 0x05 = 0x0120)
        0x32, 0x04, 0x00,       // 011B: movw bc, #4
        0xEF, 0x02,             // 011E: br 0122         (0120 + 0x02 = 0x0122)
        0xF7,                   // 0120: clrw bc
        0x51, 0x88,             // 0121: mov a, #0x88    (Wait: pad/match epilogue at 0122! Move clrw bc to 0120, epilogue at 0121? Let's keep 0122!)
    };
    (void)fcode;
    // Exact byte layout:
    // 0100: C7          push hl
    // 0101: C1          push ax
    // 0102: AE F8       movw ax, sp
    // 0104: 16          movw hl, ax
    // 0105: 8C 01       mov a, [hl+1]
    // 0107: 4C 02       cmp a, #2
    // 0109: DC 0A       bc 0115
    // 010B: 32 03 00    movw bc, #3
    // 010E: 51 77       mov a, #0x77
    // 0110: 9F 00 20    mov !0x2000, a
    // 0113: EF 0C       br 0121       (0115 + 0x0C = 0x0121)
    // 0115: 8C 00       mov a, [hl+0]
    // 0117: 4C 05       cmp a, #5
    // 0119: DD 05       bz 0120       (011B + 0x05 = 0x0120)
    // 011B: 32 04 00    movw bc, #4
    // 011E: EF 01       br 0121       (0120 + 0x01 = 0x0121)
    // 0120: F7          clrw bc
    // 0121: C0          pop ax        (non-hidden epilogue work: pop ax; movw !0x2002, ax; pop hl; ret)
    // 0122: BF 02 20    movw !0x2002, ax
    // 0125: C6          pop hl
    // 0126: D7          ret
    const std::vector<uint8_t> acode = {
        0xC7, 0xC1, 0xAE, 0xF8, 0x16,
        0x8C, 0x01, 0x4C, 0x02, 0xDC, 0x0A,
        0x32, 0x03, 0x00, 0x51, 0x77, 0x9F, 0x00, 0x20, 0xEF, 0x0C,
        0x8C, 0x00, 0x4C, 0x05, 0xDD, 0x05,
        0x32, 0x04, 0x00, 0xEF, 0x01,
        0xF7,
        0xC0, 0xBF, 0x02, 0x20, 0xC6, 0xD7
    };
    auto res = decompile_bytes(acode, 0x0100, "shared_ep_mem");
    CHECK(res.ok && res.ir_func && res.ir_func->problems.empty(), "Decompile failed");
    std::string diag;
    CHECK(compile_check_c_src(res.c_text, &diag), "cl.exe /Zs failed:\n" + diag + "\n" + res.c_text);

    struct Vec { uint8_t a, x; };
    std::vector<Vec> vecs = {{2, 0}, {0, 5}, {1, 9}};
    std::vector<std::string> expected;
    std::ostringstream cs;
    for (size_t i = 0; i < vecs.size(); ++i) {
        const auto &v = vecs[i];
        auto mp = std::make_unique<Rl78RefMachine>();
        mp->reset(0x0100);
        mp->load_bytes(0x0100, acode);
        uint16_t ax = static_cast<uint16_t>((static_cast<uint16_t>(v.a) << 8) | v.x);
        mp->set_AX(ax);
        mp->run();
        expected.push_back("sepm:" + std::to_string(i) + "=" + hex16(mp->BC()) + ":" + hex8(mp->rd8(0xF2000)));
        cs << "    RL78_MEM8(0xF2000) = 0; RL78_MEM16(0xF2002) = 0;\n"
           << "    { uint16_t r = (uint16_t)shared_ep_mem(0x" << hex16(ax) << ");\n"
           << "      printf(\"sepm:" << i << "=%04X:%02X\\n\", (unsigned)r, (unsigned)RL78_MEM8(0xF2000)); }\n";
    }
    std::string tu = res.c_text + "\nint main(void) {\n" + cs.str() + "    return 0;\n}\n";
    std::string stdout_s, err_s;
    CHECK(compile_and_run_c_exe(tu, stdout_s, err_s), "cl.exe run failed:\n" + err_s + "\n" + tu);
    std::vector<std::string> got;
    std::istringstream iss(stdout_s);
    std::string ln;
    while (std::getline(iss, ln)) {
        while (!ln.empty() && (ln.back() == '\r' || ln.back() == '\n')) ln.pop_back();
        if (!ln.empty()) got.push_back(ln);
    }
    CHECK(got == expected, "Differential mismatch in " + kTestName + ":\n" + res.c_text + "\n" + stdout_s);
    pass_msg(kTestName);
}

} // namespace

int main() {
    test_ei_di_vs_psw7();
    test_es_prefix_and_code_seg0();
    test_saddr_wraparound_and_sel_rb_bank();
    test_skip_target_variable_length();
    test_rl78_s3_mulhu_divhu_not_misdecoded_as_reserve();
    test_hidden_prologue_epilogue_and_call_setup_omitted();
    test_c_ident_sanitization();
    test_branch_flag_folds_es_and_const();
    test_btclr_inverted_if_with_else_retains_clear();
    test_nested_if_else_and_loop_break_continue();
    test_mulu_and_callt_and_brk();
    test_word_bc_indexed_and_es_movw();
    test_itron_rdyq_remove_es_0f_and_native_c_compliance();
    test_dynamic_es_not_falsely_folded_differential();
    test_struct_pointer_and_callee_es_clobber();
    test_de_hl_register_param_and_itron_queue_linked();
    test_array_of_structs_byte_index_native_c();
    test_multi_block_es_with_const_hl_folds_to_symbol();
    test_multi_block_es_0f_with_const_hl();
    test_process_conf_shared_epilogue_returns_and_no_flag_noise();
    test_adv_guard_clause_stop_ea_nonpure_epilogue();
    test_adv_psw_bittest_and_read_after_cmp();
    test_adv_bc_vs_c_return_truncation();
    test_adv_shared_epilogue_with_mem_store_and_multi_z_join();

    run_differential_suite();

    std::printf("\n=== rl78dec_tests summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
