#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace rl78dec {

enum class Width : uint8_t {
    B = 1, // 8-bit byte ("b")
    W = 2, // 16-bit word ("w")
    A = 3, // 20-bit address ("a")
    D = 4, // 32-bit dword / far ptr ("d")
};

inline const char *width_str(Width w) {
    switch (w) {
        case Width::B: return "b";
        case Width::W: return "w";
        case Width::A: return "a";
        case Width::D: return "d";
    }
    return "b";
}

inline int width_bytes(Width w) {
    return static_cast<int>(w);
}

// Machine registers (in R8 / R16 / control order)
enum class RegId : int {
    None = -1,
    // 8-bit GPRs (encoding 0..7)
    X = 0, A = 1, C = 2, B = 3, E = 4, D = 5, L = 6, H = 7,
    // 16-bit GPR pairs (encoding 0..3 -> 8..11)
    AX = 8, BC = 9, DE = 10, HL = 11,
    // Bank names
    RB0 = 12, RB1 = 13, RB2 = 14, RB3 = 15,
    // Control / Stack / Segment / Flag registers
    SP = 16, SPL = 17, SPH = 18,
    PSW = 19, CY = 20, Z = 21, RBS = 22,
    CS = 23, ES = 24,
    // 32-bit multi-register return pair
    DE_BC = 25,
};

// Bitmask over single-byte atoms
using AtomMask = uint32_t;
namespace atom {
inline constexpr AtomMask X   = 1u << 0;
inline constexpr AtomMask A   = 1u << 1;
inline constexpr AtomMask C   = 1u << 2;
inline constexpr AtomMask B   = 1u << 3;
inline constexpr AtomMask E   = 1u << 4;
inline constexpr AtomMask D   = 1u << 5;
inline constexpr AtomMask L   = 1u << 6;
inline constexpr AtomMask H   = 1u << 7;
inline constexpr AtomMask ES  = 1u << 8;
inline constexpr AtomMask CS  = 1u << 9;
inline constexpr AtomMask SPL = 1u << 10;
inline constexpr AtomMask SPH = 1u << 11;
inline constexpr AtomMask PSW = 1u << 12;
inline constexpr AtomMask CY  = 1u << 13;
inline constexpr AtomMask Z   = 1u << 14;
inline constexpr AtomMask RBS = 1u << 15;

inline constexpr AtomMask GPR_8   = X | A | C | B | E | D | L | H;
inline constexpr AtomMask ALL_PSW = PSW | CY | Z | RBS;
inline constexpr AtomMask CALLER_SAVED = X | A | C | B | E | D;
inline constexpr AtomMask SCRATCH = X | A | C | B;
} // namespace atom

inline constexpr uint32_t BRK_VECTOR        = 0x0007E;
inline constexpr uint32_t CALLT_TABLE_START = 0x00080;
inline constexpr uint32_t CALLT_TABLE_END   = 0x000C0;
inline constexpr uint32_t GPR_BASE          = 0xFFEE0;
inline constexpr uint32_t GPR_END           = 0xFFF00;

enum class Mnem : int {
    Unknown = 0,
    Nop, Mov, Xch, Oneb, Clrb, Movs, Movw, Xchw, Onew, Clrw,
    Add, Addc, Sub, Subc, And, Or, Xor, Cmp, Cmp0, Cmps,
    Addw, Subw, Cmpw, Mulu,
    // S3 expanded multiply/divide/MAC
    Mulhu, Mulh, Divhu, Divwu, Machu, Mach,
    Inc, Dec, Incw, Decw,
    Shr, Shrw, Shl, Shlw, Sar, Sarw,
    Ror, Rol, Rorc, Rolc, Rolwc,
    Mov1, And1, Or1, Xor1, Set1, Clr1, Not1,
    Call, Callt, Brk, Ret, Reti, Retb,
    Push, Pop,
    Br, Bc, Bnc, Bz, Bnz, Bh, Bnh,
    Bt, Bf, Btclr,
    Skc, Sknc, Skz, Sknz, Skh, Sknh,
    Sel, Ei, Di, Halt, Stop, Brk1,
};

enum class FlagFx : uint8_t {
    None = 0,
    Def  = 1,
    Zero = 2,
    Restore = 3,
};

struct InsnFlagEffects {
    FlagFx z = FlagFx::None;
    FlagFx cy = FlagFx::None;
};

const char *mnem_name(Mnem m);
Mnem mnem_from_name(const std::string &name);
InsnFlagEffects flag_effects(Mnem m);

inline bool is_stop_mnem(Mnem m) {
    return m == Mnem::Br || m == Mnem::Ret || m == Mnem::Reti ||
           m == Mnem::Retb || m == Mnem::Brk1 || m == Mnem::Stop;
}
inline bool is_ret_mnem(Mnem m) {
    return m == Mnem::Ret || m == Mnem::Reti || m == Mnem::Retb;
}
inline bool is_cond_branch_mnem(Mnem m) {
    return m == Mnem::Bc || m == Mnem::Bnc || m == Mnem::Bz ||
           m == Mnem::Bnz || m == Mnem::Bh || m == Mnem::Bnh;
}
inline bool is_bit_branch_mnem(Mnem m) {
    return m == Mnem::Bt || m == Mnem::Bf || m == Mnem::Btclr;
}
inline bool is_skip_mnem(Mnem m) {
    return m == Mnem::Skc || m == Mnem::Sknc || m == Mnem::Skz ||
           m == Mnem::Sknz || m == Mnem::Skh || m == Mnem::Sknh;
}
inline bool is_call_mnem(Mnem m) {
    return m == Mnem::Call || m == Mnem::Callt;
}

// Register helpers (faithful to isa.py + regs.py + 78K0R p.157)
const char *reg_name(RegId r);
RegId reg_from_name(const std::string &s);
Width reg_default_width(RegId r);
AtomMask reg_atoms(RegId r);
AtomMask reg_atoms_named(const std::string &name);
bool regs_overlap(const std::string &a, const std::string &b);
bool is_gpr_word_name(const std::string &s);
bool is_gpr_byte_name(const std::string &s);
bool is_gpr_name(const std::string &s);
bool is_pair_name(const std::string &s);
std::pair<std::string, std::string> pair_halves(const std::string &pair); // (lo, hi)
std::optional<std::pair<std::string, int>> pair_of_atom(const std::string &atom_name); // (pair, 0=lo/1=hi)

inline uint32_t bank_base(int bank) { return 0xFFEF8u - 8u * static_cast<uint32_t>(bank); }
std::optional<std::pair<int, int>> gpr_bank_slot(uint32_t addr);
std::optional<std::string> gpr_alias(uint32_t addr, Width w, std::optional<int> bank);
std::optional<std::string> special_reg(uint32_t addr, Width w);

inline constexpr RegId R8_LUT[8]  = {RegId::X, RegId::A, RegId::C, RegId::B, RegId::E, RegId::D, RegId::L, RegId::H};
inline constexpr RegId R16_LUT[4] = {RegId::AX, RegId::BC, RegId::DE, RegId::HL};
inline constexpr RegId RB_LUT[4]  = {RegId::RB0, RegId::RB1, RegId::RB2, RegId::RB3};

inline uint32_t sfr_abs(uint8_t rel) { return 0xFFF00u + rel; }
inline uint32_t saddr_abs(uint8_t rel) {
    uint32_t addr = 0xFFE00u + rel;
    if (rel < 0x20) addr |= (1u << 8);
    return addr;
}

} // namespace rl78dec
