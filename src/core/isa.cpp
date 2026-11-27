#include "rl78dec/isa.hpp"

#include <algorithm>
#include <cctype>
#include <unordered_map>

namespace rl78dec {

namespace {

std::string to_lower(std::string s) {
    for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

} // namespace

const char *mnem_name(Mnem m) {
    switch (m) {
        case Mnem::Nop:   return "nop";
        case Mnem::Mov:   return "mov";
        case Mnem::Xch:   return "xch";
        case Mnem::Oneb:  return "oneb";
        case Mnem::Clrb:  return "clrb";
        case Mnem::Movs:  return "movs";
        case Mnem::Movw:  return "movw";
        case Mnem::Xchw:  return "xchw";
        case Mnem::Onew:  return "onew";
        case Mnem::Clrw:  return "clrw";
        case Mnem::Add:   return "add";
        case Mnem::Addc:  return "addc";
        case Mnem::Sub:   return "sub";
        case Mnem::Subc:  return "subc";
        case Mnem::And:   return "and";
        case Mnem::Or:    return "or";
        case Mnem::Xor:   return "xor";
        case Mnem::Cmp:   return "cmp";
        case Mnem::Cmp0:  return "cmp0";
        case Mnem::Cmps:  return "cmps";
        case Mnem::Addw:  return "addw";
        case Mnem::Subw:  return "subw";
        case Mnem::Cmpw:  return "cmpw";
        case Mnem::Mulu:  return "mulu";
        case Mnem::Mulhu: return "mulhu";
        case Mnem::Mulh:  return "mulh";
        case Mnem::Divhu: return "divhu";
        case Mnem::Divwu: return "divwu";
        case Mnem::Machu: return "machu";
        case Mnem::Mach:  return "mach";
        case Mnem::Inc:   return "inc";
        case Mnem::Dec:   return "dec";
        case Mnem::Incw:  return "incw";
        case Mnem::Decw:  return "decw";
        case Mnem::Shr:   return "shr";
        case Mnem::Shrw:  return "shrw";
        case Mnem::Shl:   return "shl";
        case Mnem::Shlw:  return "shlw";
        case Mnem::Sar:   return "sar";
        case Mnem::Sarw:  return "sarw";
        case Mnem::Ror:   return "ror";
        case Mnem::Rol:   return "rol";
        case Mnem::Rorc:  return "rorc";
        case Mnem::Rolc:  return "rolc";
        case Mnem::Rolwc: return "rolwc";
        case Mnem::Mov1:  return "mov1";
        case Mnem::And1:  return "and1";
        case Mnem::Or1:   return "or1";
        case Mnem::Xor1:  return "xor1";
        case Mnem::Set1:  return "set1";
        case Mnem::Clr1:  return "clr1";
        case Mnem::Not1:  return "not1";
        case Mnem::Call:  return "call";
        case Mnem::Callt: return "callt";
        case Mnem::Brk:   return "brk";
        case Mnem::Ret:   return "ret";
        case Mnem::Reti:  return "reti";
        case Mnem::Retb:  return "retb";
        case Mnem::Push:  return "push";
        case Mnem::Pop:   return "pop";
        case Mnem::Br:    return "br";
        case Mnem::Bc:    return "bc";
        case Mnem::Bnc:   return "bnc";
        case Mnem::Bz:    return "bz";
        case Mnem::Bnz:   return "bnz";
        case Mnem::Bh:    return "bh";
        case Mnem::Bnh:   return "bnh";
        case Mnem::Bt:    return "bt";
        case Mnem::Bf:    return "bf";
        case Mnem::Btclr: return "btclr";
        case Mnem::Skc:   return "skc";
        case Mnem::Sknc:  return "sknc";
        case Mnem::Skz:   return "skz";
        case Mnem::Sknz:  return "sknz";
        case Mnem::Skh:   return "skh";
        case Mnem::Sknh:  return "sknh";
        case Mnem::Sel:   return "sel";
        case Mnem::Ei:    return "ei";
        case Mnem::Di:    return "di";
        case Mnem::Halt:  return "halt";
        case Mnem::Stop:  return "stop";
        case Mnem::Brk1:  return "brk1";
        default:          return "unknown";
    }
}

Mnem mnem_from_name(const std::string &name) {
    static const std::unordered_map<std::string, Mnem> kMap = {
        {"nop", Mnem::Nop}, {"mov", Mnem::Mov}, {"xch", Mnem::Xch},
        {"oneb", Mnem::Oneb}, {"clrb", Mnem::Clrb}, {"movs", Mnem::Movs},
        {"movw", Mnem::Movw}, {"xchw", Mnem::Xchw}, {"onew", Mnem::Onew},
        {"clrw", Mnem::Clrw}, {"add", Mnem::Add}, {"addc", Mnem::Addc},
        {"sub", Mnem::Sub}, {"subc", Mnem::Subc}, {"and", Mnem::And},
        {"or", Mnem::Or}, {"xor", Mnem::Xor}, {"cmp", Mnem::Cmp},
        {"cmp0", Mnem::Cmp0}, {"cmps", Mnem::Cmps}, {"addw", Mnem::Addw},
        {"subw", Mnem::Subw}, {"cmpw", Mnem::Cmpw}, {"mulu", Mnem::Mulu},
        {"mulhu", Mnem::Mulhu}, {"mulh", Mnem::Mulh}, {"divhu", Mnem::Divhu},
        {"divwu", Mnem::Divwu}, {"machu", Mnem::Machu}, {"mach", Mnem::Mach},
        {"inc", Mnem::Inc}, {"dec", Mnem::Dec}, {"incw", Mnem::Incw},
        {"decw", Mnem::Decw}, {"shr", Mnem::Shr}, {"shrw", Mnem::Shrw},
        {"shl", Mnem::Shl}, {"shlw", Mnem::Shlw}, {"sar", Mnem::Sar},
        {"sarw", Mnem::Sarw}, {"ror", Mnem::Ror}, {"rol", Mnem::Rol},
        {"rorc", Mnem::Rorc}, {"rolc", Mnem::Rolc}, {"rolwc", Mnem::Rolwc},
        {"mov1", Mnem::Mov1}, {"and1", Mnem::And1}, {"or1", Mnem::Or1},
        {"xor1", Mnem::Xor1}, {"set1", Mnem::Set1}, {"clr1", Mnem::Clr1},
        {"not1", Mnem::Not1}, {"call", Mnem::Call}, {"callt", Mnem::Callt},
        {"brk", Mnem::Brk}, {"ret", Mnem::Ret}, {"reti", Mnem::Reti},
        {"retb", Mnem::Retb}, {"push", Mnem::Push}, {"pop", Mnem::Pop},
        {"br", Mnem::Br}, {"bc", Mnem::Bc}, {"bnc", Mnem::Bnc},
        {"bz", Mnem::Bz}, {"bnz", Mnem::Bnz}, {"bh", Mnem::Bh},
        {"bnh", Mnem::Bnh}, {"bt", Mnem::Bt}, {"bf", Mnem::Bf},
        {"btclr", Mnem::Btclr}, {"skc", Mnem::Skc}, {"sknc", Mnem::Sknc},
        {"skz", Mnem::Skz}, {"sknz", Mnem::Sknz}, {"skh", Mnem::Skh},
        {"sknh", Mnem::Sknh}, {"sel", Mnem::Sel}, {"ei", Mnem::Ei},
        {"di", Mnem::Di}, {"halt", Mnem::Halt}, {"stop", Mnem::Stop},
        {"brk1", Mnem::Brk1},
    };
    auto it = kMap.find(to_lower(name));
    return it != kMap.end() ? it->second : Mnem::Unknown;
}

InsnFlagEffects flag_effects(Mnem m) {
    switch (m) {
        case Mnem::Add:
        case Mnem::Addc:
        case Mnem::Sub:
        case Mnem::Subc:
        case Mnem::Addw:
        case Mnem::Subw:
        case Mnem::Cmp:
        case Mnem::Cmpw:
        case Mnem::Cmps:
        case Mnem::Movs:
            return {FlagFx::Def, FlagFx::Def};
        case Mnem::And:
        case Mnem::Or:
        case Mnem::Xor:
        case Mnem::Inc:
        case Mnem::Dec:
            return {FlagFx::Def, FlagFx::None};
        case Mnem::Shl:
        case Mnem::Shr:
        case Mnem::Sar:
        case Mnem::Shlw:
        case Mnem::Shrw:
        case Mnem::Sarw:
        case Mnem::Ror:
        case Mnem::Rol:
        case Mnem::Rorc:
        case Mnem::Rolc:
        case Mnem::Rolwc:
        case Mnem::Set1:
        case Mnem::Clr1:
        case Mnem::Not1:
        case Mnem::Mov1:
        case Mnem::And1:
        case Mnem::Or1:
        case Mnem::Xor1:
            return {FlagFx::None, FlagFx::Def};
        case Mnem::Cmp0:
            return {FlagFx::Def, FlagFx::Zero};
        case Mnem::Reti:
        case Mnem::Retb:
            return {FlagFx::Restore, FlagFx::Restore};
        default:
            return {FlagFx::None, FlagFx::None};
    }
}

const char *reg_name(RegId r) {
    switch (r) {
        case RegId::X:     return "x";
        case RegId::A:     return "a";
        case RegId::C:     return "c";
        case RegId::B:     return "b";
        case RegId::E:     return "e";
        case RegId::D:     return "d";
        case RegId::L:     return "l";
        case RegId::H:     return "h";
        case RegId::AX:    return "ax";
        case RegId::BC:    return "bc";
        case RegId::DE:    return "de";
        case RegId::HL:    return "hl";
        case RegId::RB0:   return "rb0";
        case RegId::RB1:   return "rb1";
        case RegId::RB2:   return "rb2";
        case RegId::RB3:   return "rb3";
        case RegId::SP:    return "sp";
        case RegId::SPL:   return "spl";
        case RegId::SPH:   return "sph";
        case RegId::PSW:   return "psw";
        case RegId::CY:    return "cy";
        case RegId::Z:     return "z";
        case RegId::RBS:   return "rbs";
        case RegId::CS:    return "cs";
        case RegId::ES:    return "es";
        case RegId::DE_BC: return "de:bc";
        default:           return "?";
    }
}

RegId reg_from_name(const std::string &s) {
    static const std::unordered_map<std::string, RegId> kMap = {
        {"x", RegId::X}, {"a", RegId::A}, {"c", RegId::C}, {"b", RegId::B},
        {"e", RegId::E}, {"d", RegId::D}, {"l", RegId::L}, {"h", RegId::H},
        {"ax", RegId::AX}, {"bc", RegId::BC}, {"de", RegId::DE}, {"hl", RegId::HL},
        {"rb0", RegId::RB0}, {"rb1", RegId::RB1}, {"rb2", RegId::RB2}, {"rb3", RegId::RB3},
        {"sp", RegId::SP}, {"spl", RegId::SPL}, {"sph", RegId::SPH},
        {"psw", RegId::PSW}, {"cy", RegId::CY}, {"z", RegId::Z}, {"rbs", RegId::RBS},
        {"cs", RegId::CS}, {"es", RegId::ES}, {"de:bc", RegId::DE_BC},
    };
    auto it = kMap.find(to_lower(s));
    return it != kMap.end() ? it->second : RegId::None;
}

Width reg_default_width(RegId r) {
    if (r == RegId::DE_BC) return Width::D;
    if (r == RegId::AX || r == RegId::BC || r == RegId::DE || r == RegId::HL || r == RegId::SP) {
        return Width::W;
    }
    return Width::B;
}

AtomMask reg_atoms(RegId r) {
    switch (r) {
        case RegId::X:     return atom::X;
        case RegId::A:     return atom::A;
        case RegId::C:     return atom::C;
        case RegId::B:     return atom::B;
        case RegId::E:     return atom::E;
        case RegId::D:     return atom::D;
        case RegId::L:     return atom::L;
        case RegId::H:     return atom::H;
        case RegId::AX:    return atom::X | atom::A;
        case RegId::BC:    return atom::C | atom::B;
        case RegId::DE:    return atom::E | atom::D;
        case RegId::HL:    return atom::L | atom::H;
        case RegId::SP:    return atom::SPL | atom::SPH;
        case RegId::SPL:   return atom::SPL;
        case RegId::SPH:   return atom::SPH;
        case RegId::PSW:   return atom::ALL_PSW;
        case RegId::CY:    return atom::CY;
        case RegId::Z:     return atom::Z;
        case RegId::RBS:   return atom::RBS;
        case RegId::CS:    return atom::CS;
        case RegId::ES:    return atom::ES;
        case RegId::DE_BC: return atom::C | atom::B | atom::E | atom::D;
        default:           return 0;
    }
}

AtomMask reg_atoms_named(const std::string &name) {
    RegId r = reg_from_name(name);
    if (r != RegId::None) return reg_atoms(r);
    return 0;
}

bool regs_overlap(const std::string &a, const std::string &b) {
    AtomMask ma = reg_atoms_named(a);
    AtomMask mb = reg_atoms_named(b);
    if (ma && mb) return (ma & mb) != 0;
    return a == b;
}

bool is_gpr_word_name(const std::string &s) {
    return s == "ax" || s == "bc" || s == "de" || s == "hl";
}

bool is_gpr_byte_name(const std::string &s) {
    return s == "x" || s == "a" || s == "c" || s == "b" ||
           s == "e" || s == "d" || s == "l" || s == "h";
}

bool is_gpr_name(const std::string &s) {
    return is_gpr_word_name(s) || is_gpr_byte_name(s) || s == "de:bc";
}

bool is_pair_name(const std::string &s) {
    return is_gpr_word_name(s) || s == "sp";
}

std::pair<std::string, std::string> pair_halves(const std::string &pair) {
    if (pair == "ax") return {"x", "a"};
    if (pair == "bc") return {"c", "b"};
    if (pair == "de") return {"e", "d"};
    if (pair == "hl") return {"l", "h"};
    if (pair == "sp") return {"spl", "sph"};
    return {"", ""};
}

std::optional<std::pair<std::string, int>> pair_of_atom(const std::string &atom_name) {
    if (atom_name == "x") return std::make_pair(std::string("ax"), 0);
    if (atom_name == "a") return std::make_pair(std::string("ax"), 1);
    if (atom_name == "c") return std::make_pair(std::string("bc"), 0);
    if (atom_name == "b") return std::make_pair(std::string("bc"), 1);
    if (atom_name == "e") return std::make_pair(std::string("de"), 0);
    if (atom_name == "d") return std::make_pair(std::string("de"), 1);
    if (atom_name == "l") return std::make_pair(std::string("hl"), 0);
    if (atom_name == "h") return std::make_pair(std::string("hl"), 1);
    if (atom_name == "spl") return std::make_pair(std::string("sp"), 0);
    if (atom_name == "sph") return std::make_pair(std::string("sp"), 1);
    return std::nullopt;
}

std::optional<std::pair<int, int>> gpr_bank_slot(uint32_t addr) {
    if (addr < GPR_BASE || addr >= GPR_END) return std::nullopt;
    uint32_t rel = addr - GPR_BASE;
    return std::make_pair(static_cast<int>(3 - rel / 8), static_cast<int>(rel % 8));
}

std::optional<std::string> gpr_alias(uint32_t addr, Width w, std::optional<int> bank) {
    if (!bank.has_value()) return std::nullopt;
    auto slot = gpr_bank_slot(addr);
    if (!slot.has_value() || slot->first != *bank) return std::nullopt;
    int off = slot->second;
    if (w == Width::W) {
        if (off % 2 != 0) return std::nullopt;
        return std::string(reg_name(R16_LUT[off >> 1]));
    }
    return std::string(reg_name(R8_LUT[off]));
}

std::optional<std::string> special_reg(uint32_t addr, Width w) {
    if (addr == 0xFFFF8u) return std::string(w == Width::W ? "sp" : "spl");
    if (addr == 0xFFFF9u && w == Width::B) return std::string("sph");
    if (addr == 0xFFFFAu && w == Width::B) return std::string("psw");
    if (addr == 0xFFFFCu && w == Width::B) return std::string("cs");
    if (addr == 0xFFFFDu && w == Width::B) return std::string("es");
    return std::nullopt;
}

} // namespace rl78dec
