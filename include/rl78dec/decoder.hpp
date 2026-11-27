#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "rl78dec/database.hpp"
#include "rl78dec/isa.hpp"

namespace rl78dec {

enum class OpMode : uint8_t {
    Void = 0,
    Reg,
    Imm,
    Mem,
    Bit,
    Ind,
    Idx16,
    Hloff,
    Near,
    Far,
    Callt,
};

enum class BitBase : uint8_t {
    Reg = 0,
    Mem = 1,
    Ind = 2,
};

struct Operand {
    OpMode mode = OpMode::Void;
    RegId reg = RegId::None;
    uint32_t value = 0;
    uint32_t addr = 0;
    RegId base_reg = RegId::None;
    uint32_t disp = 0;
    uint8_t bit = 0;
    BitBase bit_base = BitBase::Reg;
    Width width = Width::B;
    bool es = false;
    std::string name;
};

struct DecodedInsn {
    uint32_t ea = 0;
    int size = 0;
    Mnem mnem = Mnem::Unknown;
    std::vector<Operand> ops;
    bool es = false;
    std::vector<uint8_t> raw;
    std::optional<SwitchInfo> sw;
    std::optional<uint32_t> vector_target;

    const Operand *op(size_t i) const { return i < ops.size() ? &ops[i] : nullptr; }
};

struct DecodedProgram {
    std::map<uint32_t, DecodedInsn> insns;
    std::set<uint32_t> calls;
};

std::optional<DecodedInsn> decode_one(const IDatabaseProvider &db, uint32_t ea);
std::optional<uint32_t> target_of(const DecodedInsn &ins);
std::vector<std::pair<std::string, uint32_t>> insn_succs(const IDatabaseProvider &db, const DecodedInsn &ins);
DecodedProgram decode_recursive(const IDatabaseProvider &db, const std::vector<uint32_t> &entries);

} // namespace rl78dec
