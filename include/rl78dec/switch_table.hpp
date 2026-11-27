#pragma once

#include <cstdint>
#include <map>
#include <optional>

#include "rl78dec/database.hpp"
#include "rl78dec/decoder.hpp"

namespace rl78dec {

std::map<int64_t, std::optional<uint32_t>> parse_switch_table(
    const IDatabaseProvider &db, uint32_t table_ea, int scale = 4, uint32_t max_cases = 64);

std::optional<SwitchInfo> detect_switch(
    const IDatabaseProvider &db, const std::map<uint32_t, DecodedInsn> &insns, const DecodedInsn &br_ins);

} // namespace rl78dec
