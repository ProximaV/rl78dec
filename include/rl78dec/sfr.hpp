#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace rl78dec {

std::optional<std::string> sfr_name_for(uint32_t addr);
std::optional<uint32_t> sfr_addr_for(const std::string &name);

std::string default_cell_name(uint32_t addr);

} // namespace rl78dec
