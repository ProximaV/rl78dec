#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "rl78dec/ir.hpp"

namespace rl78dec {

std::pair<int, StmtPtr> find_call_cleanup(const Function &func, const Block &b, size_t call_idx);
void eliminate_spills(Function &func, FrameInfo &frame_info);

} // namespace rl78dec
