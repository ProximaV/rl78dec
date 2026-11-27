#pragma once

#include "rl78dec/database.hpp"
#include "rl78dec/ir.hpp"

namespace rl78dec {

void recover_variables(Function &func, const FunctionSig &sig, FrameInfo &frame_info,
                       const IDatabaseProvider *db = nullptr);

} // namespace rl78dec
