#pragma once

#include <memory>

#include "rl78dec/database.hpp"
#include "rl78dec/ir.hpp"

namespace rl78dec {

FrameInfo analyze_frame(Function &func, const IdaFrameInfo *ida_frame = nullptr);

} // namespace rl78dec
