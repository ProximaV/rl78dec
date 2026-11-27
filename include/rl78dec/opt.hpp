#pragma once

#include "rl78dec/database.hpp"
#include "rl78dec/ir.hpp"

namespace rl78dec {

ExprPtr simplify_math(const ExprPtr &e);
void optimize(Function &func, std::optional<int> default_bank = 0, const IDatabaseProvider *db = nullptr,
              bool allow_gpr_alias = true);

} // namespace rl78dec
