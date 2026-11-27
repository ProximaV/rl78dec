#pragma once

#include <vector>

#include "rl78dec/decoder.hpp"
#include "rl78dec/ir.hpp"

namespace rl78dec {

ExprPtr operand_to_expr(const Operand &op);
std::vector<StmtPtr> lift_insn(const DecodedInsn &ins);

} // namespace rl78dec
