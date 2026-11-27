#pragma once

#include <map>
#include <memory>
#include <set>
#include <vector>

#include "rl78dec/decoder.hpp"
#include "rl78dec/ir.hpp"

namespace rl78dec {

std::unique_ptr<Function> build_func(
    const std::map<uint32_t, DecodedInsn> &insns,
    uint32_t entry,
    const std::set<uint32_t> &entry_set);

std::map<uint32_t, std::unique_ptr<Function>> build_functions(
    const std::map<uint32_t, DecodedInsn> &insns,
    const std::set<uint32_t> &calls,
    const std::vector<uint32_t> &extra_entries = {});

void resolve_flags(Function &func);

} // namespace rl78dec
