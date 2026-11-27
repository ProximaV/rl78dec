#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "rl78dec/ctree.hpp"
#include "rl78dec/database.hpp"
#include "rl78dec/ir.hpp"
#include "rl78dec/structure.hpp"
#include "rl78dec/user_data.hpp"

namespace rl78dec {

struct CGenOptions {
    const IDatabaseProvider *db = nullptr;
    FuncUserData user_data;
    bool banner = true;
    bool hide_casts = false;
};

struct GeneratedCode {
    std::shared_ptr<cfunc_t> cfunc;
    std::vector<std::string> lines;
    std::vector<std::optional<uint32_t>> line_eas;
};

GeneratedCode generate_c(const Function &func,
                         const std::vector<SNodePtr> &tree,
                         const FrameInfo &frame_info,
                         const FunctionSig &sig,
                         const CGenOptions &opts = CGenOptions());

std::string build_listing_with_decls(const IDatabaseProvider &db,
                                     const std::vector<cfuncptr_t> &cfuncs,
                                     const std::vector<std::string> &blocks);

} // namespace rl78dec
