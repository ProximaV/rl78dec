#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "rl78dec/ctree.hpp"
#include "rl78dec/database.hpp"
#include "rl78dec/decoder.hpp"
#include "rl78dec/ir.hpp"
#include "rl78dec/user_data.hpp"

namespace rl78dec {

struct DecompileOptions {
    bool banner = true;
    bool verify_ir = true;
    std::optional<int> default_bank = 0;
    FuncUserData user_data;
    std::vector<uint32_t> extra_entries;
};

struct DecompileResult {
    bool ok = false;
    uint32_t entry_ea = 0;
    std::string func_name;
    std::string c_text;
    std::vector<std::string> lines;
    std::vector<std::optional<uint32_t>> line_eas;
    std::unique_ptr<Function> ir_func;
    FrameInfo frame_info;
    FunctionSig sig;
    std::shared_ptr<cfunc_t> cfunc;
    std::string ir_dump;
    std::string error;
};

DecompileResult decompile_function(const IDatabaseProvider &db, uint32_t ea,
                                   const DecompileOptions &opts = DecompileOptions());

// Helper over pre-decoded program (avoids re-decoding the whole flash image per function)
DecompileResult decompile_decoded_function(const IDatabaseProvider &db,
                                           const DecodedProgram &prog,
                                           std::unique_ptr<Function> func,
                                           const DecompileOptions &opts = DecompileOptions());

struct DecompileImageResult {
    std::map<uint32_t, DecompileResult> funcs;
    std::string listing_text;
    std::vector<std::string> errors;
};

DecompileImageResult decompile_image(const IDatabaseProvider &db,
                                     const std::vector<uint32_t> &entries,
                                     const DecompileOptions &opts = DecompileOptions());

} // namespace rl78dec
