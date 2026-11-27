#pragma once

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "rl78dec/database.hpp"
#include "rl78dec/ir.hpp"

namespace rl78dec {

struct ParsedProto {
    std::string ret_type;
    std::string func_name;
    std::vector<std::pair<std::string, std::string>> params; // (name, type_str)
};

std::optional<ParsedProto> parse_prototype(const std::string &proto_str);

FunctionSig infer_function_sig_only(
    Function &func,
    FrameInfo &frame_info,
    const IDatabaseProvider *db = nullptr,
    const std::string &user_proto = "",
    const CallerConsensus *caller_consensus = nullptr);

FunctionSig analyze_calling_convention(
    Function &func,
    FrameInfo &frame_info,
    const IDatabaseProvider *db = nullptr,
    const std::string &user_proto = "",
    const CallerConsensus *caller_consensus = nullptr);

} // namespace rl78dec
