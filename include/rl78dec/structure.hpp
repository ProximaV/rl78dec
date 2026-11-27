#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "rl78dec/ir.hpp"

namespace rl78dec {

struct SNode;
using SNodePtr = std::shared_ptr<SNode>;

enum class SNodeKind : uint8_t {
    Stmt = 0,
    Label,
    Goto,
    Ret,
    If,
    IfGoto,
    While,
    Switch,
    Break,
    Continue,
    BreakIf,
};

struct SCase {
    std::vector<int64_t> vals;
    std::vector<SNodePtr> body;
};

struct SNode {
    SNodeKind kind = SNodeKind::Stmt;
    uint32_t ea = 0;

    // Stmt
    StmtPtr stmt;

    // Ret
    ExprPtr val;
    std::string ret_kind = "ret";

    // If / IfGoto / BreakIf / Continue / While / Switch
    ExprPtr cond;
    std::vector<SNodePtr> then_body;
    std::vector<SNodePtr> else_body;
    bool dowhile = false;
    bool btclr_clear = false;
    ExprPtr btclr_base;
    uint8_t btclr_bit = 0;

    // Switch
    ExprPtr switch_expr;
    std::vector<SCase> cases;
    std::vector<SNodePtr> default_body;
    bool has_default = false;
};

ExprPtr cond_expr(const Stmt &branch);
ExprPtr negate_cond(const ExprPtr &e);
std::vector<SNodePtr> structure(const Function &func, const FrameInfo *frame_info = nullptr);

} // namespace rl78dec
