#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "rl78dec/isa.hpp"

namespace rl78dec {

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

enum class ExprKind : uint8_t {
    Const = 0,
    Reg,
    Var,
    StackVar,
    Mem,
    Bit,
    Bin,
    Un,
    Intr,
};

struct Expr;
using ExprPtr = std::shared_ptr<Expr>;

struct Expr {
    ExprKind kind = ExprKind::Const;
    Width width = Width::B;

    // Const
    uint32_t value = 0;
    std::string name; // optional symbolic name, var name, reg name, intr name, or mem symbol

    // StackVar
    int64_t offset = 0;
    bool is_arg = false;

    // Mem
    ExprPtr addr;
    uint32_t static_addr = 0;
    bool has_static_addr = false;
    bool es = false;
    bool addr_is_linear = false;

    // Bit
    ExprPtr base;
    uint8_t bit = 0;

    // Bin / Un
    std::string op;
    ExprPtr l;
    ExprPtr r;

    // Intr
    std::vector<ExprPtr> args;

    static ExprPtr make_const(uint32_t val, Width w = Width::B, std::string sym_name = "");
    static ExprPtr make_reg(const std::string &rname, std::optional<Width> w = std::nullopt);
    static ExprPtr make_var(const std::string &vname, Width w = Width::B);
    static ExprPtr make_stack_var(const std::string &vname, Width w, int64_t off, bool arg);
    static ExprPtr make_mem_addr(ExprPtr addr_expr, Width w = Width::B, bool is_es = false,
                                 std::string sym_name = "", bool linear = false);
    static ExprPtr make_mem_abs(uint32_t abs_addr, Width w = Width::B, bool is_es = false,
                                std::string sym_name = "", bool linear = false);
    static ExprPtr make_bit(ExprPtr base_expr, uint8_t bit_idx);
    static ExprPtr make_bin(std::string op_str, ExprPtr lhs, ExprPtr rhs, Width w = Width::B);
    static ExprPtr make_un(std::string op_str, ExprPtr operand, Width w = Width::B);
    static ExprPtr make_intr(std::string intr_name, std::vector<ExprPtr> intr_args, Width w = Width::B);
};

bool expr_eq(const ExprPtr &a, const ExprPtr &b);
size_t expr_hash(const ExprPtr &e);
ExprPtr expr_clone(const ExprPtr &e);
std::string format_ir_expr(const ExprPtr &e);

// ---------------------------------------------------------------------------
// Flags (strictly separating Z and CY per 78K0R / RL78 ISA)
// ---------------------------------------------------------------------------

enum class FlagKind : uint8_t {
    Cmp = 0,    // Z = (a == b), CY = (a < b unsigned)
    Cmp0,       // Z = (a == 0), CY = 0
    Sub,        // Z = (res == 0), CY = borrow(a, b, carry_in)
    Add,        // Z = (res == 0), CY = carry(a, b, carry_in)
    Result,     // Z = (a == 0), CY untouched
    Movs,       // Z = (b == 0), CY = (a == 0 || b == 0)   [a = reg A, b = X]
    Cmps,       // Z = (a == b), CY = (a != b || c == 0 || a == 0)  [a = X, b = mem, c = A]
    CarryVal,   // CY = a (0/1 or boolean expression), Z untouched
    Unknown,    // Clobbered / non-derivable
};

struct FlagDef {
    FlagKind kind = FlagKind::Unknown;
    Width width = Width::B;
    ExprPtr a;
    ExprPtr b;
    ExprPtr c; // carry_in (for ADDC/SUBC) or A reg (for CMPS)
    uint64_t origin_stmt_id = 0; // Stmt::id of instruction that produced this flag
};
using FlagDefPtr = std::shared_ptr<FlagDef>;

inline FlagDefPtr clone_flag(const FlagDefPtr &f) {
    if (!f) return nullptr;
    auto nf = std::make_shared<FlagDef>(*f);
    nf->a = expr_clone(f->a);
    nf->b = expr_clone(f->b);
    nf->c = expr_clone(f->c);
    return nf;
}

// ---------------------------------------------------------------------------
// Statements & CFG
// ---------------------------------------------------------------------------

enum class StmtKind : uint8_t {
    Assign = 0,
    Swap,
    Compare,
    Call,
    Intrinsic,
    Ret,
    Goto,
    Branch,
    Nop,
    Switch,
};

struct Stmt;
using StmtPtr = std::shared_ptr<Stmt>;

struct Stmt {
    uint64_t id = 0; // Unique stable ID within IR lifecycle
    StmtKind kind = StmtKind::Nop;
    uint32_t ea = 0;

    // Assign
    ExprPtr dst;
    ExprPtr src;
    FlagDefPtr z_flag;
    FlagDefPtr cy_flag;

    // Swap
    ExprPtr a;
    ExprPtr b;

    // Call
    std::optional<uint32_t> target;
    ExprPtr expr;
    std::vector<ExprPtr> args;
    // Note: dst reused for call return

    // Intrinsic / Goto
    std::string name;
    std::string note;
    uint32_t goto_target = 0;

    // Ret
    std::string ret_kind = "ret"; // "ret", "reti", "retb"
    ExprPtr val;

    // Branch
    std::string cond; // "z", "nz", "cy", "ncy", "h", "nh", or "" (if bittest)
    uint32_t branch_target = 0;
    uint32_t fallthrough = 0;
    bool has_bittest = false;
    ExprPtr bittest_expr;
    bool bittest_sense = true;
    bool btclr_clear = false; // True only for BTCLR (clear bit on taken path!)

    // Switch
    std::map<int64_t, std::optional<uint32_t>> cases;
    std::optional<uint32_t> default_ea;
    std::optional<uint32_t> table_ea;

    static StmtPtr alloc(StmtKind k, uint32_t ea_val);
};

StmtPtr make_assign(uint32_t ea, ExprPtr dst, ExprPtr src,
                    FlagDefPtr zf = nullptr, FlagDefPtr cyf = nullptr);
StmtPtr make_swap(uint32_t ea, ExprPtr a, ExprPtr b);
StmtPtr make_compare(uint32_t ea, FlagDefPtr zf, FlagDefPtr cyf = nullptr);
StmtPtr make_call(uint32_t ea, std::optional<uint32_t> target, ExprPtr expr = nullptr);
StmtPtr make_intrinsic(uint32_t ea, std::string name, std::vector<ExprPtr> args = {}, std::string note = "");
StmtPtr make_ret(uint32_t ea, std::string kind = "ret", ExprPtr val = nullptr);
StmtPtr make_goto(uint32_t ea, uint32_t target);
StmtPtr make_branch(uint32_t ea, std::string cond, uint32_t target, uint32_t fall);
StmtPtr make_bittest_branch(uint32_t ea, ExprPtr bit_expr, bool sense, uint32_t target, uint32_t fall, bool btclr);
StmtPtr make_nop(uint32_t ea);
StmtPtr make_switch(uint32_t ea, ExprPtr expr, std::map<int64_t, std::optional<uint32_t>> cases,
                    std::optional<uint32_t> def_ea, std::optional<uint32_t> tbl_ea);

enum class TermKind : uint8_t {
    Fall = 0,
    Ret,
    Goto,
    Branch,
    Switch,
};

struct Block {
    uint32_t start = 0;
    std::vector<uint32_t> insn_eas; // Original instruction EAs in this block
    std::vector<StmtPtr> stmts;
    std::vector<std::pair<std::string, uint32_t>> succ;
    TermKind term = TermKind::Fall;
};
using BlockPtr = std::shared_ptr<Block>;

struct Param {
    std::string name;
    std::string type_str = "uint16_t";
    std::string location = "ax";
};

struct FunctionSig {
    std::string name;
    std::string ret_type = "void";
    ExprPtr ret_expr;
    std::vector<Param> params;

    std::string format_signature(const std::string &override_name = "") const;
};

struct FrameInfo {
    bool has_frame = false;
    std::string fp_reg; // "hl", "sp", or ""
    int frame_size = 0;
    std::vector<std::string> saved_regs;
    std::vector<std::string> homed_args;
    std::map<int64_t, std::string> homed_slot_to_arg;
    std::map<int64_t, std::string> homed_word_slots;
    std::vector<ExprPtr> initial_spill_stack;
    int fp_bias = 0;
    std::vector<std::string> prologue_pushes;
    int arg_base = 4;
    bool is_isr = false;

    struct VarDecl {
        ExprPtr var;
        Width width = Width::B;
    };
    std::map<std::string, VarDecl> locals;
    std::map<std::string, VarDecl> args;
    std::map<std::string, VarDecl> virtual_vars;

    std::unordered_set<uint64_t> hidden_stmts; // Stmt::id
    std::unordered_map<std::string, std::string> user_renames;
    std::unordered_map<std::string, std::string> user_types;

    std::optional<std::string> describe() const;
};

struct Function {
    uint32_t entry = 0;
    std::string name;
    std::map<uint32_t, BlockPtr> blocks;
    std::set<uint32_t> calls;
    std::vector<std::string> problems;

    std::vector<BlockPtr> ordered() const {
        std::vector<BlockPtr> out;
        out.reserve(blocks.size());
        for (const auto &[k, b] : blocks) out.push_back(b);
        return out;
    }
};

bool verify_ir(Function &func);
std::string format_ir_stmt(const Stmt &s);
std::vector<std::pair<std::string, std::optional<uint32_t>>> format_ir_lines(const Function &func);

} // namespace rl78dec
