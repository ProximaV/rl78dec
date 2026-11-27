#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace rl78dec {

// Exact numeric parity with IDA 9.5 <hexrays.hpp> enum ctype_t
enum ctype_t : int {
    cot_empty    = 0,
    cot_comma    = 1,
    cot_asg      = 2,
    cot_asgbor   = 3,
    cot_asgxor   = 4,
    cot_asgband  = 5,
    cot_asgadd   = 6,
    cot_asgsub   = 7,
    cot_asgmul   = 8,
    cot_asgsshr  = 9,
    cot_asgushr  = 10,
    cot_asgshl   = 11,
    cot_asgsdiv  = 12,
    cot_asgudiv  = 13,
    cot_asgsmod  = 14,
    cot_asgumod  = 15,
    cot_tern     = 16,
    cot_lor      = 17,
    cot_land     = 18,
    cot_bor      = 19,
    cot_xor      = 20,
    cot_band     = 21,
    cot_eq       = 22,
    cot_ne       = 23,
    cot_sge      = 24,
    cot_uge      = 25,
    cot_sle      = 26,
    cot_ule      = 27,
    cot_sgt      = 28,
    cot_ugt      = 29,
    cot_slt      = 30,
    cot_ult      = 31,
    cot_sshr     = 32,
    cot_ushr     = 33,
    cot_shl      = 34,
    cot_add      = 35,
    cot_sub      = 36,
    cot_mul      = 37,
    cot_sdiv     = 38,
    cot_udiv     = 39,
    cot_smod     = 40,
    cot_umod     = 41,
    cot_fadd     = 42,
    cot_fsub     = 43,
    cot_fmul     = 44,
    cot_fdiv     = 45,
    cot_fneg     = 46,
    cot_neg      = 47,
    cot_cast     = 48,
    cot_lnot     = 49,
    cot_bnot     = 50,
    cot_ptr      = 51,
    cot_ref      = 52,
    cot_postinc  = 53,
    cot_postdec  = 54,
    cot_preinc   = 55,
    cot_predec   = 56,
    cot_call     = 57,
    cot_idx      = 58,
    cot_memref   = 59,
    cot_memptr   = 60,
    cot_num      = 61,
    cot_fnum     = 62,
    cot_str      = 63,
    cot_obj      = 64,
    cot_var      = 65,
    cot_insn     = 66,
    cot_sizeof   = 67,
    cot_helper   = 68,
    cot_type     = 69,
    cot_last     = cot_type,

    cit_empty    = 70,
    cit_block    = 71,
    cit_expr     = 72,
    cit_if       = 73,
    cit_for      = 74,
    cit_while    = 75,
    cit_do       = 76,
    cit_switch   = 77,
    cit_break    = 78,
    cit_continue = 79,
    cit_return   = 80,
    cit_goto     = 81,
    cit_asm      = 82,
    cit_try      = 83,
    cit_throw    = 84,
    cit_end      = 85,
};

const char *ctype_name(ctype_t op);
ctype_t negated_relation(ctype_t op);

constexpr inline bool ctype_is_expr(ctype_t op) { return op >= cot_empty && op <= cot_last; }
constexpr inline bool ctype_is_insn(ctype_t op) { return op >= cit_empty && op < cit_end; }
constexpr inline bool ctype_uses_x(ctype_t op)  { return (op >= cot_comma && op <= cot_memptr) || op == cot_sizeof; }
constexpr inline bool ctype_uses_y(ctype_t op)  { return (op >= cot_comma && op <= cot_fdiv) || op == cot_idx; }
constexpr inline bool ctype_uses_z(ctype_t op)  { return op == cot_tern; }

enum CtreeVisitorFlags : int {
    RL78_CV_FAST    = 0x0000,
    RL78_CV_PRUNE   = 0x0001,
    RL78_CV_PARENTS = 0x0002,
    RL78_CV_POST    = 0x0004,
    RL78_CV_RESTART = 0x0008,
    RL78_CV_INSNS   = 0x0010,
};

struct lvar_locator_t {
    bool is_stk = false;
    int reg = -1;
    int64_t stk_off = 0;
    uint64_t defea = UINT64_MAX;
    std::string to_key() const;
};

struct lvar_t {
    int index = 0;
    std::string name;
    std::string canonical_name;
    std::string type_str = "uint16_t";
    std::string cmt;
    int width = 2;
    uint64_t defea = UINT64_MAX;
    lvar_locator_t location;
    bool is_arg_var = false;
    bool is_thisarg = false;
    bool is_result_var = false;
    bool is_stk_var_flag = false;
    bool has_user_name = false;
    bool has_user_type = false;

    bool is_stk_var() const { return is_stk_var_flag; }
    bool is_reg_var() const { return !is_stk_var_flag; }
};

struct var_ref_t {
    int idx = -1;
};

struct cnumber_t {
    uint64_t _value = 0;
    int bits = 16;
    int opnum = 0;
    uint64_t ea = UINT64_MAX;
    std::string repr;
    std::string default_form = "hex";
    std::string applied_form;
    bool is_addr = false;
    uint64_t addr_val = 0;

    uint64_t value() const { return _value; }
};

struct cexpr_t;
struct cinsn_t;

struct citem_t {
    uint32_t obj_id = 0;
    ctype_t op = cot_empty;
    uint64_t ea = UINT64_MAX;
    int label_num = -1;
    std::string label_name;
    bool mutated = false;

    virtual ~citem_t() = default;
    bool is_expr() const { return ctype_is_expr(op); }
    cexpr_t *cexpr();
    const cexpr_t *cexpr() const;
    cinsn_t *cinsn();
    const cinsn_t *cinsn() const;
};

struct cexpr_t : public citem_t {
    std::string type_str;
    int ptrsize = 0;
    cexpr_t *x = nullptr;
    cexpr_t *y = nullptr;
    cexpr_t *z = nullptr;
    std::vector<cexpr_t *> a;
    var_ref_t v;
    cnumber_t n;
    uint64_t obj_ea = UINT64_MAX;
    std::string string;
    std::string helper;
    std::string text_cache;

    uint64_t numval() const { return n._value; }
    void mark_mutated() { mutated = true; text_cache.clear(); }
    std::string print1(const std::vector<lvar_t> *lvars = nullptr) const;
};

struct cblock_t {
    std::vector<cinsn_t *> statements;
    size_t size() const { return statements.size(); }
    bool empty() const { return statements.empty(); }
    void push_back(cinsn_t *s) { statements.push_back(s); }
};

struct cif_t {
    cexpr_t *expr = nullptr;
    cinsn_t *ithen = nullptr;
    cinsn_t *ielse = nullptr;
};

struct cloop_t {
    cexpr_t *expr = nullptr;
    cinsn_t *body = nullptr;
};

struct creturn_t {
    cexpr_t *expr = nullptr;
};

struct cgoto_t {
    int label_num = -1;
    std::string target_name;
};

struct cswitch_case_t {
    std::vector<int64_t> values;
    cinsn_t *body = nullptr;
};

struct cswitch_t {
    cexpr_t *expr = nullptr;
    std::vector<cswitch_case_t> cases;
    cinsn_t *def_body = nullptr;
};

struct cinsn_t : public citem_t {
    cblock_t cblock;
    cexpr_t *cexpr_node = nullptr;
    cif_t cif;
    cloop_t cloop;
    creturn_t creturn;
    cgoto_t cgoto;
    cswitch_t cswitch;
    std::string user_cmt;
    std::string text_cache;

    void mark_mutated() { mutated = true; text_cache.clear(); }
};

class ctree_visitor_t {
public:
    int cv_flags = RL78_CV_FAST;
    std::vector<citem_t *> parents;

    explicit ctree_visitor_t(int flags = RL78_CV_FAST) : cv_flags(flags) {}
    virtual ~ctree_visitor_t() = default;

    bool maintain_parents() const { return (cv_flags & RL78_CV_PARENTS) != 0; }
    bool must_prune()       const { return (cv_flags & RL78_CV_PRUNE) != 0; }
    bool must_restart()     const { return (cv_flags & RL78_CV_RESTART) != 0; }
    bool is_postorder()     const { return (cv_flags & RL78_CV_POST) != 0; }
    bool only_insns()       const { return (cv_flags & RL78_CV_INSNS) != 0; }

    void prune_now()   { cv_flags |= RL78_CV_PRUNE; }
    void clr_prune()   { cv_flags &= ~RL78_CV_PRUNE; }
    void set_restart() { cv_flags |= RL78_CV_RESTART; }
    void clr_restart() { cv_flags &= ~RL78_CV_RESTART; }

    citem_t *parent_item() { return parents.empty() ? nullptr : parents.back(); }
    cexpr_t *parent_expr() {
        citem_t *p = parent_item();
        return (p && p->is_expr()) ? p->cexpr() : nullptr;
    }
    cinsn_t *parent_insn() {
        citem_t *p = parent_item();
        return (p && !p->is_expr()) ? p->cinsn() : nullptr;
    }

    virtual int visit_insn(cinsn_t *)  { return 0; }
    virtual int visit_expr(cexpr_t *)  { return 0; }
    virtual int leave_insn(cinsn_t *)  { return 0; }
    virtual int leave_expr(cexpr_t *)  { return 0; }

    int apply_to(citem_t *item, citem_t *parent = nullptr);
    int apply_to_exprs(citem_t *item, citem_t *parent = nullptr);

private:
    int walk_item(citem_t *item, bool exprs_only);
};

struct LineConstSpan {
    int idx = 0;
    uint64_t ea = 0;
    uint64_t val = 0;
    int bits = 16;
    std::string text;
    std::string default_form = "hex";
    std::string form = "hex";
    bool applied = false;
    bool is_addr = false;
    uint64_t addr_val = 0;
    int col_start = 0;
    int col_end = 0;
    uint32_t citem_id = 0;
};

struct GlobalSymRef {
    uint32_t base_ea = 0;
    uint32_t item_size = 1;
    bool is_array = false;
    bool used_scalar = false;
    bool used_indexed = false;
    std::string struct_name;
};

struct cfunc_t {
    uint64_t entry_ea = 0;
    std::string func_name;
    std::string ret_type = "void";
    std::string signature_line;
    int hdrlines = 0;
    int sig_line = 0;
    bool hide_casts = false;
    int maturity = 7;

    std::vector<std::unique_ptr<citem_t>> treeitems;
    cinsn_t *body = nullptr;
    std::vector<lvar_t> lvars;
    std::unordered_map<uint64_t, std::vector<cinsn_t *>> eamap;

    std::vector<std::string> pseudocode_lines;
    std::vector<std::string> sv;
    std::vector<std::optional<uint64_t>> line_eas;
    std::unordered_map<int, std::vector<uint64_t>> line_to_eas;
    std::unordered_map<uint64_t, int> ea_to_line;
    std::unordered_map<int, std::vector<LineConstSpan>> line_consts;
    std::unordered_map<std::string, uint64_t> call_eas;
    std::unordered_map<std::string, uint64_t> sym_eas;
    std::map<std::string, GlobalSymRef> global_syms;
    std::set<std::string> used_udts;
    std::unordered_map<std::string, std::string> var_types;
    std::vector<std::string> arg_names;
    std::unordered_map<std::string, std::string> param_types;
    std::vector<int> argidx;

    cexpr_t *alloc_expr(ctype_t op, uint64_t ea = UINT64_MAX);
    cinsn_t *alloc_insn(ctype_t op, uint64_t ea = UINT64_MAX);
    citem_t *get_item(uint32_t obj_id) const {
        return (obj_id < treeitems.size()) ? treeitems[obj_id].get() : nullptr;
    }

    void recolorize(const std::string &highlight_ident = "");
    bool has_tree_mutations() const;
    void refresh_func_ctext();
    std::string print_func() const;
};

using cfuncptr_t = std::shared_ptr<cfunc_t>;

} // namespace rl78dec
