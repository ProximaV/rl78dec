#include "rl78dec/ir.hpp"

#include <atomic>
#include <cstdio>
#include <unordered_set>

namespace rl78dec {

namespace {

std::atomic<uint64_t> g_stmt_id_counter{1};

uint32_t mask_for_width(uint32_t val, Width w) {
    switch (w) {
        case Width::B: return val & 0xFFu;
        case Width::W: return val & 0xFFFFu;
        case Width::A: return val & 0xFFFFFu;
        case Width::D: return val;
    }
    return val & 0xFFu;
}

} // namespace

ExprPtr Expr::make_const(uint32_t val, Width w, std::string sym_name) {
    auto e = std::make_shared<Expr>();
    e->kind = ExprKind::Const;
    e->width = w;
    e->value = mask_for_width(val, w);
    e->name = std::move(sym_name);
    return e;
}

ExprPtr Expr::make_reg(const std::string &rname, std::optional<Width> w) {
    auto e = std::make_shared<Expr>();
    e->kind = ExprKind::Reg;
    e->name = rname;
    if (w.has_value()) {
        e->width = *w;
    } else {
        RegId id = reg_from_name(rname);
        e->width = (id != RegId::None) ? reg_default_width(id) : Width::B;
    }
    return e;
}

ExprPtr Expr::make_var(const std::string &vname, Width w) {
    auto e = std::make_shared<Expr>();
    e->kind = ExprKind::Var;
    e->name = vname;
    e->width = w;
    return e;
}

ExprPtr Expr::make_stack_var(const std::string &vname, Width w, int64_t off, bool arg) {
    auto e = std::make_shared<Expr>();
    e->kind = ExprKind::StackVar;
    e->name = vname;
    e->width = w;
    e->offset = off;
    e->is_arg = arg;
    return e;
}

ExprPtr Expr::make_mem_addr(ExprPtr addr_expr, Width w, bool is_es, std::string sym_name, bool linear) {
    auto e = std::make_shared<Expr>();
    e->kind = ExprKind::Mem;
    e->addr = std::move(addr_expr);
    e->has_static_addr = false;
    e->width = w;
    e->es = is_es;
    e->addr_is_linear = linear;
    e->name = std::move(sym_name);
    return e;
}

ExprPtr Expr::make_mem_abs(uint32_t abs_addr, Width w, bool is_es, std::string sym_name, bool linear) {
    auto e = std::make_shared<Expr>();
    e->kind = ExprKind::Mem;
    e->static_addr = abs_addr;
    e->has_static_addr = true;
    e->width = w;
    e->es = is_es;
    e->addr_is_linear = linear;
    e->name = std::move(sym_name);
    return e;
}

ExprPtr Expr::make_bit(ExprPtr base_expr, uint8_t bit_idx) {
    auto e = std::make_shared<Expr>();
    e->kind = ExprKind::Bit;
    e->base = std::move(base_expr);
    e->bit = bit_idx;
    e->width = Width::B;
    return e;
}

ExprPtr Expr::make_bin(std::string op_str, ExprPtr lhs, ExprPtr rhs, Width w) {
    auto e = std::make_shared<Expr>();
    e->kind = ExprKind::Bin;
    e->op = std::move(op_str);
    e->l = std::move(lhs);
    e->r = std::move(rhs);
    e->width = w;
    return e;
}

ExprPtr Expr::make_un(std::string op_str, ExprPtr operand, Width w) {
    auto e = std::make_shared<Expr>();
    e->kind = ExprKind::Un;
    e->op = std::move(op_str);
    e->l = std::move(operand);
    e->width = w;
    return e;
}

ExprPtr Expr::make_intr(std::string intr_name, std::vector<ExprPtr> intr_args, Width w) {
    auto e = std::make_shared<Expr>();
    e->kind = ExprKind::Intr;
    e->name = std::move(intr_name);
    e->args = std::move(intr_args);
    e->width = w;
    return e;
}

bool expr_eq(const ExprPtr &a, const ExprPtr &b) {
    if (a.get() == b.get()) return true;
    if (!a || !b || a->kind != b->kind) return false;
    switch (a->kind) {
        case ExprKind::Const:
            return a->value == b->value && a->width == b->width && a->name == b->name;
        case ExprKind::Reg:
        case ExprKind::Var:
            return a->name == b->name;
        case ExprKind::StackVar:
            return a->name == b->name && a->offset == b->offset;
        case ExprKind::Mem:
            if (a->width != b->width || a->es != b->es || a->name != b->name ||
                a->has_static_addr != b->has_static_addr) {
                return false;
            }
            return a->has_static_addr ? (a->static_addr == b->static_addr) : expr_eq(a->addr, b->addr);
        case ExprKind::Bit:
            return a->bit == b->bit && expr_eq(a->base, b->base);
        case ExprKind::Bin:
            return a->op == b->op && expr_eq(a->l, b->l) && expr_eq(a->r, b->r);
        case ExprKind::Un:
            return a->op == b->op && expr_eq(a->l, b->l);
        case ExprKind::Intr:
            if (a->name != b->name || a->args.size() != b->args.size()) return false;
            for (size_t i = 0; i < a->args.size(); ++i) {
                if (!expr_eq(a->args[i], b->args[i])) return false;
            }
            return true;
    }
    return false;
}

size_t expr_hash(const ExprPtr &e) {
    if (!e) return 0;
    size_t h = std::hash<int>{}(static_cast<int>(e->kind));
    auto mix = [&](size_t v) { h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2); };
    switch (e->kind) {
        case ExprKind::Const:
            mix(e->value);
            mix(static_cast<size_t>(e->width));
            mix(std::hash<std::string>{}(e->name));
            break;
        case ExprKind::Reg:
        case ExprKind::Var:
            mix(std::hash<std::string>{}(e->name));
            break;
        case ExprKind::StackVar:
            mix(std::hash<std::string>{}(e->name));
            mix(static_cast<size_t>(e->offset));
            break;
        case ExprKind::Mem:
            mix(static_cast<size_t>(e->width));
            mix(e->es ? 1u : 0u);
            mix(e->has_static_addr ? e->static_addr : expr_hash(e->addr));
            break;
        case ExprKind::Bit:
            mix(e->bit);
            mix(expr_hash(e->base));
            break;
        case ExprKind::Bin:
            mix(std::hash<std::string>{}(e->op));
            mix(expr_hash(e->l));
            mix(expr_hash(e->r));
            break;
        case ExprKind::Un:
            mix(std::hash<std::string>{}(e->op));
            mix(expr_hash(e->l));
            break;
        case ExprKind::Intr:
            mix(std::hash<std::string>{}(e->name));
            for (const auto &a : e->args) mix(expr_hash(a));
            break;
    }
    return h;
}

ExprPtr expr_clone(const ExprPtr &e) {
    if (!e) return nullptr;
    auto c = std::make_shared<Expr>(*e);
    if (e->addr) c->addr = expr_clone(e->addr);
    if (e->base) c->base = expr_clone(e->base);
    if (e->l) c->l = expr_clone(e->l);
    if (e->r) c->r = expr_clone(e->r);
    c->args.clear();
    c->args.reserve(e->args.size());
    for (const auto &a : e->args) c->args.push_back(expr_clone(a));
    return c;
}

StmtPtr Stmt::alloc(StmtKind k, uint32_t ea_val) {
    auto s = std::make_shared<Stmt>();
    s->id = g_stmt_id_counter.fetch_add(1, std::memory_order_relaxed);
    s->kind = k;
    s->ea = ea_val;
    return s;
}

StmtPtr make_assign(uint32_t ea, ExprPtr dst, ExprPtr src, FlagDefPtr zf, FlagDefPtr cyf) {
    auto s = Stmt::alloc(StmtKind::Assign, ea);
    s->dst = std::move(dst);
    s->src = std::move(src);
    s->z_flag = std::move(zf);
    s->cy_flag = std::move(cyf);
    return s;
}

StmtPtr make_swap(uint32_t ea, ExprPtr a, ExprPtr b) {
    auto s = Stmt::alloc(StmtKind::Swap, ea);
    s->a = std::move(a);
    s->b = std::move(b);
    return s;
}

StmtPtr make_compare(uint32_t ea, FlagDefPtr zf, FlagDefPtr cyf) {
    auto s = Stmt::alloc(StmtKind::Compare, ea);
    s->z_flag = std::move(zf);
    s->cy_flag = cyf ? std::move(cyf) : clone_flag(s->z_flag);
    return s;
}

StmtPtr make_call(uint32_t ea, std::optional<uint32_t> target, ExprPtr expr) {
    auto s = Stmt::alloc(StmtKind::Call, ea);
    s->target = target;
    s->expr = std::move(expr);
    return s;
}

StmtPtr make_intrinsic(uint32_t ea, std::string name, std::vector<ExprPtr> args, std::string note) {
    auto s = Stmt::alloc(StmtKind::Intrinsic, ea);
    s->name = std::move(name);
    s->args = std::move(args);
    s->note = std::move(note);
    return s;
}

StmtPtr make_ret(uint32_t ea, std::string kind, ExprPtr val) {
    auto s = Stmt::alloc(StmtKind::Ret, ea);
    s->ret_kind = std::move(kind);
    s->val = std::move(val);
    return s;
}

StmtPtr make_goto(uint32_t ea, uint32_t target) {
    auto s = Stmt::alloc(StmtKind::Goto, ea);
    s->goto_target = target;
    return s;
}

StmtPtr make_branch(uint32_t ea, std::string cond, uint32_t target, uint32_t fall) {
    auto s = Stmt::alloc(StmtKind::Branch, ea);
    s->cond = std::move(cond);
    s->branch_target = target;
    s->fallthrough = fall;
    return s;
}

StmtPtr make_bittest_branch(uint32_t ea, ExprPtr bit_expr, bool sense, uint32_t target, uint32_t fall, bool btclr) {
    auto s = Stmt::alloc(StmtKind::Branch, ea);
    s->has_bittest = true;
    s->bittest_expr = std::move(bit_expr);
    s->bittest_sense = sense;
    s->btclr_clear = btclr;
    s->branch_target = target;
    s->fallthrough = fall;
    return s;
}

StmtPtr make_nop(uint32_t ea) {
    return Stmt::alloc(StmtKind::Nop, ea);
}

StmtPtr make_switch(uint32_t ea, ExprPtr expr, std::map<int64_t, std::optional<uint32_t>> cases,
                    std::optional<uint32_t> def_ea, std::optional<uint32_t> tbl_ea) {
    auto s = Stmt::alloc(StmtKind::Switch, ea);
    s->expr = std::move(expr);
    s->cases = std::move(cases);
    s->default_ea = def_ea;
    s->table_ea = tbl_ea;
    return s;
}

std::string FunctionSig::format_signature(const std::string &override_name) const {
    const std::string &nm = !override_name.empty() ? override_name : (!name.empty() ? name : "sub_unknown");
    std::string pstr;
    if (params.empty()) {
        pstr = "void";
    } else {
        for (size_t i = 0; i < params.size(); ++i) {
            if (i > 0) pstr += ", ";
            const auto &p = params[i];
            pstr += p.type_str;
            if (!p.type_str.empty() && p.type_str.back() != '*') pstr += " ";
            pstr += p.name;
        }
    }
    return ret_type + " " + nm + "(" + pstr + ")";
}

std::optional<std::string> FrameInfo::describe() const {
    std::string out;
    if (frame_size > 0) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "frame 0x%X", frame_size);
        out += buf;
    }
    if (!saved_regs.empty()) {
        if (!out.empty()) out += "; ";
        out += "saved ";
        for (size_t i = 0; i < saved_regs.size(); ++i) {
            if (i > 0) out += ", ";
            out += saved_regs[i];
        }
    }
    if (out.empty()) return std::nullopt;
    return out;
}

std::string format_ir_expr(const ExprPtr &e) {
    if (!e) return "<null>";
    char buf[48];
    switch (e->kind) {
        case ExprKind::Const:
            if (!e->name.empty()) return e->name;
            if (e->value >= 10) {
                std::snprintf(buf, sizeof(buf), "0x%X", e->value);
                return buf;
            }
            return std::to_string(e->value);
        case ExprKind::Reg:
        case ExprKind::Var:
        case ExprKind::StackVar:
            return e->name;
        case ExprKind::Mem:
            if (e->has_static_addr) {
                std::snprintf(buf, sizeof(buf), "%smem%s[0x%X]", e->es ? "es_" : "",
                              e->width == Width::W ? "16" : "8", e->static_addr);
                return buf;
            }
            return std::string(e->es ? "es_mem" : "mem") + (e->width == Width::W ? "16[" : "8[") +
                   format_ir_expr(e->addr) + "]";
        case ExprKind::Bit:
            return format_ir_expr(e->base) + "." + std::to_string(e->bit);
        case ExprKind::Bin:
            return "(" + format_ir_expr(e->l) + " " + e->op + " " + format_ir_expr(e->r) + ")";
        case ExprKind::Un:
            return e->op + format_ir_expr(e->l);
        case ExprKind::Intr: {
            std::string s = e->name + "(";
            for (size_t i = 0; i < e->args.size(); ++i) {
                if (i > 0) s += ", ";
                s += format_ir_expr(e->args[i]);
            }
            return s + ")";
        }
    }
    return "?";
}

std::string format_ir_stmt(const Stmt &s) {
    char buf[64];
    switch (s.kind) {
        case StmtKind::Assign:
            return format_ir_expr(s.dst) + " = " + format_ir_expr(s.src);
        case StmtKind::Swap:
            return "swap(" + format_ir_expr(s.a) + ", " + format_ir_expr(s.b) + ")";
        case StmtKind::Compare:
            return "cmp(...)";
        case StmtKind::Call: {
            std::string r;
            if (s.dst) r += format_ir_expr(s.dst) + " = ";
            if (s.target.has_value()) {
                std::snprintf(buf, sizeof(buf), "sub_%X(", *s.target);
                r += buf;
            } else {
                r += "(*" + format_ir_expr(s.expr) + ")(";
            }
            for (size_t i = 0; i < s.args.size(); ++i) {
                if (i > 0) r += ", ";
                r += format_ir_expr(s.args[i]);
            }
            return r + ")";
        }
        case StmtKind::Intrinsic: {
            std::string r = s.name + "(";
            for (size_t i = 0; i < s.args.size(); ++i) {
                if (i > 0) r += ", ";
                r += format_ir_expr(s.args[i]);
            }
            return r + ")";
        }
        case StmtKind::Ret:
            if (s.val) return s.ret_kind + " " + format_ir_expr(s.val);
            return s.ret_kind;
        case StmtKind::Goto:
            std::snprintf(buf, sizeof(buf), "goto loc_%X", s.goto_target);
            return buf;
        case StmtKind::Branch:
            if (s.has_bittest) {
                std::snprintf(buf, sizeof(buf), "if (%s%s)%s goto loc_%X",
                              s.bittest_sense ? "" : "!", format_ir_expr(s.bittest_expr).c_str(),
                              s.btclr_clear ? " /*btclr*/" : "", s.branch_target);
                return buf;
            }
            std::snprintf(buf, sizeof(buf), "if (%s) goto loc_%X", s.cond.c_str(), s.branch_target);
            return buf;
        case StmtKind::Nop:
            return "nop";
        case StmtKind::Switch:
            return "switch (" + format_ir_expr(s.expr) + ")";
    }
    return "?";
}

std::vector<std::pair<std::string, std::optional<uint32_t>>> format_ir_lines(const Function &func) {
    std::vector<std::pair<std::string, std::optional<uint32_t>>> lines;
    std::string fnm = !func.name.empty() ? func.name : "function";
    lines.emplace_back("// Lifted SSA/IR for " + fnm, func.entry);
    for (const auto &b : func.ordered()) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "block_%X:", b->start);
        lines.emplace_back(buf, b->start);
        for (const auto &s : b->stmts) {
            lines.emplace_back("    " + format_ir_stmt(*s), s->ea);
        }
    }
    return lines;
}

bool verify_ir(Function &func) {
    func.problems.clear();
    if (func.blocks.empty()) {
        func.problems.push_back("Function has 0 basic blocks");
        return false;
    }
    if (func.blocks.find(func.entry) == func.blocks.end()) {
        func.problems.push_back("Missing entry block");
    }
    for (const auto &[bid, blk] : func.blocks) {
        if (!blk) {
            func.problems.push_back("Null block pointer");
            continue;
        }
        if (blk->start != bid) {
            func.problems.push_back("Block key/start mismatch");
        }
        for (const auto &s : blk->stmts) {
            if (!s) {
                func.problems.push_back("Null statement in block");
                continue;
            }
            if (s->kind == StmtKind::Assign && (!s->dst || !s->src)) {
                func.problems.push_back("Assign missing dst or src");
            } else if (s->kind == StmtKind::Swap && (!s->a || !s->b)) {
                func.problems.push_back("Swap missing operand");
            } else if (s->kind == StmtKind::Call && !s->target.has_value() && !s->expr) {
                func.problems.push_back("Indirect Call missing expr");
            } else if (s->kind == StmtKind::Branch && s->has_bittest && !s->bittest_expr) {
                func.problems.push_back("Bit-test Branch missing bit expr");
            }
        }
    }
    return func.problems.empty();
}

} // namespace rl78dec
