#include "rl78dec/ctree.hpp"
#include "rl78dec/highlight.hpp"

#include <algorithm>
#include <cstdio>
#include <sstream>

namespace rl78dec {

const char *ctype_name(ctype_t op) {
    switch (op) {
        case cot_empty:    return "empty";
        case cot_comma:    return "comma";
        case cot_asg:      return "asg";
        case cot_asgbor:   return "asgbor";
        case cot_asgxor:   return "asgxor";
        case cot_asgband:  return "asgband";
        case cot_asgadd:   return "asgadd";
        case cot_asgsub:   return "asgsub";
        case cot_asgmul:   return "asgmul";
        case cot_asgsshr:  return "asgsshr";
        case cot_asgushr:  return "asgushr";
        case cot_asgshl:   return "asgshl";
        case cot_asgsdiv:  return "asgsdiv";
        case cot_asgudiv:  return "asgudiv";
        case cot_asgsmod:  return "asgsmod";
        case cot_asgumod:  return "asgumod";
        case cot_tern:     return "tern";
        case cot_lor:      return "lor";
        case cot_land:     return "land";
        case cot_bor:      return "bor";
        case cot_xor:      return "xor";
        case cot_band:     return "band";
        case cot_eq:       return "eq";
        case cot_ne:       return "ne";
        case cot_sge:      return "sge";
        case cot_uge:      return "uge";
        case cot_sle:      return "sle";
        case cot_ule:      return "ule";
        case cot_sgt:      return "sgt";
        case cot_ugt:      return "ugt";
        case cot_slt:      return "slt";
        case cot_ult:      return "ult";
        case cot_sshr:     return "sshr";
        case cot_ushr:     return "ushr";
        case cot_shl:      return "shl";
        case cot_add:      return "add";
        case cot_sub:      return "sub";
        case cot_mul:      return "mul";
        case cot_sdiv:     return "sdiv";
        case cot_udiv:     return "udiv";
        case cot_smod:     return "smod";
        case cot_umod:     return "umod";
        case cot_fadd:     return "fadd";
        case cot_fsub:     return "fsub";
        case cot_fmul:     return "fmul";
        case cot_fdiv:     return "fdiv";
        case cot_fneg:     return "fneg";
        case cot_neg:      return "neg";
        case cot_cast:     return "cast";
        case cot_lnot:     return "lnot";
        case cot_bnot:     return "bnot";
        case cot_ptr:      return "ptr";
        case cot_ref:      return "ref";
        case cot_postinc:  return "postinc";
        case cot_postdec:  return "postdec";
        case cot_preinc:   return "preinc";
        case cot_predec:   return "predec";
        case cot_call:     return "call";
        case cot_idx:      return "idx";
        case cot_memref:   return "memref";
        case cot_memptr:   return "memptr";
        case cot_num:      return "num";
        case cot_fnum:     return "fnum";
        case cot_str:      return "str";
        case cot_obj:      return "obj";
        case cot_var:      return "var";
        case cot_insn:     return "insn";
        case cot_sizeof:   return "sizeof";
        case cot_helper:   return "helper";
        case cot_type:     return "type";
        case cit_empty:    return "cit_empty";
        case cit_block:    return "block";
        case cit_expr:     return "expr";
        case cit_if:       return "if";
        case cit_for:      return "for";
        case cit_while:    return "while";
        case cit_do:       return "do";
        case cit_switch:   return "switch";
        case cit_break:    return "break";
        case cit_continue: return "continue";
        case cit_return:   return "return";
        case cit_goto:     return "goto";
        case cit_asm:      return "asm";
        case cit_try:      return "try";
        case cit_throw:    return "throw";
        default:           return "unknown";
    }
}

ctype_t negated_relation(ctype_t op) {
    switch (op) {
        case cot_eq:  return cot_ne;
        case cot_ne:  return cot_eq;
        case cot_sge: return cot_slt;
        case cot_uge: return cot_ult;
        case cot_sle: return cot_sgt;
        case cot_ule: return cot_ugt;
        case cot_sgt: return cot_sle;
        case cot_ugt: return cot_ule;
        case cot_slt: return cot_sge;
        case cot_ult: return cot_uge;
        default:      return cot_empty;
    }
}

std::string lvar_locator_t::to_key() const {
    char buf[64];
    if (is_stk) {
        uint64_t mag = static_cast<uint64_t>(stk_off < 0 ? -stk_off : stk_off);
        if (defea != UINT64_MAX) {
            std::snprintf(buf, sizeof(buf), "stk:%s0x%llX@0x%llX",
                          (stk_off < 0 ? "-" : "+"),
                          static_cast<unsigned long long>(mag),
                          static_cast<unsigned long long>(defea));
        } else {
            std::snprintf(buf, sizeof(buf), "stk:%s0x%llX",
                          (stk_off < 0 ? "-" : "+"),
                          static_cast<unsigned long long>(mag));
        }
    } else {
        if (defea != UINT64_MAX) {
            std::snprintf(buf, sizeof(buf), "reg:%d@0x%llX", reg,
                          static_cast<unsigned long long>(defea));
        } else {
            std::snprintf(buf, sizeof(buf), "reg:%d", reg);
        }
    }
    return buf;
}

cexpr_t *citem_t::cexpr() { return is_expr() ? static_cast<cexpr_t *>(this) : nullptr; }
const cexpr_t *citem_t::cexpr() const { return is_expr() ? static_cast<const cexpr_t *>(this) : nullptr; }
cinsn_t *citem_t::cinsn() { return !is_expr() ? static_cast<cinsn_t *>(this) : nullptr; }
const cinsn_t *citem_t::cinsn() const { return !is_expr() ? static_cast<const cinsn_t *>(this) : nullptr; }

namespace {

bool subtree_mutated(const cexpr_t *e) {
    if (!e) return false;
    if (e->mutated) return true;
    if (subtree_mutated(e->x) || subtree_mutated(e->y) || subtree_mutated(e->z)) return true;
    for (const cexpr_t *arg : e->a) {
        if (subtree_mutated(arg)) return true;
    }
    return false;
}

const char *binary_op_str(ctype_t op) {
    switch (op) {
        case cot_comma:   return ", ";
        case cot_asg:     return " = ";
        case cot_asgbor:  return " |= ";
        case cot_asgxor:  return " ^= ";
        case cot_asgband: return " &= ";
        case cot_asgadd:  return " += ";
        case cot_asgsub:  return " -= ";
        case cot_asgmul:  return " *= ";
        case cot_asgsshr:
        case cot_asgushr: return " >>= ";
        case cot_asgshl:  return " <<= ";
        case cot_lor:     return " || ";
        case cot_land:    return " && ";
        case cot_bor:     return " | ";
        case cot_xor:     return " ^ ";
        case cot_band:    return " & ";
        case cot_eq:      return " == ";
        case cot_ne:      return " != ";
        case cot_sge:
        case cot_uge:     return " >= ";
        case cot_sle:
        case cot_ule:     return " <= ";
        case cot_sgt:
        case cot_ugt:     return " > ";
        case cot_slt:
        case cot_ult:     return " < ";
        case cot_sshr:
        case cot_ushr:    return " >> ";
        case cot_shl:     return " << ";
        case cot_add:
        case cot_fadd:    return " + ";
        case cot_sub:
        case cot_fsub:    return " - ";
        case cot_mul:
        case cot_fmul:    return " * ";
        case cot_sdiv:
        case cot_udiv:
        case cot_fdiv:    return " / ";
        case cot_smod:
        case cot_umod:    return " % ";
        default:          return nullptr;
    }
}

void emit_insn_lines(const cinsn_t *ins, const std::vector<lvar_t> &lvars,
                     int indent, std::vector<std::string> &out,
                     std::vector<std::optional<uint64_t>> &line_eas) {
    if (!ins) return;
    std::string pad(static_cast<size_t>(indent) * 4, ' ');
    std::optional<uint64_t> ea_opt = (ins->ea != UINT64_MAX) ? std::optional<uint64_t>(ins->ea) : std::nullopt;

    if (ins->label_num >= 0 && !ins->label_name.empty()) {
        std::string lpad(static_cast<size_t>(indent > 0 ? indent - 1 : 0) * 4, ' ');
        out.push_back(lpad + ins->label_name + ":");
        line_eas.push_back(ea_opt);
    }

    auto append_cmt = [&](std::string s) -> std::string {
        if (!ins->user_cmt.empty()) s += "   // " + ins->user_cmt;
        return s;
    };

    switch (ins->op) {
        case cit_block:
            for (const cinsn_t *st : ins->cblock.statements) {
                emit_insn_lines(st, lvars, indent, out, line_eas);
            }
            break;
        case cit_expr: {
            std::string body = (!ins->mutated && !subtree_mutated(ins->cexpr_node) && !ins->text_cache.empty())
                                   ? ins->text_cache
                                   : (ins->cexpr_node ? (ins->cexpr_node->print1(&lvars) + ";") : ";");
            out.push_back(append_cmt(pad + body));
            line_eas.push_back(ea_opt);
            break;
        }
        case cit_if: {
            std::string cstr = ins->cif.expr ? ins->cif.expr->print1(&lvars) : "1";
            out.push_back(append_cmt(pad + "if (" + cstr + ")"));
            line_eas.push_back(ea_opt);
            out.push_back(pad + "{");
            line_eas.push_back(std::nullopt);
            if (ins->cif.ithen) emit_insn_lines(ins->cif.ithen, lvars, indent + 1, out, line_eas);
            out.push_back(pad + "}");
            line_eas.push_back(std::nullopt);
            if (ins->cif.ielse) {
                out.push_back(pad + "else");
                line_eas.push_back(std::nullopt);
                out.push_back(pad + "{");
                line_eas.push_back(std::nullopt);
                emit_insn_lines(ins->cif.ielse, lvars, indent + 1, out, line_eas);
                out.push_back(pad + "}");
                line_eas.push_back(std::nullopt);
            }
            break;
        }
        case cit_while: {
            std::string cstr = ins->cloop.expr ? ins->cloop.expr->print1(&lvars) : "1";
            out.push_back(append_cmt(pad + "while (" + cstr + ")"));
            line_eas.push_back(ea_opt);
            out.push_back(pad + "{");
            line_eas.push_back(std::nullopt);
            if (ins->cloop.body) emit_insn_lines(ins->cloop.body, lvars, indent + 1, out, line_eas);
            out.push_back(pad + "}");
            line_eas.push_back(std::nullopt);
            break;
        }
        case cit_do: {
            out.push_back(pad + "do");
            line_eas.push_back(ea_opt);
            out.push_back(pad + "{");
            line_eas.push_back(std::nullopt);
            if (ins->cloop.body) emit_insn_lines(ins->cloop.body, lvars, indent + 1, out, line_eas);
            std::string cstr = ins->cloop.expr ? ins->cloop.expr->print1(&lvars) : "1";
            out.push_back(append_cmt(pad + "} while (" + cstr + ");"));
            line_eas.push_back(ea_opt);
            break;
        }
        case cit_for: {
            out.push_back(append_cmt(pad + "for (;;)"));
            line_eas.push_back(ea_opt);
            out.push_back(pad + "{");
            line_eas.push_back(std::nullopt);
            if (ins->cloop.body) emit_insn_lines(ins->cloop.body, lvars, indent + 1, out, line_eas);
            out.push_back(pad + "}");
            line_eas.push_back(std::nullopt);
            break;
        }
        case cit_switch: {
            std::string estr = ins->cswitch.expr ? ins->cswitch.expr->print1(&lvars) : "0";
            out.push_back(append_cmt(pad + "switch (" + estr + ")"));
            line_eas.push_back(ea_opt);
            out.push_back(pad + "{");
            line_eas.push_back(std::nullopt);
            for (const auto &sc : ins->cswitch.cases) {
                for (int64_t val : sc.values) {
                    out.push_back(pad + "case " + std::to_string(val) + ":");
                    line_eas.push_back(std::nullopt);
                }
                if (sc.body) emit_insn_lines(sc.body, lvars, indent + 1, out, line_eas);
                out.push_back(pad + "    break;");
                line_eas.push_back(std::nullopt);
            }
            if (ins->cswitch.def_body) {
                out.push_back(pad + "default:");
                line_eas.push_back(std::nullopt);
                emit_insn_lines(ins->cswitch.def_body, lvars, indent + 1, out, line_eas);
                out.push_back(pad + "    break;");
                line_eas.push_back(std::nullopt);
            }
            out.push_back(pad + "}");
            line_eas.push_back(std::nullopt);
            break;
        }
        case cit_break:
            out.push_back(append_cmt(pad + "break;"));
            line_eas.push_back(ea_opt);
            break;
        case cit_continue:
            out.push_back(append_cmt(pad + "continue;"));
            line_eas.push_back(ea_opt);
            break;
        case cit_goto: {
            std::string g = (!ins->mutated && !ins->text_cache.empty())
                                ? ins->text_cache
                                : ("goto " + ins->cgoto.target_name + ";");
            out.push_back(append_cmt(pad + g));
            line_eas.push_back(ea_opt);
            break;
        }
        case cit_return: {
            std::string r;
            if (!ins->mutated && !subtree_mutated(ins->creturn.expr) && !ins->text_cache.empty()) {
                r = ins->text_cache;
            } else if (ins->creturn.expr) {
                r = "return " + ins->creturn.expr->print1(&lvars) + ";";
            } else {
                r = "return;";
            }
            out.push_back(append_cmt(pad + r));
            line_eas.push_back(ea_opt);
            break;
        }
        default:
            if (!ins->text_cache.empty()) {
                out.push_back(append_cmt(pad + ins->text_cache));
                line_eas.push_back(ea_opt);
            }
            break;
    }
}

} // namespace

std::string cexpr_t::print1(const std::vector<lvar_t> *lvars) const {
    if (!subtree_mutated(this) && !text_cache.empty()) {
        return text_cache;
    }
    switch (op) {
        case cot_num: {
            if (!mutated && !n.repr.empty()) return n.repr;
            char buf[48];
            std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(n._value));
            return buf;
        }
        case cot_str:
            return string;
        case cot_var:
            if (lvars && v.idx >= 0 && static_cast<size_t>(v.idx) < lvars->size()) {
                return (*lvars)[static_cast<size_t>(v.idx)].name;
            }
            return helper.empty() ? "v" : helper;
        case cot_obj:
            if (!helper.empty()) return helper;
            if (obj_ea != UINT64_MAX) {
                char buf[32];
                std::snprintf(buf, sizeof(buf), "sub_%llX", static_cast<unsigned long long>(obj_ea));
                return buf;
            }
            return "obj";
        case cot_helper:
            return helper;
        case cot_call: {
            std::string callee = x ? x->print1(lvars) : helper;
            std::string s = callee + "(";
            for (size_t i = 0; i < a.size(); ++i) {
                if (i > 0) s += ", ";
                if (a[i]) s += a[i]->print1(lvars);
            }
            s += ")";
            return s;
        }
        case cot_cast: {
            std::string inner = x ? x->print1(lvars) : "";
            if (type_str.empty()) return inner;
            return "(" + type_str + ")" + inner;
        }
        case cot_ptr: {
            std::string inner = x ? x->print1(lvars) : "";
            if (!type_str.empty()) {
                return "*(" + type_str + " *)(" + inner + ")";
            }
            return "*" + inner;
        }
        case cot_ref:
            return "&" + (x ? x->print1(lvars) : "");
        case cot_neg:
        case cot_fneg:
            return "-" + (x ? x->print1(lvars) : "");
        case cot_lnot:
            return "!(" + (x ? x->print1(lvars) : "") + ")";
        case cot_bnot:
            return "~" + (x ? x->print1(lvars) : "");
        case cot_idx:
            return (x ? x->print1(lvars) : "") + "[" + (y ? y->print1(lvars) : "0") + "]";
        case cot_memref:
            return (x ? x->print1(lvars) : "") + "." + string;
        case cot_memptr:
            return (x ? x->print1(lvars) : "") + "->" + string;
        case cot_tern:
            return (x ? x->print1(lvars) : "") + " ? " +
                   (y ? y->print1(lvars) : "") + " : " +
                   (z ? z->print1(lvars) : "");
        default: {
            const char *bop = binary_op_str(op);
            if (bop) {
                std::string lhs = x ? x->print1(lvars) : "";
                std::string rhs = y ? y->print1(lvars) : "";
                return lhs + bop + rhs;
            }
            return text_cache;
        }
    }
}

int ctree_visitor_t::walk_item(citem_t *item, bool exprs_only) {
    if (!item) return 0;
    clr_prune();

    int rc = 0;
    if (item->is_expr()) {
        if (only_insns()) return 0;
        cexpr_t *e = item->cexpr();
        rc = visit_expr(e);
        if (rc != 0) return rc;
        if (!must_prune()) {
            if (maintain_parents()) parents.push_back(item);
            if (e->x) { rc = walk_item(e->x, exprs_only); if (rc != 0) { if (maintain_parents()) parents.pop_back(); return rc; } }
            if (e->y) { rc = walk_item(e->y, exprs_only); if (rc != 0) { if (maintain_parents()) parents.pop_back(); return rc; } }
            if (e->z) { rc = walk_item(e->z, exprs_only); if (rc != 0) { if (maintain_parents()) parents.pop_back(); return rc; } }
            for (cexpr_t *arg : e->a) {
                if (arg) {
                    rc = walk_item(arg, exprs_only);
                    if (rc != 0) {
                        if (maintain_parents()) parents.pop_back();
                        return rc;
                    }
                }
            }
            if (maintain_parents()) parents.pop_back();
        } else {
            clr_prune();
        }
        if (is_postorder()) {
            rc = leave_expr(e);
            if (rc != 0) return rc;
        }
    } else {
        cinsn_t *i = item->cinsn();
        if (!exprs_only) {
            rc = visit_insn(i);
            if (rc != 0) return rc;
        }
        if (!must_prune()) {
            if (maintain_parents()) parents.push_back(item);
            switch (i->op) {
                case cit_block:
                    for (cinsn_t *st : i->cblock.statements) {
                        rc = walk_item(st, exprs_only);
                        if (rc != 0) { if (maintain_parents()) parents.pop_back(); return rc; }
                    }
                    break;
                case cit_expr:
                    if (i->cexpr_node) rc = walk_item(i->cexpr_node, exprs_only);
                    break;
                case cit_if:
                    if (i->cif.expr)  rc = walk_item(i->cif.expr, exprs_only);
                    if (rc == 0 && i->cif.ithen) rc = walk_item(i->cif.ithen, exprs_only);
                    if (rc == 0 && i->cif.ielse) rc = walk_item(i->cif.ielse, exprs_only);
                    break;
                case cit_while:
                case cit_do:
                case cit_for:
                    if (i->cloop.expr) rc = walk_item(i->cloop.expr, exprs_only);
                    if (rc == 0 && i->cloop.body) rc = walk_item(i->cloop.body, exprs_only);
                    break;
                case cit_switch:
                    if (i->cswitch.expr) rc = walk_item(i->cswitch.expr, exprs_only);
                    for (const auto &sc : i->cswitch.cases) {
                        if (rc == 0 && sc.body) rc = walk_item(sc.body, exprs_only);
                    }
                    if (rc == 0 && i->cswitch.def_body) rc = walk_item(i->cswitch.def_body, exprs_only);
                    break;
                case cit_return:
                    if (i->creturn.expr) rc = walk_item(i->creturn.expr, exprs_only);
                    break;
                default:
                    break;
            }
            if (maintain_parents()) parents.pop_back();
            if (rc != 0) return rc;
        } else {
            clr_prune();
        }
        if (!exprs_only && is_postorder()) {
            rc = leave_insn(i);
            if (rc != 0) return rc;
        }
    }
    return 0;
}

int ctree_visitor_t::apply_to(citem_t *item, citem_t *parent) {
    parents.clear();
    if (parent && maintain_parents()) parents.push_back(parent);
    return walk_item(item, false);
}

int ctree_visitor_t::apply_to_exprs(citem_t *item, citem_t *parent) {
    do {
        clr_restart();
        parents.clear();
        if (parent && maintain_parents()) parents.push_back(parent);
        int rc = walk_item(item, true);
        if (rc != 0) return rc;
    } while (must_restart());
    return 0;
}

cexpr_t *cfunc_t::alloc_expr(ctype_t op, uint64_t ea) {
    auto node = std::make_unique<cexpr_t>();
    node->obj_id = static_cast<uint32_t>(treeitems.size());
    node->op = op;
    node->ea = ea;
    cexpr_t *ptr = node.get();
    treeitems.push_back(std::move(node));
    return ptr;
}

cinsn_t *cfunc_t::alloc_insn(ctype_t op, uint64_t ea) {
    auto node = std::make_unique<cinsn_t>();
    node->obj_id = static_cast<uint32_t>(treeitems.size());
    node->op = op;
    node->ea = ea;
    cinsn_t *ptr = node.get();
    treeitems.push_back(std::move(node));
    if (ea != UINT64_MAX) {
        eamap[ea].push_back(ptr);
    }
    return ptr;
}

void cfunc_t::recolorize(const std::string &highlight_ident) {
    sv.clear();
    sv.reserve(pseudocode_lines.size());
    for (size_t i = 0; i < pseudocode_lines.size(); ++i) {
        std::string col = colorize_c_line(pseudocode_lines[i], highlight_ident);
        if (i < line_eas.size() && line_eas[i].has_value()) {
            col = make_color_addr_tag(*line_eas[i]) + col;
        }
        sv.push_back(std::move(col));
    }
}

bool cfunc_t::has_tree_mutations() const {
    for (const auto &it : treeitems) {
        if (it && it->mutated) return true;
    }
    return false;
}

void cfunc_t::refresh_func_ctext() {
    if (!body) {
        recolorize();
        return;
    }
    std::vector<std::string> new_lines;
    std::vector<std::optional<uint64_t>> new_eas;
    size_t keep_hdr = std::min(static_cast<size_t>(hdrlines), pseudocode_lines.size());
    for (size_t i = 0; i < keep_hdr; ++i) {
        new_lines.push_back(pseudocode_lines[i]);
        new_eas.push_back(i < line_eas.size() ? line_eas[i] : std::nullopt);
    }
    emit_insn_lines(body, lvars, 1, new_lines, new_eas);
    new_lines.push_back("}");
    new_eas.push_back(std::nullopt);

    pseudocode_lines = std::move(new_lines);
    line_eas = std::move(new_eas);
    recolorize();
}

std::string cfunc_t::print_func() const {
    std::ostringstream os;
    for (size_t i = 0; i < pseudocode_lines.size(); ++i) {
        if (i > 0) os << '\n';
        os << pseudocode_lines[i];
    }
    return os.str();
}

} // namespace rl78dec
