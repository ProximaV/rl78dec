#include "rl78dec/cgen.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include "rl78dec/highlight.hpp"
#include "rl78dec/sfr.hpp"

namespace rl78dec {

namespace {

std::string width_ctype(Width w) {
    switch (w) {
        case Width::B: return "uint8_t";
        case Width::W: return "uint16_t";
        case Width::A:
        case Width::D: return "uint32_t";
    }
    return "uint16_t";
}

int width_bits(Width w) {
    switch (w) {
        case Width::B: return 8;
        case Width::W: return 16;
        case Width::A: return 20;
        case Width::D: return 32;
    }
    return 16;
}

std::string format_hex(uint64_t val, int bits) {
    char buf[32];
    if (bits <= 8)       std::snprintf(buf, sizeof(buf), "0x%02llX", static_cast<unsigned long long>(val & 0xFFu));
    else if (bits <= 16) std::snprintf(buf, sizeof(buf), "0x%04llX", static_cast<unsigned long long>(val & 0xFFFFu));
    else                 std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(val));
    return buf;
}

std::string format_num_with_form(uint64_t val, int bits, const std::string &form) {
    if (form == "dec") {
        return std::to_string(val);
    }
    if (form == "udec") {
        return std::to_string(val) + "U";
    }
    if (form == "sdec") {
        if (bits == 8)  return std::to_string(static_cast<int8_t>(val & 0xFFu));
        if (bits == 16) return std::to_string(static_cast<int16_t>(val & 0xFFFFu));
        return std::to_string(static_cast<int32_t>(val & 0xFFFFFFFFu));
    }
    if (form == "char") {
        unsigned ch = static_cast<unsigned>(val & 0xFFu);
        if (ch >= 0x20 && ch < 0x7F && ch != '\'' && ch != '\\') {
            return std::string("'") + static_cast<char>(ch) + "'";
        }
    }
    if (form == "bin") {
        std::string s = "0b";
        int b = (bits <= 8) ? 8 : ((bits <= 16) ? 16 : 32);
        for (int i = b - 1; i >= 0; --i) s.push_back(((val >> i) & 1u) ? '1' : '0');
        return s;
    }
    return format_hex(val, bits);
}

std::string label_name_for(uint32_t ea) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "loc_%X", ea);
    return buf;
}

std::string sanitize_c_ident(const std::string &raw, const char *fallback = "sym") {
    if (raw.empty()) return fallback;
    std::string out;
    out.reserve(raw.size() + 2);
    for (unsigned char c : raw) {
        if (std::isalnum(c) || c == '_') out.push_back(static_cast<char>(c));
        else out.push_back('_');
    }
    if (out.empty()) return fallback;
    if (std::isdigit(static_cast<unsigned char>(out[0]))) out.insert(out.begin(), '_');
    // Avoid colliding with C keywords
    static const char *const kKw[] = {
        "auto", "break", "case", "char", "const", "continue", "default", "do", "double",
        "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long",
        "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct",
        "switch", "typedef", "union", "unsigned", "void", "volatile", "while"
    };
    for (const char *kw : kKw) {
        if (out == kw) { out.push_back('_'); break; }
    }
    return out;
}

bool is_reserved_c_lib_ident(const std::string &s) {
    static const std::unordered_set<std::string> kReserved = {
        "es", "cs", "psw", "CY", "ZF", "HF", "mem8", "es_mem8", "g_rl78_mem",
        "NULL", "size_t", "ptrdiff_t", "wchar_t", "bool", "true", "false",
        "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "int8_t", "int16_t", "int32_t", "int64_t",
        "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64",
        "div", "ldiv", "lldiv", "abs", "labs", "llabs", "exit", "_Exit", "abort",
        "free", "malloc", "calloc", "realloc", "rand", "srand", "qsort", "bsearch",
        "atoi", "atol", "atoll", "atof", "strtol", "strtoul", "strtoll", "strtoull", "strtod",
        "system", "getenv", "atexit", "quick_exit", "at_quick_exit", "printf", "puts",
        "ei", "di", "halt", "stop", "brk", "brk1", "sel", "movs", "JUMPOUT",
    };
    return kReserved.count(s) != 0;
}

std::string strip_struct_kw(std::string s) {
    if (s.rfind("struct ", 0) == 0) s = s.substr(7);
    else if (s.rfind("union ", 0) == 0) s = s.substr(6);
    while (!s.empty() && s.front() == ' ') s.erase(s.begin());
    while (!s.empty() && s.back() == ' ') s.pop_back();
    return s;
}

std::string ptr_pointee_struct(const std::string &tstr) {
    std::string clean = tstr;
    while (!clean.empty() && std::isspace(static_cast<unsigned char>(clean.back()))) clean.pop_back();
    if (clean.empty() || clean.back() != '*') return {};
    clean.pop_back();
    return strip_struct_kw(clean);
}

const StructMemberInfo *find_struct_member(const StructDef &sd, int64_t offset) {
    for (const auto &m : sd.members) {
        if (m.offset == offset) return &m;
    }
    for (const auto &m : sd.members) {
        int64_t sz = std::max<int64_t>(1, m.size);
        if (m.offset <= offset && offset < m.offset + sz) return &m;
    }
    return nullptr;
}

bool extract_base_and_offset(const ExprPtr &addr, std::string &out_var, int64_t &out_off) {
    if (!addr) return false;
    // Unwrap linear segment OR/cast wrappers around a base pointer expression, e.g. (0 | (u16)v0) or (u32)(u16)v0
    if (addr->kind == ExprKind::Un && (addr->op == "u16" || addr->op == "u32")) {
        return extract_base_and_offset(addr->l, out_var, out_off);
    }
    if (addr->kind == ExprKind::Bin && addr->op == "|") {
        if (addr->l && addr->l->kind == ExprKind::Const && addr->l->name.empty()) {
            return extract_base_and_offset(addr->r, out_var, out_off);
        }
        if (addr->r && addr->r->kind == ExprKind::Const && addr->r->name.empty()) {
            return extract_base_and_offset(addr->l, out_var, out_off);
        }
    }
    if (addr->kind == ExprKind::Var || addr->kind == ExprKind::StackVar || addr->kind == ExprKind::Reg) {
        out_var = addr->name;
        out_off = 0;
        return true;
    }
    if (addr->kind == ExprKind::Bin && (addr->op == "+" || addr->op == "-")) {
        if (addr->l && (addr->l->kind == ExprKind::Var || addr->l->kind == ExprKind::StackVar || addr->l->kind == ExprKind::Reg) &&
            addr->r && addr->r->kind == ExprKind::Const && addr->r->name.empty()) {
            out_var = addr->l->name;
            out_off = (addr->op == "+") ? static_cast<int64_t>(addr->r->value) : -static_cast<int64_t>(addr->r->value);
            return true;
        }
        if (addr->op == "+" &&
            addr->r && (addr->r->kind == ExprKind::Var || addr->r->kind == ExprKind::StackVar || addr->r->kind == ExprKind::Reg) &&
            addr->l && addr->l->kind == ExprKind::Const && addr->l->name.empty()) {
            out_var = addr->r->name;
            out_off = static_cast<int64_t>(addr->l->value);
            return true;
        }
    }
    return false;
}

std::string expr_struct_type(const ExprPtr &e,
                             const std::unordered_map<std::string, std::string> &var_structs,
                             const IDatabaseProvider *db) {
    if (!e) return {};
    if (e->kind == ExprKind::Const) {
        if (db) {
            if (auto sn = db->get_symbol_struct(e->value); sn.has_value()) {
                std::string clean = strip_struct_kw(*sn);
                if (db->get_udt_info(clean).has_value()) return clean;
            }
        }
        return {};
    }
    if (e->kind == ExprKind::Var || e->kind == ExprKind::StackVar || e->kind == ExprKind::Reg) {
        auto it = var_structs.find(e->name);
        return (it != var_structs.end()) ? it->second : std::string();
    }
    if (e->kind == ExprKind::Bin && (e->op == "+" || e->op == "-")) {
        std::string st = expr_struct_type(e->l, var_structs, db);
        if (!st.empty()) return st;
        if (e->op == "+") return expr_struct_type(e->r, var_structs, db);
    }
    return {};
}

std::unordered_map<std::string, std::string> infer_struct_pointers(
    const Function &func,
    const FrameInfo &fi,
    const FunctionSig &sig,
    const CGenOptions &opts) {
    std::unordered_map<std::string, std::string> explicit_vars;
    std::unordered_map<std::string, std::string> cand_structs;
    auto check_udt = [&](const std::string &pt) -> std::string {
        if (pt.empty()) return {};
        if (!opts.db) return {};
        std::string san = sanitize_c_ident(pt, "");
        if (opts.db->get_udt_info(pt).has_value()) return pt;
        if (!san.empty() && opts.db->get_udt_info(san).has_value()) return san;
        return {};
    };
    auto seed_explicit = [&](const std::string &vname, const std::string &tstr) {
        std::string u = check_udt(ptr_pointee_struct(tstr));
        if (!u.empty()) {
            explicit_vars[vname] = u;
            cand_structs[vname] = u;
        }
    };
    for (const auto &[vname, tstr] : fi.user_types) seed_explicit(vname, tstr);
    for (const auto &[vname, tstr] : opts.user_data.types) seed_explicit(vname, tstr);
    for (const auto &[k, ent] : opts.user_data.lvars) {
        if (!ent.type.empty()) seed_explicit(k, ent.type);
    }
    for (const auto &p : sig.params) seed_explicit(p.name, p.type_str);
    if (!opts.db) return explicit_vars;

    bool changed = true;
    int iter = 0;
    while (changed && iter++ < 16) {
        changed = false;
        for (const auto &[bid, blk] : func.blocks) {
            for (const auto &s : blk->stmts) {
                if (s->kind == StmtKind::Assign && s->dst &&
                    (s->dst->kind == ExprKind::Var || s->dst->kind == ExprKind::StackVar || s->dst->kind == ExprKind::Reg)) {
                    std::string st = expr_struct_type(s->src, cand_structs, opts.db);
                    if (!st.empty() && cand_structs[s->dst->name] != st) {
                        cand_structs[s->dst->name] = st;
                        changed = true;
                    }
                }
            }
        }
    }

    // Only keep constant-derived struct pointer types if actually dereferenced (or flowed into a deref'd var)
    std::unordered_set<std::string> deref_vars;
    auto scan_expr_for_deref = [&](const auto &self, const ExprPtr &e) -> void {
        if (!e) return;
        switch (e->kind) {
            case ExprKind::Mem: {
                if (!e->has_static_addr && e->addr) {
                    std::string raw_var;
                    int64_t off = 0;
                    if (extract_base_and_offset(e->addr, raw_var, off) && cand_structs.count(raw_var)) {
                        deref_vars.insert(raw_var);
                    }
                    self(self, e->addr);
                }
                break;
            }
            case ExprKind::Bin: self(self, e->l); self(self, e->r); break;
            case ExprKind::Un:  self(self, e->l); break;
            case ExprKind::Bit: self(self, e->base); break;
            case ExprKind::Intr: for (const auto &a : e->args) self(self, a); break;
            default: break;
        }
    };
    auto scan_flag = [&](const FlagDefPtr &f) {
        if (!f) return;
        scan_expr_for_deref(scan_expr_for_deref, f->a);
        scan_expr_for_deref(scan_expr_for_deref, f->b);
        scan_expr_for_deref(scan_expr_for_deref, f->c);
    };
    for (const auto &[bid, blk] : func.blocks) {
        for (const auto &s : blk->stmts) {
            scan_expr_for_deref(scan_expr_for_deref, s->dst);
            scan_expr_for_deref(scan_expr_for_deref, s->src);
            scan_expr_for_deref(scan_expr_for_deref, s->a);
            scan_expr_for_deref(scan_expr_for_deref, s->b);
            scan_expr_for_deref(scan_expr_for_deref, s->expr);
            scan_expr_for_deref(scan_expr_for_deref, s->val);
            for (const auto &a : s->args) scan_expr_for_deref(scan_expr_for_deref, a);
            scan_flag(s->z_flag);
            scan_flag(s->cy_flag);
        }
    }

    auto collect_expr_vars = [&](const auto &self, const ExprPtr &e, std::vector<std::string> &out) -> void {
        if (!e) return;
        if (e->kind == ExprKind::Var || e->kind == ExprKind::StackVar || e->kind == ExprKind::Reg) {
            out.push_back(e->name);
            return;
        }
        if (e->kind == ExprKind::Bin) { self(self, e->l, out); self(self, e->r, out); }
        else if (e->kind == ExprKind::Un) self(self, e->l, out);
    };
    bool bchanged = true;
    int biter = 0;
    while (bchanged && biter++ < 16) {
        bchanged = false;
        for (const auto &[bid, blk] : func.blocks) {
            for (const auto &s : blk->stmts) {
                if (s->kind == StmtKind::Assign && s->dst &&
                    (s->dst->kind == ExprKind::Var || s->dst->kind == ExprKind::StackVar || s->dst->kind == ExprKind::Reg)) {
                    if (deref_vars.count(s->dst->name) && cand_structs.count(s->dst->name)) {
                        const std::string &dst_st = cand_structs[s->dst->name];
                        std::vector<std::string> src_vars;
                        collect_expr_vars(collect_expr_vars, s->src, src_vars);
                        for (const auto &sv : src_vars) {
                            auto cit = cand_structs.find(sv);
                            if (cit != cand_structs.end() && cit->second == dst_st && deref_vars.insert(sv).second) {
                                bchanged = true;
                            }
                        }
                    }
                }
            }
        }
    }

    std::unordered_map<std::string, std::string> var_structs = explicit_vars;
    for (const auto &[vn, st] : cand_structs) {
        if (deref_vars.count(vn)) var_structs[vn] = st;
    }
    return var_structs;
}

struct CGenCtx {
    const Function &func;
    const FrameInfo &frame_info;
    const FunctionSig &sig;
    const CGenOptions &opts;
    std::shared_ptr<cfunc_t> cf;
    std::unordered_map<std::string, int> var_idx_map;
    std::unordered_map<std::string, std::string> rename_map;
    std::unordered_map<std::string, std::string> type_map;
    std::unordered_map<std::string, std::string> var_structs;
    int cur_line_op_idx = 0;

    std::string display_var_name(const std::string &raw) const {
        std::string nm = raw;
        if (auto it = rename_map.find(raw); it != rename_map.end()) nm = it->second;
        else if (auto it = frame_info.user_renames.find(raw); it != frame_info.user_renames.end()) nm = it->second;
        return sanitize_c_ident(nm, "v_tmp");
    }

    std::string var_type_of(const std::string &raw, Width w) const {
        if (auto it = type_map.find(raw); it != type_map.end()) return it->second;
        if (auto it = frame_info.user_types.find(raw); it != frame_info.user_types.end()) return it->second;
        if (auto it = var_structs.find(raw); it != var_structs.end()) {
            return sanitize_c_ident(it->second, "struct_t") + " *";
        }
        return width_ctype(w);
    }

    bool is_safe_global_ident(const std::string &cand) const {
        if (cand.empty() || is_reserved_c_lib_ident(cand)) return false;
        if (cand == cf->func_name) return false;
        for (const auto &p : sig.params) {
            if (p.name == cand || display_var_name(p.name) == cand) return false;
        }
        for (const auto &[k, _] : frame_info.locals) {
            if (k == cand || display_var_name(k) == cand) return false;
        }
        for (const auto &[k, _] : frame_info.args) {
            if (k == cand || display_var_name(k) == cand) return false;
        }
        for (const auto &lv : cf->lvars) {
            if (lv.name == cand || lv.canonical_name == cand) return false;
        }
        return true;
    }

    std::string lookup_sym_rename(const std::string &raw_nm) const {
        std::string nm = raw_nm;
        if (auto it = rename_map.find(raw_nm); it != rename_map.end()) nm = it->second;
        else if (auto it = frame_info.user_renames.find(raw_nm); it != frame_info.user_renames.end()) nm = it->second;
        return sanitize_c_ident(nm, "g_sym");
    }

    void record_global_sym(const std::string &nm, uint32_t base_ea, uint32_t item_size,
                           bool is_array, const std::string &struct_name,
                           bool used_scalar, bool used_indexed) {
        cf->sym_eas[nm] = base_ea;
        auto &ref = cf->global_syms[nm];
        if (ref.base_ea == 0) {
            ref.base_ea = base_ea;
            ref.item_size = std::max<uint32_t>(1, item_size);
        }
        ref.is_array = ref.is_array || is_array;
        ref.used_scalar = ref.used_scalar || used_scalar;
        ref.used_indexed = ref.used_indexed || used_indexed;
        if (!struct_name.empty()) {
            ref.struct_name = sanitize_c_ident(struct_name, "struct_t");
            cf->used_udts.insert(struct_name);
        }
    }

    cexpr_t *make_obj_expr(const std::string &nm, uint32_t obj_ea, const std::string &ty, uint64_t ea) {
        cexpr_t *obj = cf->alloc_expr(cot_obj, ea);
        obj->obj_ea = obj_ea;
        obj->helper = nm;
        obj->type_str = ty;
        obj->text_cache = nm;
        cf->sym_eas[nm] = obj_ea;
        return obj;
    }

    cexpr_t *make_raw_deref(Width w, const std::string &addr_inner, cexpr_t *child, uint64_t ea) {
        cexpr_t *p = cf->alloc_expr(cot_ptr, ea);
        p->x = child;
        p->type_str = width_ctype(w);
        p->text_cache = "*(" + p->type_str + " *)(" + addr_inner + ")";
        return p;
    }

    cexpr_t *try_struct_deref(const ExprPtr &addr, Width access_w, uint64_t ea) {
        if (!opts.db || var_structs.empty()) return nullptr;
        std::string raw_var;
        int64_t off = 0;
        if (!extract_base_and_offset(addr, raw_var, off)) return nullptr;
        auto sit = var_structs.find(raw_var);
        if (sit == var_structs.end()) return nullptr;
        auto sd = opts.db->get_udt_info(sit->second);
        if (!sd.has_value()) return nullptr;
        const StructMemberInfo *m = find_struct_member(*sd, off);
        if (!m) return nullptr;

        cf->used_udts.insert(sd->name);
        int idx = ensure_lvar(raw_var, Width::W, frame_info.args.count(raw_var) > 0);
        cexpr_t *v = cf->alloc_expr(cot_var, ea);
        v->v.idx = idx;
        v->helper = cf->lvars[idx].name;
        v->type_str = cf->lvars[idx].type_str;
        v->text_cache = cf->lvars[idx].name;

        std::string mname = sanitize_c_ident(m->name, "field");
        cexpr_t *mp = cf->alloc_expr(cot_memptr, ea);
        mp->x = v;
        mp->string = mname;
        int64_t rem = off - m->offset;
        std::string base_mem = v->text_cache + "->" + mname;
        int acc_bytes = width_bytes(access_w);
        if (rem == 0 && m->size == acc_bytes) {
            mp->type_str = width_ctype(access_w);
            mp->text_cache = base_mem;
        } else if (rem == 0) {
            mp->type_str = width_ctype(access_w);
            mp->text_cache = "*(" + mp->type_str + " *)&" + base_mem;
        } else {
            mp->type_str = width_ctype(access_w);
            mp->text_cache = "*(" + mp->type_str + " *)((uint8_t *)&" + base_mem + " + " + std::to_string(rem) + ")";
        }
        return mp;
    }

    int ensure_lvar(const std::string &raw, Width w, bool is_arg, bool is_stk = false, int64_t stk_off = 0) {
        if (auto lit = frame_info.locals.find(raw); lit != frame_info.locals.end() &&
            width_bytes(lit->second.width) > width_bytes(w)) {
            w = lit->second.width;
        }
        if (auto ait = frame_info.args.find(raw); ait != frame_info.args.end() &&
            width_bytes(ait->second.width) > width_bytes(w)) {
            w = ait->second.width;
        }
        if (auto it = var_idx_map.find(raw); it != var_idx_map.end()) {
            int idx = it->second;
            auto &existing = cf->lvars[idx];
            if (!existing.has_user_type && !var_structs.count(raw) && width_bytes(w) > existing.width) {
                existing.width = width_bytes(w);
                existing.type_str = var_type_of(raw, w);
                cf->var_types[existing.name] = existing.type_str;
            }
            return idx;
        }
        lvar_t lv;
        lv.index = static_cast<int>(cf->lvars.size());
        lv.canonical_name = raw;
        lv.name = display_var_name(raw);
        lv.has_user_name = (lv.name != raw);
        lv.type_str = var_type_of(raw, w);
        lv.has_user_type = (type_map.count(raw) || frame_info.user_types.count(raw));
        lv.width = width_bytes(w);
        lv.is_arg_var = is_arg;
        lv.is_stk_var_flag = is_stk;
        lv.location.is_stk = is_stk;
        lv.location.stk_off = stk_off;
        if (auto sit = var_structs.find(raw); sit != var_structs.end()) {
            cf->used_udts.insert(sit->second);
        }
        cf->lvars.push_back(lv);
        var_idx_map[raw] = lv.index;
        cf->var_types[lv.name] = lv.type_str;
        return lv.index;
    }

    static bool is_synthetic_global_name(const std::string &s) {
        return s.rfind("saddr_", 0) == 0 || s.rfind("ram_", 0) == 0 ||
               s.rfind("m_", 0) == 0 || s.rfind("sfr_", 0) == 0;
    }

    cexpr_t *build_cexpr(const ExprPtr &e, uint64_t ea) {
        if (!e) {
            cexpr_t *n = cf->alloc_expr(cot_num, ea);
            n->n._value = 0;
            n->n.repr = "0";
            n->text_cache = "0";
            return n;
        }
        switch (e->kind) {
            case ExprKind::Const: {
                cexpr_t *n = cf->alloc_expr(cot_num, ea);
                n->n._value = e->value;
                n->n.bits = width_bits(e->width);
                n->n.ea = ea;
                n->n.opnum = cur_line_op_idx++;
                n->type_str = width_ctype(e->width);
                std::string const_sym = e->name;
                if (!const_sym.empty() && opts.db) {
                    if (auto si = opts.db->get_symbol_info(e->value); si.has_value()) {
                        if (!si->struct_name.empty() || !si->is_array) {
                            const_sym.clear();
                        }
                    }
                }
                if (!const_sym.empty() && const_sym.rfind("sub_", 0) != 0) {
                    std::string san = lookup_sym_rename(const_sym);
                    if (is_safe_global_ident(san)) {
                        if (opts.db) {
                            if (auto si = opts.db->get_symbol_info(e->value); si.has_value()) {
                                record_global_sym(san, si->base_ea, si->item_size, si->is_array, si->struct_name, false, true);
                            }
                        }
                        n->text_cache = san;
                        n->n.repr = san;
                        n->n.is_addr = true;
                        n->n.addr_val = e->value;
                        cf->sym_eas[san] = e->value;
                        return n;
                    }
                }
                std::string form = "hex";
                if (e->value <= 9) form = "dec";
                if (auto nf = opts.user_data.get_numform(ea, n->n.opnum); nf.has_value()) {
                    form = *nf;
                    n->n.applied_form = *nf;
                }
                n->n.default_form = (e->value <= 9) ? "dec" : "hex";
                n->n.repr = format_num_with_form(e->value, n->n.bits, form);
                n->text_cache = n->n.repr;
                return n;
            }
            case ExprKind::Var:
            case ExprKind::StackVar: {
                bool is_stk = (e->kind == ExprKind::StackVar);
                bool is_arg = (frame_info.args.count(e->name) > 0) || e->is_arg;
                int idx = ensure_lvar(e->name, e->width, is_arg, is_stk, e->offset);
                cexpr_t *v = cf->alloc_expr(cot_var, ea);
                v->v.idx = idx;
                v->helper = cf->lvars[idx].name;
                v->type_str = cf->lvars[idx].type_str;
                v->text_cache = cf->lvars[idx].name;
                return v;
            }
            case ExprKind::Reg: {
                std::string rname = e->name;
                std::string ty = width_ctype(e->width);
                if (rname == "cy") rname = "CY";
                else if (rname == "z") rname = "ZF";
                else if (rname == "sp") { rname = "*(uint16_t *)(0xFFFF8)"; ty = "uint16_t"; }
                else if (rname == "spl") { rname = "*(uint8_t *)(0xFFFF8)"; ty = "uint8_t"; }
                else if (rname == "sph") { rname = "*(uint8_t *)(0xFFFF9)"; ty = "uint8_t"; }
                cexpr_t *r = cf->alloc_expr(cot_helper, ea);
                r->helper = rname;
                r->type_str = ty;
                r->text_cache = rname;
                return r;
            }
            case ExprKind::Mem: {
                const bool is_static = e->has_static_addr || (e->addr && e->addr->kind == ExprKind::Const);
                if (is_static) {
                    uint32_t addr = e->has_static_addr ? e->static_addr : e->addr->value;
                    if (!e->es && (!e->has_static_addr && addr < 0x10000u && e->addr->width != Width::A)) {
                        addr = (0xF0000u | addr) & 0xFFFFFu;
                    }
                    if (e->es) {
                        std::string a16 = format_hex(addr & 0xFFFFu, 16);
                        return make_raw_deref(e->width, "((uint32_t)(es & 0xFu) << 16) | " + a16, nullptr, ea);
                    }

                    // 1. Explicit documented SFR name on IR node
                    if (!e->name.empty() && sfr_addr_for(e->name).has_value() && *sfr_addr_for(e->name) == addr) {
                        if (e->width == Width::B) {
                            return make_obj_expr(e->name, addr, "uint8_t", ea);
                        }
                        cexpr_t *p = cf->alloc_expr(cot_ptr, ea);
                        p->x = make_obj_expr(e->name, addr, "uint8_t", ea);
                        p->type_str = width_ctype(e->width);
                        p->text_cache = "*(" + p->type_str + " *)&" + e->name;
                        return p;
                    }

                    // 2. Database symbol resolution (including interior offsets & structs)
                    std::optional<SymbolInfo> sym_opt;
                    if (opts.db) sym_opt = opts.db->get_symbol_info(addr);
                    if (!sym_opt.has_value() && !e->name.empty() && addr < 0xFFE00u) {
                        SymbolInfo fallback;
                        fallback.name = e->name;
                        fallback.base_ea = addr;
                        fallback.item_size = static_cast<uint32_t>(width_bytes(e->width));
                        sym_opt = fallback;
                    }
                    if (sym_opt.has_value() && !sym_opt->name.empty()) {
                        std::string nm = lookup_sym_rename(sym_opt->name);
                        auto sfr_hit = sfr_addr_for(nm);
                        bool sfr_mismatch = sfr_hit.has_value() && *sfr_hit != sym_opt->base_ea;
                        if (!sfr_mismatch && is_safe_global_ident(nm)) {
                            int acc_bytes = width_bytes(e->width);
                            if (!sym_opt->struct_name.empty() && opts.db) {
                                if (auto udt = opts.db->get_udt_info(sym_opt->struct_name); udt.has_value()) {
                                    if (const StructMemberInfo *m = find_struct_member(*udt, sym_opt->offset)) {
                                        record_global_sym(nm, sym_opt->base_ea, sym_opt->item_size, sym_opt->is_array,
                                                          sym_opt->struct_name, true, false);
                                        std::string mname = sanitize_c_ident(m->name, "field");
                                        cexpr_t *mr = cf->alloc_expr(cot_memref, ea);
                                        mr->x = make_obj_expr(nm, sym_opt->base_ea, sanitize_c_ident(udt->name, "struct_t"), ea);
                                        mr->string = mname;
                                        mr->type_str = width_ctype(e->width);
                                        int64_t rem = static_cast<int64_t>(sym_opt->offset) - m->offset;
                                        if (rem == 0 && m->size == acc_bytes) {
                                            mr->text_cache = nm + "." + mname;
                                        } else if (rem == 0) {
                                            mr->text_cache = "*(" + mr->type_str + " *)&" + nm + "." + mname;
                                        } else {
                                            mr->text_cache = "*(" + mr->type_str + " *)((uint8_t *)&" + nm + "." + mname +
                                                             " + " + std::to_string(rem) + ")";
                                        }
                                        return mr;
                                    }
                                }
                            }
                            if (sym_opt->is_array) {
                                record_global_sym(nm, sym_opt->base_ea, sym_opt->item_size, true,
                                                  sym_opt->struct_name, false, true);
                                cexpr_t *idxn = cf->alloc_expr(cot_num, ea);
                                idxn->n._value = sym_opt->offset;
                                idxn->n.repr = std::to_string(sym_opt->offset);
                                idxn->text_cache = idxn->n.repr;
                                if (e->width == Width::B) {
                                    cexpr_t *ix = cf->alloc_expr(cot_idx, ea);
                                    ix->x = make_obj_expr(nm, sym_opt->base_ea, "uint8_t", ea);
                                    ix->y = idxn;
                                    ix->type_str = "uint8_t";
                                    ix->text_cache = nm + "[" + idxn->text_cache + "]";
                                    return ix;
                                }
                                cexpr_t *p = cf->alloc_expr(cot_ptr, ea);
                                p->x = make_obj_expr(nm, sym_opt->base_ea, "uint8_t", ea);
                                p->type_str = width_ctype(e->width);
                                p->text_cache = "*(" + p->type_str + " *)&" + nm + "[" + idxn->text_cache + "]";
                                return p;
                            }
                            record_global_sym(nm, sym_opt->base_ea, sym_opt->item_size, false,
                                              sym_opt->struct_name, true, false);
                            if (sym_opt->offset == 0) {
                                if (acc_bytes == static_cast<int>(sym_opt->item_size)) {
                                    return make_obj_expr(nm, sym_opt->base_ea, width_ctype(e->width), ea);
                                }
                                cexpr_t *p = cf->alloc_expr(cot_ptr, ea);
                                p->x = make_obj_expr(nm, sym_opt->base_ea, width_ctype(e->width), ea);
                                p->type_str = width_ctype(e->width);
                                p->text_cache = "*(" + p->type_str + " *)&" + nm;
                                return p;
                            }
                            cexpr_t *p = cf->alloc_expr(cot_ptr, ea);
                            p->x = make_obj_expr(nm, sym_opt->base_ea, width_ctype(e->width), ea);
                            p->type_str = width_ctype(e->width);
                            if (e->width == Width::B) {
                                p->text_cache = "*((uint8_t *)&" + nm + " + " + std::to_string(sym_opt->offset) + ")";
                            } else {
                                p->text_cache = "*(" + p->type_str + " *)((uint8_t *)&" + nm + " + " +
                                                std::to_string(sym_opt->offset) + ")";
                            }
                            return p;
                        }
                    }

                    // 3. Documented RL78 SFR register fallback by address
                    if (auto sfrn = sfr_name_for(addr); sfrn.has_value()) {
                        if (e->width == Width::B) {
                            return make_obj_expr(*sfrn, addr, "uint8_t", ea);
                        }
                        cexpr_t *p = cf->alloc_expr(cot_ptr, ea);
                        p->x = make_obj_expr(*sfrn, addr, "uint8_t", ea);
                        p->type_str = width_ctype(e->width);
                        p->text_cache = "*(" + p->type_str + " *)&" + *sfrn;
                        return p;
                    }

                    // 4. Unnamed static linear address -> native C pointer dereference
                    return make_raw_deref(e->width, format_hex(addr, 20), nullptr, ea);
                }

                // Dynamic memory access
                if (cexpr_t *sd = try_struct_deref(e->addr, e->width, ea)) {
                    return sd;
                }

                // Dynamic global array / base + index form (e.g. byte_FB3E5[(uint8_t)a1])
                if (!e->es && e->addr && e->addr->kind == ExprKind::Bin &&
                    (e->addr->op == "+" || e->addr->op == "-")) {
                    ExprPtr base_c;
                    ExprPtr idx_e;
                    bool negate_idx = false;
                    if (e->addr->l && e->addr->l->kind == ExprKind::Const) {
                        base_c = e->addr->l;
                        idx_e = e->addr->r;
                        negate_idx = (e->addr->op == "-");
                    } else if (e->addr->op == "+" && e->addr->r && e->addr->r->kind == ExprKind::Const) {
                        base_c = e->addr->r;
                        idx_e = e->addr->l;
                    }
                    if (base_c && idx_e) {
                        uint32_t lin_base = base_c->value;
                        if (lin_base < 0x10000u && base_c->width != Width::A) {
                            lin_base = (0xF0000u | lin_base) & 0xFFFFFu;
                        }
                        std::optional<SymbolInfo> sym_opt;
                        if (opts.db) sym_opt = opts.db->get_symbol_info(lin_base);
                        if (!sym_opt.has_value() && !base_c->name.empty()) {
                            SymbolInfo fallback;
                            fallback.name = base_c->name;
                            fallback.base_ea = lin_base;
                            fallback.item_size = 1;
                            fallback.is_array = true;
                            sym_opt = fallback;
                        }
                        if (sym_opt.has_value() && !sym_opt->name.empty()) {
                            std::string nm = lookup_sym_rename(sym_opt->name);
                            auto sfr_hit = sfr_addr_for(nm);
                            bool sfr_mismatch = sfr_hit.has_value() && *sfr_hit != sym_opt->base_ea;
                            if (!sfr_mismatch && is_safe_global_ident(nm)) {
                                cexpr_t *idx_ce = build_cexpr(idx_e, ea);
                                std::string idx_s = idx_ce->print1(&cf->lvars);
                                if (negate_idx) idx_s = "-(" + idx_s + ")";
                                if (sym_opt->offset > 0) idx_s = "(" + idx_s + ") + " + std::to_string(sym_opt->offset);

                                const bool has_struct = !sym_opt->struct_name.empty();
                                if (e->width == Width::B) {
                                    if (!has_struct && (sym_opt->is_array || (sym_opt->item_size == 1 && !sym_opt->has_scalar_xref))) {
                                        record_global_sym(nm, sym_opt->base_ea, sym_opt->item_size, sym_opt->is_array,
                                                          sym_opt->struct_name, false, true);
                                        cexpr_t *ix = cf->alloc_expr(cot_idx, ea);
                                        ix->x = make_obj_expr(nm, sym_opt->base_ea, "uint8_t", ea);
                                        ix->y = idx_ce;
                                        ix->type_str = "uint8_t";
                                        ix->text_cache = nm + "[" + idx_s + "]";
                                        return ix;
                                    }
                                    record_global_sym(nm, sym_opt->base_ea, sym_opt->item_size, sym_opt->is_array,
                                                      sym_opt->struct_name, !has_struct && !sym_opt->is_array, true);
                                    cexpr_t *ix = cf->alloc_expr(cot_idx, ea);
                                    ix->x = make_obj_expr(nm, sym_opt->base_ea, "uint8_t", ea);
                                    ix->y = idx_ce;
                                    ix->type_str = "uint8_t";
                                    if (has_struct && sym_opt->is_array) {
                                        ix->text_cache = "((uint8_t *)" + nm + ")[" + idx_s + "]";
                                    } else if (!has_struct && sym_opt->item_size == 1) {
                                        ix->text_cache = "(&" + nm + ")[" + idx_s + "]";
                                    } else {
                                        ix->text_cache = "((uint8_t *)&" + nm + ")[" + idx_s + "]";
                                    }
                                    return ix;
                                }
                                std::string ty = width_ctype(e->width);
                                if (sym_opt->is_array) {
                                    record_global_sym(nm, sym_opt->base_ea, sym_opt->item_size, true,
                                                      sym_opt->struct_name, false, true);
                                    cexpr_t *p = cf->alloc_expr(cot_ptr, ea);
                                    p->x = idx_ce;
                                    p->type_str = ty;
                                    if (has_struct) {
                                        p->text_cache = "*(" + ty + " *)((uint8_t *)" + nm + " + (" + idx_s + "))";
                                    } else {
                                        p->text_cache = "*(" + ty + " *)&" + nm + "[" + idx_s + "]";
                                    }
                                    return p;
                                }
                                record_global_sym(nm, sym_opt->base_ea, sym_opt->item_size, false,
                                                  sym_opt->struct_name, true, false);
                                cexpr_t *p = cf->alloc_expr(cot_ptr, ea);
                                p->x = idx_ce;
                                p->type_str = ty;
                                p->text_cache = "*(" + ty + " *)((uint8_t *)&" + nm + " + (" + idx_s + "))";
                                return p;
                            }
                        }
                    }
                }

                cexpr_t *ae = build_cexpr(e->addr, ea);
                std::string astr = ae->print1(&cf->lvars);
                std::string idx_expr;
                if (e->es) {
                    idx_expr = "((uint32_t)(es & 0xFu) << 16) | (uint16_t)(" + astr + ")";
                } else if (e->addr && e->addr->width == Width::A) {
                    bool has_linear_base = false;
                    if (e->addr->kind == ExprKind::Bin &&
                        (e->addr->op == "+" || e->addr->op == "-" || e->addr->op == "|")) {
                        if ((e->addr->l && e->addr->l->kind == ExprKind::Const && e->addr->l->value >= 0x10000u) ||
                            (e->addr->r && e->addr->r->kind == ExprKind::Const && e->addr->r->value >= 0x10000u)) {
                            has_linear_base = true;
                        }
                    }
                    if (e->addr->kind == ExprKind::Un && e->addr->op == "u32") {
                        idx_expr = astr;
                    } else {
                        idx_expr = has_linear_base ? astr : ("(uint32_t)(" + astr + ") & 0xFFFFFu");
                    }
                } else {
                    idx_expr = "0xF0000u | (uint16_t)(" + astr + ")";
                }
                return make_raw_deref(e->width, idx_expr, ae, ea);
            }
            case ExprKind::Bit: {
                cexpr_t *be = build_cexpr(e->base, ea);
                cexpr_t *node = cf->alloc_expr(cot_band, ea);
                node->x = be;
                cexpr_t *mask = cf->alloc_expr(cot_num, ea);
                mask->n._value = (1ULL << e->bit);
                mask->n.repr = format_hex(1ULL << e->bit, 8);
                mask->text_cache = mask->n.repr;
                node->y = mask;
                node->type_str = "uint8_t";
                node->text_cache = "((" + be->print1(&cf->lvars) + " & " + mask->text_cache + ") != 0)";
                return node;
            }
            case ExprKind::Un: {
                if (e->op == "u8" || e->op == "u16" || e->op == "u32" ||
                    e->op == "i8" || e->op == "i16" || e->op == "i32") {
                    if (opts.hide_casts && (e->op == "u8" || e->op == "u16" || e->op == "u32")) {
                        return build_cexpr(e->l, ea);
                    }
                    cexpr_t *inner = build_cexpr(e->l, ea);
                    std::string target_ty;
                    if      (e->op == "u8")  target_ty = "uint8_t";
                    else if (e->op == "u16") target_ty = "uint16_t";
                    else if (e->op == "u32") target_ty = "uint32_t";
                    else if (e->op == "i8")  target_ty = "int8_t";
                    else if (e->op == "i16") target_ty = "int16_t";
                    else                     target_ty = "int32_t";

                    if ((e->op == "u8" || e->op == "u16" || e->op == "u32") && inner &&
                        inner->type_str == target_ty) {
                        bool exact_atom = (inner->op == cot_var || inner->op == cot_ptr ||
                                           inner->op == cot_idx || inner->op == cot_memref ||
                                           inner->op == cot_memptr || inner->op == cot_cast);
                        if (inner->op == cot_obj) {
                            auto git = cf->global_syms.find(inner->helper);
                            if (git == cf->global_syms.end() || !git->second.is_array) exact_atom = true;
                        }
                        if (exact_atom) return inner;
                    }

                    cexpr_t *c = cf->alloc_expr(cot_cast, ea);
                    c->x = inner;
                    c->type_str = target_ty;
                    if (inner && !inner->type_str.empty() && inner->type_str.back() == '*') {
                        c->text_cache = "(" + c->type_str + ")(uintptr_t)(" + inner->print1(&cf->lvars) + ")";
                    } else {
                        c->text_cache = "(" + c->type_str + ")(" + inner->print1(&cf->lvars) + ")";
                    }
                    return c;
                }
                ctype_t op = cot_neg;
                if (e->op == "!") op = cot_lnot;
                else if (e->op == "~") op = cot_bnot;
                cexpr_t *u = cf->alloc_expr(op, ea);
                u->x = build_cexpr(e->l, ea);
                u->type_str = width_ctype(e->width);
                std::string xs = u->x->print1(&cf->lvars);
                if (op == cot_lnot) u->text_cache = "!(" + xs + ")";
                else if (op == cot_bnot) u->text_cache = "~(" + xs + ")";
                else u->text_cache = "-(" + xs + ")";
                return u;
            }
            case ExprKind::Bin: {
                // Cleanly emit low/high byte extracts as casts when appropriate
                if (e->op == "&" && e->r && e->r->kind == ExprKind::Const && e->r->value == 0xFF &&
                    e->l && e->l->kind == ExprKind::Var && e->l->width == Width::W) {
                    cexpr_t *c = cf->alloc_expr(cot_cast, ea);
                    c->x = build_cexpr(e->l, ea);
                    c->type_str = "uint8_t";
                    if (var_structs.count(e->l->name)) {
                        c->text_cache = "(uint8_t)(uintptr_t)(" + c->x->print1(&cf->lvars) + ")";
                    } else {
                        c->text_cache = "(uint8_t)" + c->x->print1(&cf->lvars);
                    }
                    return c;
                }
                ctype_t cop = cot_add;
                if      (e->op == "+")  cop = cot_add;
                else if (e->op == "-")  cop = cot_sub;
                else if (e->op == "*")  cop = cot_mul;
                else if (e->op == "/")  cop = cot_udiv;
                else if (e->op == "%")  cop = cot_umod;
                else if (e->op == "&")  cop = cot_band;
                else if (e->op == "|")  cop = cot_bor;
                else if (e->op == "^")  cop = cot_xor;
                else if (e->op == "<<") cop = cot_shl;
                else if (e->op == ">>") cop = cot_ushr;
                else if (e->op == "==") cop = cot_eq;
                else if (e->op == "!=") cop = cot_ne;
                else if (e->op == "<")  cop = cot_ult;
                else if (e->op == "<=") cop = cot_ule;
                else if (e->op == ">")  cop = cot_ugt;
                else if (e->op == ">=") cop = cot_uge;
                else if (e->op == "&&") cop = cot_land;
                else if (e->op == "||") cop = cot_lor;

                cexpr_t *b = cf->alloc_expr(cop, ea);
                b->x = build_cexpr(e->l, ea);
                b->y = build_cexpr(e->r, ea);
                b->type_str = width_ctype(e->width);

                auto is_struct_ptr_expr = [&](const ExprPtr &sub) -> bool {
                    if (!sub) return false;
                    if (sub->kind == ExprKind::Var || sub->kind == ExprKind::StackVar || sub->kind == ExprKind::Reg) {
                        return var_structs.count(sub->name) > 0;
                    }
                    return false;
                };
                bool l_ptr = is_struct_ptr_expr(e->l);
                bool r_ptr = is_struct_ptr_expr(e->r);
                bool non_ptr_op = (e->op != "+" && e->op != "-" && e->op != "==" && e->op != "!=");
                auto wrap_sub = [&](const ExprPtr &sub, cexpr_t *ce, bool cast_ptr) {
                    std::string s = ce->print1(&cf->lvars);
                    if (cast_ptr) return std::string("(uintptr_t)(") + s + ")";
                    if (sub && sub->kind == ExprKind::Bin) return "(" + s + ")";
                    return s;
                };
                bool cast_l = l_ptr && (non_ptr_op || (r_ptr && (e->op == "==" || e->op == "!=" || e->op == "+")));
                bool cast_r = r_ptr && (non_ptr_op || e->op == "+" || (e->op == "-" && !l_ptr) ||
                                        (!l_ptr && (e->op == "==" || e->op == "!=")));
                std::string ls = wrap_sub(e->l, b->x, cast_l);
                std::string rs = wrap_sub(e->r, b->y, cast_r);
                b->text_cache = ls + " " + e->op + " " + rs;
                return b;
            }
            case ExprKind::Intr: {
                if (e->name == "__tern" && e->args.size() == 3) {
                    cexpr_t *t = cf->alloc_expr(cot_tern, ea);
                    t->x = build_cexpr(e->args[0], ea);
                    t->y = build_cexpr(e->args[1], ea);
                    t->z = build_cexpr(e->args[2], ea);
                    t->type_str = width_ctype(e->width);
                    t->text_cache = "((" + t->x->print1(&cf->lvars) + ") ? (" +
                                    t->y->print1(&cf->lvars) + ") : (" +
                                    t->z->print1(&cf->lvars) + "))";
                    return t;
                }
                cexpr_t *c = cf->alloc_expr(cot_call, ea);
                c->helper = sanitize_c_ident(e->name, "intr");
                c->type_str = width_ctype(e->width);
                for (const auto &a : e->args) c->a.push_back(build_cexpr(a, ea));
                std::ostringstream os;
                os << c->helper << "(";
                for (size_t i = 0; i < c->a.size(); ++i) {
                    if (i > 0) os << ", ";
                    os << c->a[i]->print1(&cf->lvars);
                }
                os << ")";
                c->text_cache = os.str();
                return c;
            }
        }
        return cf->alloc_expr(cot_empty, ea);
    }

    cinsn_t *build_bitclr_assign(const ExprPtr &base_expr, uint8_t bit, uint64_t ea) {
        cinsn_t *ins = cf->alloc_insn(cit_expr, ea);
        cexpr_t *lhs = build_cexpr(base_expr, ea);
        cexpr_t *asg = cf->alloc_expr(cot_asgband, ea);
        asg->x = lhs;
        cexpr_t *mask = cf->alloc_expr(cot_num, ea);
        mask->n._value = static_cast<uint8_t>(~(1u << bit));
        mask->n.repr = format_hex(mask->n._value, 8);
        mask->text_cache = mask->n.repr;
        asg->y = mask;
        asg->text_cache = lhs->print1(&cf->lvars) + " &= " + mask->n.repr;
        ins->cexpr_node = asg;
        ins->text_cache = asg->text_cache + ";";
        return ins;
    }

    std::string stmt_bit_expr_lval(const ExprPtr &bit_expr, uint64_t ea, std::string &mask_hex_out) {
        cexpr_t *be = build_cexpr(bit_expr->base, ea);
        mask_hex_out = format_hex(1ULL << bit_expr->bit, 8);
        return be->print1(&cf->lvars);
    }

    cinsn_t *build_cinsn_stmt(const Stmt &s) {
        cur_line_op_idx = 0;
        uint64_t ea = s.ea;
        if (s.kind == StmtKind::Assign) {
            if (s.dst && s.dst->kind == ExprKind::Bit) {
                std::string mask_hex;
                std::string base_s = stmt_bit_expr_lval(s.dst, ea, mask_hex);
                bool set_one = (s.src && s.src->kind == ExprKind::Const && s.src->value != 0);
                bool clr_zero = (s.src && s.src->kind == ExprKind::Const && s.src->value == 0);
                cinsn_t *ins = cf->alloc_insn(cit_expr, ea);
                cexpr_t *asg = cf->alloc_expr(set_one ? cot_asgbor : (clr_zero ? cot_asgband : cot_asg), ea);
                asg->x = build_cexpr(s.dst->base, ea);
                if (set_one) {
                    asg->text_cache = base_s + " |= " + mask_hex;
                } else if (clr_zero) {
                    std::string inv = format_hex(static_cast<uint8_t>(~(1u << s.dst->bit)), 8);
                    asg->text_cache = base_s + " &= " + inv;
                } else {
                    cexpr_t *rhs = build_cexpr(s.src, ea);
                    asg->y = rhs;
                    std::string rstr = rhs->print1(&cf->lvars);
                    std::string inv = format_hex(static_cast<uint8_t>(~(1u << s.dst->bit)), 8);
                    asg->text_cache = base_s + " = (" + base_s + " & " + inv + ") | (((" + rstr + ") & 1) << " + std::to_string(s.dst->bit) + ")";
                }
                ins->cexpr_node = asg;
                ins->text_cache = asg->text_cache + ";";
                return ins;
            }
            // Also propagate CY = ... when Assign writes to CY
            cinsn_t *ins = cf->alloc_insn(cit_expr, ea);
            cexpr_t *asg = cf->alloc_expr(cot_asg, ea);
            asg->x = build_cexpr(s.dst, ea);
            asg->type_str = asg->x->type_str;

            std::string dst_struct;
            if (s.dst && (s.dst->kind == ExprKind::Var || s.dst->kind == ExprKind::StackVar || s.dst->kind == ExprKind::Reg)) {
                auto sit = var_structs.find(s.dst->name);
                if (sit != var_structs.end()) dst_struct = sit->second;
            }
            if (!dst_struct.empty() && s.src) {
                std::string T = sanitize_c_ident(dst_struct, "struct_t");
                auto matches_dst_struct = [&](uint32_t val, SymbolInfo &si_out) -> bool {
                    if (!opts.db) return false;
                    auto si = opts.db->get_symbol_info(val);
                    if (!si.has_value() || si->struct_name.empty()) return false;
                    if (sanitize_c_ident(strip_struct_kw(si->struct_name), "struct_t") != T) return false;
                    std::string nm = lookup_sym_rename(si->name);
                    if (!is_safe_global_ident(nm)) return false;
                    si_out = *si;
                    si_out.name = nm;
                    return true;
                };
                SymbolInfo si_hit;
                if (s.src->kind == ExprKind::Const && matches_dst_struct(s.src->value, si_hit)) {
                    record_global_sym(si_hit.name, si_hit.base_ea, si_hit.item_size, si_hit.is_array,
                                      si_hit.struct_name, !si_hit.is_array, si_hit.is_array);
                    asg->y = make_obj_expr(si_hit.name, si_hit.base_ea, T + " *", ea);
                    std::string rstr = si_hit.is_array ? si_hit.name : ("&" + si_hit.name);
                    asg->text_cache = asg->x->print1(&cf->lvars) + " = " + rstr;
                    ins->cexpr_node = asg;
                    ins->text_cache = asg->text_cache + ";";
                    return ins;
                }
                if (s.src->kind == ExprKind::Bin && (s.src->op == "+" || s.src->op == "-")) {
                    ExprPtr c_op, idx_op;
                    if (s.src->l && s.src->l->kind == ExprKind::Const && matches_dst_struct(s.src->l->value, si_hit)) {
                        c_op = s.src->l;
                        idx_op = s.src->r;
                    } else if (s.src->op == "+" && s.src->r && s.src->r->kind == ExprKind::Const &&
                               matches_dst_struct(s.src->r->value, si_hit)) {
                        c_op = s.src->r;
                        idx_op = s.src->l;
                    }
                    if (c_op && idx_op) {
                        record_global_sym(si_hit.name, si_hit.base_ea, si_hit.item_size, si_hit.is_array,
                                          si_hit.struct_name, !si_hit.is_array, si_hit.is_array);
                        cexpr_t *idx_ce = build_cexpr(idx_op, ea);
                        asg->y = idx_ce;
                        std::string base_addr = si_hit.is_array ? ("(uint8_t *)" + si_hit.name)
                                                                : ("(uint8_t *)&" + si_hit.name);
                        std::string off_str = idx_ce->print1(&cf->lvars);
                        if (si_hit.offset > 0) off_str = "(" + off_str + ") + " + std::to_string(si_hit.offset);
                        asg->text_cache = asg->x->print1(&cf->lvars) + " = (" + T + " *)(" + base_addr + " " +
                                          s.src->op + " (" + off_str + "))";
                        ins->cexpr_node = asg;
                        ins->text_cache = asg->text_cache + ";";
                        return ins;
                    }
                }
                bool same_struct_var = false;
                if (s.src->kind == ExprKind::Var || s.src->kind == ExprKind::StackVar || s.src->kind == ExprKind::Reg) {
                    auto sit2 = var_structs.find(s.src->name);
                    if (sit2 != var_structs.end() &&
                        sanitize_c_ident(strip_struct_kw(sit2->second), "struct_t") == T) {
                        same_struct_var = true;
                    }
                }
                asg->y = build_cexpr(s.src, ea);
                if (!same_struct_var) {
                    asg->text_cache = asg->x->print1(&cf->lvars) + " = (" + T + " *)(uintptr_t)(" +
                                      asg->y->print1(&cf->lvars) + ")";
                    ins->cexpr_node = asg;
                    ins->text_cache = asg->text_cache + ";";
                    return ins;
                }
            } else {
                asg->y = build_cexpr(s.src, ea);
            }
            asg->text_cache = asg->x->print1(&cf->lvars) + " = " + asg->y->print1(&cf->lvars);
            ins->cexpr_node = asg;
            ins->text_cache = asg->text_cache + ";";
            return ins;
        }
        if (s.kind == StmtKind::Swap) {
            // Emit valid C swap via comma or inline helper comment? Wait: emit valid C block!
            // `_tmp = a; a = b; b = _tmp;` Wait: single cinsn_t block!
            cinsn_t *blk = cf->alloc_insn(cit_block, ea);
            cexpr_t *va = build_cexpr(s.a, ea);
            cexpr_t *vb = build_cexpr(s.b, ea);
            std::string tnm = "_swap_tmp";
            int tidx = ensure_lvar(tnm, s.a ? s.a->width : Width::B, false);
            auto emit_asg = [&](cexpr_t *lhs, cexpr_t *rhs) {
                cinsn_t *i = cf->alloc_insn(cit_expr, ea);
                cexpr_t *a = cf->alloc_expr(cot_asg, ea);
                a->x = lhs;
                a->y = rhs;
                a->text_cache = lhs->print1(&cf->lvars) + " = " + rhs->print1(&cf->lvars);
                i->cexpr_node = a;
                i->text_cache = a->text_cache + ";";
                blk->cblock.push_back(i);
            };
            cexpr_t *tv = cf->alloc_expr(cot_var, ea);
            tv->v.idx = tidx;
            tv->helper = cf->lvars[tidx].name;
            tv->text_cache = cf->lvars[tidx].name;
            emit_asg(tv, va);
            emit_asg(va, vb);
            emit_asg(vb, tv);
            return blk;
        }
        if (s.kind == StmtKind::Call) {
            cinsn_t *ins = cf->alloc_insn(cit_expr, ea);
            cexpr_t *call = cf->alloc_expr(cot_call, ea);
            std::string callee;
            auto is_data_label_name = [](const std::string &nm) {
                return nm.rfind("byte_", 0) == 0 || nm.rfind("word_", 0) == 0 ||
                       nm.rfind("dword_", 0) == 0 || nm.rfind("unk_", 0) == 0 ||
                       nm.rfind("asc_", 0) == 0 || nm.rfind("off_", 0) == 0 ||
                       nm.rfind("stru_", 0) == 0;
            };
            bool direct_target_as_fptr = false;
            if (s.target.has_value()) {
                if (opts.db) {
                    if (auto nm = opts.db->get_func_name(*s.target); nm.has_value()) callee = *nm;
                    else if (auto snm = opts.db->get_symbol_name(*s.target); snm.has_value()) callee = *snm;
                }
                if (callee.empty()) {
                    char buf[32];
                    std::snprintf(buf, sizeof(buf), "sub_%X", *s.target);
                    callee = buf;
                } else {
                    callee = sanitize_c_ident(callee, "sub_fn");
                }
                if (opts.db && !opts.db->get_func_start(*s.target).has_value() && is_data_label_name(callee)) {
                    direct_target_as_fptr = true;
                } else {
                    cexpr_t *fn = cf->alloc_expr(cot_obj, ea);
                    fn->obj_ea = *s.target;
                    fn->helper = callee;
                    fn->text_cache = callee;
                    call->x = fn;
                    cf->call_eas[callee] = *s.target;
                    cf->sym_eas[callee] = *s.target;
                }
            }
            if (!s.target.has_value() || direct_target_as_fptr) {
                if (direct_target_as_fptr) {
                    cexpr_t *addr_n = cf->alloc_expr(cot_num, ea);
                    addr_n->n._value = *s.target;
                    addr_n->n.bits = 20;
                    addr_n->n.repr = format_hex(*s.target, 20);
                    addr_n->text_cache = addr_n->n.repr;
                    call->x = addr_n;
                } else {
                    call->x = build_cexpr(s.expr, ea);
                }
                std::string ret_t = s.dst ? width_ctype(s.dst->width) : std::string("void");
                std::string param_t;
                if (s.args.empty()) {
                    param_t = "void";
                } else {
                    for (size_t i = 0; i < s.args.size(); ++i) {
                        if (i > 0) param_t += ", ";
                        param_t += s.args[i] ? width_ctype(s.args[i]->width) : std::string("uint16_t");
                    }
                }
                callee = "((" + ret_t + " (*)(" + param_t + "))(uintptr_t)(" + call->x->print1(&cf->lvars) + "))";
            }
            std::ostringstream args_os;
            for (size_t i = 0; i < s.args.size(); ++i) {
                cexpr_t *ae = build_cexpr(s.args[i], ea);
                call->a.push_back(ae);
                if (i > 0) args_os << ", ";
                args_os << ae->print1(&cf->lvars);
            }
            call->text_cache = callee + "(" + args_os.str() + ")";

            if (s.dst) {
                cexpr_t *asg = cf->alloc_expr(cot_asg, ea);
                asg->x = build_cexpr(s.dst, ea);
                asg->y = call;
                asg->text_cache = asg->x->print1(&cf->lvars) + " = " + call->text_cache;
                ins->cexpr_node = asg;
                ins->text_cache = asg->text_cache + ";";
            } else {
                ins->cexpr_node = call;
                ins->text_cache = call->text_cache + ";";
            }
            return ins;
        }
        if (s.kind == StmtKind::Intrinsic) {
            if (s.name == "set_bit" && !s.args.empty() && s.args[0] && s.args[0]->kind == ExprKind::Bit) {
                cinsn_t *ins = cf->alloc_insn(cit_expr, ea);
                std::string mask_hex;
                std::string bs = stmt_bit_expr_lval(s.args[0], ea, mask_hex);
                cexpr_t *asg = cf->alloc_expr(cot_asgbor, ea);
                asg->x = build_cexpr(s.args[0]->base, ea);
                asg->text_cache = bs + " |= " + mask_hex;
                ins->cexpr_node = asg;
                ins->text_cache = asg->text_cache + ";";
                return ins;
            }
            if (s.name == "clr_bit" && !s.args.empty() && s.args[0] && s.args[0]->kind == ExprKind::Bit) {
                return build_bitclr_assign(s.args[0]->base, s.args[0]->bit, ea);
            }
            if (s.name == "xor_bit" && !s.args.empty() && s.args[0] && s.args[0]->kind == ExprKind::Bit) {
                cinsn_t *ins = cf->alloc_insn(cit_expr, ea);
                std::string mask_hex;
                std::string bs = stmt_bit_expr_lval(s.args[0], ea, mask_hex);
                cexpr_t *asg = cf->alloc_expr(cot_asgxor, ea);
                asg->x = build_cexpr(s.args[0]->base, ea);
                asg->text_cache = bs + " ^= " + mask_hex;
                ins->cexpr_node = asg;
                ins->text_cache = asg->text_cache + ";";
                return ins;
            }
            if (s.name == "brk") {
                cinsn_t *ins = cf->alloc_insn(cit_expr, ea);
                cexpr_t *call = cf->alloc_expr(cot_call, ea);
                call->helper = "brk";
                call->text_cache = "brk()";
                ins->cexpr_node = call;
                ins->text_cache = "brk();";
                return ins;
            }
            if (s.name == "goto" && !s.args.empty()) {
                cinsn_t *ins = cf->alloc_insn(cit_expr, ea);
                cexpr_t *call = cf->alloc_expr(cot_call, ea);
                call->helper = "JUMPOUT";
                cexpr_t *ae = build_cexpr(s.args[0], ea);
                call->a.push_back(ae);
                call->text_cache = "JUMPOUT((uint32_t)(" + ae->print1(&cf->lvars) + "))";
                ins->cexpr_node = call;
                ins->text_cache = call->text_cache + ";";
                return ins;
            }
            if (s.name == "nop" || s.name == "push" || s.name == "pop") {
                return nullptr;
            }
            cinsn_t *ins = cf->alloc_insn(cit_expr, ea);
            cexpr_t *call = cf->alloc_expr(cot_call, ea);
            call->helper = s.name;
            std::ostringstream os;
            os << s.name << "(";
            for (size_t i = 0; i < s.args.size(); ++i) {
                ExprPtr arg_e = s.args[i];
                if (s.name == "sel" && arg_e && arg_e->kind == ExprKind::Reg && arg_e->name.rfind("rb", 0) == 0) {
                    arg_e = Expr::make_const(static_cast<uint32_t>(std::atoi(arg_e->name.c_str() + 2)), Width::B);
                }
                cexpr_t *ae = build_cexpr(arg_e, ea);
                call->a.push_back(ae);
                if (i > 0) os << ", ";
                os << ae->print1(&cf->lvars);
            }
            os << ")";
            call->text_cache = os.str();
            ins->cexpr_node = call;
            ins->text_cache = call->text_cache + ";";
            return ins;
        }
        return nullptr;
    }

    cinsn_t *build_snode_list(const std::vector<SNodePtr> &nodes, uint64_t block_ea = UINT64_MAX) {
        cinsn_t *blk = cf->alloc_insn(cit_block, block_ea);
        int pending_label_num = -1;
        std::string pending_label_name;

        auto attach_pending_label = [&](cinsn_t *ins) {
            if (pending_label_num >= 0 && ins) {
                ins->label_num = pending_label_num;
                ins->label_name = pending_label_name;
                pending_label_num = -1;
                pending_label_name.clear();
            }
        };

        auto flush_pending_label_as_empty = [&]() {
            if (pending_label_num >= 0) {
                cinsn_t *empty_ins = cf->alloc_insn(cit_expr, static_cast<uint64_t>(pending_label_num));
                empty_ins->text_cache = ";";
                attach_pending_label(empty_ins);
                blk->cblock.push_back(empty_ins);
            }
        };

        for (const auto &n : nodes) {
            if (n->kind == SNodeKind::Label) {
                flush_pending_label_as_empty();
                pending_label_num = static_cast<int>(n->ea);
                pending_label_name = label_name_for(n->ea);
                continue;
            }
            if (n->kind == SNodeKind::Stmt && n->stmt) {
                if (frame_info.hidden_stmts.count(n->stmt->id)) continue;
                cinsn_t *ins = build_cinsn_stmt(*n->stmt);
                if (ins) {
                    if (auto cit = opts.user_data.comments.find(
                            [&]() { char b[32]; std::snprintf(b, sizeof(b), "0x%llx", static_cast<unsigned long long>(n->ea)); return std::string(b); }());
                        cit != opts.user_data.comments.end()) {
                        ins->user_cmt = cit->second;
                    }
                    attach_pending_label(ins);
                    blk->cblock.push_back(ins);
                }
                continue;
            }
            if (n->kind == SNodeKind::Ret) {
                cinsn_t *ins = cf->alloc_insn(cit_return, n->ea);
                if (n->val && sig.ret_type != "void") {
                    cur_line_op_idx = 0;
                    ins->creturn.expr = build_cexpr(n->val, n->ea);
                    ins->text_cache = "return " + ins->creturn.expr->print1(&cf->lvars) + ";";
                } else {
                    ins->text_cache = "return;";
                }
                attach_pending_label(ins);
                blk->cblock.push_back(ins);
                continue;
            }
            if (n->kind == SNodeKind::Goto) {
                cinsn_t *ins = cf->alloc_insn(cit_goto, n->ea);
                ins->cgoto.label_num = static_cast<int>(n->ea);
                ins->cgoto.target_name = label_name_for(n->ea);
                ins->text_cache = "goto " + ins->cgoto.target_name + ";";
                attach_pending_label(ins);
                blk->cblock.push_back(ins);
                continue;
            }
            if (n->kind == SNodeKind::Break) {
                cinsn_t *ins = cf->alloc_insn(cit_break, n->ea);
                attach_pending_label(ins);
                blk->cblock.push_back(ins);
                continue;
            }
            if (n->kind == SNodeKind::Continue) {
                cinsn_t *ins = cf->alloc_insn(cit_continue, n->ea);
                attach_pending_label(ins);
                blk->cblock.push_back(ins);
                continue;
            }
            if (n->kind == SNodeKind::BreakIf) {
                ExprPtr cond = n->cond;
                if (opts.user_data.is_iflag_inverted(n->ea)) cond = negate_cond(cond);
                cinsn_t *ifn = cf->alloc_insn(cit_if, n->ea);
                cur_line_op_idx = 0;
                ifn->cif.expr = build_cexpr(cond, n->ea);
                cinsn_t *tb = cf->alloc_insn(cit_block, n->ea);
                if (n->btclr_clear && n->btclr_base) {
                    tb->cblock.push_back(build_bitclr_assign(n->btclr_base, n->btclr_bit, n->ea));
                }
                tb->cblock.push_back(cf->alloc_insn(cit_break, n->ea));
                ifn->cif.ithen = tb;
                attach_pending_label(ifn);
                blk->cblock.push_back(ifn);
                continue;
            }
            if (n->kind == SNodeKind::If) {
                ExprPtr cond = n->cond;
                bool inv = opts.user_data.is_iflag_inverted(n->ea);
                const auto *then_p = &n->then_body;
                const auto *else_p = &n->else_body;
                if (inv) {
                    cond = negate_cond(cond);
                    if (!n->else_body.empty()) {
                        then_p = &n->else_body;
                        else_p = &n->then_body;
                    }
                }
                cinsn_t *ifn = cf->alloc_insn(cit_if, n->ea);
                cur_line_op_idx = 0;
                ifn->cif.expr = build_cexpr(cond, n->ea);
                ifn->cif.ithen = build_snode_list(*then_p, n->ea);
                if (!else_p->empty()) {
                    ifn->cif.ielse = build_snode_list(*else_p, n->ea);
                }
                if (n->btclr_clear && n->btclr_base) {
                    // Only clear the tested bit on the TAKEN path of BTCLR!
                    if (inv) {
                        if (!ifn->cif.ielse) ifn->cif.ielse = cf->alloc_insn(cit_block, n->ea);
                        ifn->cif.ielse->cblock.statements.insert(
                            ifn->cif.ielse->cblock.statements.begin(),
                            build_bitclr_assign(n->btclr_base, n->btclr_bit, n->ea));
                    } else {
                        ifn->cif.ithen->cblock.statements.insert(
                            ifn->cif.ithen->cblock.statements.begin(),
                            build_bitclr_assign(n->btclr_base, n->btclr_bit, n->ea));
                    }
                }
                attach_pending_label(ifn);
                blk->cblock.push_back(ifn);
                continue;
            }
            if (n->kind == SNodeKind::While) {
                cinsn_t *lp = cf->alloc_insn(n->dowhile ? cit_do : cit_while, n->ea);
                cur_line_op_idx = 0;
                lp->cloop.expr = build_cexpr(n->cond, n->ea);
                lp->cloop.body = build_snode_list(n->then_body, n->ea);
                if (n->btclr_clear && n->btclr_base && lp->cloop.body) {
                    lp->cloop.body->cblock.statements.push_back(
                        build_bitclr_assign(n->btclr_base, n->btclr_bit, n->ea));
                }
                attach_pending_label(lp);
                blk->cblock.push_back(lp);
                continue;
            }
            if (n->kind == SNodeKind::Switch) {
                cinsn_t *sw = cf->alloc_insn(cit_switch, n->ea);
                cur_line_op_idx = 0;
                sw->cswitch.expr = build_cexpr(n->switch_expr, n->ea);
                for (const auto &sc : n->cases) {
                    cswitch_case_t cs;
                    cs.values = sc.vals;
                    cs.body = build_snode_list(sc.body, n->ea);
                    sw->cswitch.cases.push_back(std::move(cs));
                }
                if (n->has_default) {
                    sw->cswitch.def_body = build_snode_list(n->default_body, n->ea);
                }
                attach_pending_label(sw);
                blk->cblock.push_back(sw);
                continue;
            }
        }
        flush_pending_label_as_empty();
        return blk;
    }
};

} // namespace

GeneratedCode generate_c(const Function &func,
                         const std::vector<SNodePtr> &tree,
                         const FrameInfo &frame_info,
                         const FunctionSig &sig,
                         const CGenOptions &opts) {
    GeneratedCode out;
    auto cf = std::make_shared<cfunc_t>();
    cf->entry_ea = func.entry;
    cf->func_name = sanitize_c_ident(sig.name.empty() ? func.name : sig.name, "sub_fn");
    cf->ret_type = sig.ret_type;
    cf->hide_casts = opts.hide_casts;

    CGenCtx ctx{func, frame_info, sig, opts, cf, {}, {}, {}, {}, 0};
    ctx.rename_map = opts.user_data.renames;
    ctx.type_map = opts.user_data.types;
    for (const auto &[k, ent] : opts.user_data.lvars) {
        if (!ent.name.empty()) ctx.rename_map[k] = ent.name;
        if (!ent.type.empty()) ctx.type_map[k] = ent.type;
    }
    ctx.var_structs = infer_struct_pointers(func, frame_info, sig, opts);

    // Seed parameter lvars in declared order
    for (const auto &p : sig.params) {
        Width pw = (p.type_str == "uint8_t" || p.type_str == "int8_t") ? Width::B
                 : ((p.type_str == "uint32_t" || p.type_str == "int32_t") ? Width::D : Width::W);
        int idx = ctx.ensure_lvar(p.name, pw, true, p.location.rfind("stk+", 0) == 0);
        if (!p.type_str.empty() && !ctx.type_map.count(p.name)) {
            cf->lvars[idx].type_str = p.type_str;
            cf->var_types[cf->lvars[idx].name] = p.type_str;
        }
        cf->argidx.push_back(idx);
        cf->arg_names.push_back(cf->lvars[idx].name);
        cf->param_types[cf->lvars[idx].name] = cf->lvars[idx].type_str;
    }

    // Build structured ctree body (this populates cf->lvars with all referenced locals too)
    cf->body = ctx.build_snode_list(tree, func.entry);

    // Format header + signature + local variable declarations
    std::vector<std::string> hdr;
    std::vector<std::optional<uint32_t>> hdr_eas;
    if (opts.banner) {
        char buf[96];
        std::snprintf(buf, sizeof(buf), "// Function: %s (0x%05X)", cf->func_name.c_str(), func.entry);
        hdr.push_back(buf);
        hdr_eas.push_back(func.entry);
        if (auto desc = frame_info.describe(); desc.has_value()) {
            hdr.push_back("// Frame: " + *desc);
            hdr_eas.push_back(std::nullopt);
        }
        for (const auto &prob : func.problems) {
            hdr.push_back("// IR problem: " + prob);
            hdr_eas.push_back(std::nullopt);
        }
    }

    std::ostringstream sig_os;
    sig_os << sig.ret_type << " " << cf->func_name << "(";
    if (sig.params.empty()) {
        sig_os << "void";
    } else {
        for (size_t i = 0; i < sig.params.size(); ++i) {
            if (i > 0) sig_os << ", ";
            std::string pname = ctx.display_var_name(sig.params[i].name);
            std::string ptype = cf->param_types.count(pname) ? cf->param_types[pname] : sig.params[i].type_str;
            sig_os << ptype << " " << pname;
        }
    }
    sig_os << ")";
    cf->signature_line = sig_os.str();
    cf->sig_line = static_cast<int>(hdr.size());
    hdr.push_back(cf->signature_line);
    hdr_eas.push_back(func.entry);
    hdr.push_back("{");
    hdr_eas.push_back(std::nullopt);

    bool any_locals = false;
    for (const auto &lv : cf->lvars) {
        if (lv.is_arg_var) continue;
        hdr.push_back("    " + lv.type_str + " " + lv.name + " = 0;");
        hdr_eas.push_back(std::nullopt);
        any_locals = true;
    }
    if (any_locals) {
        hdr.push_back("");
        hdr_eas.push_back(std::nullopt);
    }

    cf->hdrlines = static_cast<int>(hdr.size());
    cf->pseudocode_lines = hdr;
    cf->line_eas.reserve(hdr_eas.size());
    for (const auto &ea_o : hdr_eas) {
        cf->line_eas.push_back(ea_o.has_value() ? std::optional<uint64_t>(*ea_o) : std::nullopt);
    }
    cf->refresh_func_ctext();

    // Populate line_to_eas / ea_to_line for interactive navigation & comment mapping
    out.cfunc = cf;
    out.lines = cf->pseudocode_lines;
    out.line_eas.reserve(cf->line_eas.size());
    for (size_t i = 0; i < cf->line_eas.size(); ++i) {
        if (cf->line_eas[i].has_value()) {
            uint32_t lea = static_cast<uint32_t>(*cf->line_eas[i]);
            out.line_eas.push_back(lea);
            cf->line_to_eas[static_cast<int>(i)].push_back(lea);
            if (!cf->ea_to_line.count(lea)) cf->ea_to_line[lea] = static_cast<int>(i);
        } else {
            out.line_eas.push_back(std::nullopt);
        }
    }

    return out;
}

namespace {

bool is_ident_ch(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

std::string rewrite_conflicting_subscript(std::string src, const std::string &sym) {
    if (sym.empty()) return src;
    size_t pos = 0;
    const std::string needle = sym + "[";
    while ((pos = src.find(needle, pos)) != std::string::npos) {
        if (pos > 0 && (is_ident_ch(src[pos - 1]) || src[pos - 1] == '&' || src[pos - 1] == '.')) {
            pos += needle.size();
            continue;
        }
        // Skip string/char or comment? Good enough: also skip 'extern uint8_t sym[];' though we only emit scalar for conflicts.
        std::string repl = "(&" + sym + ")[";
        src.replace(pos, needle.size(), repl);
        pos += repl.size();
    }
    return src;
}

std::string emit_struct_typedef(const StructDef &sd) {
    std::string sname = sanitize_c_ident(strip_struct_kw(sd.name), "struct_t");
    std::vector<StructMemberInfo> sorted = sd.members;
    std::sort(sorted.begin(), sorted.end(), [](const StructMemberInfo &a, const StructMemberInfo &b) {
        return a.offset < b.offset;
    });
    std::ostringstream os;
    os << "typedef struct " << sname << " {\n";
    int64_t cur = 0;
    std::unordered_set<std::string> used_fields;
    for (const auto &m : sorted) {
        if (m.offset < cur) continue;
        if (m.offset > cur) {
            os << "    uint8_t _pad_" << cur << "[" << (m.offset - cur) << "];\n";
            cur = m.offset;
        }
        int64_t sz = std::max<int64_t>(1, m.size);
        std::string fnm = sanitize_c_ident(m.name, "field");
        if (!used_fields.insert(fnm).second) {
            fnm += "_" + std::to_string(m.offset);
            used_fields.insert(fnm);
        }
        if (sz == 1)      os << "    uint8_t " << fnm << ";\n";
        else if (sz == 2) os << "    uint16_t " << fnm << ";\n";
        else if (sz == 4) os << "    uint32_t " << fnm << ";\n";
        else              os << "    uint8_t " << fnm << "[" << sz << "];\n";
        cur += sz;
    }
    if (cur == 0) os << "    uint8_t _dummy;\n";
    os << "} " << sname << ";\n";
    return os.str();
}

} // namespace

std::string build_listing_with_decls(const IDatabaseProvider &db,
                                     const std::vector<cfuncptr_t> &cfuncs,
                                     const std::vector<std::string> &blocks) {
    std::unordered_set<std::string> func_names;
    std::set<std::string> used_udts;
    std::map<std::string, GlobalSymRef> merged_syms;

    for (const auto &cf : cfuncs) {
        if (!cf) continue;
        if (!cf->func_name.empty()) func_names.insert(cf->func_name);
        for (const auto &u : cf->used_udts) used_udts.insert(u);
        for (const auto &[nm, ref] : cf->global_syms) {
            auto &dst = merged_syms[nm];
            if (dst.base_ea == 0) {
                dst.base_ea = ref.base_ea;
                dst.item_size = ref.item_size;
            }
            dst.is_array = dst.is_array || ref.is_array;
            dst.used_scalar = dst.used_scalar || ref.used_scalar;
            dst.used_indexed = dst.used_indexed || ref.used_indexed;
            if (!ref.struct_name.empty()) dst.struct_name = ref.struct_name;
        }
    }

    std::ostringstream hdr;
    std::set<std::string> emitted_udts;
    for (const auto &raw_udt : used_udts) {
        std::string sname = sanitize_c_ident(strip_struct_kw(raw_udt), "");
        if (sname.empty() || !emitted_udts.insert(sname).second) continue;
        if (auto sd = db.get_udt_info(raw_udt); sd.has_value()) {
            hdr << emit_struct_typedef(*sd);
        } else if (auto sd2 = db.get_udt_info(sname); sd2.has_value()) {
            hdr << emit_struct_typedef(*sd2);
        }
    }
    if (!emitted_udts.empty()) hdr << "\n";

    std::vector<std::string> conflicting_idx_syms;
    bool any_globals = false;
    for (const auto &[nm, ref] : merged_syms) {
        if (sfr_addr_for(nm).has_value() || func_names.count(nm) || is_reserved_c_lib_ident(nm)) continue;
        if (!ref.struct_name.empty() && emitted_udts.count(ref.struct_name)) {
            if (ref.is_array) hdr << "extern " << ref.struct_name << " " << nm << "[];\n";
            else              hdr << "extern " << ref.struct_name << " " << nm << ";\n";
            any_globals = true;
            continue;
        }
        if (ref.is_array) {
            hdr << "extern uint8_t " << nm << "[];\n";
            any_globals = true;
        } else if (ref.used_indexed && !ref.used_scalar) {
            hdr << "extern uint8_t " << nm << "[];\n";
            any_globals = true;
        } else {
            if (ref.used_indexed && ref.used_scalar) {
                conflicting_idx_syms.push_back(nm);
            }
            const char *ty = (ref.item_size >= 4) ? "uint32_t" : ((ref.item_size == 2) ? "uint16_t" : "uint8_t");
            hdr << "extern " << ty << " " << nm << ";\n";
            any_globals = true;
        }
    }
    if (any_globals) hdr << "\n";

    bool any_protos = false;
    std::unordered_set<std::string> emitted_protos;
    for (const auto &cf : cfuncs) {
        if (!cf || cf->signature_line.empty() || cf->func_name.empty()) continue;
        if (!emitted_protos.insert(cf->func_name).second) continue;
        hdr << cf->signature_line << ";\n";
        any_protos = true;
    }
    if (any_protos) hdr << "\n";

    std::ostringstream body;
    for (size_t i = 0; i < blocks.size(); ++i) {
        if (i > 0) body << "\n";
        std::string btxt = blocks[i];
        for (const auto &csym : conflicting_idx_syms) {
            btxt = rewrite_conflicting_subscript(std::move(btxt), csym);
        }
        body << btxt << "\n";
    }
    return hdr.str() + body.str();
}

} // namespace rl78dec
