#define RL78DEC_BUILDING_DLL 1

#include <ida.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>

#include "api_dispatch.hpp"
#include "db.hpp"
#include "ida_provider.hpp"
#include "plugin.hpp"
#include "summary_cache.hpp"
#include "view.hpp"

#include "rl78dec/abi.hpp"
#include "rl78dec/ctree.hpp"
#include "rl78dec/pipeline.hpp"
#include "rl78dec/rl78dec_c_api.h"
#include "rl78dec/user_data.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>

namespace rl78dec {

namespace {

struct ApiState {
    uint64_t next_handle = 1;
    std::unordered_map<uint64_t, cfuncptr_t> handles;
    std::unordered_map<const cfunc_t *, uint64_t> ptr_to_handle;
};

ApiState &api_state() {
    static ApiState st;
    return st;
}

uint64_t register_cfunc_handle(const cfuncptr_t &cf) {
    if (!cf) return 0;
    ApiState &st = api_state();
    auto it = st.ptr_to_handle.find(cf.get());
    if (it != st.ptr_to_handle.end()) {
        st.handles[it->second] = cf;
        return it->second;
    }
    uint64_t h = st.next_handle++;
    st.handles[h] = cf;
    st.ptr_to_handle[cf.get()] = h;
    return h;
}

cfuncptr_t lookup_cfunc_handle(uint64_t h) {
    if (h == 0) return nullptr;
    ApiState &st = api_state();
    auto it = st.handles.find(h);
    return (it != st.handles.end()) ? it->second : nullptr;
}

char *dup_cstr(const std::string &s) {
    char *buf = static_cast<char *>(std::malloc(s.size() + 1));
    if (!buf) return nullptr;
    std::memcpy(buf, s.data(), s.size());
    buf[s.size()] = '\0';
    return buf;
}

void append_json_escaped(std::string &out, const std::string &s) {
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char hex[8];
                    std::snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned>(c));
                    out += hex;
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    out.push_back('"');
}

void append_u64_or_null(std::string &out, uint64_t v) {
    if (v == UINT64_MAX) out += "null";
    else out += std::to_string(v);
}

std::string serialize_cfunc_to_json(const cfunc_t &cf, bool include_ctree) {
    std::string out;
    out.reserve(include_ctree ? (cf.treeitems.size() * 128 + 4096) : 4096);

    out += "{";
    out += "\"entry_ea\":" + std::to_string(cf.entry_ea);
    out += ",\"func_name\":"; append_json_escaped(out, cf.func_name);
    out += ",\"ret_type\":"; append_json_escaped(out, cf.ret_type);
    out += ",\"signature_line\":"; append_json_escaped(out, cf.signature_line);
    out += ",\"hdrlines\":" + std::to_string(cf.hdrlines);
    out += ",\"sig_line\":" + std::to_string(cf.sig_line);
    out += ",\"maturity\":" + std::to_string(cf.maturity);
    out += ",\"body_id\":" + (cf.body ? std::to_string(cf.body->obj_id) : std::string("-1"));

    out += ",\"lines\":[";
    for (size_t i = 0; i < cf.pseudocode_lines.size(); ++i) {
        if (i) out.push_back(',');
        append_json_escaped(out, cf.pseudocode_lines[i]);
    }
    out += "]";

    out += ",\"sv\":[";
    for (size_t i = 0; i < cf.sv.size(); ++i) {
        if (i) out.push_back(',');
        append_json_escaped(out, cf.sv[i]);
    }
    out += "]";

    out += ",\"line_eas\":[";
    for (size_t i = 0; i < cf.line_eas.size(); ++i) {
        if (i) out.push_back(',');
        if (cf.line_eas[i].has_value()) out += std::to_string(*cf.line_eas[i]);
        else out += "null";
    }
    out += "]";

    out += ",\"lvars\":[";
    for (size_t i = 0; i < cf.lvars.size(); ++i) {
        if (i) out.push_back(',');
        const auto &lv = cf.lvars[i];
        out += "{\"idx\":" + std::to_string(lv.index);
        out += ",\"name\":"; append_json_escaped(out, lv.name);
        out += ",\"canon\":"; append_json_escaped(out, lv.canonical_name);
        out += ",\"type\":"; append_json_escaped(out, lv.type_str);
        out += ",\"cmt\":"; append_json_escaped(out, lv.cmt);
        out += ",\"width\":" + std::to_string(lv.width);
        out += ",\"defea\":"; append_u64_or_null(out, lv.defea);
        out += ",\"loc_stk\":" + std::string(lv.location.is_stk ? "true" : "false");
        out += ",\"loc_reg\":" + std::to_string(lv.location.reg);
        out += ",\"loc_off\":" + std::to_string(lv.location.stk_off);
        out += ",\"is_arg\":" + std::string(lv.is_arg_var ? "true" : "false");
        out += ",\"is_this\":" + std::string(lv.is_thisarg ? "true" : "false");
        out += ",\"is_res\":" + std::string(lv.is_result_var ? "true" : "false");
        out += ",\"is_stk\":" + std::string(lv.is_stk_var_flag ? "true" : "false");
        out += ",\"user_name\":" + std::string(lv.has_user_name ? "true" : "false");
        out += ",\"user_type\":" + std::string(lv.has_user_type ? "true" : "false");
        out += "}";
    }
    out += "]";

    out += ",\"argidx\":[";
    for (size_t i = 0; i < cf.argidx.size(); ++i) {
        if (i) out.push_back(',');
        out += std::to_string(cf.argidx[i]);
    }
    out += "]";

    out += ",\"eamap\":{";
    bool first_ea = true;
    for (const auto &kv : cf.eamap) {
        if (kv.first == UINT64_MAX) continue;
        if (!first_ea) out.push_back(',');
        first_ea = false;
        out.push_back('"');
        out += std::to_string(kv.first);
        out += "\":[";
        for (size_t j = 0; j < kv.second.size(); ++j) {
            if (j) out.push_back(',');
            out += std::to_string(kv.second[j] ? static_cast<int>(kv.second[j]->obj_id) : -1);
        }
        out.push_back(']');
    }
    out += "}";

    if (include_ctree) {
        out += ",\"items\":[";
        for (size_t i = 0; i < cf.treeitems.size(); ++i) {
            if (i) out.push_back(',');
            const citem_t *it = cf.treeitems[i].get();
            if (!it) { out += "null"; continue; }
            out += "{\"id\":" + std::to_string(it->obj_id);
            out += ",\"op\":" + std::to_string(static_cast<int>(it->op));
            out += ",\"ea\":"; append_u64_or_null(out, it->ea);
            out += ",\"lbl\":" + std::to_string(it->label_num);
            if (!it->label_name.empty()) {
                out += ",\"lbl_name\":"; append_json_escaped(out, it->label_name);
            }
            if (it->is_expr()) {
                const cexpr_t *e = it->cexpr();
                out += ",\"k\":\"e\"";
                out += ",\"ty\":"; append_json_escaped(out, e->type_str);
                if (e->x) out += ",\"x\":" + std::to_string(e->x->obj_id);
                if (e->y) out += ",\"y\":" + std::to_string(e->y->obj_id);
                if (e->z) out += ",\"z\":" + std::to_string(e->z->obj_id);
                if (!e->a.empty()) {
                    out += ",\"a\":[";
                    for (size_t k = 0; k < e->a.size(); ++k) {
                        if (k) out.push_back(',');
                        out += std::to_string(e->a[k] ? static_cast<int>(e->a[k]->obj_id) : -1);
                    }
                    out += "]";
                }
                if (e->op == cot_var) {
                    out += ",\"v\":" + std::to_string(e->v.idx);
                } else if (e->op == cot_num || e->op == cot_fnum) {
                    out += ",\"n\":" + std::to_string(e->n._value);
                    out += ",\"nb\":" + std::to_string(e->n.bits);
                    out += ",\"nr\":"; append_json_escaped(out, e->n.repr);
                } else if (e->op == cot_obj || e->obj_ea != UINT64_MAX) {
                    out += ",\"oea\":"; append_u64_or_null(out, e->obj_ea);
                }
                if (!e->string.empty()) { out += ",\"s\":"; append_json_escaped(out, e->string); }
                if (!e->helper.empty()) { out += ",\"h\":"; append_json_escaped(out, e->helper); }
                out += ",\"txt\":"; append_json_escaped(out, e->print1(&cf.lvars));
            } else {
                const cinsn_t *ins = it->cinsn();
                out += ",\"k\":\"i\"";
                if (ins->op == cit_block) {
                    out += ",\"blk\":[";
                    for (size_t k = 0; k < ins->cblock.statements.size(); ++k) {
                        if (k) out.push_back(',');
                        out += std::to_string(ins->cblock.statements[k]
                                                  ? static_cast<int>(ins->cblock.statements[k]->obj_id)
                                                  : -1);
                    }
                    out += "]";
                } else if (ins->op == cit_expr && ins->cexpr_node) {
                    out += ",\"e\":" + std::to_string(ins->cexpr_node->obj_id);
                } else if (ins->op == cit_if) {
                    out += ",\"ic\":" + std::to_string(ins->cif.expr ? static_cast<int>(ins->cif.expr->obj_id) : -1);
                    out += ",\"it\":" + std::to_string(ins->cif.ithen ? static_cast<int>(ins->cif.ithen->obj_id) : -1);
                    out += ",\"ie\":" + std::to_string(ins->cif.ielse ? static_cast<int>(ins->cif.ielse->obj_id) : -1);
                } else if (ins->op == cit_while || ins->op == cit_do || ins->op == cit_for) {
                    out += ",\"lc\":" + std::to_string(ins->cloop.expr ? static_cast<int>(ins->cloop.expr->obj_id) : -1);
                    out += ",\"lb\":" + std::to_string(ins->cloop.body ? static_cast<int>(ins->cloop.body->obj_id) : -1);
                } else if (ins->op == cit_return && ins->creturn.expr) {
                    out += ",\"re\":" + std::to_string(ins->creturn.expr->obj_id);
                } else if (ins->op == cit_goto) {
                    out += ",\"gl\":" + std::to_string(ins->cgoto.label_num);
                    out += ",\"gt\":"; append_json_escaped(out, ins->cgoto.target_name);
                } else if (ins->op == cit_switch) {
                    out += ",\"se\":" + std::to_string(ins->cswitch.expr ? static_cast<int>(ins->cswitch.expr->obj_id) : -1);
                    out += ",\"sw_cases\":[";
                    for (size_t k = 0; k < ins->cswitch.cases.size(); ++k) {
                        if (k) out.push_back(',');
                        const auto &sc = ins->cswitch.cases[k];
                        out += "{\"vals\":[";
                        for (size_t vi = 0; vi < sc.values.size(); ++vi) {
                            if (vi) out.push_back(',');
                            out += std::to_string(sc.values[vi]);
                        }
                        out += "],\"b\":" + std::to_string(sc.body ? static_cast<int>(sc.body->obj_id) : -1) + "}";
                    }
                    out += "]";
                    out += ",\"sw_def\":" + std::to_string(ins->cswitch.def_body ? static_cast<int>(ins->cswitch.def_body->obj_id) : -1);
                }
                if (!ins->user_cmt.empty()) {
                    out += ",\"cmt\":"; append_json_escaped(out, ins->user_cmt);
                }
            }
            out += "}";
        }
        out += "]";
    }

    out += "}";
    return out;
}

uint64_t normalize_func_ea(uint64_t ea) {
    if (func_t *pfn = get_func(static_cast<ea_t>(ea))) {
        return static_cast<uint64_t>(pfn->start_ea);
    }
    return ea;
}

} // namespace

void clear_api_handles() {
    ApiState &st = api_state();
    st.handles.clear();
    st.ptr_to_handle.clear();
}

bool handle_rl78dec_broadcast(Rl78decBroadcastReq *req) {
    if (!req || req->struct_size != sizeof(Rl78decBroadcastReq)) return false;
    if (!is_rl78_database_active()) {
        req->status = -1;
        return false;
    }

    req->status = 0;
    switch (req->op) {
        case RL78DEC_BCAST_PING:
            req->out_str = RL78DEC_VERSION;
            return true;
        case RL78DEC_BCAST_DECOMPILE_CFUNC: {
            std::string err;
            cfuncptr_t cf = decompile_or_get_cached(req->ea, (req->flags & 1) != 0, &err);
            if (!cf) { req->status = -2; req->out_str = err.c_str(); return true; }
            if (req->ptr_arg) *static_cast<cfuncptr_t *>(req->ptr_arg) = cf;
            req->out_ptr = cf.get();
            return true;
        }
        case RL78DEC_BCAST_DECOMPILE_TEXT: {
            std::string err;
            std::string txt = decompile_single_to_text(req->ea, &err);
            if (txt.empty() && !err.empty()) { req->status = -2; req->out_str = err.c_str(); return true; }
            req->out_str = txt.c_str();
            return true;
        }
        case RL78DEC_BCAST_DUMP_IR_TEXT: {
            std::string err;
            std::string txt = dump_single_ir_to_text(req->ea, &err);
            if (txt.empty() && !err.empty()) { req->status = -2; req->out_str = err.c_str(); return true; }
            req->out_str = txt.c_str();
            return true;
        }
        case RL78DEC_BCAST_OPEN_PSEUDOCODE: {
            bool ok = global_vdui().open_or_focus(req->ea, req->flags, true);
            req->status = ok ? 0 : -1;
            req->out_ptr = ok ? &global_vdui() : nullptr;
            return true;
        }
        case RL78DEC_BCAST_MARK_DIRTY:
            if (req->ea == BADADDR || req->ea == UINT64_MAX) global_summary_cache().clear_all();
            else global_summary_cache().invalidate_func(static_cast<uint32_t>(normalize_func_ea(req->ea)));
            if (global_vdui().is_open()) global_vdui().refresh_view(true);
            return true;
        case RL78DEC_BCAST_CLEAR_CACHES:
            global_summary_cache().clear_all();
            clear_api_handles();
            if (global_vdui().is_open()) global_vdui().refresh_view(true);
            return true;
        default:
            req->status = -1;
            return false;
    }
}

} // namespace rl78dec

extern "C" {

RL78DEC_API_EXPORT const char * __cdecl rl78dec_abi_version(void) {
    return rl78dec::RL78DEC_VERSION;
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_is_rl78_db(void) {
    return rl78dec::is_rl78_database_active() ? 1 : 0;
}

RL78DEC_API_EXPORT void __cdecl rl78dec_abi_free_str(char *s) {
    std::free(s);
}

RL78DEC_API_EXPORT void __cdecl rl78dec_abi_clear_caches(void) {
    rl78dec::global_summary_cache().clear_all();
    rl78dec::clear_api_handles();
}

RL78DEC_API_EXPORT void __cdecl rl78dec_abi_mark_dirty(uint64_t func_ea, int close_views) {
    if (func_ea == BADADDR || func_ea == UINT64_MAX) {
        rl78dec::global_summary_cache().clear_all();
    } else {
        rl78dec::global_summary_cache().invalidate_func(
            static_cast<uint32_t>(rl78dec::normalize_func_ea(func_ea)));
    }
    if (close_views && rl78dec::global_vdui().is_open()) {
        rl78dec::global_vdui().close_and_cleanup();
    } else if (rl78dec::global_vdui().is_open()) {
        rl78dec::global_vdui().refresh_view(true);
    }
}

RL78DEC_API_EXPORT uint64_t __cdecl rl78dec_abi_decompile(uint64_t ea, int flags, char **out_err) {
    if (out_err) *out_err = nullptr;
    if (!rl78dec::is_rl78_database_active()) {
        if (out_err) *out_err = rl78dec::dup_cstr("Active database is not Renesas RL78");
        return 0;
    }
    std::string err;
    const bool no_cache = (flags & 0x0002) != 0;
    rl78dec::cfuncptr_t cf = rl78dec::decompile_or_get_cached(ea, no_cache, &err);
    if (!cf) {
        if (out_err) *out_err = rl78dec::dup_cstr(err.empty() ? "Decompilation failed" : err);
        return 0;
    }
    rl78dec::notify_event(rl78dec::rle_maturity, cf.get());
    rl78dec::notify_event(rl78dec::rle_func_printed, cf.get());
    return rl78dec::register_cfunc_handle(cf);
}

RL78DEC_API_EXPORT void __cdecl rl78dec_abi_release_cfunc(uint64_t handle) {
    auto &st = rl78dec::api_state();
    auto it = st.handles.find(handle);
    if (it != st.handles.end()) {
        st.ptr_to_handle.erase(it->second.get());
        st.handles.erase(it);
    }
}

RL78DEC_API_EXPORT char * __cdecl rl78dec_abi_cfunc_text(uint64_t handle) {
    auto cf = rl78dec::lookup_cfunc_handle(handle);
    if (!cf) return nullptr;
    return rl78dec::dup_cstr(cf->print_func());
}

RL78DEC_API_EXPORT char * __cdecl rl78dec_abi_cfunc_json(uint64_t handle, int include_ctree) {
    auto cf = rl78dec::lookup_cfunc_handle(handle);
    if (!cf) return nullptr;
    return rl78dec::dup_cstr(rl78dec::serialize_cfunc_to_json(*cf, include_ctree != 0));
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_cfunc_mutate_item(
    uint64_t handle, uint32_t obj_id, int new_op, uint64_t new_numval,
    int new_var_idx, const char *new_str, const char *new_helper) {
    auto cf = rl78dec::lookup_cfunc_handle(handle);
    if (!cf) return 0;
    rl78dec::citem_t *it = cf->get_item(obj_id);
    if (!it) return 0;

    if (it->is_expr()) {
        rl78dec::cexpr_t *e = it->cexpr();
        if (new_op >= 0) e->op = static_cast<rl78dec::ctype_t>(new_op);
        if (e->op == rl78dec::cot_num) {
            e->n._value = new_numval;
            e->n.repr.clear();
        }
        if (new_var_idx >= 0) e->v.idx = new_var_idx;
        if (new_str) e->string = new_str;
        if (new_helper) e->helper = new_helper;
        e->mark_mutated();
    } else {
        rl78dec::cinsn_t *ins = it->cinsn();
        if (new_op >= 0) ins->op = static_cast<rl78dec::ctype_t>(new_op);
        if (new_str) ins->user_cmt = new_str;
        ins->mark_mutated();
    }
    return 1;
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_cfunc_swap_if(uint64_t handle, uint32_t if_obj_id) {
    auto cf = rl78dec::lookup_cfunc_handle(handle);
    if (!cf) return 0;
    rl78dec::citem_t *it = cf->get_item(if_obj_id);
    if (!it || it->is_expr()) return 0;
    rl78dec::cinsn_t *ins = it->cinsn();
    if (ins->op != rl78dec::cit_if) return 0;

    std::swap(ins->cif.ithen, ins->cif.ielse);
    if (ins->cif.expr) {
        rl78dec::ctype_t neg = rl78dec::negated_relation(ins->cif.expr->op);
        if (neg != rl78dec::cot_empty) {
            ins->cif.expr->op = neg;
        } else {
            rl78dec::cexpr_t *not_e = cf->alloc_expr(rl78dec::cot_lnot, ins->cif.expr->ea);
            not_e->x = ins->cif.expr;
            not_e->mark_mutated();
            ins->cif.expr = not_e;
        }
        ins->cif.expr->mark_mutated();
    }
    ins->mark_mutated();
    return 1;
}

RL78DEC_API_EXPORT char * __cdecl rl78dec_abi_cfunc_refresh_ctext(uint64_t handle) {
    auto cf = rl78dec::lookup_cfunc_handle(handle);
    if (!cf) return nullptr;
    cf->refresh_func_ctext();
    return rl78dec::dup_cstr(cf->print_func());
}

RL78DEC_API_EXPORT char * __cdecl rl78dec_abi_decompile_text(uint64_t ea, char **out_err) {
    if (out_err) *out_err = nullptr;
    if (!rl78dec::is_rl78_database_active()) {
        if (out_err) *out_err = rl78dec::dup_cstr("Active database is not Renesas RL78");
        return nullptr;
    }
    std::string err;
    std::string txt = rl78dec::decompile_single_to_text(ea, &err);
    if (txt.empty() && !err.empty()) {
        if (out_err) *out_err = rl78dec::dup_cstr(err);
        return nullptr;
    }
    return rl78dec::dup_cstr(txt);
}

RL78DEC_API_EXPORT char * __cdecl rl78dec_abi_dump_ir(uint64_t ea, char **out_err) {
    if (out_err) *out_err = nullptr;
    if (!rl78dec::is_rl78_database_active()) {
        if (out_err) *out_err = rl78dec::dup_cstr("Active database is not Renesas RL78");
        return nullptr;
    }
    std::string err;
    std::string txt = rl78dec::dump_single_ir_to_text(ea, &err);
    if (txt.empty() && !err.empty()) {
        if (out_err) *out_err = rl78dec::dup_cstr(err);
        return nullptr;
    }
    return rl78dec::dup_cstr(txt);
}

RL78DEC_API_EXPORT char * __cdecl rl78dec_abi_decompile_all(const char *out_path, int *out_ok, int *out_fail) {
    if (out_ok) *out_ok = 0;
    if (out_fail) *out_fail = 0;
    if (!rl78dec::is_rl78_database_active()) return rl78dec::dup_cstr("");

    std::string txt = rl78dec::decompile_all_to_string(false, out_ok, out_fail);
    if (out_path && out_path[0] != '\0') {
        FILE *fp = qfopen(out_path, "wb");
        if (fp) {
            qfwrite(fp, txt.data(), txt.size());
            qfclose(fp);
        }
    }
    return rl78dec::dup_cstr(txt);
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_open_pseudocode(uint64_t ea, int open_flags) {
    if (!rl78dec::is_rl78_database_active()) return 0;
    return rl78dec::global_vdui().open_or_focus(ea, open_flags, true) ? 1 : 0;
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_vdui_is_open(void) {
    return (rl78dec::is_rl78_database_active() && rl78dec::global_vdui().is_open()) ? 1 : 0;
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_vdui_refresh(int force_redecompile) {
    if (!rl78dec::is_rl78_database_active() || !rl78dec::global_vdui().is_open()) return 0;
    return rl78dec::global_vdui().refresh_view(force_redecompile != 0) ? 1 : 0;
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_vdui_switch_to(uint64_t ea, int push_history) {
    if (!rl78dec::is_rl78_database_active() || !rl78dec::global_vdui().is_open()) return 0;
    return rl78dec::global_vdui().switch_to(ea, push_history != 0) ? 1 : 0;
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_vdui_get_state(
    uint64_t *out_func_ea, uint64_t *out_cfunc_handle,
    int *out_lineno, int *out_col, uint32_t *out_citem_id) {
    if (!rl78dec::is_rl78_database_active()) return 0;
    rl78dec::Rl78Vdui &v = rl78dec::global_vdui();
    if (!v.is_open() || !v.current_func_ea().has_value()) return 0;

    if (out_func_ea) *out_func_ea = *v.current_func_ea();
    if (out_cfunc_handle) *out_cfunc_handle = rl78dec::register_cfunc_handle(v.cfunc());
    int ln = v.selected_line(), col = 0;
    v.get_cursor_pos(&ln, &col, false);
    if (out_lineno) *out_lineno = ln;
    if (out_col) *out_col = col;
    if (out_citem_id) {
        rl78dec::citem_t *it = v.get_current_citem(false);
        *out_citem_id = it ? it->obj_id : UINT32_MAX;
    }
    return 1;
}

RL78DEC_API_EXPORT char * __cdecl rl78dec_abi_get_user_data_json(uint64_t func_ea) {
    if (!rl78dec::is_rl78_database_active()) return nullptr;
    uint64_t fea = rl78dec::normalize_func_ea(func_ea);
    return rl78dec::dup_cstr(rl78dec::serialize_func_user_data_json(rl78dec::idadb::get_func_data(fea)));
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_set_user_data_json(uint64_t func_ea, const char *json_str) {
    if (!rl78dec::is_rl78_database_active() || !json_str) return 0;
    uint64_t fea = rl78dec::normalize_func_ea(func_ea);
    rl78dec::FuncUserData ud;
    if (!rl78dec::parse_func_user_data_json(json_str, ud)) return 0;
    rl78dec::idadb::set_func_data(fea, ud);
    rl78dec::global_summary_cache().invalidate_func(static_cast<uint32_t>(fea));
    if (rl78dec::global_vdui().is_open() && rl78dec::global_vdui().current_func_ea() == fea) {
        rl78dec::global_vdui().refresh_view(true);
    }
    return 1;
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_rename_lvar(uint64_t func_ea, const char *old_name, const char *new_name) {
    if (!rl78dec::is_rl78_database_active() || !old_name || !new_name) return 0;
    uint64_t fea = rl78dec::normalize_func_ea(func_ea);
    rl78dec::idadb::set_var_rename(fea, old_name, new_name);
    rl78dec::global_summary_cache().invalidate_func(static_cast<uint32_t>(fea));
    if (rl78dec::global_vdui().is_open() && rl78dec::global_vdui().current_func_ea() == fea) {
        rl78dec::global_vdui().refresh_view(true);
    }
    return 1;
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_set_lvar_type(uint64_t func_ea, const char *var_name, const char *type_str) {
    if (!rl78dec::is_rl78_database_active() || !var_name || !type_str) return 0;
    uint64_t fea = rl78dec::normalize_func_ea(func_ea);
    rl78dec::idadb::set_var_type(fea, var_name, type_str);
    rl78dec::global_summary_cache().invalidate_func(static_cast<uint32_t>(fea));
    if (rl78dec::global_vdui().is_open() && rl78dec::global_vdui().current_func_ea() == fea) {
        rl78dec::global_vdui().refresh_view(true);
    }
    return 1;
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_set_proto(uint64_t func_ea, const char *proto_str) {
    if (!rl78dec::is_rl78_database_active() || !proto_str) return 0;
    uint64_t fea = rl78dec::normalize_func_ea(func_ea);
    std::string s(proto_str);
    if (!s.empty() && !rl78dec::parse_prototype(s).has_value()) return 0;
    rl78dec::idadb::set_func_proto(fea, s);
    if (!s.empty()) rl78dec::apply_proto_to_ida(static_cast<ea_t>(fea), s);
    else del_tinfo(static_cast<ea_t>(fea));
    rl78dec::global_summary_cache().clear_summaries();
    rl78dec::global_summary_cache().invalidate_func(static_cast<uint32_t>(fea));
    if (rl78dec::global_vdui().is_open()) rl78dec::global_vdui().refresh_view(true);
    return 1;
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_set_cmt(uint64_t func_ea, uint64_t stmt_ea, const char *cmt_str) {
    if (!rl78dec::is_rl78_database_active() || !cmt_str) return 0;
    uint64_t fea = rl78dec::normalize_func_ea(func_ea);
    rl78dec::idadb::set_statement_cmt(fea, stmt_ea, cmt_str);
    rl78dec::global_summary_cache().invalidate_func(static_cast<uint32_t>(fea));
    if (rl78dec::global_vdui().is_open() && rl78dec::global_vdui().current_func_ea() == fea) {
        rl78dec::global_vdui().refresh_view(true);
    }
    return 1;
}

RL78DEC_API_EXPORT char * __cdecl rl78dec_abi_get_cmt(uint64_t func_ea, uint64_t stmt_ea) {
    if (!rl78dec::is_rl78_database_active()) return nullptr;
    uint64_t fea = rl78dec::normalize_func_ea(func_ea);
    auto cmt = rl78dec::idadb::get_statement_cmt(fea, stmt_ea);
    return cmt.has_value() ? rl78dec::dup_cstr(*cmt) : nullptr;
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_set_numform(uint64_t func_ea, uint64_t stmt_ea, int op_idx, const char *form_str) {
    if (!rl78dec::is_rl78_database_active() || !form_str) return 0;
    uint64_t fea = rl78dec::normalize_func_ea(func_ea);
    rl78dec::idadb::set_numform(fea, stmt_ea, op_idx, form_str);
    rl78dec::global_summary_cache().invalidate_func(static_cast<uint32_t>(fea));
    if (rl78dec::global_vdui().is_open() && rl78dec::global_vdui().current_func_ea() == fea) {
        rl78dec::global_vdui().refresh_view(true);
    }
    return 1;
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_invert_if(uint64_t func_ea, uint64_t branch_ea) {
    if (!rl78dec::is_rl78_database_active()) return 0;
    uint64_t fea = rl78dec::normalize_func_ea(func_ea);
    bool inv = rl78dec::idadb::toggle_iflag(fea, branch_ea);
    rl78dec::global_summary_cache().invalidate_func(static_cast<uint32_t>(fea));
    if (rl78dec::global_vdui().is_open() && rl78dec::global_vdui().current_func_ea() == fea) {
        rl78dec::global_vdui().refresh_view(true);
    }
    return inv ? 1 : 0;
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_get_hide_casts(void) {
    return rl78dec::idadb::get_hide_casts() ? 1 : 0;
}

RL78DEC_API_EXPORT void __cdecl rl78dec_abi_set_hide_casts(int hide) {
    rl78dec::idadb::set_hide_casts(hide != 0);
    if (rl78dec::global_vdui().is_open()) rl78dec::global_vdui().refresh_view(true);
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_reset_overrides(uint64_t func_ea) {
    if (!rl78dec::is_rl78_database_active()) return 0;
    uint64_t fea = rl78dec::normalize_func_ea(func_ea);
    rl78dec::idadb::clear_func_overrides(fea);
    rl78dec::global_summary_cache().clear_summaries();
    rl78dec::global_summary_cache().invalidate_func(static_cast<uint32_t>(fea));
    if (rl78dec::global_vdui().is_open()) rl78dec::global_vdui().refresh_view(true);
    return 1;
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_register_callback(rl78dec_abi_event_cb_t cb, void *ud) {
    if (!cb) return -1;
    return rl78dec::register_event_callback(
        [cb, ud](rl78dec::rl78dec_event_t ev, void *arg0, void *arg1) -> int {
            uint64_t cf_handle = 0;
            uint64_t aux = 0;
            if (ev == rl78dec::rle_maturity || ev == rl78dec::rle_func_printed) {
                auto *cf_raw = static_cast<rl78dec::cfunc_t *>(arg0);
                if (cf_raw) {
                    rl78dec::cfuncptr_t alias(std::shared_ptr<rl78dec::cfunc_t>{}, cf_raw);
                    cf_handle = rl78dec::register_cfunc_handle(alias);
                }
                if (ev == rl78dec::rle_maturity) aux = 7;
            } else if (ev >= rl78dec::rle_open_pseudocode && ev <= rl78dec::rle_populating_popup) {
                auto *v = static_cast<rl78dec::Rl78Vdui *>(arg0);
                if (v && v->cfunc()) cf_handle = rl78dec::register_cfunc_handle(v->cfunc());
                if (ev == rl78dec::rle_keyboard && arg1) aux = static_cast<uint64_t>(*static_cast<int *>(arg1));
            }
            return cb(static_cast<int>(ev), cf_handle, aux, ud);
        });
}

RL78DEC_API_EXPORT int __cdecl rl78dec_abi_unregister_callback(int cb_handle) {
    return rl78dec::unregister_event_callback(cb_handle) ? 1 : 0;
}

} // extern "C"
