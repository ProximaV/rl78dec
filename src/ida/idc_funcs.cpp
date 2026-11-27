#include <ida.hpp>
#include <expr.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>

#include "idc_funcs.hpp"
#include "db.hpp"
#include "ida_provider.hpp"
#include "plugin.hpp"
#include "summary_cache.hpp"
#include "view.hpp"
#include "rl78dec/abi.hpp"
#include "rl78dec/pipeline.hpp"

namespace rl78dec {

namespace {

uint64_t arg_to_ea(idc_value_t &v) {
    idcv_int64(&v);
    return static_cast<uint64_t>(v.i64);
}

int arg_to_int(idc_value_t &v) {
    idcv_long(&v);
    return static_cast<int>(v.num);
}

std::string arg_to_str(idc_value_t &v) {
    idcv_string(&v);
    return v.c_str() ? std::string(v.c_str()) : std::string();
}

error_t idaapi idc_rl78dec_version(idc_value_t *, idc_value_t *res) {
    res->set_string(RL78DEC_VERSION);
    return eOk;
}

error_t idaapi idc_rl78dec_decompile(idc_value_t *argv, idc_value_t *res) {
    if (!is_rl78_database_active()) {
        res->set_string("");
        return eOk;
    }
    uint64_t ea = arg_to_ea(argv[0]);
    std::string err;
    std::string text = decompile_single_to_text(ea, &err);
    res->set_string(text.c_str(), text.size());
    return eOk;
}

error_t idaapi idc_rl78dec_dump_ir(idc_value_t *argv, idc_value_t *res) {
    if (!is_rl78_database_active()) {
        res->set_string("");
        return eOk;
    }
    uint64_t ea = arg_to_ea(argv[0]);
    std::string err;
    std::string text = dump_single_ir_to_text(ea, &err);
    res->set_string(text.c_str(), text.size());
    return eOk;
}

error_t idaapi idc_rl78dec_decompile_all(idc_value_t *argv, idc_value_t *res) {
    if (!is_rl78_database_active()) {
        res->set_long(0);
        return eOk;
    }
    std::string out_path = arg_to_str(argv[0]);
    int ok_cnt = 0, fail_cnt = 0;
    std::string full_text = decompile_all_to_string(false, &ok_cnt, &fail_cnt);
    if (!out_path.empty()) {
        FILE *fp = qfopen(out_path.c_str(), "wb");
        if (!fp) {
            res->set_long(-1);
            return eOk;
        }
        qfwrite(fp, full_text.data(), full_text.size());
        qfclose(fp);
    }
    res->set_long(ok_cnt);
    return eOk;
}

error_t idaapi idc_rl78dec_open_pseudocode(idc_value_t *argv, idc_value_t *res) {
    if (!is_rl78_database_active()) {
        res->set_long(0);
        return eOk;
    }
    uint64_t ea = arg_to_ea(argv[0]);
    int flags = arg_to_int(argv[1]);
    bool ok = global_vdui().open_or_focus(ea, flags, true);
    res->set_long(ok ? 1 : 0);
    return eOk;
}

error_t idaapi idc_rl78dec_rename_lvar(idc_value_t *argv, idc_value_t *res) {
    if (!is_rl78_database_active()) {
        res->set_long(0);
        return eOk;
    }
    uint64_t fea = arg_to_ea(argv[0]);
    if (func_t *pfn = get_func(static_cast<ea_t>(fea))) fea = static_cast<uint64_t>(pfn->start_ea);
    idadb::set_var_rename(fea, arg_to_str(argv[1]), arg_to_str(argv[2]));
    global_summary_cache().invalidate_func(static_cast<uint32_t>(fea));
    if (global_vdui().is_open() && global_vdui().current_func_ea() == fea) {
        global_vdui().refresh_view(true);
    }
    res->set_long(1);
    return eOk;
}

error_t idaapi idc_rl78dec_set_lvar_type(idc_value_t *argv, idc_value_t *res) {
    if (!is_rl78_database_active()) {
        res->set_long(0);
        return eOk;
    }
    uint64_t fea = arg_to_ea(argv[0]);
    if (func_t *pfn = get_func(static_cast<ea_t>(fea))) fea = static_cast<uint64_t>(pfn->start_ea);
    idadb::set_var_type(fea, arg_to_str(argv[1]), arg_to_str(argv[2]));
    global_summary_cache().invalidate_func(static_cast<uint32_t>(fea));
    if (global_vdui().is_open() && global_vdui().current_func_ea() == fea) {
        global_vdui().refresh_view(true);
    }
    res->set_long(1);
    return eOk;
}

error_t idaapi idc_rl78dec_set_proto(idc_value_t *argv, idc_value_t *res) {
    if (!is_rl78_database_active()) {
        res->set_long(0);
        return eOk;
    }
    uint64_t fea = arg_to_ea(argv[0]);
    if (func_t *pfn = get_func(static_cast<ea_t>(fea))) fea = static_cast<uint64_t>(pfn->start_ea);
    std::string proto_str = arg_to_str(argv[1]);
    if (!proto_str.empty() && !parse_prototype(proto_str).has_value()) {
        res->set_long(0);
        return eOk;
    }
    idadb::set_func_proto(fea, proto_str);
    if (!proto_str.empty()) apply_proto_to_ida(static_cast<ea_t>(fea), proto_str);
    global_summary_cache().clear_summaries();
    global_summary_cache().invalidate_func(static_cast<uint32_t>(fea));
    if (global_vdui().is_open()) global_vdui().refresh_view(true);
    res->set_long(1);
    return eOk;
}

error_t idaapi idc_rl78dec_clear_caches(idc_value_t *, idc_value_t *res) {
    global_summary_cache().clear_all();
    res->set_long(1);
    return eOk;
}

static const char kArgsNone[]     = {0};
static const char kArgsEa[]       = {VT_INT64, 0};
static const char kArgsStr[]      = {VT_STR, 0};
static const char kArgsEaLong[]   = {VT_INT64, VT_LONG, 0};
static const char kArgsEaStr[]    = {VT_INT64, VT_STR, 0};
static const char kArgsEaStrStr[] = {VT_INT64, VT_STR, VT_STR, 0};
static const idc_value_t kDefZero(static_cast<sval_t>(0));

static const ext_idcfunc_t kRl78decIdcFuncs[] = {
    {"rl78dec_version",         idc_rl78dec_version,         kArgsNone,     nullptr,   0, 0},
    {"rl78dec_decompile",       idc_rl78dec_decompile,       kArgsEa,       nullptr,   0, EXTFUN_BASE},
    {"rl78dec_dump_ir",         idc_rl78dec_dump_ir,         kArgsEa,       nullptr,   0, EXTFUN_BASE},
    {"rl78dec_decompile_all",   idc_rl78dec_decompile_all,   kArgsStr,      nullptr,   0, EXTFUN_BASE},
    {"rl78dec_open_pseudocode", idc_rl78dec_open_pseudocode, kArgsEaLong,   &kDefZero, 1, EXTFUN_BASE},
    {"rl78dec_rename_lvar",     idc_rl78dec_rename_lvar,     kArgsEaStrStr, nullptr,   0, EXTFUN_BASE},
    {"rl78dec_set_lvar_type",   idc_rl78dec_set_lvar_type,   kArgsEaStrStr, nullptr,   0, EXTFUN_BASE},
    {"rl78dec_set_proto",       idc_rl78dec_set_proto,       kArgsEaStr,    nullptr,   0, EXTFUN_BASE},
    {"rl78dec_clear_caches",    idc_rl78dec_clear_caches,    kArgsNone,     nullptr,   0, 0},
};

} // namespace

void register_rl78dec_idc_funcs() {
    for (const auto &fn : kRl78decIdcFuncs) add_idc_func(fn);
}

void unregister_rl78dec_idc_funcs() {
    for (const auto &fn : kRl78decIdcFuncs) del_idc_func(fn.name);
}

} // namespace rl78dec
