#include "rl78dec/pipeline.hpp"

#include <algorithm>
#include <cstdio>
#include <set>
#include <sstream>

#include "rl78dec/abi.hpp"
#include "rl78dec/cfg.hpp"
#include "rl78dec/cgen.hpp"
#include "rl78dec/decoder.hpp"
#include "rl78dec/frame.hpp"
#include "rl78dec/opt.hpp"
#include "rl78dec/spill.hpp"
#include "rl78dec/structure.hpp"
#include "rl78dec/vars.hpp"

namespace rl78dec {

namespace {

std::string join_lines(const std::vector<std::string> &lines) {
    std::ostringstream os;
    for (size_t i = 0; i < lines.size(); ++i) {
        if (i > 0) os << '\n';
        os << lines[i];
    }
    return os.str();
}

} // namespace

DecompileResult decompile_decoded_function(const IDatabaseProvider &db,
                                           const DecodedProgram & /*prog*/,
                                           std::unique_ptr<Function> func,
                                           const DecompileOptions &opts) {
    DecompileResult res;
    if (!func) {
        res.error = "Null function";
        return res;
    }

    res.entry_ea = func->entry;
    if (func->name.empty()) {
        if (auto nm = db.get_func_name(func->entry); nm.has_value()) func->name = *nm;
        else if (auto snm = db.get_symbol_name(func->entry); snm.has_value()) func->name = *snm;
        else {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "sub_%X", func->entry);
            func->name = buf;
        }
    }
    res.func_name = func->name;

    // 1. Analyze stack frame & prologue/epilogue
    auto ida_frame = db.get_ida_frame_info(func->entry);
    FrameInfo frame_info = analyze_frame(*func, ida_frame ? &*ida_frame : nullptr);

    // 2. Optimize (folds ES:, constants, and bank GPR aliases into instructions and flags)
    optimize(*func, opts.default_bank, &db);

    // 3. Eliminate register spills / stack noise
    eliminate_spills(*func, frame_info);

    // 3b. Duplicate pure-epilogue Ret blocks into Goto/Fall predecessors & thread known-flag jumps
    duplicate_epilogue_returns(*func, frame_info);
    thread_condition_jumps(*func, frame_info);

    // 4. Resolve Z/CY flags ONCE after folding so branches inherit folded FlagDefs + carry chains
    resolve_flags(*func);
    for (const auto &[bid, blk] : func->blocks) {
        for (const auto &st : blk->stmts) {
            if (st && (st->kind == StmtKind::Assign || st->kind == StmtKind::Compare)) {
                st->z_flag.reset();
                st->cy_flag.reset();
            }
        }
    }

    // 5. Infer signature & calling convention
    std::string uproto = opts.user_data.proto.value_or("");
    if (uproto.empty()) {
        if (auto idap = db.get_ida_func_proto(func->entry); idap.has_value()) {
            uproto = *idap;
        }
    }
    auto consensus = db.get_caller_consensus(func->entry);
    FunctionSig sig = analyze_calling_convention(
        *func, frame_info, &db, uproto, consensus ? &*consensus : nullptr);

    // 6. Variable web recovery & subregister handling
    recover_variables(*func, sig, frame_info, &db);

    // 7. Second optimization pass over recovered variables (never synthesize raw GPR aliases)
    optimize(*func, opts.default_bank, &db, false);

    // 7b. Eliminate dead synthetic variables & inline single-use compiler temporaries
    eliminate_dead_and_single_use_vars(*func, frame_info, sig, opts.user_data);

    // 8. Optional IR integrity check
    if (opts.verify_ir) {
        verify_ir(*func);
    }

    // 9. Dump IR text for diagnostic views
    {
        auto ir_lines = format_ir_lines(*func);
        std::ostringstream ir_os;
        for (size_t i = 0; i < ir_lines.size(); ++i) {
            if (i > 0) ir_os << '\n';
            ir_os << ir_lines[i].first;
        }
        res.ir_dump = ir_os.str();
    }

    // 10. Structure CFG (omitting frame_info.hidden_stmts) and generate C + cfunc_t
    auto tree = structure(*func, &frame_info);
    CGenOptions cg_opts;
    cg_opts.db = &db;
    cg_opts.user_data = opts.user_data;
    cg_opts.banner = opts.banner;
    GeneratedCode gen = generate_c(*func, tree, frame_info, sig, cg_opts);

    res.ok = true;
    res.lines = std::move(gen.lines);
    res.line_eas = std::move(gen.line_eas);
    res.c_text = join_lines(res.lines);
    res.cfunc = std::move(gen.cfunc);
    res.frame_info = std::move(frame_info);
    res.sig = std::move(sig);
    res.ir_func = std::move(func);
    return res;
}

DecompileResult decompile_function(const IDatabaseProvider &db, uint32_t ea,
                                   const DecompileOptions &opts) {
    std::vector<uint32_t> entries = opts.extra_entries;
    if (std::find(entries.begin(), entries.end(), ea) == entries.end()) {
        entries.insert(entries.begin(), ea);
    }
    DecodedProgram prog = decode_recursive(db, entries);
    if (!prog.insns.count(ea)) {
        DecompileResult err;
        err.entry_ea = ea;
        err.error = "No instructions decoded at entry";
        return err;
    }

    std::set<uint32_t> entry_set = prog.calls;
    for (uint32_t e : entries) entry_set.insert(e);

    std::unique_ptr<Function> func = build_func(prog.insns, ea, entry_set);
    if (!func) {
        DecompileResult err;
        err.entry_ea = ea;
        err.error = "Failed to build CFG for function";
        return err;
    }
    return decompile_decoded_function(db, prog, std::move(func), opts);
}

namespace {

class ImageCalleeDbAdapter final : public IDatabaseProvider {
public:
    explicit ImageCalleeDbAdapter(const IDatabaseProvider &base) : base_(base) {}

    void set_callee_sig(uint32_t ea, CalleeSigHint h) { sigs_[ea] = std::move(h); }

    bool is_loaded(uint32_t ea) const override { return base_.is_loaded(ea); }
    size_t image_size() const override { return base_.image_size(); }
    size_t read_bytes(uint32_t ea, uint8_t *buf, size_t len) const override { return base_.read_bytes(ea, buf, len); }
    std::vector<uint32_t> get_func_entries() const override { return base_.get_func_entries(); }
    std::optional<uint32_t> get_func_start(uint32_t ea) const override { return base_.get_func_start(ea); }
    std::optional<std::string> get_symbol_name(uint32_t ea) const override { return base_.get_symbol_name(ea); }
    std::optional<std::string> get_func_name(uint32_t ea) const override { return base_.get_func_name(ea); }
    std::optional<IdaFrameInfo> get_ida_frame_info(uint32_t func_ea) const override { return base_.get_ida_frame_info(func_ea); }
    std::optional<std::string> get_ida_func_proto(uint32_t func_ea) const override { return base_.get_ida_func_proto(func_ea); }
    std::optional<SwitchInfo> get_switch_info(uint32_t br_ea) const override { return base_.get_switch_info(br_ea); }
    std::optional<CallerConsensus> get_caller_consensus(uint32_t func_ea) const override { return base_.get_caller_consensus(func_ea); }
    std::set<std::string> get_callee_preserved_regs(uint32_t callee_ea) const override { return base_.get_callee_preserved_regs(callee_ea); }
    std::optional<bool> callee_expects_ax(uint32_t callee_ea) const override { return base_.callee_expects_ax(callee_ea); }
    bool callee_returns_dword(uint32_t callee_ea) const override { return base_.callee_returns_dword(callee_ea); }
    std::optional<FarParamSpecs> get_callee_far_param_specs(uint32_t callee_ea) const override { return base_.get_callee_far_param_specs(callee_ea); }
    std::optional<CalleeSigHint> get_callee_sig(uint32_t callee_ea) const override {
        if (auto h = base_.get_callee_sig(callee_ea); h.has_value()) return h;
        if (auto it = sigs_.find(callee_ea); it != sigs_.end()) return it->second;
        return std::nullopt;
    }
    std::optional<uint8_t> get_es_at(uint32_t ea) const override { return base_.get_es_at(ea); }
    CalleeEsInfo get_callee_es_effect(uint32_t callee_ea) const override { return base_.get_callee_es_effect(callee_ea); }
    std::optional<SymbolInfo> get_symbol_info(uint32_t ea) const override { return base_.get_symbol_info(ea); }
    std::optional<StructDef> get_udt_info(const std::string &name) const override { return base_.get_udt_info(name); }
    std::optional<std::string> get_symbol_struct(uint32_t ea) const override { return base_.get_symbol_struct(ea); }
    std::vector<StructDef> get_all_udts() const override { return base_.get_all_udts(); }
    std::unordered_map<uint32_t, std::string> get_all_symbol_structs() const override { return base_.get_all_symbol_structs(); }

private:
    const IDatabaseProvider &base_;
    std::unordered_map<uint32_t, CalleeSigHint> sigs_;
};

} // namespace

DecompileImageResult decompile_image(const IDatabaseProvider &db,
                                     const std::vector<uint32_t> &entries,
                                     const DecompileOptions &opts) {
    DecompileImageResult out;
    DecodedProgram prog = decode_recursive(db, entries);

    std::set<uint32_t> entry_set = prog.calls;
    for (uint32_t e : entries) entry_set.insert(e);

    ImageCalleeDbAdapter adapter(db);
    auto funcs = build_functions(prog.insns, prog.calls, entries);
    for (const auto &[fea, _] : funcs) {
        if (db.get_callee_sig(fea).has_value()) continue;
        std::unique_ptr<Function> tmp_fn = build_func(prog.insns, fea, entry_set);
        if (!tmp_fn) continue;
        auto ida_frame = db.get_ida_frame_info(fea);
        FrameInfo fi = analyze_frame(*tmp_fn, ida_frame ? &*ida_frame : nullptr);
        optimize(*tmp_fn, opts.default_bank, &db);
        eliminate_spills(*tmp_fn, fi);
        duplicate_epilogue_returns(*tmp_fn, fi);
        thread_condition_jumps(*tmp_fn, fi);
        resolve_flags(*tmp_fn);
        std::string uproto;
        if (auto idap = db.get_ida_func_proto(fea); idap.has_value()) uproto = *idap;
        auto consensus = db.get_caller_consensus(fea);
        FunctionSig sig = infer_function_sig_only(
            *tmp_fn, fi, &db, uproto, consensus ? &*consensus : nullptr);
        CalleeSigHint hint;
        hint.valid = true;
        hint.ret_type = sig.ret_type;
        for (const auto &p : sig.params) {
            hint.params.push_back(ParamHint{p.type_str, p.location});
        }
        adapter.set_callee_sig(fea, std::move(hint));
    }

    std::vector<cfuncptr_t> cfuncs;
    std::vector<std::string> blocks;
    for (auto &[fea, func] : funcs) {
        DecompileResult r = decompile_decoded_function(adapter, prog, std::move(func), opts);
        if (!r.ok) {
            out.errors.push_back(r.error);
        } else {
            if (r.cfunc) cfuncs.push_back(r.cfunc);
            blocks.push_back(r.c_text);
        }
        out.funcs.emplace(fea, std::move(r));
    }
    out.listing_text = build_listing_with_decls(adapter, cfuncs, blocks);
    return out;
}

} // namespace rl78dec
