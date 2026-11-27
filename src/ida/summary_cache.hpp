#pragma once

#include <ida.hpp>
#include <idp.hpp>

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "rl78dec/ctree.hpp"
#include "rl78dec/database.hpp"

namespace rl78dec {

class IdaDatabaseProvider;

class SummaryCache : public event_listener_t {
public:
    SummaryCache() = default;
    ~SummaryCache() override = default;

    ssize_t idaapi on_event(ssize_t code, va_list va) override;

    void clear_all();
    void clear_summaries();
    void invalidate_func(uint32_t func_ea);
    void invalidate_names_and_symbols();
    void invalidate_types();

    cfuncptr_t get_cached_cfunc(uint32_t func_ea) const;
    void put_cached_cfunc(uint32_t func_ea, cfuncptr_t cf);

    std::optional<std::string> get_func_name(uint32_t ea);
    std::optional<std::string> get_symbol_name(uint32_t ea);
    std::optional<SymbolInfo> get_symbol_info(const IdaDatabaseProvider &prov, uint32_t ea);
    CalleeEsInfo get_callee_es_effect(const IdaDatabaseProvider &prov, uint32_t callee_ea);
    std::vector<StructDef> get_all_udts(const IdaDatabaseProvider &prov);
    std::unordered_map<uint32_t, std::string> get_all_symbol_structs(const IdaDatabaseProvider &prov);
    std::optional<IdaFrameInfo> get_frame_info(uint32_t func_ea);
    std::optional<CallerConsensus> get_caller_consensus(const IdaDatabaseProvider &prov, uint32_t func_ea);
    std::set<std::string> get_callee_preserved(const IdaDatabaseProvider &prov, uint32_t callee_ea);
    std::optional<bool> callee_expects_ax(const IdaDatabaseProvider &prov, uint32_t callee_ea);
    bool callee_returns_dword(const IdaDatabaseProvider &prov, uint32_t callee_ea);
    std::optional<CalleeSigHint> get_callee_sig(const IdaDatabaseProvider &prov, uint32_t callee_ea);

private:
    std::unordered_map<uint32_t, cfuncptr_t> cfunc_cache_;
    std::unordered_map<uint32_t, std::optional<std::string>> func_names_;
    std::unordered_map<uint32_t, std::optional<std::string>> symbol_names_;
    std::unordered_map<uint32_t, std::optional<SymbolInfo>> symbol_infos_;
    std::unordered_map<uint32_t, CalleeEsInfo> callee_es_effects_;
    std::unordered_set<uint32_t> es_active_;
    std::optional<std::vector<StructDef>> all_udts_;
    std::optional<std::unordered_map<uint32_t, std::string>> all_sym_structs_;
    std::unordered_map<uint32_t, std::optional<IdaFrameInfo>> frame_infos_;
    std::unordered_map<uint32_t, std::optional<CallerConsensus>> consensus_;
    std::unordered_map<uint32_t, std::set<std::string>> preserved_regs_;
    std::unordered_map<uint32_t, std::optional<bool>> expects_ax_;
    std::unordered_map<uint32_t, bool> returns_dword_;
    std::unordered_map<uint32_t, std::optional<CalleeSigHint>> sig_cache_;
    std::unordered_set<uint32_t> sig_active_;
};

SummaryCache &global_summary_cache();

} // namespace rl78dec
