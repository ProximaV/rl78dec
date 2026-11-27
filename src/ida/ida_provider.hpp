#pragma once

#include <ida.hpp>
#include <typeinf.hpp>

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "rl78dec/database.hpp"

namespace rl78dec {

class SummaryCache;

void ensure_rl78_types();
bool parse_c_type_tinfo(const std::string &type_str, tinfo_t *out_tif);
bool apply_proto_to_ida(ea_t ea, const std::string &proto_str);
std::vector<std::string> find_ida_enum_matches(uint64_t val);

class IdaDatabaseProvider : public IDatabaseProvider {
public:
    explicit IdaDatabaseProvider(SummaryCache *cache = nullptr) : cache_(cache) {}

    bool is_loaded(uint32_t ea) const override;
    size_t image_size() const override;
    size_t read_bytes(uint32_t ea, uint8_t *buf, size_t len) const override;

    std::vector<uint32_t> get_func_entries() const override;
    std::optional<uint32_t> get_func_start(uint32_t ea) const override;
    std::optional<std::string> get_symbol_name(uint32_t ea) const override;
    std::optional<std::string> get_func_name(uint32_t ea) const override;

    std::optional<IdaFrameInfo> get_ida_frame_info(uint32_t func_ea) const override;
    std::optional<std::string> get_ida_func_proto(uint32_t func_ea) const override;
    std::optional<SwitchInfo> get_switch_info(uint32_t br_ea) const override;

    std::optional<CallerConsensus> get_caller_consensus(uint32_t func_ea) const override;
    std::set<std::string> get_callee_preserved_regs(uint32_t callee_ea) const override;
    std::optional<bool> callee_expects_ax(uint32_t callee_ea) const override;
    virtual bool callee_returns_dword(uint32_t callee_ea) const override;
    virtual std::optional<FarParamSpecs> get_callee_far_param_specs(uint32_t callee_ea) const override;
    std::optional<CalleeSigHint> get_callee_sig(uint32_t callee_ea) const override;

    std::optional<uint8_t> get_es_at(uint32_t ea) const override;
    CalleeEsInfo get_callee_es_effect(uint32_t callee_ea) const override;
    std::optional<SymbolInfo> get_symbol_info(uint32_t ea) const override;

    std::optional<StructDef> get_udt_info(const std::string &name) const override;
    std::optional<std::string> get_symbol_struct(uint32_t ea) const override;
    std::vector<StructDef> get_all_udts() const override;
    std::unordered_map<uint32_t, std::string> get_all_symbol_structs() const override;

    // Uncached direct helpers used by SummaryCache on cache miss
    std::optional<IdaFrameInfo> compute_frame_info_uncached(uint32_t func_ea) const;
    std::optional<CallerConsensus> compute_caller_consensus_uncached(uint32_t func_ea) const;
    std::set<std::string> compute_callee_preserved_uncached(uint32_t callee_ea) const;
    std::optional<bool> compute_callee_expects_ax_uncached(uint32_t callee_ea) const;
    bool compute_callee_returns_dword_uncached(uint32_t callee_ea) const;
    std::optional<CalleeSigHint> compute_callee_sig_uncached(uint32_t callee_ea) const;
    CalleeEsInfo compute_callee_es_effect_uncached(uint32_t callee_ea) const;
    std::optional<SymbolInfo> compute_symbol_info_uncached(uint32_t ea) const;
    std::vector<StructDef> compute_all_udts_uncached() const;
    std::unordered_map<uint32_t, std::string> compute_all_symbol_structs_uncached() const;

private:
    SummaryCache *cache_ = nullptr;
};

} // namespace rl78dec
