#include <ida.hpp>
#include <funcs.hpp>
#include <idp.hpp>
#include <name.hpp>

#include "summary_cache.hpp"
#include "ida_provider.hpp"

#include <cstdio>

namespace rl78dec {

SummaryCache &global_summary_cache() {
    static SummaryCache s_cache;
    return s_cache;
}

void SummaryCache::clear_all() {
    clear_summaries();
    func_names_.clear();
    symbol_names_.clear();
    symbol_infos_.clear();
    all_udts_.reset();
    all_sym_structs_.reset();
    frame_infos_.clear();
    cfunc_cache_.clear();
}

void SummaryCache::clear_summaries() {
    consensus_.clear();
    preserved_regs_.clear();
    expects_ax_.clear();
    returns_dword_.clear();
    sig_cache_.clear();
    callee_es_effects_.clear();
}

void SummaryCache::invalidate_func(uint32_t func_ea) {
    cfunc_cache_.erase(func_ea);
    frame_infos_.erase(func_ea);
    consensus_.erase(func_ea);
    preserved_regs_.erase(func_ea);
    expects_ax_.erase(func_ea);
    returns_dword_.erase(func_ea);
    sig_cache_.erase(func_ea);
    callee_es_effects_.erase(func_ea);
}

void SummaryCache::invalidate_names_and_symbols() {
    func_names_.clear();
    symbol_names_.clear();
    symbol_infos_.clear();
    all_sym_structs_.reset();
    cfunc_cache_.clear();
}

void SummaryCache::invalidate_types() {
    clear_summaries();
    symbol_infos_.clear();
    all_udts_.reset();
    all_sym_structs_.reset();
    frame_infos_.clear();
    cfunc_cache_.clear();
}

ssize_t idaapi SummaryCache::on_event(ssize_t code, va_list va) {
    switch (code) {
        case idb_event::renamed: {
            ea_t ea = va_arg(va, ea_t);
            invalidate_names_and_symbols();
            if (func_t *pfn = get_func(ea)) {
                invalidate_func(static_cast<uint32_t>(pfn->start_ea));
            }
            break;
        }
        case idb_event::ti_changed: {
            ea_t ea = va_arg(va, ea_t);
            invalidate_types();
            if (func_t *pfn = get_func(ea)) {
                invalidate_func(static_cast<uint32_t>(pfn->start_ea));
            }
            break;
        }
        case idb_event::func_added:
        case idb_event::func_deleted:
        case idb_event::func_updated: {
            func_t *pfn = va_arg(va, func_t *);
            if (pfn) {
                invalidate_func(static_cast<uint32_t>(pfn->start_ea));
            }
            break;
        }
        default:
            break;
    }
    return 0;
}

cfuncptr_t SummaryCache::get_cached_cfunc(uint32_t func_ea) const {
    auto it = cfunc_cache_.find(func_ea);
    return (it != cfunc_cache_.end()) ? it->second : nullptr;
}

void SummaryCache::put_cached_cfunc(uint32_t func_ea, cfuncptr_t cf) {
    cfunc_cache_[func_ea] = std::move(cf);
}

std::optional<std::string> SummaryCache::get_func_name(uint32_t ea) {
    auto it = func_names_.find(ea);
    if (it != func_names_.end()) return it->second;
    qstring qnm;
    std::optional<std::string> res;
    if (::get_func_name(&qnm, static_cast<ea_t>(ea)) > 0 && !qnm.empty()) {
        res = std::string(qnm.c_str(), qnm.length());
    } else if (::get_name(&qnm, static_cast<ea_t>(ea)) > 0 && !qnm.empty()) {
        std::string raw(qnm.c_str(), qnm.length());
        if (raw.rfind("loc_", 0) != 0) res = raw;
    }
    func_names_[ea] = res;
    return res;
}

std::optional<std::string> SummaryCache::get_symbol_name(uint32_t ea) {
    auto it = symbol_names_.find(ea);
    if (it != symbol_names_.end()) return it->second;
    qstring qnm;
    std::optional<std::string> res;
    if (::get_name(&qnm, static_cast<ea_t>(ea)) > 0 && !qnm.empty()) {
        std::string raw(qnm.c_str(), qnm.length());
        if (raw.rfind("loc_", 0) != 0) res = raw;
    }
    symbol_names_[ea] = res;
    return res;
}

std::optional<SymbolInfo> SummaryCache::get_symbol_info(const IdaDatabaseProvider &prov, uint32_t ea) {
    auto it = symbol_infos_.find(ea);
    if (it != symbol_infos_.end()) return it->second;
    auto res = prov.compute_symbol_info_uncached(ea);
    symbol_infos_[ea] = res;
    return res;
}

CalleeEsInfo SummaryCache::get_callee_es_effect(const IdaDatabaseProvider &prov, uint32_t callee_ea) {
    if (func_t *pfn = ::get_func(static_cast<ea_t>(callee_ea))) {
        callee_ea = static_cast<uint32_t>(pfn->start_ea);
    }
    auto it = callee_es_effects_.find(callee_ea);
    if (it != callee_es_effects_.end()) return it->second;
    if (!es_active_.insert(callee_ea).second) {
        return CalleeEsInfo{CalleeEsEffect::Clobbered, 0x0F};
    }
    auto res = prov.compute_callee_es_effect_uncached(callee_ea);
    es_active_.erase(callee_ea);
    callee_es_effects_[callee_ea] = res;
    return res;
}

std::vector<StructDef> SummaryCache::get_all_udts(const IdaDatabaseProvider &prov) {
    if (!all_udts_.has_value()) {
        all_udts_ = prov.compute_all_udts_uncached();
    }
    return *all_udts_;
}

std::unordered_map<uint32_t, std::string> SummaryCache::get_all_symbol_structs(const IdaDatabaseProvider &prov) {
    if (!all_sym_structs_.has_value()) {
        all_sym_structs_ = prov.compute_all_symbol_structs_uncached();
    }
    return *all_sym_structs_;
}

std::optional<IdaFrameInfo> SummaryCache::get_frame_info(uint32_t func_ea) {
    auto it = frame_infos_.find(func_ea);
    if (it != frame_infos_.end()) return it->second;
    IdaDatabaseProvider prov(nullptr);
    auto res = prov.compute_frame_info_uncached(func_ea);
    frame_infos_[func_ea] = res;
    return res;
}

std::optional<CallerConsensus> SummaryCache::get_caller_consensus(const IdaDatabaseProvider &prov, uint32_t func_ea) {
    auto it = consensus_.find(func_ea);
    if (it != consensus_.end()) return it->second;
    auto res = prov.compute_caller_consensus_uncached(func_ea);
    consensus_[func_ea] = res;
    return res;
}

std::set<std::string> SummaryCache::get_callee_preserved(const IdaDatabaseProvider &prov, uint32_t callee_ea) {
    auto it = preserved_regs_.find(callee_ea);
    if (it != preserved_regs_.end()) return it->second;
    auto res = prov.compute_callee_preserved_uncached(callee_ea);
    preserved_regs_[callee_ea] = res;
    return res;
}

std::optional<bool> SummaryCache::callee_expects_ax(const IdaDatabaseProvider &prov, uint32_t callee_ea) {
    auto it = expects_ax_.find(callee_ea);
    if (it != expects_ax_.end()) return it->second;
    auto res = prov.compute_callee_expects_ax_uncached(callee_ea);
    expects_ax_[callee_ea] = res;
    return res;
}

bool SummaryCache::callee_returns_dword(const IdaDatabaseProvider &prov, uint32_t callee_ea) {
    auto it = returns_dword_.find(callee_ea);
    if (it != returns_dword_.end()) return it->second;
    bool res = prov.compute_callee_returns_dword_uncached(callee_ea);
    returns_dword_[callee_ea] = res;
    return res;
}

std::optional<CalleeSigHint> SummaryCache::get_callee_sig(const IdaDatabaseProvider &prov, uint32_t callee_ea) {
    if (func_t *pfn = ::get_func(static_cast<ea_t>(callee_ea))) {
        callee_ea = static_cast<uint32_t>(pfn->start_ea);
    }
    auto it = sig_cache_.find(callee_ea);
    if (it != sig_cache_.end()) return it->second;
    if (!sig_active_.insert(callee_ea).second) return std::nullopt;
    auto res = prov.compute_callee_sig_uncached(callee_ea);
    sig_active_.erase(callee_ea);
    sig_cache_[callee_ea] = res;
    return res;
}

} // namespace rl78dec
