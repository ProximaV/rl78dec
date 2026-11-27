#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "rl78dec/isa.hpp"

namespace rl78dec {

struct SwitchInfo {
    uint32_t ea = 0;
    uint32_t table_ea = 0;
    int scale = 2;
    std::map<int64_t, std::optional<uint32_t>> cases; // val -> target_ea (or nullopt for 0)
    std::optional<uint32_t> default_ea;
    std::string idx_reg = "a";
    std::vector<uint32_t> targets;
    std::set<uint32_t> dispatch_eas;
};

struct CallerConsensus {
    bool valid = false;
    bool has_ax = false;
    bool has_bc = false;
};

struct FarParamSpecs {
    bool has_far_reg = false;
    std::set<int> far_stack_indices;
};

struct ParamHint {
    std::string type_str = "uint16_t";
    std::string location = "ax";
};

struct CalleeSigHint {
    bool valid = false;
    std::string ret_type = "void";
    std::vector<ParamHint> params;
};

struct IdaStkvarHit {
    int64_t offset = 0;
    std::string name;
    int size = 1;
    bool is_arg = false;
};

struct IdaFrameInfo {
    bool valid = false;
    struct Member {
        std::string name;
        int size = 1;
        std::string type_str;
    };
    std::map<int64_t, Member> members;
    std::unordered_map<uint32_t, std::map<int, IdaStkvarHit>> stkvars_by_ea;
};

struct StructMemberInfo {
    int64_t offset = 0;
    int64_t size = 1;
    std::string name;
};

struct StructDef {
    std::string name;
    std::vector<StructMemberInfo> members;
};

struct SymbolInfo {
    std::string name;
    uint32_t base_ea = 0;
    uint32_t offset = 0;          // query_ea - base_ea (0 for exact, >0 for interior e.g. word_FB2C8+1)
    uint32_t item_size = 1;       // byte size of item in DB (1, 2, 4, or larger)
    bool is_array = false;        // true for string literals, arrays, or non-struct items > 4 bytes
    bool has_scalar_xref = false; // true if 1-byte item also has non-indexed scalar data xrefs
    std::string struct_name;      // UDT name if item is a struct
};

enum class CalleeEsEffect : uint8_t {
    Preserved = 0,
    ReturnsConst,
    Clobbered,
};

struct CalleeEsInfo {
    CalleeEsEffect effect = CalleeEsEffect::Clobbered;
    uint8_t const_val = 0x0F;
};

class IDatabaseProvider {
public:
    virtual ~IDatabaseProvider() = default;

    virtual bool is_loaded(uint32_t ea) const = 0;
    virtual size_t image_size() const = 0;
    virtual size_t read_bytes(uint32_t ea, uint8_t *buf, size_t len) const = 0;
    virtual bool read_u8(uint32_t ea, uint8_t *out) const;
    virtual bool read_u16_le(uint32_t ea, uint16_t *out) const;
    virtual bool read_u32_le(uint32_t ea, uint32_t *out) const;

    virtual std::vector<uint32_t> get_func_entries() const = 0;
    virtual std::optional<uint32_t> get_func_start(uint32_t ea) const = 0;
    virtual std::optional<std::string> get_symbol_name(uint32_t ea) const = 0;
    virtual std::optional<std::string> get_func_name(uint32_t ea) const = 0;

    virtual std::optional<IdaFrameInfo> get_ida_frame_info(uint32_t func_ea) const = 0;
    virtual std::optional<std::string> get_ida_func_proto(uint32_t func_ea) const = 0;
    virtual std::optional<SwitchInfo> get_switch_info(uint32_t br_ea) const = 0;

    virtual std::optional<CallerConsensus> get_caller_consensus(uint32_t func_ea) const = 0;
    virtual std::set<std::string> get_callee_preserved_regs(uint32_t callee_ea) const = 0;
    virtual std::optional<bool> callee_expects_ax(uint32_t callee_ea) const = 0;
    virtual bool callee_returns_dword(uint32_t callee_ea) const = 0;
    virtual std::optional<FarParamSpecs> get_callee_far_param_specs(uint32_t callee_ea) const = 0;
    virtual std::optional<CalleeSigHint> get_callee_sig(uint32_t /*callee_ea*/) const {
        return std::nullopt;
    }

    virtual std::optional<uint8_t> get_es_at(uint32_t /*ea*/) const {
        return std::nullopt;
    }
    virtual CalleeEsInfo get_callee_es_effect(uint32_t /*callee_ea*/) const {
        return CalleeEsInfo{CalleeEsEffect::Clobbered, 0x0F};
    }
    virtual std::optional<SymbolInfo> get_symbol_info(uint32_t ea) const;

    virtual std::optional<StructDef> get_udt_info(const std::string &name) const = 0;
    virtual std::optional<std::string> get_symbol_struct(uint32_t ea) const = 0;
    virtual std::vector<StructDef> get_all_udts() const = 0;
    virtual std::unordered_map<uint32_t, std::string> get_all_symbol_structs() const = 0;
};

class MemoryDatabaseProvider : public IDatabaseProvider {
public:
    explicit MemoryDatabaseProvider(size_t size = 0x10000, uint32_t base_ea = 0);
    MemoryDatabaseProvider(std::vector<uint8_t> image, uint32_t base_ea = 0);

    uint32_t base_ea() const { return base_ea_; }
    const std::vector<uint8_t> &raw_image() const { return image_; }
    void resize_if_needed(size_t needed);
    void write_bytes(uint32_t ea, const std::vector<uint8_t> &bytes);
    void write_u8(uint32_t ea, uint8_t val);
    void write_u16_le(uint32_t ea, uint16_t val);
    void write_u32_le(uint32_t ea, uint32_t val);

    void add_func_entry(uint32_t ea, const std::string &name = "");
    void set_symbol_name(uint32_t ea, const std::string &name);
    void set_symbol_info(uint32_t ea, const SymbolInfo &info);
    void set_default_es(uint8_t es_val);
    void set_es_at(uint32_t ea, uint8_t es_val);
    void set_callee_es_effect(uint32_t ea, CalleeEsInfo info);
    void set_func_proto(uint32_t ea, const std::string &proto);
    void set_callee_preserved(uint32_t ea, std::set<std::string> regs);
    void set_callee_expects_ax(uint32_t ea, bool expects);
    void set_callee_returns_dword(uint32_t ea, bool ret_dword);
    void set_callee_far_specs(uint32_t ea, const FarParamSpecs &specs);
    void set_caller_consensus(uint32_t ea, const CallerConsensus &cc);
    void set_ida_frame_info(uint32_t ea, const IdaFrameInfo &fi);
    void add_udt(const StructDef &def);
    void set_symbol_struct(uint32_t ea, const std::string &struct_name);

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
    bool callee_returns_dword(uint32_t callee_ea) const override;
    std::optional<FarParamSpecs> get_callee_far_param_specs(uint32_t callee_ea) const override;
    std::optional<CalleeSigHint> get_callee_sig(uint32_t callee_ea) const override;

    std::optional<uint8_t> get_es_at(uint32_t ea) const override;
    CalleeEsInfo get_callee_es_effect(uint32_t callee_ea) const override;
    std::optional<SymbolInfo> get_symbol_info(uint32_t ea) const override;

    std::optional<StructDef> get_udt_info(const std::string &name) const override;
    std::optional<std::string> get_symbol_struct(uint32_t ea) const override;
    std::vector<StructDef> get_all_udts() const override;
    std::unordered_map<uint32_t, std::string> get_all_symbol_structs() const override;

private:
    std::vector<uint8_t> image_;
    uint32_t base_ea_ = 0;
    std::set<uint32_t> entries_;
    std::unordered_map<uint32_t, std::string> func_names_;
    std::unordered_map<uint32_t, std::string> sym_names_;
    std::unordered_map<uint32_t, SymbolInfo> sym_infos_;
    std::optional<uint8_t> default_es_;
    std::unordered_map<uint32_t, uint8_t> es_at_;
    std::unordered_map<uint32_t, CalleeEsInfo> callee_es_effects_;
    std::unordered_map<uint32_t, std::string> protos_;
    std::unordered_map<uint32_t, std::set<std::string>> preserved_;
    std::unordered_map<uint32_t, bool> expects_ax_;
    std::unordered_map<uint32_t, bool> returns_dword_;
    std::unordered_map<uint32_t, FarParamSpecs> far_specs_;
    std::unordered_map<uint32_t, CallerConsensus> caller_consensus_;
    std::unordered_map<uint32_t, IdaFrameInfo> frames_;
    std::unordered_map<std::string, StructDef> udts_;
    std::unordered_map<uint32_t, std::string> sym_structs_;
};

} // namespace rl78dec
