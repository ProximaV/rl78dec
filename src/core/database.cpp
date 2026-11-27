#include "rl78dec/database.hpp"
#include "rl78dec/abi.hpp"
#include "rl78dec/decoder.hpp"

#include <cstring>
#include <unordered_set>

namespace rl78dec {

namespace {

uint32_t infer_size_from_name(const std::string &nm) {
    if (nm.rfind("dword_", 0) == 0 || nm.rfind("off_", 0) == 0) return 4;
    if (nm.rfind("word_", 0) == 0) return 2;
    return 1;
}

struct MiniEsState {
    enum Kind { Top = 0, Entry, Const, Dynamic } kind = Top;
    uint8_t val = 0x0F;
};

MiniEsState meet_es(MiniEsState a, MiniEsState b) {
    if (a.kind == MiniEsState::Top) return b;
    if (b.kind == MiniEsState::Top) return a;
    if (a.kind == MiniEsState::Dynamic || b.kind == MiniEsState::Dynamic) {
        return {MiniEsState::Dynamic, 0};
    }
    if (a.kind == MiniEsState::Entry && b.kind == MiniEsState::Entry) {
        return {MiniEsState::Entry, 0};
    }
    if (a.kind == MiniEsState::Const && b.kind == MiniEsState::Const && a.val == b.val) {
        return a;
    }
    return {MiniEsState::Dynamic, 0};
}

CalleeEsInfo analyze_mem_callee_es(const IDatabaseProvider &db, uint32_t entry_ea,
                                   std::unordered_set<uint32_t> &visiting) {
    if (!visiting.insert(entry_ea).second || visiting.size() > 8) {
        return CalleeEsInfo{CalleeEsEffect::Clobbered, 0x0F};
    }

    struct WorkItem {
        uint32_t ea;
        MiniEsState es;
        std::optional<uint8_t> a_const;
    };
    std::vector<WorkItem> work;
    std::unordered_map<uint32_t, MiniEsState> seen_es;
    work.push_back({entry_ea, {MiniEsState::Entry, 0}, std::nullopt});

    MiniEsState ret_meet{MiniEsState::Top, 0};
    int steps = 0;

    while (!work.empty() && steps < 512) {
        WorkItem cur = work.back();
        work.pop_back();
        ++steps;

        auto sit = seen_es.find(cur.ea);
        if (sit != seen_es.end()) {
            MiniEsState joined = meet_es(sit->second, cur.es);
            if (joined.kind == sit->second.kind && joined.val == sit->second.val) {
                continue;
            }
            cur.es = joined;
            cur.a_const = std::nullopt;
        }
        seen_es[cur.ea] = cur.es;

        auto ins = decode_one(db, cur.ea);
        if (!ins.has_value() || ins->size <= 0) {
            ret_meet = {MiniEsState::Dynamic, 0};
            break;
        }

        // Update tracked constant A & ES
        if (ins->mnem == Mnem::Mov && ins->ops.size() >= 2 && ins->ops[0].mode == OpMode::Reg) {
            RegId r0 = ins->ops[0].reg;
            if (r0 == RegId::ES) {
                if (ins->ops[1].mode == OpMode::Imm) {
                    cur.es = {MiniEsState::Const, static_cast<uint8_t>(ins->ops[1].value & 0xFu)};
                } else if (ins->ops[1].mode == OpMode::Reg && ins->ops[1].reg == RegId::A && cur.a_const.has_value()) {
                    cur.es = {MiniEsState::Const, static_cast<uint8_t>(*cur.a_const & 0xFu)};
                } else {
                    cur.es = {MiniEsState::Dynamic, 0};
                }
            } else if (r0 == RegId::A) {
                if (ins->ops[1].mode == OpMode::Imm) cur.a_const = static_cast<uint8_t>(ins->ops[1].value & 0xFFu);
                else cur.a_const = std::nullopt;
            } else if (r0 == RegId::AX) {
                cur.a_const = std::nullopt;
            }
        } else if (ins->mnem == Mnem::Clrb && !ins->ops.empty() && ins->ops[0].mode == OpMode::Reg) {
            if (ins->ops[0].reg == RegId::ES) cur.es = {MiniEsState::Const, 0};
            else if (ins->ops[0].reg == RegId::A) cur.a_const = 0;
        } else if (ins->mnem == Mnem::Oneb && !ins->ops.empty() && ins->ops[0].mode == OpMode::Reg) {
            if (ins->ops[0].reg == RegId::ES) cur.es = {MiniEsState::Const, 1};
            else if (ins->ops[0].reg == RegId::A) cur.a_const = 1;
        } else if (ins->mnem == Mnem::Clrw && !ins->ops.empty() && ins->ops[0].mode == OpMode::Reg && ins->ops[0].reg == RegId::AX) {
            cur.a_const = 0;
        } else if (ins->mnem == Mnem::Onew && !ins->ops.empty() && ins->ops[0].mode == OpMode::Reg && ins->ops[0].reg == RegId::AX) {
            cur.a_const = 0;
        } else if (ins->mnem == Mnem::Pop && !ins->ops.empty() && ins->ops[0].mode == OpMode::Reg) {
            if (ins->ops[0].reg == RegId::ES) cur.es = {MiniEsState::Dynamic, 0};
            else if (ins->ops[0].reg == RegId::AX) cur.a_const = std::nullopt;
        } else if (ins->mnem == Mnem::Call || ins->mnem == Mnem::Callt || ins->mnem == Mnem::Brk) {
            cur.a_const = std::nullopt;
            auto tgt = target_of(*ins);
            if (tgt.has_value()) {
                CalleeEsInfo ce = analyze_mem_callee_es(db, *tgt, visiting);
                if (ce.effect == CalleeEsEffect::ReturnsConst) {
                    cur.es = {MiniEsState::Const, static_cast<uint8_t>(ce.const_val & 0xFu)};
                } else if (ce.effect == CalleeEsEffect::Clobbered) {
                    cur.es = {MiniEsState::Dynamic, 0};
                }
            } else {
                cur.es = {MiniEsState::Dynamic, 0};
            }
        } else if (!ins->ops.empty() && ins->ops[0].mode == OpMode::Reg) {
            RegId r0 = ins->ops[0].reg;
            if (r0 == RegId::A || r0 == RegId::AX || r0 == RegId::X) cur.a_const = std::nullopt;
        }

        if (is_ret_mnem(ins->mnem)) {
            ret_meet = meet_es(ret_meet, cur.es);
            continue;
        }
        for (const auto &[how, tgt] : insn_succs(db, *ins)) {
            if (how == "call") continue;
            work.push_back({tgt, cur.es, cur.a_const});
        }
    }

    visiting.erase(entry_ea);
    if (ret_meet.kind == MiniEsState::Entry) return CalleeEsInfo{CalleeEsEffect::Preserved, 0x0F};
    if (ret_meet.kind == MiniEsState::Const) return CalleeEsInfo{CalleeEsEffect::ReturnsConst, ret_meet.val};
    return CalleeEsInfo{CalleeEsEffect::Clobbered, 0x0F};
}

} // namespace

std::optional<SymbolInfo> IDatabaseProvider::get_symbol_info(uint32_t ea) const {
    auto nm = get_symbol_name(ea);
    auto st = get_symbol_struct(ea);
    if (!nm.has_value() && !st.has_value()) return std::nullopt;
    SymbolInfo info;
    info.name = nm.value_or("");
    info.base_ea = ea;
    info.offset = 0;
    info.item_size = nm.has_value() ? infer_size_from_name(*nm) : 1;
    info.struct_name = st.value_or("");
    if (!info.struct_name.empty()) {
        if (auto udt = get_udt_info(info.struct_name); udt.has_value() && !udt->members.empty()) {
            uint32_t max_end = 1;
            for (const auto &m : udt->members) {
                uint32_t mend = static_cast<uint32_t>(std::max<int64_t>(1, m.offset + m.size));
                if (mend > max_end) max_end = mend;
            }
            info.item_size = max_end;
        }
    }
    return info;
}

bool IDatabaseProvider::read_u8(uint32_t ea, uint8_t *out) const {
    return out && read_bytes(ea, out, 1) == 1;
}

bool IDatabaseProvider::read_u16_le(uint32_t ea, uint16_t *out) const {
    uint8_t b[2]{};
    if (!out || read_bytes(ea, b, 2) != 2) return false;
    *out = static_cast<uint16_t>(b[0]) | (static_cast<uint16_t>(b[1]) << 8);
    return true;
}

bool IDatabaseProvider::read_u32_le(uint32_t ea, uint32_t *out) const {
    uint8_t b[4]{};
    if (!out || read_bytes(ea, b, 4) != 4) return false;
    *out = static_cast<uint32_t>(b[0]) |
           (static_cast<uint32_t>(b[1]) << 8) |
           (static_cast<uint32_t>(b[2]) << 16) |
           (static_cast<uint32_t>(b[3]) << 24);
    return true;
}

MemoryDatabaseProvider::MemoryDatabaseProvider(size_t size, uint32_t base_ea)
    : image_(size, 0), base_ea_(base_ea) {}

MemoryDatabaseProvider::MemoryDatabaseProvider(std::vector<uint8_t> image, uint32_t base_ea)
    : image_(std::move(image)), base_ea_(base_ea) {}

void MemoryDatabaseProvider::resize_if_needed(size_t needed) {
    if (needed > image_.size()) image_.resize(needed, 0);
}

void MemoryDatabaseProvider::write_bytes(uint32_t ea, const std::vector<uint8_t> &bytes) {
    if (ea < base_ea_) return;
    size_t off = static_cast<size_t>(ea - base_ea_);
    resize_if_needed(off + bytes.size());
    if (!bytes.empty()) std::memcpy(&image_[off], bytes.data(), bytes.size());
}

void MemoryDatabaseProvider::write_u8(uint32_t ea, uint8_t val) {
    write_bytes(ea, {val});
}

void MemoryDatabaseProvider::write_u16_le(uint32_t ea, uint16_t val) {
    write_bytes(ea, {static_cast<uint8_t>(val & 0xFFu), static_cast<uint8_t>((val >> 8) & 0xFFu)});
}

void MemoryDatabaseProvider::write_u32_le(uint32_t ea, uint32_t val) {
    write_bytes(ea, {
        static_cast<uint8_t>(val & 0xFFu),
        static_cast<uint8_t>((val >> 8) & 0xFFu),
        static_cast<uint8_t>((val >> 16) & 0xFFu),
        static_cast<uint8_t>((val >> 24) & 0xFFu),
    });
}

void MemoryDatabaseProvider::add_func_entry(uint32_t ea, const std::string &name) {
    entries_.insert(ea);
    if (!name.empty()) func_names_[ea] = name;
}

void MemoryDatabaseProvider::set_symbol_name(uint32_t ea, const std::string &name) {
    sym_names_[ea] = name;
}

void MemoryDatabaseProvider::set_symbol_info(uint32_t ea, const SymbolInfo &info) {
    SymbolInfo copy = info;
    if (copy.base_ea == 0) copy.base_ea = ea;
    sym_infos_[ea] = copy;
    if (!copy.name.empty()) sym_names_[ea] = copy.name;
    if (!copy.struct_name.empty()) sym_structs_[ea] = copy.struct_name;
}

void MemoryDatabaseProvider::set_default_es(uint8_t es_val) {
    default_es_ = static_cast<uint8_t>(es_val & 0x0Fu);
}

void MemoryDatabaseProvider::set_es_at(uint32_t ea, uint8_t es_val) {
    es_at_[ea] = static_cast<uint8_t>(es_val & 0x0Fu);
}

void MemoryDatabaseProvider::set_callee_es_effect(uint32_t ea, CalleeEsInfo info) {
    callee_es_effects_[ea] = info;
}

void MemoryDatabaseProvider::set_func_proto(uint32_t ea, const std::string &proto) {
    protos_[ea] = proto;
}

void MemoryDatabaseProvider::set_callee_preserved(uint32_t ea, std::set<std::string> regs) {
    preserved_[ea] = std::move(regs);
}

void MemoryDatabaseProvider::set_callee_expects_ax(uint32_t ea, bool expects) {
    expects_ax_[ea] = expects;
}

void MemoryDatabaseProvider::set_callee_returns_dword(uint32_t ea, bool ret_dword) {
    returns_dword_[ea] = ret_dword;
}

void MemoryDatabaseProvider::set_callee_far_specs(uint32_t ea, const FarParamSpecs &specs) {
    far_specs_[ea] = specs;
}

void MemoryDatabaseProvider::set_caller_consensus(uint32_t ea, const CallerConsensus &cc) {
    caller_consensus_[ea] = cc;
}

void MemoryDatabaseProvider::set_ida_frame_info(uint32_t ea, const IdaFrameInfo &fi) {
    frames_[ea] = fi;
}

void MemoryDatabaseProvider::add_udt(const StructDef &def) {
    udts_[def.name] = def;
}

void MemoryDatabaseProvider::set_symbol_struct(uint32_t ea, const std::string &struct_name) {
    sym_structs_[ea] = struct_name;
}

bool MemoryDatabaseProvider::is_loaded(uint32_t ea) const {
    return ea >= base_ea_ && static_cast<size_t>(ea - base_ea_) < image_.size();
}

size_t MemoryDatabaseProvider::image_size() const {
    return image_.size();
}

size_t MemoryDatabaseProvider::read_bytes(uint32_t ea, uint8_t *buf, size_t len) const {
    if (!buf || len == 0 || ea < base_ea_) return 0;
    size_t off = static_cast<size_t>(ea - base_ea_);
    if (off >= image_.size()) return 0;
    size_t n = std::min(len, image_.size() - off);
    std::memcpy(buf, &image_[off], n);
    return n;
}

std::vector<uint32_t> MemoryDatabaseProvider::get_func_entries() const {
    return {entries_.begin(), entries_.end()};
}

std::optional<uint32_t> MemoryDatabaseProvider::get_func_start(uint32_t ea) const {
    if (entries_.count(ea)) return ea;
    return std::nullopt;
}

std::optional<std::string> MemoryDatabaseProvider::get_symbol_name(uint32_t ea) const {
    if (auto it = sym_names_.find(ea); it != sym_names_.end()) return it->second;
    if (auto it = func_names_.find(ea); it != func_names_.end()) return it->second;
    return std::nullopt;
}

std::optional<std::string> MemoryDatabaseProvider::get_func_name(uint32_t ea) const {
    if (auto it = func_names_.find(ea); it != func_names_.end()) return it->second;
    if (auto it = sym_names_.find(ea); it != sym_names_.end()) return it->second;
    return std::nullopt;
}

std::optional<IdaFrameInfo> MemoryDatabaseProvider::get_ida_frame_info(uint32_t func_ea) const {
    if (auto it = frames_.find(func_ea); it != frames_.end()) return it->second;
    return std::nullopt;
}

std::optional<std::string> MemoryDatabaseProvider::get_ida_func_proto(uint32_t func_ea) const {
    if (auto it = protos_.find(func_ea); it != protos_.end()) return it->second;
    return std::nullopt;
}

std::optional<SwitchInfo> MemoryDatabaseProvider::get_switch_info(uint32_t) const {
    return std::nullopt;
}

std::optional<CallerConsensus> MemoryDatabaseProvider::get_caller_consensus(uint32_t func_ea) const {
    if (auto it = caller_consensus_.find(func_ea); it != caller_consensus_.end()) return it->second;
    return std::nullopt;
}

std::set<std::string> MemoryDatabaseProvider::get_callee_preserved_regs(uint32_t callee_ea) const {
    if (auto it = preserved_.find(callee_ea); it != preserved_.end()) return it->second;
    return {};
}

std::optional<bool> MemoryDatabaseProvider::callee_expects_ax(uint32_t callee_ea) const {
    if (auto it = expects_ax_.find(callee_ea); it != expects_ax_.end()) return it->second;
    return std::nullopt;
}

bool MemoryDatabaseProvider::callee_returns_dword(uint32_t callee_ea) const {
    if (auto it = returns_dword_.find(callee_ea); it != returns_dword_.end()) return it->second;
    return false;
}

std::optional<FarParamSpecs> MemoryDatabaseProvider::get_callee_far_param_specs(uint32_t callee_ea) const {
    if (auto it = far_specs_.find(callee_ea); it != far_specs_.end()) return it->second;
    return std::nullopt;
}

std::optional<CalleeSigHint> MemoryDatabaseProvider::get_callee_sig(uint32_t callee_ea) const {
    auto pit = protos_.find(callee_ea);
    if (pit == protos_.end()) return std::nullopt;
    auto parsed = parse_prototype(pit->second);
    if (!parsed.has_value()) return std::nullopt;
    auto is_8bit = [](const std::string &t) {
        return t == "uint8_t" || t == "int8_t" || t == "bool";
    };
    auto is_32bit = [](const std::string &t) {
        return t == "uint32_t" || t == "int32_t";
    };
    CalleeSigHint hint;
    hint.valid = true;
    hint.ret_type = parsed->ret_type;
    bool first_is_far = !parsed->params.empty() && is_32bit(parsed->params[0].second);
    size_t reg_slots = 0;
    if (parsed->params.size() >= 1) {
        std::string loc0 = first_is_far ? "ax:bc" : (is_8bit(parsed->params[0].second) ? "a" : "ax");
        hint.params.push_back(ParamHint{parsed->params[0].second, loc0});
        reg_slots = 1;
    }
    if (!first_is_far && parsed->params.size() >= 2) {
        std::string loc1 = is_8bit(parsed->params[1].second) ? "c" : "bc";
        hint.params.push_back(ParamHint{parsed->params[1].second, loc1});
        reg_slots = 2;
    }
    for (size_t i = reg_slots; i < parsed->params.size(); ++i) {
        hint.params.push_back(ParamHint{parsed->params[i].second, "stack"});
    }
    return hint;
}

std::optional<uint8_t> MemoryDatabaseProvider::get_es_at(uint32_t ea) const {
    if (auto it = es_at_.find(ea); it != es_at_.end()) return it->second;
    return default_es_;
}

CalleeEsInfo MemoryDatabaseProvider::get_callee_es_effect(uint32_t callee_ea) const {
    if (auto it = callee_es_effects_.find(callee_ea); it != callee_es_effects_.end()) return it->second;
    if (is_loaded(callee_ea)) {
        std::unordered_set<uint32_t> visiting;
        return analyze_mem_callee_es(*this, callee_ea, visiting);
    }
    return CalleeEsInfo{CalleeEsEffect::Clobbered, 0x0F};
}

std::optional<SymbolInfo> MemoryDatabaseProvider::get_symbol_info(uint32_t ea) const {
    if (auto it = sym_infos_.find(ea); it != sym_infos_.end()) {
        SymbolInfo out = it->second;
        out.offset = (ea >= out.base_ea) ? (ea - out.base_ea) : 0;
        return out;
    }
    for (const auto &[base, info] : sym_infos_) {
        uint32_t span = std::max<uint32_t>(1, info.item_size);
        if (ea >= base && ea < base + span) {
            SymbolInfo out = info;
            out.base_ea = base;
            out.offset = ea - base;
            return out;
        }
    }
    return IDatabaseProvider::get_symbol_info(ea);
}

std::optional<StructDef> MemoryDatabaseProvider::get_udt_info(const std::string &name) const {
    if (auto it = udts_.find(name); it != udts_.end()) return it->second;
    return std::nullopt;
}

std::optional<std::string> MemoryDatabaseProvider::get_symbol_struct(uint32_t ea) const {
    if (auto it = sym_structs_.find(ea); it != sym_structs_.end()) return it->second;
    return std::nullopt;
}

std::vector<StructDef> MemoryDatabaseProvider::get_all_udts() const {
    std::vector<StructDef> out;
    out.reserve(udts_.size());
    for (const auto &[k, v] : udts_) out.push_back(v);
    return out;
}

std::unordered_map<uint32_t, std::string> MemoryDatabaseProvider::get_all_symbol_structs() const {
    return sym_structs_;
}

} // namespace rl78dec
