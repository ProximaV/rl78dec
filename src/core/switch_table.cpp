#include "rl78dec/switch_table.hpp"

#include <algorithm>
#include <set>
#include <vector>

namespace rl78dec {

std::map<int64_t, std::optional<uint32_t>> parse_switch_table(
    const IDatabaseProvider &db, uint32_t table_ea, int scale, uint32_t max_cases) {
    std::map<int64_t, std::optional<uint32_t>> cases;
    uint32_t img_sz = static_cast<uint32_t>(db.image_size());
    uint32_t min_target = img_sz;

    for (uint32_t i = 0; i < max_cases; ++i) {
        uint32_t addr = table_ea + i * static_cast<uint32_t>(scale);
        if (addr >= min_target || addr + static_cast<uint32_t>(scale) > img_sz) break;
        uint32_t tgt = 0;
        if (scale == 4) {
            uint32_t raw = 0;
            if (!db.read_u32_le(addr, &raw)) break;
            tgt = (raw & 0xFFFFu) | (((raw >> 16) & 0xFFu) << 16);
        } else {
            uint16_t raw = 0;
            if (!db.read_u16_le(addr, &raw)) break;
            tgt = raw;
        }
        if (tgt == 0) {
            cases[static_cast<int64_t>(i)] = std::nullopt;
        } else if (tgt < img_sz) {
            min_target = std::min(min_target, tgt);
            cases[static_cast<int64_t>(i)] = tgt;
        } else {
            break;
        }
    }
    return cases;
}

std::optional<SwitchInfo> detect_switch(
    const IDatabaseProvider &db, const std::map<uint32_t, DecodedInsn> &insns, const DecodedInsn &br_ins) {
    if (br_ins.mnem != Mnem::Br || br_ins.ops.empty() ||
        br_ins.ops[0].mode != OpMode::Reg || br_ins.ops[0].reg != RegId::AX) {
        return std::nullopt;
    }

    if (auto ida_sw = db.get_switch_info(br_ins.ea); ida_sw.has_value()) {
        if (!ida_sw->cases.empty()) return ida_sw;
    }

    // Heuristic window search backward by contiguous decoded instruction addresses
    std::vector<const DecodedInsn *> window;
    uint32_t cur = br_ins.ea;
    for (int step = 0; step < 16; ++step) {
        const DecodedInsn *prev = nullptr;
        for (const auto &[ea, it] : insns) {
            if (ea + static_cast<uint32_t>(it.size) == cur) {
                prev = &it;
                break;
            }
        }
        if (!prev) break;
        cur = prev->ea;
        window.insert(window.begin(), prev);
    }
    if (window.empty()) return std::nullopt;

    std::optional<uint32_t> table_ea;
    int scale = 2;
    std::string idx_reg = "a";
    const DecodedInsn *shlw_ins = nullptr;
    size_t shlw_idx = 0;
    uint32_t img_sz = static_cast<uint32_t>(db.image_size());

    for (size_t idx = 0; idx < window.size(); ++idx) {
        const DecodedInsn *it = window[idx];
        if (it->mnem == Mnem::Shlw && it->ops.size() >= 2 && it->ops[1].mode == OpMode::Imm) {
            shlw_ins = it;
            shlw_idx = idx;
            scale = 1 << (it->ops[1].value & 0xFu);
            if (it->ops[0].mode == OpMode::Reg &&
                (it->ops[0].reg == RegId::BC || it->ops[0].reg == RegId::C)) {
                idx_reg = "c";
            }
        }
        if ((it->mnem == Mnem::Addw || it->mnem == Mnem::Movw) &&
            it->ops.size() >= 2 && it->ops[1].mode == OpMode::Imm) {
            uint32_t val = it->ops[1].value;
            if (val < img_sz) table_ea = val;
        }
    }

    if (!table_ea.has_value()) return std::nullopt;
    auto cases = parse_switch_table(db, *table_ea, scale);
    bool any_non_null = false;
    for (const auto &[k, v] : cases) {
        if (v.has_value() && *v != 0) { any_non_null = true; break; }
    }
    if (!any_non_null) return std::nullopt;

    std::set<uint32_t> dispatch_eas;
    dispatch_eas.insert(br_ins.ea);
    if (shlw_ins != nullptr) {
        for (size_t idx = shlw_idx; idx < window.size(); ++idx) {
            dispatch_eas.insert(window[idx]->ea);
        }
        if (idx_reg == "a") {
            for (size_t r = shlw_idx; r > 0; --r) {
                const DecodedInsn *it = window[r - 1];
                if (it->mnem == Mnem::Clrb) {
                    if (!it->ops.empty() && it->ops[0].mode == OpMode::Reg) {
                        if (it->ops[0].reg == RegId::A) idx_reg = "x";
                        else if (it->ops[0].reg == RegId::X) idx_reg = "a";
                    }
                    dispatch_eas.insert(it->ea);
                } else if (it->mnem == Mnem::Mov && it->ops.size() >= 2 && it->ops[0].mode == OpMode::Reg) {
                    if ((it->ops[0].reg == RegId::X || it->ops[0].reg == RegId::A) &&
                        it->ops[1].mode == OpMode::Reg) {
                        idx_reg = reg_name(it->ops[1].reg);
                        dispatch_eas.insert(it->ea);
                        break;
                    }
                    break;
                } else {
                    break;
                }
            }
        }
    }

    SwitchInfo info;
    info.ea = br_ins.ea;
    info.table_ea = *table_ea;
    info.scale = scale;
    info.cases = std::move(cases);
    info.idx_reg = idx_reg;
    info.dispatch_eas = std::move(dispatch_eas);
    std::set<uint32_t> uniq;
    for (const auto &[v, tgt] : info.cases) {
        if (tgt.has_value() && *tgt != 0) uniq.insert(*tgt);
    }
    info.targets.assign(uniq.begin(), uniq.end());
    return info;
}

} // namespace rl78dec
