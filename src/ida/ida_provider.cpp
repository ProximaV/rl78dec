#include <ida.hpp>
#include <bytes.hpp>
#include <frame.hpp>
#include <funcs.hpp>
#include <idp.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <segregs.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>

#include "ida_provider.hpp"
#include "summary_cache.hpp"
#include "rl78dec/abi.hpp"
#include "rl78dec/cfg.hpp"
#include "rl78dec/decoder.hpp"
#include "rl78dec/frame.hpp"
#include "rl78dec/isa.hpp"
#include "rl78dec/opt.hpp"
#include "rl78dec/spill.hpp"
#include "rl78dec/switch_table.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <unordered_set>

namespace rl78dec {

namespace {

std::string trim_s(const std::string &s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

} // namespace

void ensure_rl78_types() {
    static bool s_registered = false;
    if (s_registered) return;
    static const char *const kHeader =
        "typedef unsigned char u8;\n"
        "typedef unsigned short u16;\n"
        "typedef unsigned int u32;\n"
        "typedef signed char s8;\n"
        "typedef signed short s16;\n"
        "typedef signed int s32;\n";
    parse_decls(nullptr, kHeader, nullptr, HTI_DCL);
    s_registered = true;
}

bool parse_c_type_tinfo(const std::string &type_str, tinfo_t *out_tif) {
    if (!out_tif) return false;
    ensure_rl78_types();
    std::string clean = trim_s(type_str);
    while (!clean.empty() && clean.back() == ';') clean.pop_back();
    clean = trim_s(clean);
    if (clean.empty()) return false;

    tinfo_t tif;
    qstring qname;
    if (parse_decl(&tif, &qname, nullptr, (clean + ";").c_str(), PT_TYP | PT_SIL)) {
        *out_tif = tif;
        return true;
    }
    if (parse_decl(&tif, &qname, nullptr, (clean + " _rl78_var;").c_str(), PT_SIL)) {
        *out_tif = tif;
        return true;
    }
    return false;
}

bool apply_proto_to_ida(ea_t ea, const std::string &proto_str) {
    ensure_rl78_types();
    std::string clean = trim_s(proto_str);
    while (!clean.empty() && clean.back() == ';') clean.pop_back();
    if (clean.empty()) return false;

    tinfo_t tif;
    qstring qname;
    if (parse_decl(&tif, &qname, nullptr, (clean + ";").c_str(), PT_SIL) && tif.is_func()) {
        apply_tinfo(ea, tif, TINFO_DEFINITE);
        return true;
    }
    return false;
}

std::vector<std::string> find_ida_enum_matches(uint64_t val) {
    std::vector<std::string> matches;
    std::unordered_set<std::string> seen;
    const til_t *til = get_idati();
    if (!til) return matches;

    const uint32 limit = get_ordinal_limit(til);
    for (uint32 ord = 1; ord < limit; ++ord) {
        tinfo_t tif;
        if (!tif.get_numbered_type(til, ord) || !tif.is_enum()) continue;
        enum_type_data_t etd;
        if (!tif.get_enum_details(&etd)) continue;
        for (const auto &edm : etd) {
            if (edm.value == val && !edm.name.empty()) {
                std::string nm(edm.name.c_str(), edm.name.length());
                if (seen.insert(nm).second) matches.push_back(std::move(nm));
            }
        }
    }
    return matches;
}

bool IdaDatabaseProvider::is_loaded(uint32_t ea) const {
    return ::is_loaded(static_cast<ea_t>(ea));
}

size_t IdaDatabaseProvider::image_size() const {
    size_t max_end = 0;
    const int nseg = get_segm_qty();
    for (int i = 0; i < nseg; ++i) {
        segment_t *seg = getnseg(i);
        if (!seg) continue;
        if (seg->end_ea <= 0x100000ULL && static_cast<size_t>(seg->end_ea) > max_end) {
            max_end = static_cast<size_t>(seg->end_ea);
        }
    }
    return max_end > 0 ? max_end : 0x100000u;
}

size_t IdaDatabaseProvider::read_bytes(uint32_t ea, uint8_t *buf, size_t len) const {
    ssize_t n = get_bytes(buf, static_cast<ssize_t>(len), static_cast<ea_t>(ea), GMB_READALL);
    if (n > 0) return static_cast<size_t>(n);
    size_t got = 0;
    for (; got < len; ++got) {
        ea_t cur = static_cast<ea_t>(ea + got);
        if (!::is_loaded(cur)) break;
        buf[got] = static_cast<uint8_t>(get_byte(cur));
    }
    return got;
}

std::vector<uint32_t> IdaDatabaseProvider::get_func_entries() const {
    std::vector<uint32_t> out;
    const size_t qty = get_func_qty();
    out.reserve(qty);
    for (size_t i = 0; i < qty; ++i) {
        if (func_t *pfn = getn_func(i)) {
            out.push_back(static_cast<uint32_t>(pfn->start_ea));
        }
    }
    return out;
}

std::optional<uint32_t> IdaDatabaseProvider::get_func_start(uint32_t ea) const {
    if (func_t *pfn = get_func(static_cast<ea_t>(ea))) {
        return static_cast<uint32_t>(pfn->start_ea);
    }
    return std::nullopt;
}

std::optional<std::string> IdaDatabaseProvider::get_symbol_name(uint32_t ea) const {
    if (cache_) return cache_->get_symbol_name(ea);
    qstring qnm;
    if (::get_name(&qnm, static_cast<ea_t>(ea)) > 0 && !qnm.empty()) {
        std::string raw(qnm.c_str(), qnm.length());
        if (raw.rfind("loc_", 0) != 0) return raw;
    }
    return std::nullopt;
}

std::optional<std::string> IdaDatabaseProvider::get_func_name(uint32_t ea) const {
    if (cache_) return cache_->get_func_name(ea);
    qstring qnm;
    if (::get_func_name(&qnm, static_cast<ea_t>(ea)) > 0 && !qnm.empty()) {
        return std::string(qnm.c_str(), qnm.length());
    }
    if (::get_name(&qnm, static_cast<ea_t>(ea)) > 0 && !qnm.empty()) {
        std::string raw(qnm.c_str(), qnm.length());
        if (raw.rfind("loc_", 0) != 0) return raw;
    }
    return std::nullopt;
}

std::optional<IdaFrameInfo> IdaDatabaseProvider::compute_frame_info_uncached(uint32_t func_ea) const {
    func_t *pfn = get_func(static_cast<ea_t>(func_ea));
    if (!pfn) return std::nullopt;

    tinfo_t ftif;
    udt_type_data_t udt;
    if (!get_func_frame(&ftif, pfn) || !ftif.get_udt_details(&udt)) {
        return std::nullopt;
    }

    IdaFrameInfo out;
    out.valid = true;
    const ea_t retaddr_off = pfn->frsize + pfn->frregs;

    for (const auto &m : udt) {
        if (m.name.empty()) continue;
        std::string mname(m.name.c_str(), m.name.length());
        if (mname.empty() || mname[0] == ' ') continue;
        int64_t raw_off = static_cast<int64_t>(m.offset / 8);
        int64_t sp_rel = raw_off; // frame struct byte offset
        int m_sz = static_cast<int>(m.size / 8);
        if (m_sz <= 0) m_sz = 1;
        qstring qmt;
        m.type.print(&qmt);
        out.members[sp_rel] = IdaFrameInfo::Member{
            mname, m_sz, qmt.empty() ? std::string() : std::string(qmt.c_str(), qmt.length())};
    }

    func_item_iterator_t fii;
    for (bool ok = fii.set(pfn); ok; ok = fii.next_addr()) {
        ea_t iea = fii.current();
        insn_t insn;
        if (decode_insn(&insn, iea) <= 0) continue;
        for (int n = 0; n < UA_MAXOP; ++n) {
            const op_t &op = insn.ops[n];
            if (op.type == o_void) break;
            if (op.type != o_displ && op.type != o_imm) continue;
            ea_t soff = calc_stkvar_struc_offset(pfn, insn, n);
            if (soff == BADADDR) continue;
            int64_t off_val = static_cast<int64_t>(soff);
            bool is_arg = (soff >= retaddr_off + 4);
            std::string hit_name;
            int hit_sz = 1;
            for (const auto &m : udt) {
                if (static_cast<ea_t>(m.offset / 8) == soff && !m.name.empty()) {
                    hit_name = std::string(m.name.c_str(), m.name.length());
                    hit_sz = std::max(1, static_cast<int>(m.size / 8));
                    break;
                }
            }
            if (!hit_name.empty() && hit_name[0] != ' ') {
                out.stkvars_by_ea[static_cast<uint32_t>(iea)][n] = IdaStkvarHit{
                    off_val, hit_name, hit_sz, is_arg};
            }
        }
    }

    if (out.members.empty() && out.stkvars_by_ea.empty()) return std::nullopt;
    return out;
}

std::optional<IdaFrameInfo> IdaDatabaseProvider::get_ida_frame_info(uint32_t func_ea) const {
    if (cache_) return cache_->get_frame_info(func_ea);
    return compute_frame_info_uncached(func_ea);
}

std::optional<std::string> IdaDatabaseProvider::get_ida_func_proto(uint32_t func_ea) const {
    tinfo_t tif;
    if (!get_tinfo(&tif, static_cast<ea_t>(func_ea)) || !tif.is_func()) {
        return std::nullopt;
    }
    std::string fn_name = get_func_name(func_ea).value_or([&]() {
        char b[32];
        std::snprintf(b, sizeof(b), "sub_%X", func_ea);
        return std::string(b);
    }());

    func_type_data_t ftd;
    if (tif.get_func_details(&ftd)) {
        qstring qret;
        ftd.rettype.print(&qret);
        std::string ret_s = qret.empty() ? "void" : std::string(qret.c_str(), qret.length());
        std::string pjoin;
        for (size_t i = 0; i < ftd.size(); ++i) {
            if (i > 0) pjoin += ", ";
            qstring qat;
            ftd[i].type.print(&qat);
            std::string at = qat.empty() ? "uint16_t" : std::string(qat.c_str(), qat.length());
            std::string an = ftd[i].name.empty()
                                 ? ("a" + std::to_string(i))
                                 : std::string(ftd[i].name.c_str(), ftd[i].name.length());
            std::string sep = (!at.empty() && at.back() == '*') ? "" : " ";
            pjoin += at + sep + an;
        }
        if (pjoin.empty()) pjoin = "void";
        std::string rsep = (!ret_s.empty() && ret_s.back() == '*') ? "" : " ";
        return ret_s + rsep + fn_name + "(" + pjoin + ")";
    }
    return std::nullopt;
}

std::optional<SwitchInfo> IdaDatabaseProvider::get_switch_info(uint32_t br_ea) const {
    switch_info_t si;
    if (::get_switch_info(&si, static_cast<ea_t>(br_ea)) <= 0) {
        return std::nullopt;
    }
    casevec_t cases;
    eavec_t targets;
    if (!calc_switch_cases(&cases, &targets, static_cast<ea_t>(br_ea), si)) {
        return std::nullopt;
    }
    SwitchInfo out;
    out.ea = br_ea;
    out.table_ea = static_cast<uint32_t>(si.jumps);
    out.scale = (si.get_jtable_element_size() == 4) ? 4 : 2;
    if (si.defjump != BADADDR) out.default_ea = static_cast<uint32_t>(si.defjump);

    size_t n = std::min(cases.size(), targets.size());
    for (size_t i = 0; i < n; ++i) {
        uint32_t tgt = static_cast<uint32_t>(targets[i]);
        out.targets.push_back(tgt);
        for (sval_t cval : cases[i]) {
            out.cases[static_cast<int64_t>(cval)] = tgt;
        }
    }
    return out;
}

std::optional<CallerConsensus> IdaDatabaseProvider::compute_caller_consensus_uncached(uint32_t func_ea) const {
    CallerConsensus cc;
    int call_cnt = 0, ax_cnt = 0, bc_cnt = 0;
    auto op_mentions_ax = [](const Operand &op) {
        if (op.mode == OpMode::Reg) return op.reg == RegId::AX || op.reg == RegId::A || op.reg == RegId::X;
        if (op.mode == OpMode::Ind || op.mode == OpMode::Idx16 || op.mode == OpMode::Hloff) {
            return op.base_reg == RegId::AX || op.base_reg == RegId::A || op.base_reg == RegId::X;
        }
        return false;
    };
    auto op_mentions_bc = [](const Operand &op) {
        if (op.mode == OpMode::Reg) return op.reg == RegId::BC || op.reg == RegId::B || op.reg == RegId::C;
        if (op.mode == OpMode::Ind || op.mode == OpMode::Idx16 || op.mode == OpMode::Hloff) {
            return op.base_reg == RegId::BC || op.base_reg == RegId::B || op.base_reg == RegId::C;
        }
        return false;
    };

    xrefblk_t xb;
    for (bool ok = xb.first_to(static_cast<ea_t>(func_ea), XREF_ALL); ok; ok = xb.next_to()) {
        if (!xb.iscode || xb.type == fl_JN || xb.type == fl_F) continue;
        ea_t caller_ea = xb.from;
        ea_t prev = caller_ea;
        bool writes_ax = false, writes_bc = false;
        bool consumed_ax = false, consumed_bc = false;
        for (int step = 0; step < 5; ++step) {
            prev = prev_head(prev, 0);
            if (prev == BADADDR) break;
            auto ins = decode_one(*this, static_cast<uint32_t>(prev));
            if (!ins.has_value()) break;
            if (is_call_mnem(ins->mnem) || is_stop_mnem(ins->mnem) ||
                is_cond_branch_mnem(ins->mnem) || is_bit_branch_mnem(ins->mnem)) {
                break;
            }
            bool def_ax = (ins->ops.size() >= 1 && ins->ops[0].mode == OpMode::Reg &&
                           (ins->ops[0].reg == RegId::AX || ins->ops[0].reg == RegId::A || ins->ops[0].reg == RegId::X));
            bool def_bc = (ins->ops.size() >= 1 && ins->ops[0].mode == OpMode::Reg &&
                           (ins->ops[0].reg == RegId::BC || ins->ops[0].reg == RegId::B || ins->ops[0].reg == RegId::C));
            if (def_ax && !consumed_ax) writes_ax = true;
            if (def_bc && !consumed_bc) writes_bc = true;

            // If AX/BC was read to write memory or another register (e.g. `movw tmp_buf1, ax`),
            // any earlier write to AX/BC was a scratch shuttle, not a call argument!
            if (!writes_ax) {
                for (size_t oi = (def_ax ? 1 : 0); oi < ins->ops.size(); ++oi) {
                    if (op_mentions_ax(ins->ops[oi])) consumed_ax = true;
                }
            }
            if (!writes_bc) {
                for (size_t oi = (def_bc ? 1 : 0); oi < ins->ops.size(); ++oi) {
                    if (op_mentions_bc(ins->ops[oi])) consumed_bc = true;
                }
            }
        }
        ++call_cnt;
        if (writes_ax) ++ax_cnt;
        if (writes_bc) ++bc_cnt;
        if (call_cnt >= 16) break;
    }
    if (call_cnt >= 2) {
        cc.valid = true;
        cc.has_ax = (ax_cnt * 2 >= call_cnt);
        cc.has_bc = (bc_cnt * 2 >= call_cnt);
        return cc;
    }
    return std::nullopt;
}

std::optional<CallerConsensus> IdaDatabaseProvider::get_caller_consensus(uint32_t func_ea) const {
    if (cache_) return cache_->get_caller_consensus(*this, func_ea);
    return compute_caller_consensus_uncached(func_ea);
}

std::set<std::string> IdaDatabaseProvider::compute_callee_preserved_uncached(uint32_t callee_ea) const {
    std::set<std::string> out;
    uint32_t cur = callee_ea;
    for (int i = 0; i < 6; ++i) {
        auto ins = decode_one(*this, cur);
        if (!ins.has_value()) break;
        if (ins->mnem == Mnem::Push && !ins->ops.empty() && ins->ops[0].mode == OpMode::Reg) {
            out.insert(reg_name(ins->ops[0].reg));
        } else if (ins->mnem == Mnem::Subw && !ins->ops.empty() && ins->ops[0].reg == RegId::SP) {
            break;
        } else if (i > 0) {
            break;
        }
        cur += static_cast<uint32_t>(ins->size);
    }
    return out;
}

std::set<std::string> IdaDatabaseProvider::get_callee_preserved_regs(uint32_t callee_ea) const {
    if (cache_) return cache_->get_callee_preserved(*this, callee_ea);
    return compute_callee_preserved_uncached(callee_ea);
}

std::optional<bool> IdaDatabaseProvider::compute_callee_expects_ax_uncached(uint32_t callee_ea) const {
    uint32_t cur = callee_ea;
    for (int step = 0; step < 16; ++step) {
        auto ins = decode_one(*this, cur);
        if (!ins.has_value() || ins->size <= 0) return std::nullopt;
        for (const auto &op : ins->ops) {
            if (op.mode == OpMode::Reg && (op.reg == RegId::AX || op.reg == RegId::A || op.reg == RegId::X)) {
                return std::nullopt;
            }
            if ((op.mode == OpMode::Ind || op.mode == OpMode::Idx16 || op.mode == OpMode::Hloff) &&
                (op.base_reg == RegId::AX || op.base_reg == RegId::A || op.base_reg == RegId::X)) {
                return std::nullopt;
            }
        }
        if (ins->mnem == Mnem::Mulu || ins->mnem == Mnem::Mulh || ins->mnem == Mnem::Mulhu ||
            ins->mnem == Mnem::Divhu || ins->mnem == Mnem::Divwu ||
            ins->mnem == Mnem::Mach || ins->mnem == Mnem::Machu ||
            ins->mnem == Mnem::Movs || ins->mnem == Mnem::Cmps) {
            return std::nullopt;
        }
        if (is_ret_mnem(ins->mnem)) return false;
        if (is_call_mnem(ins->mnem) || is_stop_mnem(ins->mnem) ||
            is_cond_branch_mnem(ins->mnem) || is_bit_branch_mnem(ins->mnem) ||
            is_skip_mnem(ins->mnem) || ins->mnem == Mnem::Br) {
            return std::nullopt;
        }
        cur += static_cast<uint32_t>(ins->size);
    }
    return std::nullopt;
}

std::optional<bool> IdaDatabaseProvider::callee_expects_ax(uint32_t callee_ea) const {
    if (cache_) return cache_->callee_expects_ax(*this, callee_ea);
    return compute_callee_expects_ax_uncached(callee_ea);
}

bool IdaDatabaseProvider::compute_callee_returns_dword_uncached(uint32_t callee_ea) const {
    tinfo_t tif;
    if (get_tinfo(&tif, static_cast<ea_t>(callee_ea)) && tif.is_func()) {
        tinfo_t rt = tif.get_rettype();
        if (!rt.empty() && rt.get_size() == 4) return true;
    }
    return false;
}

bool IdaDatabaseProvider::callee_returns_dword(uint32_t callee_ea) const {
    if (cache_) return cache_->callee_returns_dword(*this, callee_ea);
    return compute_callee_returns_dword_uncached(callee_ea);
}

std::optional<FarParamSpecs> IdaDatabaseProvider::get_callee_far_param_specs(uint32_t /*callee_ea*/) const {
    return std::nullopt;
}

std::optional<CalleeSigHint> IdaDatabaseProvider::compute_callee_sig_uncached(uint32_t callee_ea) const {
    func_t *pfn = get_func(static_cast<ea_t>(callee_ea));
    if (!pfn) return std::nullopt;
    callee_ea = static_cast<uint32_t>(pfn->start_ea);

    if (auto idap = get_ida_func_proto(callee_ea); idap.has_value()) {
        if (auto parsed = parse_prototype(*idap); parsed.has_value()) {
            CalleeSigHint hint;
            hint.valid = true;
            hint.ret_type = parsed->ret_type;
            bool first_far = !parsed->params.empty() &&
                             (parsed->params[0].second == "uint32_t" || parsed->params[0].second == "int32_t");
            for (size_t i = 0; i < parsed->params.size(); ++i) {
                const std::string &pt = parsed->params[i].second;
                bool is8 = (pt == "uint8_t" || pt == "int8_t" || pt == "bool");
                std::string loc = "stack";
                if (i == 0) loc = first_far ? "ax:bc" : (is8 ? "a" : "ax");
                else if (i == 1 && !first_far) loc = is8 ? "c" : "bc";
                hint.params.push_back(ParamHint{pt, loc});
            }
            return hint;
        }
    }

    DecodedProgram prog;
    std::unordered_set<uint32_t> seen;
    std::vector<uint32_t> work{callee_ea};
    constexpr size_t kMaxInsnScan = 4096;
    while (!work.empty() && prog.insns.size() < kMaxInsnScan) {
        uint32_t cur = work.back();
        work.pop_back();
        if (!seen.insert(cur).second || !is_loaded(cur)) continue;
        auto ins = decode_one(*this, cur);
        if (!ins.has_value() || ins->size <= 0) continue;
        prog.insns[cur] = *ins;
        DecodedInsn &stored = prog.insns[cur];
        if (stored.mnem == Mnem::Br && !stored.ops.empty() &&
            stored.ops[0].mode == OpMode::Reg && stored.ops[0].reg == RegId::AX) {
            if (auto sw = detect_switch(*this, prog.insns, stored); sw.has_value()) {
                stored.sw = *sw;
            }
        }
        for (const auto &[kind, tgt] : insn_succs(*this, stored)) {
            if (kind == "call") {
                prog.calls.insert(tgt);
            } else if (!seen.count(tgt)) {
                work.push_back(tgt);
            }
        }
    }
    if (!prog.insns.count(callee_ea)) return std::nullopt;

    std::set<uint32_t> entry_set = prog.calls;
    entry_set.insert(callee_ea);
    auto fn = build_func(prog.insns, callee_ea, entry_set);
    if (!fn) return std::nullopt;

    auto ida_frame = get_ida_frame_info(callee_ea);
    FrameInfo fi = analyze_frame(*fn, ida_frame ? &*ida_frame : nullptr);
    optimize(*fn, 0, this);
    eliminate_spills(*fn, fi);
    duplicate_epilogue_returns(*fn, fi);
    thread_condition_jumps(*fn, fi);
    resolve_flags(*fn);
    auto consensus = get_caller_consensus(callee_ea);
    FunctionSig sig = infer_function_sig_only(*fn, fi, this, "", consensus ? &*consensus : nullptr);

    CalleeSigHint hint;
    hint.valid = true;
    hint.ret_type = sig.ret_type;
    for (const auto &p : sig.params) {
        hint.params.push_back(ParamHint{p.type_str, p.location});
    }
    return hint;
}

std::optional<CalleeSigHint> IdaDatabaseProvider::get_callee_sig(uint32_t callee_ea) const {
    if (cache_) return cache_->get_callee_sig(*this, callee_ea);
    return std::nullopt;
}

std::optional<StructDef> IdaDatabaseProvider::get_udt_info(const std::string &name) const {
    if (name.empty() || name == "void") return std::nullopt;
    tinfo_t tif;
    if (!tif.get_named_type(nullptr, name.c_str()) || !tif.is_udt()) return std::nullopt;
    udt_type_data_t udt;
    if (!tif.get_udt_details(&udt)) return std::nullopt;
    StructDef def;
    def.name = name;
    for (const auto &m : udt) {
        if (m.name.empty()) continue;
        int64_t sz = static_cast<int64_t>(m.size / 8);
        if (sz <= 0) sz = 1;
        def.members.push_back(StructMemberInfo{
            static_cast<int64_t>(m.offset / 8), sz,
            std::string(m.name.c_str(), m.name.length())});
    }
    return def;
}

std::optional<std::string> IdaDatabaseProvider::get_symbol_struct(uint32_t ea) const {
    ea_t a = static_cast<ea_t>(ea);
    tinfo_t tif;
    if (get_tinfo(&tif, a) && tif.is_udt()) {
        qstring qn;
        if (tif.get_type_name(&qn) && !qn.empty()) {
            return std::string(qn.c_str(), qn.length());
        }
    }
    flags64_t fl = get_flags(a);
    if (is_struct(fl)) {
        opinfo_t oi;
        if (get_opinfo(&oi, a, 0, fl)) {
            qstring qsn;
            if (get_tid_name(&qsn, oi.tid) && !qsn.empty()) {
                return std::string(qsn.c_str(), qsn.length());
            }
        }
    }
    return std::nullopt;
}

std::optional<uint8_t> IdaDatabaseProvider::get_es_at(uint32_t ea) const {
    int es_reg = -1;
    if (PH.reg_names && PH.regs_num > 0) {
        for (int i = 0; i < PH.regs_num; ++i) {
            const char *rn = PH.reg_names[i];
            if (rn && (rn[0] == 'e' || rn[0] == 'E') && (rn[1] == 's' || rn[1] == 'S') && rn[2] == '\0') {
                es_reg = i;
                break;
            }
        }
    }
    if (es_reg < 0) return std::nullopt;
    sel_t sel = ::get_sreg(static_cast<ea_t>(ea), es_reg);
    if (sel == BADSEL || sel > 0x0Fu) return std::nullopt;
    return static_cast<uint8_t>(sel);
}

CalleeEsInfo IdaDatabaseProvider::compute_callee_es_effect_uncached(uint32_t callee_ea) const {
    func_t *pfn = get_func(static_cast<ea_t>(callee_ea));
    if (!pfn) return CalleeEsInfo{CalleeEsEffect::Clobbered, 0x0F};
    uint32_t entry = static_cast<uint32_t>(pfn->start_ea);

    struct EsLat {
        enum Kind { Top = 0, Entry, Const, Dynamic } kind = Top;
        uint8_t val = 0x0F;
    };
    auto meet = [](EsLat a, EsLat b) -> EsLat {
        if (a.kind == EsLat::Top) return b;
        if (b.kind == EsLat::Top) return a;
        if (a.kind == EsLat::Dynamic || b.kind == EsLat::Dynamic) return {EsLat::Dynamic, 0};
        if (a.kind == EsLat::Entry && b.kind == EsLat::Entry) return {EsLat::Entry, 0};
        if (a.kind == EsLat::Const && b.kind == EsLat::Const && a.val == b.val) return a;
        return {EsLat::Dynamic, 0};
    };

    struct Work {
        uint32_t ea;
        EsLat es;
        std::optional<uint8_t> a_const;
    };
    std::vector<Work> work;
    std::unordered_map<uint32_t, EsLat> seen;
    work.push_back({entry, {EsLat::Entry, 0}, std::nullopt});

    EsLat ret_meet{EsLat::Top, 0};
    int steps = 0;

    while (!work.empty() && steps < 2048) {
        Work cur = work.back();
        work.pop_back();
        ++steps;

        auto sit = seen.find(cur.ea);
        if (sit != seen.end()) {
            EsLat joined = meet(sit->second, cur.es);
            if (joined.kind == sit->second.kind && joined.val == sit->second.val) continue;
            cur.es = joined;
            cur.a_const = std::nullopt;
        }
        seen[cur.ea] = cur.es;

        auto ins = decode_one(*this, cur.ea);
        if (!ins.has_value() || ins->size <= 0) {
            ret_meet = {EsLat::Dynamic, 0};
            break;
        }

        if (ins->mnem == Mnem::Mov && ins->ops.size() >= 2 && ins->ops[0].mode == OpMode::Reg) {
            RegId r0 = ins->ops[0].reg;
            if (r0 == RegId::ES) {
                if (ins->ops[1].mode == OpMode::Imm) {
                    cur.es = {EsLat::Const, static_cast<uint8_t>(ins->ops[1].value & 0xFu)};
                } else if (ins->ops[1].mode == OpMode::Reg && ins->ops[1].reg == RegId::A && cur.a_const.has_value()) {
                    cur.es = {EsLat::Const, static_cast<uint8_t>(*cur.a_const & 0xFu)};
                } else {
                    cur.es = {EsLat::Dynamic, 0};
                }
            } else if (r0 == RegId::A) {
                if (ins->ops[1].mode == OpMode::Imm) cur.a_const = static_cast<uint8_t>(ins->ops[1].value & 0xFFu);
                else cur.a_const = std::nullopt;
            } else if (r0 == RegId::AX) {
                cur.a_const = std::nullopt;
            }
        } else if (ins->mnem == Mnem::Clrb && !ins->ops.empty() && ins->ops[0].mode == OpMode::Reg) {
            if (ins->ops[0].reg == RegId::ES) cur.es = {EsLat::Const, 0};
            else if (ins->ops[0].reg == RegId::A) cur.a_const = 0;
        } else if (ins->mnem == Mnem::Oneb && !ins->ops.empty() && ins->ops[0].mode == OpMode::Reg) {
            if (ins->ops[0].reg == RegId::ES) cur.es = {EsLat::Const, 1};
            else if (ins->ops[0].reg == RegId::A) cur.a_const = 1;
        } else if ((ins->mnem == Mnem::Clrw || ins->mnem == Mnem::Onew) &&
                   !ins->ops.empty() && ins->ops[0].mode == OpMode::Reg && ins->ops[0].reg == RegId::AX) {
            cur.a_const = 0;
        } else if (ins->mnem == Mnem::Pop && !ins->ops.empty() && ins->ops[0].mode == OpMode::Reg) {
            if (ins->ops[0].reg == RegId::ES) cur.es = {EsLat::Dynamic, 0};
            else if (ins->ops[0].reg == RegId::AX) cur.a_const = std::nullopt;
        } else if (ins->mnem == Mnem::Call || ins->mnem == Mnem::Callt || ins->mnem == Mnem::Brk) {
            cur.a_const = std::nullopt;
            auto tgt = target_of(*ins);
            if (tgt.has_value()) {
                CalleeEsInfo ce = get_callee_es_effect(*tgt);
                if (ce.effect == CalleeEsEffect::ReturnsConst) {
                    cur.es = {EsLat::Const, static_cast<uint8_t>(ce.const_val & 0xFu)};
                } else if (ce.effect == CalleeEsEffect::Clobbered) {
                    cur.es = {EsLat::Dynamic, 0};
                }
            } else {
                cur.es = {EsLat::Dynamic, 0};
            }
        } else if (!ins->ops.empty() && ins->ops[0].mode == OpMode::Reg) {
            RegId r0 = ins->ops[0].reg;
            if (r0 == RegId::A || r0 == RegId::AX || r0 == RegId::X) cur.a_const = std::nullopt;
        }

        if (is_ret_mnem(ins->mnem)) {
            ret_meet = meet(ret_meet, cur.es);
            continue;
        }
        if (ins->mnem == Mnem::Br && !ins->ops.empty() &&
            ins->ops[0].mode == OpMode::Reg && ins->ops[0].reg == RegId::AX) {
            ret_meet = {EsLat::Dynamic, 0};
            continue;
        }
        for (const auto &[how, tgt] : insn_succs(*this, *ins)) {
            if (how == "call") continue;
            func_t *tf = get_func(static_cast<ea_t>(tgt));
            if (tf != pfn) {
                if (how == "jump" && tf != nullptr) {
                    // Tail jump to another function
                    CalleeEsInfo te = get_callee_es_effect(static_cast<uint32_t>(tf->start_ea));
                    if (te.effect == CalleeEsEffect::Preserved) ret_meet = meet(ret_meet, cur.es);
                    else if (te.effect == CalleeEsEffect::ReturnsConst) ret_meet = meet(ret_meet, {EsLat::Const, te.const_val});
                    else ret_meet = {EsLat::Dynamic, 0};
                }
                continue;
            }
            work.push_back({tgt, cur.es, cur.a_const});
        }
    }

    if (steps >= 2048) return CalleeEsInfo{CalleeEsEffect::Clobbered, 0x0F};
    if (ret_meet.kind == EsLat::Entry) return CalleeEsInfo{CalleeEsEffect::Preserved, 0x0F};
    if (ret_meet.kind == EsLat::Const) return CalleeEsInfo{CalleeEsEffect::ReturnsConst, ret_meet.val};
    return CalleeEsInfo{CalleeEsEffect::Clobbered, 0x0F};
}

CalleeEsInfo IdaDatabaseProvider::get_callee_es_effect(uint32_t callee_ea) const {
    if (cache_) return cache_->get_callee_es_effect(*this, callee_ea);
    return compute_callee_es_effect_uncached(callee_ea);
}

std::optional<SymbolInfo> IdaDatabaseProvider::compute_symbol_info_uncached(uint32_t ea) const {
    ea_t a = static_cast<ea_t>(ea);
    flags64_t fl_exact = get_flags(a);
    if (is_code(fl_exact)) return std::nullopt;

    auto is_ignored_name = [](const std::string &s) {
        return s.empty() || s.rfind("loc_", 0) == 0 || s.rfind("locret_", 0) == 0 ||
               s.rfind("sub_", 0) == 0 || s.rfind("nullsub_", 0) == 0 ||
               s.rfind("j_", 0) == 0 || s.rfind("def_", 0) == 0;
    };

    ea_t base_ea = a;
    qstring qnm;
    std::string raw;
    if (::get_name(&qnm, a) > 0 && !qnm.empty()) {
        raw.assign(qnm.c_str(), qnm.length());
    }
    if (is_ignored_name(raw)) {
        raw.clear();
        ea_t head = ::get_item_head(a);
        if (head != BADADDR && head < a && !is_code(get_flags(head))) {
            asize_t hsz = ::get_item_size(head);
            if (a < head + hsz && ::get_name(&qnm, head) > 0 && !qnm.empty()) {
                std::string hraw(qnm.c_str(), qnm.length());
                if (!is_ignored_name(hraw)) {
                    raw = std::move(hraw);
                    base_ea = head;
                }
            }
        }
    }
    if (raw.empty()) return std::nullopt;

    flags64_t base_fl = get_flags(base_ea);
    asize_t sz = ::get_item_size(base_ea);

    SymbolInfo info;
    info.name = std::move(raw);
    info.base_ea = static_cast<uint32_t>(base_ea);
    info.offset = static_cast<uint32_t>(a - base_ea);
    info.item_size = static_cast<uint32_t>(std::max<asize_t>(1, sz));

    if (auto sname = get_symbol_struct(info.base_ea); sname.has_value()) {
        info.struct_name = *sname;
    }

    tinfo_t tif;
    bool tif_is_arr = (get_tinfo(&tif, base_ea) && tif.is_array());
    info.is_array = is_strlit(base_fl) || tif_is_arr || (info.struct_name.empty() && info.item_size > 4);

    // For 1-byte non-array symbols, check whether any instruction accesses it via scalar (non-idx16) mode
    if (!info.is_array && info.struct_name.empty() && info.item_size == 1) {
        xrefblk_t xb;
        for (bool ok = xb.first_to(base_ea, XREF_DATA); ok; ok = xb.next_to()) {
            if (xb.iscode || (xb.type != dr_R && xb.type != dr_W)) continue;
            uint8_t b0 = get_byte(xb.from);
            ea_t pos = (b0 == 0x11) ? (xb.from + 1) : xb.from;
            uint8_t op = get_byte(pos);
            bool is_idx16 = (op == 0x09 || op == 0x18 || op == 0x19 || op == 0x28 || op == 0x29 ||
                             op == 0x38 || op == 0x39 || op == 0x48 || op == 0x49 || op == 0x58 ||
                             op == 0x59 || op == 0x68 || op == 0x69 || op == 0x78 || op == 0x79);
            if (!is_idx16) {
                info.has_scalar_xref = true;
                break;
            }
        }
    }

    return info;
}

std::optional<SymbolInfo> IdaDatabaseProvider::get_symbol_info(uint32_t ea) const {
    if (cache_) return cache_->get_symbol_info(*this, ea);
    return compute_symbol_info_uncached(ea);
}

std::vector<StructDef> IdaDatabaseProvider::compute_all_udts_uncached() const {
    std::vector<StructDef> out;
    const til_t *til = get_idati();
    if (!til) return out;
    const uint32 limit = get_ordinal_limit(til);
    for (uint32 ord = 1; ord < limit; ++ord) {
        tinfo_t tif;
        if (!tif.get_numbered_type(til, ord) || !tif.is_udt()) continue;
        qstring qtn;
        if (!tif.get_type_name(&qtn) || qtn.empty()) continue;
        udt_type_data_t udt;
        if (!tif.get_udt_details(&udt)) continue;
        StructDef def;
        def.name.assign(qtn.c_str(), qtn.length());
        for (const auto &m : udt) {
            if (m.name.empty()) continue;
            int64_t msz = static_cast<int64_t>(m.size / 8);
            if (msz <= 0) msz = 1;
            def.members.push_back(StructMemberInfo{
                static_cast<int64_t>(m.offset / 8), msz,
                std::string(m.name.c_str(), m.name.length())});
        }
        out.push_back(std::move(def));
    }
    return out;
}

std::unordered_map<uint32_t, std::string> IdaDatabaseProvider::compute_all_symbol_structs_uncached() const {
    std::unordered_map<uint32_t, std::string> out;
    const int nseg = get_segm_qty();
    for (int i = 0; i < nseg; ++i) {
        segment_t *seg = getnseg(i);
        if (!seg) continue;
        ea_t cur = seg->start_ea;
        while (cur < seg->end_ea && cur != BADADDR) {
            if (cur >= 0x100000ULL) break;
            uint32_t ea32 = static_cast<uint32_t>(cur);
            if (auto sn = get_symbol_struct(ea32); sn.has_value()) {
                out[ea32] = *sn;
            }
            ea_t nxt = next_head(cur, seg->end_ea);
            if (nxt == BADADDR || nxt <= cur) break;
            cur = nxt;
        }
    }
    return out;
}

std::vector<StructDef> IdaDatabaseProvider::get_all_udts() const {
    if (cache_) return cache_->get_all_udts(*this);
    return compute_all_udts_uncached();
}

std::unordered_map<uint32_t, std::string> IdaDatabaseProvider::get_all_symbol_structs() const {
    if (cache_) return cache_->get_all_symbol_structs(*this);
    return compute_all_symbol_structs_uncached();
}

} // namespace rl78dec
