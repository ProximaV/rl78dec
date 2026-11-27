#include <ida.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <name.hpp>
#include <typeinf.hpp>
#include <xref.hpp>

#ifdef strtoull
#undef strtoull
#endif

#include "view.hpp"
#include "db.hpp"
#include "ida_provider.hpp"
#include "plugin.hpp"
#include "summary_cache.hpp"

#include "rl78dec/abi.hpp"
#include "rl78dec/cgen.hpp"
#include "rl78dec/highlight.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace rl78dec {

namespace {

std::string trim_copy(const std::string &s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

bool is_valid_c_ident(const std::string &s) {
    if (s.empty()) return false;
    unsigned char c0 = static_cast<unsigned char>(s[0]);
    if (!(std::isalpha(c0) || c0 == '_')) return false;
    for (size_t i = 1; i < s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (!(std::isalnum(c) || c == '_')) return false;
    }
    return true;
}

std::string extract_word_at(const std::string &line, int col) {
    if (line.empty()) return {};
    int idx = std::max(0, std::min(col, static_cast<int>(line.size()) - 1));
    auto is_w = [](char ch) {
        unsigned char u = static_cast<unsigned char>(ch);
        return std::isalnum(u) || ch == '_';
    };
    if (!is_w(line[idx]) && idx > 0 && is_w(line[idx - 1])) --idx;
    if (!is_w(line[idx])) return {};
    int l = idx, r = idx + 1;
    while (l > 0 && is_w(line[l - 1])) --l;
    while (r < static_cast<int>(line.size()) && is_w(line[r])) ++r;
    return line.substr(l, r - l);
}

struct EventCbEntry {
    int handle = 0;
    EventCallbackFn fn;
};

struct CallbackRegistry {
    int next_handle = 1;
    std::vector<EventCbEntry> entries;
};

CallbackRegistry &cb_registry() {
    static CallbackRegistry reg;
    return reg;
}

struct XrefRow {
    uint64_t ea = 0;
    std::string kind;
    std::string text;
};

struct XrefChooser : public chooser_t {
    static constexpr int kWidths[] = {12, 10, 48};
    static constexpr const char *const kHeaders[] = {"Address", "Type", "Context"};
    std::vector<XrefRow> rows;

    XrefChooser(const char *title_str, std::vector<XrefRow> r)
        : chooser_t(CH_MODAL | CH_KEEP, 3, kWidths, kHeaders, title_str),
          rows(std::move(r)) {}

    size_t idaapi get_count() const override { return rows.size(); }

    void idaapi get_row(qstrvec_t *cols, int *, chooser_item_attrs_t *, size_t n) const override {
        if (!cols || n >= rows.size()) return;
        char eabuf[32];
        std::snprintf(eabuf, sizeof(eabuf), "0x%llX", static_cast<unsigned long long>(rows[n].ea));
        (*cols)[0] = eabuf;
        (*cols)[1] = rows[n].kind.c_str();
        (*cols)[2] = rows[n].text.c_str();
    }
};

bool idaapi vdui_ct_keyboard(TWidget *, int key, int shift, void *ud) {
    auto *v = static_cast<Rl78Vdui *>(ud);
    return v ? v->handle_keyboard(key, shift) : false;
}

void idaapi vdui_ct_curpos(TWidget *, void *ud) {
    auto *v = static_cast<Rl78Vdui *>(ud);
    if (v) v->handle_curpos();
}

bool idaapi vdui_ct_click(TWidget *, int shift, void *ud) {
    auto *v = static_cast<Rl78Vdui *>(ud);
    if (v) v->handle_click(shift);
    return false;
}

bool idaapi vdui_ct_dblclick(TWidget *, int shift, void *ud) {
    auto *v = static_cast<Rl78Vdui *>(ud);
    return v ? v->handle_dblclick(shift) : false;
}

static const custom_viewer_handlers_t kVduiHandlers(
    vdui_ct_keyboard, nullptr, nullptr, vdui_ct_click, vdui_ct_dblclick,
    vdui_ct_curpos, nullptr, nullptr, nullptr);

struct ListingViewState {
    TWidget *widget = nullptr;
    strvec_t lines;
    std::string raw_c_text;
};

ListingViewState &listing_state() {
    static ListingViewState st;
    return st;
}

bool idaapi listing_ct_dblclick(TWidget *v, int, void *) {
    const char *cur = get_custom_viewer_curline(v, false);
    if (!cur) return false;
    qstring clean;
    tag_remove(&clean, cur);
    const char *s = clean.c_str();
    const char *p = std::strstr(s, "sub_");
    if (!p) p = std::strstr(s, "0x");
    if (p) {
        p += (p[0] == 's') ? 4 : 2;
        char *endp = nullptr;
        unsigned long long val = std::strtoull(p, &endp, 16);
        if (endp > p && is_loaded(static_cast<ea_t>(val))) {
            global_vdui().open_or_focus(static_cast<uint64_t>(val), 1, true);
            return true;
        }
    }
    return false;
}

static const custom_viewer_handlers_t kListingHandlers(
    nullptr, nullptr, nullptr, nullptr, listing_ct_dblclick, nullptr, nullptr, nullptr, nullptr);

} // namespace

int register_event_callback(EventCallbackFn cb) {
    if (!cb) return -1;
    CallbackRegistry &reg = cb_registry();
    int h = reg.next_handle++;
    reg.entries.push_back(EventCbEntry{h, std::move(cb)});
    return h;
}

bool unregister_event_callback(int handle) {
    auto &vec = cb_registry().entries;
    for (auto it = vec.begin(); it != vec.end(); ++it) {
        if (it->handle == handle) {
            vec.erase(it);
            return true;
        }
    }
    return false;
}

int notify_event(rl78dec_event_t ev, void *arg0, void *arg1) {
    auto snapshot = cb_registry().entries;
    int last_rc = 0;
    for (const auto &entry : snapshot) {
        if (entry.fn) {
            int rc = entry.fn(ev, arg0, arg1);
            if (rc != 0) last_rc = rc;
        }
    }
    return last_rc;
}

Rl78Vdui &global_vdui() {
    static Rl78Vdui instance;
    return instance;
}

Rl78Vdui *find_vdui_for_widget(TWidget *w) {
    if (!w) return nullptr;
    Rl78Vdui &v = global_vdui();
    if (v.widget() == w) return &v;
    qstring title;
    if (get_widget_title(&title, w) && title == RL78DEC_VIEW_TITLE) return &v;
    return nullptr;
}

TWidget *get_listing_widget() { return listing_state().widget; }

cfuncptr_t decompile_or_get_cached(uint64_t ea, bool force_redecompile, std::string *out_error) {
    SummaryCache &cache = global_summary_cache();
    IdaDatabaseProvider prov(&cache);

    uint32_t func_ea = static_cast<uint32_t>(ea);
    if (auto fs = prov.get_func_start(func_ea); fs.has_value()) func_ea = *fs;

    if (!force_redecompile) {
        cfuncptr_t cached = cache.get_cached_cfunc(func_ea);
        if (cached) {
            if (cached->has_tree_mutations()) cached->refresh_func_ctext();
            return cached;
        }
    }

    ensure_rl78_types();
    DecompileOptions opts;
    opts.user_data = idadb::get_func_data(func_ea);
    DecompileResult res = decompile_function(prov, func_ea, opts);
    if (!res.ok || !res.cfunc) {
        if (out_error) *out_error = res.error.empty() ? "Decompilation failed" : res.error;
        return nullptr;
    }
    cache.put_cached_cfunc(func_ea, res.cfunc);
    return res.cfunc;
}

std::string decompile_single_to_text(uint64_t ea, std::string *out_error) {
    cfuncptr_t cf = decompile_or_get_cached(ea, false, out_error);
    if (!cf) return {};
    return cf->print_func();
}

std::string dump_single_ir_to_text(uint64_t ea, std::string *out_error) {
    SummaryCache &cache = global_summary_cache();
    IdaDatabaseProvider prov(&cache);
    uint32_t func_ea = static_cast<uint32_t>(ea);
    if (auto fs = prov.get_func_start(func_ea); fs.has_value()) func_ea = *fs;

    DecompileOptions opts;
    opts.user_data = idadb::get_func_data(func_ea);
    DecompileResult out = decompile_function(prov, func_ea, opts);
    if (!out.ok) {
        if (out_error) *out_error = out.error.empty() ? "IR lift failed" : out.error;
        return {};
    }
    return out.ir_dump;
}

std::string decompile_all_to_string(bool show_progress, int *out_ok, int *out_fail) {
    SummaryCache &cache = global_summary_cache();
    IdaDatabaseProvider prov(&cache);
    ensure_rl78_types();

    std::vector<uint32_t> entries = prov.get_func_entries();
    const size_t total = entries.size();
    int ok_cnt = 0, fail_cnt = 0;

    std::vector<cfuncptr_t> ok_cfuncs;
    std::vector<std::string> ok_blocks;
    std::string fail_notes;

    if (show_progress) show_wait_box("Decompiling %zu RL78 functions...", total);

    for (size_t idx = 0; idx < total; ++idx) {
        if (show_progress && (idx % 50) == 0) {
            if (user_cancelled()) break;
            replace_wait_box("Decompiling function %zu / %zu...", idx, total);
        }
        uint32_t fea = entries[idx];
        std::string err;
        cfuncptr_t cf = decompile_or_get_cached(fea, false, &err);
        if (cf) {
            ok_cfuncs.push_back(cf);
            ok_blocks.push_back(cf->print_func());
            ++ok_cnt;
        } else {
            char fbuf[64];
            std::snprintf(fbuf, sizeof(fbuf), "// Failed 0x%X: ", fea);
            fail_notes += std::string(fbuf) + err + "\n";
            ++fail_cnt;
        }
    }

    if (show_progress) hide_wait_box();
    if (out_ok) *out_ok = ok_cnt;
    if (out_fail) *out_fail = fail_cnt;

    std::ostringstream oss;
    oss << "// rl78dec - All Decompiled Functions (" << total << " functions)\n\n";
    if (!fail_notes.empty()) oss << fail_notes << "\n";
    oss << build_listing_with_decls(prov, ok_cfuncs, ok_blocks);
    return oss.str();
}

bool open_decompile_all_viewer() {
    if (!is_rl78_database_active()) return false;
    int ok_cnt = 0, fail_cnt = 0;
    std::string text = decompile_all_to_string(true, &ok_cnt, &fail_cnt);

    ListingViewState &st = listing_state();
    st.raw_c_text = text;
    st.lines.qclear();

    std::istringstream iss(text);
    std::string ln;
    while (std::getline(iss, ln)) {
        if (!ln.empty() && ln.back() == '\r') ln.pop_back();
        st.lines.push_back(simpleline_t(colorize_c_line(ln).c_str()));
    }
    if (st.lines.empty()) st.lines.push_back(simpleline_t("// Empty"));

    if (st.widget && find_widget(RL78DEC_LISTING_TITLE) == st.widget) {
        simpleline_place_t s1, s2(static_cast<int>(st.lines.size()) - 1);
        set_custom_viewer_range(st.widget, &s1, &s2);
        refresh_custom_viewer(st.widget);
        activate_widget(st.widget, true);
    } else {
        simpleline_place_t s1, s2(static_cast<int>(st.lines.size()) - 1);
        st.widget = create_custom_viewer(
            RL78DEC_LISTING_TITLE, &s1, &s2, &s1, nullptr, &st.lines, &kListingHandlers, nullptr);
        if (st.widget) {
            display_widget(st.widget, WOPN_DP_TAB | WOPN_RESTORE);
            activate_widget(st.widget, true);
        }
    }
    msg("[rl78dec] Decompiled %d functions (%d failed).\n", ok_cnt, fail_cnt);
    return st.widget != nullptr;
}

int act_save_listing_to_c_file() {
    ListingViewState &st = listing_state();
    if (st.raw_c_text.empty()) {
        warning("rl78dec: No listing generated yet. Press Ctrl+F5 first.");
        return 0;
    }
    const char *path = ask_file(true, "*.c", "Save decompiled RL78 pseudocode");
    if (!path || !path[0]) return 0;
    FILE *fp = qfopen(path, "wb");
    if (!fp) {
        warning("rl78dec: Failed to open %s for writing.", path);
        return 0;
    }
    qfwrite(fp, st.raw_c_text.data(), st.raw_c_text.size());
    qfclose(fp);
    msg("[rl78dec] Saved pseudocode to %s\n", path);
    return 1;
}

bool Rl78Vdui::ensure_widget_created(bool dock_right, bool activate) {
    if (widget_ != nullptr && find_widget(RL78DEC_VIEW_TITLE) == widget_) {
        if (activate) activate_widget(widget_, true);
        return true;
    }
    TWidget *existing = find_widget(RL78DEC_VIEW_TITLE);
    if (existing != nullptr) {
        widget_ = existing;
        set_custom_viewer_handlers(widget_, &kVduiHandlers, this);
        if (activate) activate_widget(widget_, true);
        return true;
    }
    if (lines_.empty()) lines_.push_back(simpleline_t("/* Ready */"));
    simpleline_place_t s1, s2(static_cast<int>(lines_.size()) - 1);
    widget_ = create_custom_viewer(
        RL78DEC_VIEW_TITLE, &s1, &s2, &s1, nullptr, &lines_, &kVduiHandlers, this);
    if (!widget_) return false;
    display_widget(widget_, WOPN_DP_TAB | WOPN_RESTORE);
    if (dock_right) set_dock_pos(RL78DEC_VIEW_TITLE, "IDA View-A", DP_RIGHT);
    if (activate) activate_widget(widget_, true);
    notify_event(rle_open_pseudocode, this);
    return true;
}

bool Rl78Vdui::open_or_focus(uint64_t target_ea, int open_flags, bool push_history) {
    sync_with_disasm_ = idadb::get_sync_enabled();
    uint64_t func_ea = target_ea;
    if (func_t *pfn = get_func(static_cast<ea_t>(target_ea))) {
        func_ea = static_cast<uint64_t>(pfn->start_ea);
    }
    const bool was_open = (widget_ != nullptr && find_widget(RL78DEC_VIEW_TITLE) == widget_);
    if (push_history && was_open && current_func_ea_.has_value()) {
        push_current_nav();
        nav_forward_.clear();
    }
    if (!ensure_widget_created(!was_open, open_flags >= 0)) return false;
    bool ok = render_function(func_ea, target_ea, -1, 0, false);
    if (ok) persist_window_state(true);
    return ok;
}

TWidget *Rl78Vdui::create_for_desktop() {
    sync_with_disasm_ = idadb::get_sync_enabled();
    WindowState st = idadb::load_window_state();
    mode_ = (st.mode == "ir") ? "ir" : "c";
    if (lines_.empty()) lines_.push_back(simpleline_t("/* Loading RL78 pseudocode... */"));
    simpleline_place_t s1, s2(static_cast<int>(lines_.size()) - 1);
    widget_ = create_custom_viewer(
        RL78DEC_VIEW_TITLE, &s1, &s2, &s1, nullptr, &lines_, &kVduiHandlers, this);
    return widget_;
}

void Rl78Vdui::restore_saved_window() {
    sync_with_disasm_ = idadb::get_sync_enabled();
    WindowState st = idadb::load_window_state();
    mode_ = (st.mode == "ir") ? "ir" : "c";
    TWidget *existing = find_widget(RL78DEC_VIEW_TITLE);
    if (existing != nullptr) {
        widget_ = existing;
        set_custom_viewer_handlers(widget_, &kVduiHandlers, this);
    } else if (!st.is_open) {
        return;
    }
    uint64_t target_ea = 0;
    if (st.func_ea.has_value() && is_loaded(static_cast<ea_t>(*st.func_ea))) target_ea = *st.func_ea;
    else if (ea_t scr = get_screen_ea(); scr != BADADDR) target_ea = static_cast<uint64_t>(scr);
    if (target_ea == 0 && !is_loaded(0)) return;
    if (!widget_ && !ensure_widget_created(true, false)) return;
    render_function(target_ea, std::nullopt, st.lineno, st.col, false);
}

void Rl78Vdui::persist_window_state(bool force_open_state) {
    bool open_flag = force_open_state ? (widget_ != nullptr) : false;
    int lineno = selected_line_, col = 0;
    if (widget_ != nullptr) get_cursor_pos(&lineno, &col, false);
    idadb::save_window_state(open_flag, current_func_ea_, lineno, col, mode_, true);
}

void Rl78Vdui::close_and_cleanup() {
    highlighted_asm_eas_.clear();
    if (widget_ != nullptr) {
        TWidget *w = widget_;
        widget_ = nullptr;
        close_widget(w, WCLS_SAVE);
    }
    cfunc_.reset();
    ir_func_.reset();
    lines_.qclear();
}

bool Rl78Vdui::refresh_view(bool force_redecompile) {
    if (!current_func_ea_.has_value()) return false;
    int lineno = selected_line_, col = 0;
    get_cursor_pos(&lineno, &col, false);
    if (force_redecompile) global_summary_cache().invalidate_func(static_cast<uint32_t>(*current_func_ea_));
    bool ok = render_function(*current_func_ea_, std::nullopt, lineno, col, force_redecompile);
    if (ok) notify_event(rle_refresh_pseudocode, this);
    return ok;
}

bool Rl78Vdui::switch_to(uint64_t target_ea, bool push_history) {
    func_t *pfn = get_func(static_cast<ea_t>(target_ea));
    if (!pfn) {
        if (push_history && current_func_ea_.has_value()) { push_current_nav(); nav_forward_.clear(); }
        jumpto(static_cast<ea_t>(target_ea), -1, UIJMP_IDAVIEW | UIJMP_ACTIVATE);
        return true;
    }
    uint64_t new_func_ea = static_cast<uint64_t>(pfn->start_ea);
    if (push_history && current_func_ea_.has_value()) { push_current_nav(); nav_forward_.clear(); }
    bool switched = (!current_func_ea_.has_value() || *current_func_ea_ != new_func_ea);
    bool ok = render_function(new_func_ea, target_ea, -1, 0, false);
    if (ok && switched) notify_event(rle_switch_pseudocode, this);
    return ok;
}

bool Rl78Vdui::render_function(uint64_t func_ea, std::optional<uint64_t> focus_ea,
                               int restore_line, int restore_col, bool force_redecompile) {
    SummaryCache &cache = global_summary_cache();
    IdaDatabaseProvider prov(&cache);
    if (auto fs = prov.get_func_start(static_cast<uint32_t>(func_ea)); fs.has_value()) func_ea = *fs;

    ensure_rl78_types();
    std::string err;
    cfuncptr_t cf = decompile_or_get_cached(func_ea, force_redecompile, &err);
    if (!cf) {
        warning("rl78dec: failed to decompile 0x%llX: %s",
                static_cast<unsigned long long>(func_ea), err.c_str());
        return false;
    }
    cfunc_ = cf;
    current_func_ea_ = func_ea;
    rebuild_strvec_from_current();

    int target_line = 0;
    if (restore_line >= 0) {
        target_line = std::min(restore_line, std::max(0, static_cast<int>(lines_.size()) - 1));
    } else if (focus_ea.has_value() && *focus_ea != func_ea) {
        if (auto it = cfunc_->ea_to_line.find(*focus_ea); it != cfunc_->ea_to_line.end()) {
            target_line = it->second;
        }
    }
    update_viewer_bounds_and_cursor(target_line, std::max(0, restore_col));
    return true;
}

void Rl78Vdui::rebuild_strvec_from_current() {
    lines_.qclear();
    plain_lines_.clear();
    view_line_eas_.clear();
    if (mode_ == "ir" && current_func_ea_.has_value()) {
        std::string err;
        std::string ir = dump_single_ir_to_text(*current_func_ea_, &err);
        std::istringstream iss(ir);
        std::string ln;
        while (std::getline(iss, ln)) {
            if (!ln.empty() && ln.back() == '\r') ln.pop_back();
            plain_lines_.push_back(ln);
            view_line_eas_.push_back(std::nullopt);
            lines_.push_back(simpleline_t(colorize_c_line(ln, last_token_).c_str()));
        }
    } else if (cfunc_) {
        cfunc_->recolorize(last_token_);
        plain_lines_ = cfunc_->pseudocode_lines;
        view_line_eas_ = cfunc_->line_eas;
        for (size_t i = 0; i < cfunc_->sv.size(); ++i) {
            lines_.push_back(simpleline_t(cfunc_->sv[i].c_str()));
        }
    }
    if (lines_.empty()) {
        plain_lines_.push_back("// Empty");
        view_line_eas_.push_back(std::nullopt);
        lines_.push_back(simpleline_t("// Empty"));
    }
}

void Rl78Vdui::update_viewer_bounds_and_cursor(int target_line, int target_col) {
    if (!widget_) return;
    int max_ln = std::max(0, static_cast<int>(lines_.size()) - 1);
    int ln = std::max(0, std::min(target_line, max_ln));
    simpleline_place_t s1(0), s2(max_ln), cur(ln);
    set_custom_viewer_range(widget_, &s1, &s2);
    jumpto(widget_, &cur, std::max(0, target_col), 0);
    selected_line_ = ln;
    refresh_custom_viewer(widget_);
}

bool Rl78Vdui::get_cursor_pos(int *out_lineno, int *out_col, bool mouse) const {
    if (!widget_) return false;
    int x = 0, y = 0;
    place_t *pl = get_custom_viewer_place(widget_, mouse, &x, &y);
    if (!pl) return false;
    auto *spl = static_cast<simpleline_place_t *>(pl);
    if (out_lineno) *out_lineno = static_cast<int>(spl->n);
    if (out_col) *out_col = std::max(0, x);
    return true;
}

std::string Rl78Vdui::get_current_word(bool mouse) const {
    int lineno = 0, col = 0;
    if (!get_cursor_pos(&lineno, &col, mouse)) return {};
    if (lineno < 0 || lineno >= static_cast<int>(plain_lines_.size())) return {};
    return extract_word_at(plain_lines_[lineno], col);
}

citem_t *Rl78Vdui::get_current_citem(bool mouse) const {
    if (!cfunc_ || mode_ != "c") return nullptr;
    int lineno = 0, col = 0;
    if (!get_cursor_pos(&lineno, &col, mouse)) return nullptr;
    if (lineno >= 0 && lineno < static_cast<int>(cfunc_->line_eas.size()) &&
        cfunc_->line_eas[lineno].has_value()) {
        auto it = cfunc_->eamap.find(*cfunc_->line_eas[lineno]);
        if (it != cfunc_->eamap.end() && !it->second.empty()) return it->second.front();
    }
    return cfunc_->body;
}

std::optional<uint64_t> Rl78Vdui::get_current_line_ea(bool mouse) const {
    int lineno = 0, col = 0;
    if (!get_cursor_pos(&lineno, &col, mouse)) return current_func_ea_;
    if (lineno >= 0 && lineno < static_cast<int>(view_line_eas_.size()) &&
        view_line_eas_[lineno].has_value()) return view_line_eas_[lineno];
    return current_func_ea_;
}

void Rl78Vdui::sync_cursor_to_disasm(int lineno, bool) {
    if (!sync_with_disasm_ || sync_lock_) return;
    if (lineno < 0 || lineno >= static_cast<int>(view_line_eas_.size())) return;
    if (!view_line_eas_[lineno].has_value()) return;
    sync_lock_ = true;
    jumpto(static_cast<ea_t>(*view_line_eas_[lineno]), -1, UIJMP_IDAVIEW | UIJMP_DONTPUSH);
    sync_lock_ = false;
}

void Rl78Vdui::on_screen_ea_changed(ea_t ea, ea_t) {
    if (!sync_with_disasm_ || sync_lock_ || !widget_) return;
    func_t *pfn = get_func(ea);
    if (!pfn) return;
    sync_lock_ = true;
    uint64_t fea = static_cast<uint64_t>(pfn->start_ea);
    if (!current_func_ea_.has_value() || *current_func_ea_ != fea) {
        render_function(fea, static_cast<uint64_t>(ea), -1, 0, false);
    } else if (cfunc_) {
        if (auto it = cfunc_->ea_to_line.find(static_cast<uint64_t>(ea)); it != cfunc_->ea_to_line.end()) {
            update_viewer_bounds_and_cursor(it->second, 0);
        }
    }
    sync_lock_ = false;
}

void Rl78Vdui::on_widget_invisible(TWidget *w) {
    if (w && w == listing_state().widget) {
        listing_state().widget = nullptr;
        listing_state().lines.qclear();
        return;
    }
    if (w && w == widget_) {
        notify_event(rle_close_pseudocode, this);
        widget_ = nullptr;
        if (!errorexit) idadb::save_window_state(false, current_func_ea_, selected_line_, 0, mode_, true);
    }
}

void Rl78Vdui::populate_popup(TWidget *w, TPopupMenu *popup) {
    if (!w || w != widget_ || !popup) return;
    attach_action_to_popup(w, popup, ACTION_RENAME, nullptr, SETMENU_APP);
    attach_action_to_popup(w, popup, ACTION_SET_TYPE, nullptr, SETMENU_APP);
    attach_action_to_popup(w, popup, ACTION_EDIT_CMT, nullptr, SETMENU_APP);
    attach_action_to_popup(w, popup, ACTION_TOGGLE_HEX, "Number format/", SETMENU_APP);
    attach_action_to_popup(w, popup, ACTION_TOGGLE_CHAR, "Number format/", SETMENU_APP);
    attach_action_to_popup(w, popup, ACTION_TOGGLE_BIN, "Number format/", SETMENU_APP);
    attach_action_to_popup(w, popup, ACTION_TOGGLE_SIGNED, "Number format/", SETMENU_APP);
    attach_action_to_popup(w, popup, ACTION_INVERT_IF, nullptr, SETMENU_APP);
    attach_action_to_popup(w, popup, ACTION_SHOW_XREFS, nullptr, SETMENU_APP);
    attach_action_to_popup(w, popup, ACTION_TOGGLE_IR, nullptr, SETMENU_APP);
    attach_action_to_popup(w, popup, ACTION_REFRESH, nullptr, SETMENU_APP);
    attach_action_to_popup(w, popup, ACTION_RESET_OVERRIDES, nullptr, SETMENU_APP);
    notify_event(rle_populating_popup, this, popup);
}

bool Rl78Vdui::get_hint(TWidget *, place_t *, qstring &, int *) { return false; }

void Rl78Vdui::get_lines_rendering_info(lines_rendering_output_t *out,
                                        const TWidget *viewer,
                                        const lines_rendering_input_t *info) const {
    if (!out || !viewer || viewer != widget_ || !info) return;
    if (last_token_.empty()) return;
}

void Rl78Vdui::push_current_nav() {
    if (!current_func_ea_.has_value()) return;
    int ln = selected_line_, col = 0;
    get_cursor_pos(&ln, &col, false);
    nav_history_.push_back(NavEntry{*current_func_ea_, get_current_line_ea(false).value_or(*current_func_ea_), ln, col});
}

void Rl78Vdui::handle_curpos() {
    int ln = 0, col = 0;
    if (!get_cursor_pos(&ln, &col, false)) return;
    selected_line_ = ln;
    sync_cursor_to_disasm(ln, false);
    notify_event(rle_curpos, this);
}

void Rl78Vdui::handle_click(int) {
    last_token_ = get_current_word(false);
}

bool Rl78Vdui::handle_dblclick(int) {
    std::string tok = get_current_word(false);
    if (tok.empty() || !cfunc_) return false;
    if (auto it = cfunc_->call_eas.find(tok); it != cfunc_->call_eas.end()) {
        return switch_to(it->second, true);
    }
    if (auto it = cfunc_->sym_eas.find(tok); it != cfunc_->sym_eas.end()) {
        return switch_to(it->second, true);
    }
    notify_event(rle_double_click, this);
    return false;
}

bool Rl78Vdui::handle_keyboard(int key, int shift) {
    if (notify_event(rle_keyboard, this, &key) != 0) return true;
    (void)shift;
    return false;
}

std::optional<uint64_t> Rl78Vdui::find_enclosing_if_ea(int lineno) const {
    if (lineno < 0 || lineno >= static_cast<int>(plain_lines_.size())) return std::nullopt;
    for (int i = lineno; i >= 0; --i) {
        if (plain_lines_[i].find("if (") != std::string::npos &&
            i < static_cast<int>(view_line_eas_.size()) && view_line_eas_[i].has_value()) {
            return view_line_eas_[i];
        }
    }
    return std::nullopt;
}

int Rl78Vdui::act_rename() {
    if (!current_func_ea_.has_value()) return 0;
    std::string tok = get_current_word(false);
    if (tok.empty() || !is_valid_c_ident(tok)) return 0;
    qstring qnew = tok.c_str();
    if (!ask_str(&qnew, HIST_IDENT, "Rename '%s':", tok.c_str())) return 0;
    std::string nn(qnew.c_str(), qnew.length());
    nn = trim_copy(nn);
    if (nn.empty() || !is_valid_c_ident(nn)) return 0;

    if (cfunc_ && cfunc_->sym_eas.count(tok)) {
        set_name(static_cast<ea_t>(cfunc_->sym_eas[tok]), nn.c_str(), SN_CHECK);
    } else {
        idadb::set_var_rename(*current_func_ea_, tok, nn);
    }
    refresh_view(true);
    return 1;
}

int Rl78Vdui::act_set_type() {
    if (!current_func_ea_.has_value() || !cfunc_) return 0;
    std::string tok = get_current_word(false);
    if (tok == cfunc_->func_name) {
        qstring qp = cfunc_->signature_line.c_str();
        if (!ask_str(&qp, HIST_TYPE, "Enter function prototype:")) return 0;
        std::string ps(qp.c_str(), qp.length());
        if (!ps.empty() && parse_prototype(ps).has_value()) {
            idadb::set_func_proto(*current_func_ea_, ps);
            apply_proto_to_ida(static_cast<ea_t>(*current_func_ea_), ps);
            refresh_view(true);
            return 1;
        }
        return 0;
    }
    if (tok.empty()) return 0;
    qstring qt = (cfunc_->var_types.count(tok) ? cfunc_->var_types[tok] : "uint16_t").c_str();
    if (!ask_str(&qt, HIST_TYPE, "Enter type for '%s':", tok.c_str())) return 0;
    idadb::set_var_type(*current_func_ea_, tok, trim_copy(std::string(qt.c_str(), qt.length())));
    refresh_view(true);
    return 1;
}

int Rl78Vdui::act_edit_comment() {
    if (!current_func_ea_.has_value()) return 0;
    auto ea_o = get_current_line_ea(false);
    if (!ea_o.has_value()) return 0;
    auto existing = idadb::get_statement_cmt(*current_func_ea_, *ea_o);
    qstring qc = existing ? existing->c_str() : "";
    if (!ask_str(&qc, HIST_CMT, "Enter comment at 0x%llX:", static_cast<unsigned long long>(*ea_o))) return 0;
    idadb::set_statement_cmt(*current_func_ea_, *ea_o, std::string(qc.c_str(), qc.length()));
    refresh_view(true);
    return 1;
}

int Rl78Vdui::act_toggle_numform(const char *target_form) {
    if (!current_func_ea_.has_value() || !target_form) return 0;
    auto ea_o = get_current_line_ea(false);
    if (!ea_o.has_value()) return 0;
    idadb::set_numform(*current_func_ea_, *ea_o, 0, target_form);
    refresh_view(true);
    return 1;
}

int Rl78Vdui::act_set_enum() { return 0; }

int Rl78Vdui::act_invert_if() {
    if (!current_func_ea_.has_value()) return 0;
    int ln = 0, col = 0;
    get_cursor_pos(&ln, &col, false);
    auto if_ea = find_enclosing_if_ea(ln);
    if (!if_ea.has_value()) return 0;
    idadb::toggle_iflag(*current_func_ea_, *if_ea);
    refresh_view(true);
    return 1;
}

int Rl78Vdui::act_toggle_casts() {
    idadb::set_hide_casts(!idadb::get_hide_casts());
    refresh_view(true);
    return 1;
}

int Rl78Vdui::act_show_xrefs() {
    if (!current_func_ea_.has_value()) return 0;
    std::string tok = get_current_word(false);
    uint64_t target_ea = *current_func_ea_;
    if (cfunc_ && cfunc_->sym_eas.count(tok)) target_ea = cfunc_->sym_eas[tok];
    std::vector<XrefRow> rows;
    xrefblk_t xb;
    for (bool ok = xb.first_to(static_cast<ea_t>(target_ea), XREF_ALL); ok; ok = xb.next_to()) {
        qstring fnm;
        ::get_func_name(&fnm, xb.from);
        rows.push_back(XrefRow{static_cast<uint64_t>(xb.from), xb.iscode ? "code" : "data",
                               fnm.empty() ? "" : std::string(fnm.c_str(), fnm.length())});
    }
    if (rows.empty()) return 0;
    XrefChooser ch("RL78 Cross-references", std::move(rows));
    ssize_t sel = ch.choose();
    if (sel >= 0 && static_cast<size_t>(sel) < ch.rows.size()) {
        switch_to(ch.rows[static_cast<size_t>(sel)].ea, true);
        return 1;
    }
    return 0;
}

int Rl78Vdui::act_jump_addr() {
    ea_t ea = current_func_ea_.has_value() ? static_cast<ea_t>(*current_func_ea_) : get_screen_ea();
    if (!ask_addr(&ea, "Jump to RL78 address:")) return 0;
    return switch_to(static_cast<uint64_t>(ea), true) ? 1 : 0;
}

int Rl78Vdui::act_jump_disasm() {
    auto ea_o = get_current_line_ea(false);
    if (!ea_o.has_value()) return 0;
    jumpto(static_cast<ea_t>(*ea_o), -1, UIJMP_IDAVIEW | UIJMP_ACTIVATE);
    return 1;
}

int Rl78Vdui::act_switch_disasm() { return act_jump_disasm(); }

int Rl78Vdui::act_nav_back() {
    if (nav_history_.empty()) return 0;
    NavEntry prev = nav_history_.back();
    nav_history_.pop_back();
    render_function(prev.func_ea, std::nullopt, prev.lineno, prev.col, false);
    return 1;
}

int Rl78Vdui::act_nav_forward() {
    if (nav_forward_.empty()) return 0;
    NavEntry nxt = nav_forward_.back();
    nav_forward_.pop_back();
    render_function(nxt.func_ea, std::nullopt, nxt.lineno, nxt.col, false);
    return 1;
}

int Rl78Vdui::act_toggle_sync() {
    sync_with_disasm_ = !sync_with_disasm_;
    idadb::set_sync_enabled(sync_with_disasm_);
    return 1;
}

int Rl78Vdui::act_toggle_ir() {
    mode_ = (mode_ == "c") ? "ir" : "c";
    refresh_view(false);
    return 1;
}

int Rl78Vdui::act_refresh() { return refresh_view(true) ? 1 : 0; }

int Rl78Vdui::act_reset_overrides() {
    if (!current_func_ea_.has_value()) return 0;
    idadb::clear_func_overrides(*current_func_ea_);
    refresh_view(true);
    return 1;
}

namespace {

enum class ActId {
    Decompile, DecompileAll, ClearCaches, SaveListingC,
    Rename, SetType, EditCmt, EditCmtSemi,
    ToggleHex, ToggleChar, ToggleBin, ToggleSigned,
    InvertIf, ToggleCasts, ShowXrefs, JumpAddr, JumpDisasm, SwitchDisasm,
    NavBack, NavForward, ToggleSync, ToggleIr, Refresh, ResetOverrides,
};

struct Rl78ActionHandler : public action_handler_t {
    ActId id;
    explicit Rl78ActionHandler(ActId i) : id(i) {}

    int idaapi activate(action_activation_ctx_t *ctx) override {
        if (!is_rl78_database_active()) return 0;
        Rl78Vdui &v = global_vdui();
        switch (id) {
            case ActId::Decompile: {
                if (v.widget() && ((ctx && ctx->widget == v.widget()) || get_current_widget() == v.widget())) {
                    return v.act_refresh();
                }
                ea_t ea = (ctx && ctx->cur_ea != BADADDR) ? ctx->cur_ea : get_screen_ea();
                if (ea == BADADDR && v.current_func_ea().has_value()) ea = static_cast<ea_t>(*v.current_func_ea());
                if (ea == BADADDR) return 0;
                return v.open_or_focus(static_cast<uint64_t>(ea), 1, true) ? 1 : 0;
            }
            case ActId::DecompileAll: return open_decompile_all_viewer() ? 1 : 0;
            case ActId::ClearCaches:
                global_summary_cache().clear_all();
                if (v.is_open()) v.refresh_view(true);
                return 1;
            case ActId::SaveListingC:  return act_save_listing_to_c_file();
            case ActId::Rename:        return v.act_rename();
            case ActId::SetType:       return v.act_set_type();
            case ActId::EditCmt:
            case ActId::EditCmtSemi:   return v.act_edit_comment();
            case ActId::ToggleHex:     return v.act_toggle_numform("hex");
            case ActId::ToggleChar:    return v.act_toggle_numform("char");
            case ActId::ToggleBin:     return v.act_toggle_numform("bin");
            case ActId::ToggleSigned:  return v.act_toggle_numform("sdec");
            case ActId::InvertIf:      return v.act_invert_if();
            case ActId::ToggleCasts:   return v.act_toggle_casts();
            case ActId::ShowXrefs:     return v.act_show_xrefs();
            case ActId::JumpAddr:      return v.act_jump_addr();
            case ActId::JumpDisasm:    return v.act_jump_disasm();
            case ActId::SwitchDisasm:  return v.act_switch_disasm();
            case ActId::NavBack:       return v.act_nav_back();
            case ActId::NavForward:    return v.act_nav_forward();
            case ActId::ToggleSync:    return v.act_toggle_sync();
            case ActId::ToggleIr:      return v.act_toggle_ir();
            case ActId::Refresh:       return v.act_refresh();
            case ActId::ResetOverrides:return v.act_reset_overrides();
        }
        return 0;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override {
        if (!ctx || !is_rl78_database_active()) return AST_DISABLE_FOR_IDB;
        if (id == ActId::Decompile || id == ActId::DecompileAll || id == ActId::ClearCaches) {
            return AST_ENABLE_ALWAYS;
        }
        if (id == ActId::SaveListingC) {
            return (ctx->widget == listing_state().widget) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
        }
        return (ctx->widget == global_vdui().widget()) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
    }
};

struct ActionEntry {
    const char *name;
    const char *label;
    const char *shortcut;
    const char *tooltip;
    Rl78ActionHandler handler;
    ActionEntry(const char *n, const char *l, const char *sc, const char *tt, ActId i)
        : name(n), label(l), shortcut(sc), tooltip(tt), handler(i) {}
};

std::vector<ActionEntry> &action_table() {
    static std::vector<ActionEntry> tbl = {
        {ACTION_DECOMPILE,       "Decompile RL78 function",         "F5",         "Generate RL78 C pseudocode", ActId::Decompile},
        {ACTION_DECOMPILE_ALL,   "Decompile all RL78 functions",    "Ctrl-F5",    "Decompile all RL78 functions", ActId::DecompileAll},
        {ACTION_CLEAR_CACHES,    "Clear rl78dec caches",            "Ctrl-Shift-S","Clear summary & pseudocode caches", ActId::ClearCaches},
        {ACTION_SAVE_LISTING_C,  "Save all pseudocode to .c file...", nullptr,    "Save all RL78 C code", ActId::SaveListingC},
        {ACTION_RENAME,          "Rename variable / symbol...",    "N",          "Rename local or symbol", ActId::Rename},
        {ACTION_SET_TYPE,        "Set C type / prototype...",      "Y",          "Set variable type or function prototype", ActId::SetType},
        {ACTION_EDIT_CMT,        "Edit comment...",                "/",          "Edit pseudocode comment", ActId::EditCmt},
        {ACTION_EDIT_CMT_SEMI,   "Edit comment (;)",               ";",          "Edit pseudocode comment", ActId::EditCmtSemi},
        {ACTION_TOGGLE_HEX,      "Hexadecimal / Decimal",          "H",          "Toggle hex / decimal", ActId::ToggleHex},
        {ACTION_TOGGLE_CHAR,     "Character constant",             "R",          "Toggle char constant", ActId::ToggleChar},
        {ACTION_TOGGLE_BIN,      "Binary literal",                 "B",          "Toggle binary literal", ActId::ToggleBin},
        {ACTION_TOGGLE_SIGNED,   "Signed / Unsigned decimal",      "Shift--",    "Toggle signed decimal", ActId::ToggleSigned},
        {ACTION_INVERT_IF,       "Invert if/else branches",        "I",          "Invert branch", ActId::InvertIf},
        {ACTION_TOGGLE_CASTS,    "Hide / Show scalar casts",       "\\",         "Toggle casts", ActId::ToggleCasts},
        {ACTION_SHOW_XREFS,      "Jump to xrefs...",               "X",          "Show cross-references", ActId::ShowXrefs},
        {ACTION_JUMP_ADDR,       "Jump to address...",             "G",          "Jump to address", ActId::JumpAddr},
        {ACTION_JUMP_DISASM,     "Jump to disassembly",            nullptr,      "Jump to IDA View", ActId::JumpDisasm},
        {ACTION_SWITCH_DISASM,   "Switch to disassembly",          "Tab",        "Switch to IDA View", ActId::SwitchDisasm},
        {ACTION_NAV_BACK,        "Navigate backward",              "Escape",     "Back", ActId::NavBack},
        {ACTION_NAV_FORWARD,     "Navigate forward",               "Ctrl-Return","Forward", ActId::NavForward},
        {ACTION_TOGGLE_SYNC,     "Sync cursor with disassembly",   "Alt-S",      "Toggle sync", ActId::ToggleSync},
        {ACTION_TOGGLE_IR,       "Toggle C / IR view",             "Shift-I",    "Toggle C / IR view", ActId::ToggleIr},
        {ACTION_REFRESH,         "Refresh pseudocode",             nullptr,      "Re-run decompiler", ActId::Refresh},
        {ACTION_RESET_OVERRIDES, "Reset function overrides",       nullptr,      "Clear overrides", ActId::ResetOverrides},
    };
    return tbl;
}

} // namespace

void register_all_rl78dec_actions(plugmod_t *owner) {
    for (auto &entry : action_table()) {
        unregister_action(entry.name);
        action_desc_t desc = ACTION_DESC_LITERAL_PLUGMOD(
            entry.name, entry.label, &entry.handler, owner, entry.shortcut, entry.tooltip, -1);
        register_action(desc);
    }
    attach_action_to_menu("View/Open subviews/Generate pseudocode", ACTION_DECOMPILE, SETMENU_APP);
    attach_action_to_menu("View/Open subviews/", ACTION_DECOMPILE, SETMENU_APP);
    attach_action_to_menu("View/Open subviews/", ACTION_DECOMPILE_ALL, SETMENU_APP);
    update_action_shortcut(ACTION_DECOMPILE, "F5");
    update_action_shortcut(ACTION_DECOMPILE_ALL, "Ctrl-F5");
}

void unregister_all_rl78dec_actions() {
    detach_action_from_menu("View/Open subviews/Generate pseudocode", ACTION_DECOMPILE);
    detach_action_from_menu("View/Open subviews/", ACTION_DECOMPILE);
    detach_action_from_menu("View/Open subviews/", ACTION_DECOMPILE_ALL);
    for (const auto &entry : action_table()) unregister_action(entry.name);
}

} // namespace rl78dec
