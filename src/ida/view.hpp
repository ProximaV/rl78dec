#pragma once

#include <ida.hpp>
#include <kernwin.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include "rl78dec/ctree.hpp"
#include "rl78dec/ir.hpp"
#include "rl78dec/pipeline.hpp"

namespace rl78dec {

inline constexpr const char *RL78DEC_VIEW_TITLE    = "rl78dec - Pseudocode";
inline constexpr const char *RL78DEC_LISTING_TITLE = "rl78dec - All Decompiled Functions";

inline constexpr const char *ACTION_DECOMPILE       = "rl78dec:decompile";
inline constexpr const char *ACTION_DECOMPILE_ALL   = "rl78dec:decompile_all";
inline constexpr const char *ACTION_CLEAR_CACHES    = "rl78dec:clear_caches";
inline constexpr const char *ACTION_RENAME          = "rl78dec:rename_var";
inline constexpr const char *ACTION_SET_TYPE        = "rl78dec:set_type";
inline constexpr const char *ACTION_EDIT_CMT        = "rl78dec:edit_comment";
inline constexpr const char *ACTION_EDIT_CMT_SEMI   = "rl78dec:edit_comment_semi";
inline constexpr const char *ACTION_TOGGLE_HEX      = "rl78dec:toggle_hex";
inline constexpr const char *ACTION_TOGGLE_CHAR     = "rl78dec:toggle_char";
inline constexpr const char *ACTION_TOGGLE_BIN      = "rl78dec:toggle_bin";
inline constexpr const char *ACTION_TOGGLE_SIGNED   = "rl78dec:toggle_signed";
inline constexpr const char *ACTION_TOGGLE_OFFSET   = "rl78dec:toggle_offset";
inline constexpr const char *ACTION_SET_ENUM        = "rl78dec:set_enum";
inline constexpr const char *ACTION_INVERT_IF       = "rl78dec:invert_if";
inline constexpr const char *ACTION_TOGGLE_CASTS    = "rl78dec:toggle_casts";
inline constexpr const char *ACTION_SHOW_XREFS      = "rl78dec:show_xrefs";
inline constexpr const char *ACTION_JUMP_ADDR       = "rl78dec:jump_addr";
inline constexpr const char *ACTION_JUMP_DISASM     = "rl78dec:jump_disasm";
inline constexpr const char *ACTION_SWITCH_DISASM   = "rl78dec:switch_disasm";
inline constexpr const char *ACTION_NAV_BACK        = "rl78dec:nav_back";
inline constexpr const char *ACTION_NAV_FORWARD     = "rl78dec:nav_forward";
inline constexpr const char *ACTION_TOGGLE_SYNC     = "rl78dec:toggle_sync";
inline constexpr const char *ACTION_TOGGLE_IR       = "rl78dec:toggle_ir";
inline constexpr const char *ACTION_REFRESH         = "rl78dec:refresh";
inline constexpr const char *ACTION_RESET_OVERRIDES = "rl78dec:reset_overrides";
inline constexpr const char *ACTION_SAVE_LISTING_C  = "rl78dec:save_listing_c";

enum rl78dec_event_t : int {
    rle_maturity          = 0,
    rle_lifting_done      = 1,
    rle_ssa_optimized     = 2,
    rle_func_printed      = 4,
    rle_open_pseudocode   = 5,
    rle_switch_pseudocode = 6,
    rle_refresh_pseudocode= 7,
    rle_close_pseudocode  = 8,
    rle_curpos            = 9,
    rle_double_click      = 10,
    rle_keyboard          = 11,
    rle_populating_popup  = 12,
};

using EventCallbackFn = std::function<int(rl78dec_event_t, void *, void *)>;
int register_event_callback(EventCallbackFn cb);
bool unregister_event_callback(int handle);
int notify_event(rl78dec_event_t ev, void *arg0 = nullptr, void *arg1 = nullptr);

struct NavEntry {
    uint64_t func_ea = 0;
    uint64_t ea = 0;
    int lineno = 0;
    int col = 0;
};

class Rl78Vdui {
public:
    Rl78Vdui() = default;
    ~Rl78Vdui() = default;

    TWidget *widget() const { return widget_; }
    bool is_open() const { return widget_ != nullptr; }
    std::optional<uint64_t> current_func_ea() const { return current_func_ea_; }
    cfuncptr_t cfunc() const { return cfunc_; }
    const Function *ir_func() const { return ir_func_.get(); }
    const std::string &mode() const { return mode_; }
    bool sync_enabled() const { return sync_with_disasm_; }
    int selected_line() const { return selected_line_; }

    bool open_or_focus(uint64_t target_ea, int open_flags = 0, bool push_history = false);
    TWidget *create_for_desktop();
    void restore_saved_window();
    void persist_window_state(bool force_open_state = true);
    void close_and_cleanup();

    bool refresh_view(bool force_redecompile = true);
    bool switch_to(uint64_t target_ea, bool push_history = true);

    void on_screen_ea_changed(ea_t ea, ea_t prev_ea);
    void on_widget_invisible(TWidget *w);
    void populate_popup(TWidget *w, TPopupMenu *popup);
    bool get_hint(TWidget *viewer, place_t *place, qstring &out_hint, int *important_lines);
    void get_lines_rendering_info(lines_rendering_output_t *out,
                                  const TWidget *viewer,
                                  const lines_rendering_input_t *info) const;

    bool get_cursor_pos(int *out_lineno, int *out_col, bool mouse = false) const;
    std::string get_current_word(bool mouse = false) const;
    citem_t *get_current_citem(bool mouse = false) const;
    std::optional<uint64_t> get_current_line_ea(bool mouse = false) const;

    int act_rename();
    int act_set_type();
    int act_edit_comment();
    int act_toggle_numform(const char *target_form);
    int act_set_enum();
    int act_invert_if();
    int act_toggle_casts();
    int act_show_xrefs();
    int act_jump_addr();
    int act_jump_disasm();
    int act_switch_disasm();
    int act_nav_back();
    int act_nav_forward();
    int act_toggle_sync();
    int act_toggle_ir();
    int act_refresh();
    int act_reset_overrides();

    void handle_curpos();
    void handle_click(int shift);
    bool handle_dblclick(int shift);
    bool handle_keyboard(int key, int shift);

private:
    bool ensure_widget_created(bool dock_right, bool activate);
    bool render_function(uint64_t func_ea, std::optional<uint64_t> focus_ea = std::nullopt,
                         int restore_line = -1, int restore_col = 0, bool force_redecompile = false);
    void rebuild_strvec_from_current();
    void update_viewer_bounds_and_cursor(int target_line, int target_col);
    void sync_cursor_to_disasm(int lineno, bool push_history);
    void push_current_nav();
    std::optional<uint64_t> find_enclosing_if_ea(int lineno) const;

    TWidget *widget_ = nullptr;
    strvec_t lines_;
    std::vector<std::string> plain_lines_;
    std::vector<std::optional<uint64_t>> view_line_eas_;

    std::optional<uint64_t> current_func_ea_;
    cfuncptr_t cfunc_;
    std::unique_ptr<Function> ir_func_;
    std::string mode_ = "c";

    int selected_line_ = 0;
    std::string last_token_;
    std::unordered_set<uint64_t> highlighted_asm_eas_;

    bool sync_with_disasm_ = true;
    bool sync_lock_ = false;
    bool in_nav_action_ = false;
    std::vector<NavEntry> nav_history_;
    std::vector<NavEntry> nav_forward_;
};

std::string decompile_single_to_text(uint64_t ea, std::string *out_error = nullptr);
std::string dump_single_ir_to_text(uint64_t ea, std::string *out_error = nullptr);
cfuncptr_t decompile_or_get_cached(uint64_t ea, bool force_redecompile = false, std::string *out_error = nullptr);
std::string decompile_all_to_string(bool show_progress = false, int *out_ok = nullptr, int *out_fail = nullptr);
bool open_decompile_all_viewer();
int act_save_listing_to_c_file();
TWidget *get_listing_widget();

Rl78Vdui &global_vdui();
Rl78Vdui *find_vdui_for_widget(TWidget *w);
void register_all_rl78dec_actions(plugmod_t *owner);
void unregister_all_rl78dec_actions();

} // namespace rl78dec
