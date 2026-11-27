#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <mergemod.hpp>

#include <cstring>

#include "plugin.hpp"
#include "api_dispatch.hpp"
#include "db.hpp"
#include "ida_provider.hpp"
#include "idc_funcs.hpp"
#include "merge.hpp"
#include "summary_cache.hpp"
#include "view.hpp"

namespace rl78dec {

namespace {

Rl78DecPlugmod *g_active_plugmod = nullptr;

void register_rl78dec_addon_info() {
    static bool registered = false;
    if (registered) return;
    addon_info_t addon;
    addon.id = "org.rl78dec.native";
    addon.name = "RL78 / 78K0R Native Decompiler (rl78dec)";
    addon.producer = "rl78dec";
    addon.version = RL78DEC_VERSION;
    addon.url = "";
    addon.freeform = "Compiled C++17 Renesas RL78 / 78K0R Decompiler";
    register_addon(&addon);
    registered = true;
}

} // namespace

bool is_rl78_processor() {
    if (PH.id == PLFM_RL78_CUSTOM) return true;
    if (PH.psnames && PH.psnames[0]) {
        const char *p = PH.psnames[0];
        if ((p[0] == 'r' || p[0] == 'R') && (p[1] == 'l' || p[1] == 'L') && p[2] == '7' && p[3] == '8') {
            return true;
        }
    }
    return false;
}

bool is_rl78_database_active() {
    return g_active_plugmod != nullptr && g_active_plugmod->active_on_rl78 && is_rl78_processor();
}

Rl78DecPlugmod *active_rl78dec_plugmod() {
    return g_active_plugmod;
}

ssize_t idaapi Rl78DecPlugmod::IdpListener::on_event(ssize_t code, va_list va) {
    return pm.on_idp_event(code, va);
}

Rl78DecPlugmod::Rl78DecPlugmod() {
    active_on_rl78 = is_rl78_processor();
    g_active_plugmod = this;
    set_module_data(&data_id, this);

    register_rl78dec_addon_info();
    hook_event_listener(HT_UI, this);
    hook_event_listener(HT_IDB, &global_summary_cache());
    hook_event_listener(HT_IDP, &idp_listener);

    register_all_rl78dec_actions(this);
    register_rl78dec_idc_funcs();
}

Rl78DecPlugmod::~Rl78DecPlugmod() {
    global_vdui().close_and_cleanup();
    clear_api_handles();
    global_summary_cache().clear_all();

    unregister_rl78dec_idc_funcs();
    unregister_all_rl78dec_actions();

    unhook_event_listener(HT_IDP, &idp_listener);
    unhook_event_listener(HT_IDB, &global_summary_cache());
    unhook_event_listener(HT_UI, this);

    clr_module_data(data_id);
    if (g_active_plugmod == this) g_active_plugmod = nullptr;
    active_on_rl78 = false;
}

bool idaapi Rl78DecPlugmod::run(size_t arg) {
    if (!is_rl78_database_active()) return false;
    if (arg == 1) return open_decompile_all_viewer();
    if (arg == 2) {
        global_summary_cache().clear_all();
        clear_api_handles();
        if (global_vdui().is_open()) global_vdui().refresh_view(true);
        msg("[rl78dec] Cleared all caches.\n");
        return true;
    }

    Rl78Vdui &v = global_vdui();
    if (v.widget() && get_current_widget() == v.widget()) {
        return v.refresh_view(true);
    }

    ea_t ea = get_screen_ea();
    if (ea == BADADDR && v.current_func_ea().has_value()) {
        ea = static_cast<ea_t>(*v.current_func_ea());
    }
    if (ea == BADADDR) return false;
    return v.open_or_focus(static_cast<uint64_t>(ea), 1, true);
}

ssize_t Rl78DecPlugmod::on_idp_event(ssize_t code, va_list va) {
    switch (code) {
        case processor_t::ev_create_merge_handlers: {
            merge_data_t *md = va_arg(va, merge_data_t *);
            if (md) register_rl78dec_merge_handlers(*md, data_id);
            break;
        }
        case processor_t::ev_ending_undo: {
            global_summary_cache().clear_all();
            if (global_vdui().is_open()) global_vdui().refresh_view(true);
            break;
        }
        default:
            break;
    }
    return 0;
}

ssize_t idaapi Rl78DecPlugmod::on_event(ssize_t code, va_list va) {
    if (!active_on_rl78) return 0;

    switch (code) {
        case ui_broadcast: {
            int magic = va_arg(va, int);
            if (magic == RL78DEC_BROADCAST_MAGIC) {
                auto *req = va_arg(va, Rl78decBroadcastReq *);
                if (handle_rl78dec_broadcast(req)) return 1;
            }
            break;
        }

        case ui_create_desktop_widget: {
            const char *ttl = va_arg(va, const char *);
            (void)va_arg(va, const void *);
            if (ttl && qstrcmp(ttl, RL78DEC_VIEW_TITLE) == 0) {
                TWidget *w = global_vdui().create_for_desktop();
                return reinterpret_cast<ssize_t>(w);
            }
            break;
        }

        case ui_ready_to_run: {
            update_action_shortcut(ACTION_DECOMPILE, "F5");
            update_action_shortcut(ACTION_DECOMPILE_ALL, "Ctrl-F5");
            if (!desktop_restored && is_idaq()) {
                desktop_restored = true;
                global_vdui().restore_saved_window();
            }
            break;
        }

        case ui_desktop_applied: {
            if (!desktop_restored && is_idaq()) {
                desktop_restored = true;
                global_vdui().restore_saved_window();
            }
            break;
        }

        case ui_database_inited: {
            ensure_rl78_types();
            if (!desktop_restored && is_idaq()) {
                desktop_restored = true;
                global_vdui().restore_saved_window();
            }
            break;
        }

        case ui_saving: {
            global_vdui().persist_window_state(true);
            break;
        }

        case ui_screen_ea_changed: {
            ea_t ea = va_arg(va, ea_t);
            ea_t prev_ea = va_arg(va, ea_t);
            global_vdui().on_screen_ea_changed(ea, prev_ea);
            break;
        }

        case ui_widget_invisible: {
            TWidget *w = va_arg(va, TWidget *);
            global_vdui().on_widget_invisible(w);
            break;
        }

        case ui_finish_populating_widget_popup: {
            TWidget *w = va_arg(va, TWidget *);
            TPopupMenu *popup = va_arg(va, TPopupMenu *);
            global_vdui().populate_popup(w, popup);
            break;
        }

        case ui_get_custom_viewer_hint: {
            qstring *hint = va_arg(va, qstring *);
            TWidget *viewer = va_arg(va, TWidget *);
            place_t *place = va_arg(va, place_t *);
            int *important_lines = va_arg(va, int *);
            if (hint && global_vdui().get_hint(viewer, place, *hint, important_lines)) return 1;
            break;
        }

        case ui_get_lines_rendering_info: {
            auto *out = va_arg(va, lines_rendering_output_t *);
            const TWidget *viewer = va_arg(va, const TWidget *);
            const auto *info = va_arg(va, const lines_rendering_input_t *);
            global_vdui().get_lines_rendering_info(out, viewer, info);
            break;
        }

        default:
            break;
    }
    return 0;
}

} // namespace rl78dec

static plugmod_t *idaapi rl78dec_init() {
    if (!rl78dec::is_rl78_processor()) {
        return nullptr; // Strictly inactive on non-RL78 architectures!
    }
    return new rl78dec::Rl78DecPlugmod();
}

static const char kRl78decComment[] = "Renesas RL78 / 78K0R native decompiler plugin.";
static const char kRl78decHelp[] =
    "RL78 / 78K0R Decompiler (rl78dec)\n"
    "Press F5 in any RL78 function to open interactive C pseudocode.\n"
    "Press Ctrl+F5 to decompile all functions in the database.\n";
static const char kRl78decWantedName[] = "RL78 decompiler (rl78dec)";
static const char kRl78decWantedHotkey[] = "F5";

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_PROC | PLUGIN_MULTI,
    rl78dec_init,
    nullptr,
    nullptr,
    kRl78decComment,
    kRl78decHelp,
    kRl78decWantedName,
    kRl78decWantedHotkey,
};
