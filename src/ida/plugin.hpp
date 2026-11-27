#pragma once

#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>

#include "summary_cache.hpp"
#include "view.hpp"

namespace rl78dec {

inline constexpr const char *RL78DEC_VERSION = "2.0.0-native";
inline constexpr int PLFM_RL78_CUSTOM = 0x8078;

bool is_rl78_processor();
bool is_rl78_database_active();

struct Rl78DecPlugmod : public plugmod_t, public event_listener_t {
    int data_id = 0;
    bool active_on_rl78 = false;
    bool desktop_restored = false;

    DECLARE_LISTENER(IdpListener, Rl78DecPlugmod, pm);
    IdpListener idp_listener = IdpListener(*this);

    Rl78DecPlugmod();
    ~Rl78DecPlugmod() override;

    bool idaapi run(size_t arg) override;
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
    ssize_t on_idp_event(ssize_t code, va_list va);
};

Rl78DecPlugmod *active_rl78dec_plugmod();

} // namespace rl78dec
