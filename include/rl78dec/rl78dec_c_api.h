#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
  #if defined(RL78DEC_BUILDING_DLL)
    #define RL78DEC_API_EXPORT __declspec(dllexport)
  #else
    #define RL78DEC_API_EXPORT __declspec(dllimport)
  #endif
#else
  #define RL78DEC_API_EXPORT __attribute__((visibility("default")))
#endif

typedef int (__cdecl *rl78dec_abi_event_cb_t)(int event_code, uint64_t cfunc_handle, uint64_t aux, void *ud);

RL78DEC_API_EXPORT const char * __cdecl rl78dec_abi_version(void);
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_is_rl78_db(void);
RL78DEC_API_EXPORT void         __cdecl rl78dec_abi_free_str(char *s);

/* Cache & lifecycle */
RL78DEC_API_EXPORT void         __cdecl rl78dec_abi_clear_caches(void);
RL78DEC_API_EXPORT void         __cdecl rl78dec_abi_mark_dirty(uint64_t func_ea, int close_views);

/* Core decompilation & cfunc_t handle management */
RL78DEC_API_EXPORT uint64_t     __cdecl rl78dec_abi_decompile(uint64_t ea, int flags, char **out_err);
RL78DEC_API_EXPORT void         __cdecl rl78dec_abi_release_cfunc(uint64_t handle);
RL78DEC_API_EXPORT char *       __cdecl rl78dec_abi_cfunc_text(uint64_t handle);
RL78DEC_API_EXPORT char *       __cdecl rl78dec_abi_cfunc_json(uint64_t handle, int include_ctree);
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_cfunc_mutate_item(
    uint64_t handle,
    uint32_t obj_id,
    int new_op,
    uint64_t new_numval,
    int new_var_idx,
    const char *new_str,
    const char *new_helper);
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_cfunc_swap_if(uint64_t handle, uint32_t if_obj_id);
RL78DEC_API_EXPORT char *       __cdecl rl78dec_abi_cfunc_refresh_ctext(uint64_t handle);

/* Fast text helpers */
RL78DEC_API_EXPORT char *       __cdecl rl78dec_abi_decompile_text(uint64_t ea, char **out_err);
RL78DEC_API_EXPORT char *       __cdecl rl78dec_abi_dump_ir(uint64_t ea, char **out_err);
RL78DEC_API_EXPORT char *       __cdecl rl78dec_abi_decompile_all(const char *out_path, int *out_ok, int *out_fail);

/* Interactive pseudocode viewer (vdui_t) */
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_open_pseudocode(uint64_t ea, int open_flags);
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_vdui_is_open(void);
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_vdui_refresh(int force_redecompile);
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_vdui_switch_to(uint64_t ea, int push_history);
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_vdui_get_state(
    uint64_t *out_func_ea,
    uint64_t *out_cfunc_handle,
    int *out_lineno,
    int *out_col,
    uint32_t *out_citem_id);

/* Persistent "$ rl78dec" netnode user annotations */
RL78DEC_API_EXPORT char *       __cdecl rl78dec_abi_get_user_data_json(uint64_t func_ea);
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_set_user_data_json(uint64_t func_ea, const char *json_str);
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_rename_lvar(uint64_t func_ea, const char *old_name, const char *new_name);
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_set_lvar_type(uint64_t func_ea, const char *var_name, const char *type_str);
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_set_proto(uint64_t func_ea, const char *proto_str);
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_set_cmt(uint64_t func_ea, uint64_t stmt_ea, const char *cmt_str);
RL78DEC_API_EXPORT char *       __cdecl rl78dec_abi_get_cmt(uint64_t func_ea, uint64_t stmt_ea);
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_set_numform(uint64_t func_ea, uint64_t stmt_ea, int op_idx, const char *form_str);
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_invert_if(uint64_t func_ea, uint64_t branch_ea);
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_get_hide_casts(void);
RL78DEC_API_EXPORT void         __cdecl rl78dec_abi_set_hide_casts(int hide);
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_reset_overrides(uint64_t func_ea);

/* Scripting callbacks */
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_register_callback(rl78dec_abi_event_cb_t cb, void *ud);
RL78DEC_API_EXPORT int          __cdecl rl78dec_abi_unregister_callback(int cb_handle);

#ifdef __cplusplus
}
#endif
