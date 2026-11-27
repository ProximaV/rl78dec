#pragma once

#include <ida.hpp>
#include <cstdint>

namespace rl78dec {

inline constexpr int RL78DEC_BROADCAST_MAGIC = 0x524C3738; // 'RL78'

struct Rl78decBroadcastReq {
    uint32_t struct_size = sizeof(Rl78decBroadcastReq);
    int op = 0;
    uint64_t ea = 0;
    uint64_t ea2 = 0;
    int flags = 0;
    const char *str_arg1 = nullptr;
    const char *str_arg2 = nullptr;
    void *ptr_arg = nullptr;
    int status = -1;
    void *out_ptr = nullptr;
    qstring out_str;
};

enum Rl78decBroadcastOp : int {
    RL78DEC_BCAST_PING            = 1,
    RL78DEC_BCAST_DECOMPILE_CFUNC = 2,
    RL78DEC_BCAST_DECOMPILE_TEXT  = 3,
    RL78DEC_BCAST_DUMP_IR_TEXT    = 4,
    RL78DEC_BCAST_OPEN_PSEUDOCODE = 5,
    RL78DEC_BCAST_MARK_DIRTY      = 6,
    RL78DEC_BCAST_CLEAR_CACHES    = 7,
    RL78DEC_BCAST_RENAME_LVAR     = 8,
    RL78DEC_BCAST_SET_LVAR_TYPE   = 9,
    RL78DEC_BCAST_SET_PROTO       = 10,
    RL78DEC_BCAST_SET_CMT         = 11,
    RL78DEC_BCAST_SET_NUMFORM     = 12,
    RL78DEC_BCAST_INVERT_IF       = 13,
};

bool handle_rl78dec_broadcast(Rl78decBroadcastReq *req);
void clear_api_handles();

} // namespace rl78dec
