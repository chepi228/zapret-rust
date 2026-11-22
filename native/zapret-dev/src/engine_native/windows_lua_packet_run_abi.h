/* MIT. Live packet invocation and its native layout checks. */
#pragma once
#include "lua_rules_abi.h"
#include "lua_context_windows.h"
#include "lua_packet_arguments_windows.h"
#include "lua_invocation_abi.h"
#include "desync_policy_abi.h"

_Static_assert(offsetof(struct func_list, func) == 0 && offsetof(struct params_s, ref_desync_ctx) == 16880 &&
    offsetof(struct params_s, L) == 16888 && offsetof(struct params_s, debug) == 4252 &&
    offsetof(struct params_s, server) == 12705 && LUA_NOREF == -2, "Rust Lua invocation inputs");

uint8_t zapret_native_desync(struct desync_profile *, uint32_t, const char *, const char *,
    bool, t_ctrack *, const t_ctrack_positions *, t_l7payload, t_l7proto, const struct dissect *,
    const struct in_addr *, const struct in6_addr *, uint16_t, uint8_t *, size_t *,
    unsigned int, unsigned int, size_t, const uint8_t *, size_t, const uint8_t *, size_t);
