/* Rust metadata and policy. Every Lua operation stays on the C stack. */
#pragma once
#include <stdbool.h>
#include <stdint.h>

enum {
    LUA_CTX_NIL, LUA_CTX_HAS_DIRECTION, LUA_CTX_DIRECTION_PROVIDED,
    LUA_CTX_SCRIPT_DIRECTION, LUA_CTX_NATIVE_DIRECTION, LUA_CTX_TABLE_NEEDED,
    LUA_CTX_CREATE_REF, LUA_CTX_RELEASE_REF,
};
enum {
    LUA_CTX_METATABLE, LUA_CTX_MISSING, LUA_CTX_INVALID, LUA_CTX_CUTOFF_INVALID,
    LUA_CTX_EXECUTION_INVALID, LUA_CTX_PACKET_INVALID, LUA_CTX_PLAN_INVALID,
    LUA_CTX_STORAGE_INVALID, LUA_PLAN_FUNC, LUA_PLAN_FUNC_N, LUA_PLAN_INSTANCE,
    LUA_PLAN_RANGE, LUA_PLAN_PAYLOAD, LUA_PLAN_FILTER, LUA_PLAN_ARG,
    LUA_CTX_INSTANCE_CUTOFF, LUA_CTX_LUA_CUTOFF, LUA_CTX_CANCEL, LUA_CTX_RAW_PACKET,
};
enum {
    LUA_CTX_REPORT_MISSING, LUA_CTX_REPORT_INSTANCE_CUTOFF,
    LUA_CTX_REPORT_LUA_CUTOFF, LUA_CTX_REPORT_CANCEL,
};

const char *zapret_lua_arity_error(int, int, int, bool);
uint32_t zapret_lua_context_vm(uint32_t, int);
const char *zapret_lua_context_label(uint32_t);
const char *zapret_lua_context_report(uint32_t, bool);
uint32_t zapret_lua_error_report_next(uint32_t, bool, bool);
const char *zapret_lua_error_report_format(uint32_t);
