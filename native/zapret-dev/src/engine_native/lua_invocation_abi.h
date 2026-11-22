/* MIT. Plain state returned before every C-owned Lua operation. */
#pragma once
#include "runtime_log_windows.h"
typedef struct {uint32_t phase;uint8_t verdict;}zapret_lua_invocation_flow;
typedef struct {
    uint8_t verdict;bool available,cutoff,in_range,payload,function,args,call,result,cancelled;
}zapret_lua_invocation_feedback;
enum zapret_lua_invocation_action {
    LUA_INVOKE_NEXT=1,LUA_INVOKE_INSTANCE,LUA_INVOKE_CUTOFF,LUA_INVOKE_RANGE,LUA_INVOKE_PAYLOAD,
    LUA_INVOKE_LOOKUP,LUA_INVOKE_ARGUMENTS,LUA_INVOKE_IDENTITY,LUA_INVOKE_CALL,LUA_INVOKE_CALL_ERROR,
    LUA_INVOKE_RESULT,LUA_INVOKE_CANCEL,LUA_INVOKE_DONE,LUA_INVOKE_FAILED,LUA_INVOKE_INVALID
};
uint32_t zapret_lua_invocation_step(zapret_lua_invocation_flow *,const zapret_lua_invocation_feedback *);
uint32_t zapret_lua_invocation_result(int32_t,uint32_t,int64_t,uint8_t *);
void zapret_lua_invocation_error_report(uint32_t,int32_t,zapret_log_sink);
_Static_assert(sizeof(zapret_lua_invocation_flow)==8 && sizeof(zapret_lua_invocation_feedback)==10 &&
    offsetof(zapret_lua_invocation_flow,verdict)==4 && offsetof(zapret_lua_invocation_feedback,cancelled)==9,
    "Rust Lua invocation state ABI");
