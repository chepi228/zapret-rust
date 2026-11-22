/* MIT. Resource-free Rust context operations; the caller owns every VM call. */
#pragma once
#include "lua_aux_abi.h"
#include <stddef.h>
#include <stdint.h>
typedef struct {
    const char *instance;
    uint32_t profile;
    int32_t registry;
    bool incoming, outgoing, tracked;
} zapret_lua_context_scope_values;
typedef struct { const uint8_t *data; size_t length; } zapret_lua_context_span;
bool zapret_lua_context_init(t_lua_desync_context *);
bool zapret_lua_context_valid(const t_lua_desync_context *,size_t);
bool zapret_lua_context_prepare(t_lua_desync_context *,const struct desync_profile *,t_ctrack *,const struct dissect *,bool);
bool zapret_lua_context_active(t_lua_desync_context *,bool);
bool zapret_lua_context_rule(t_lua_desync_context *,const char *,uint32_t,char *,size_t);
bool zapret_lua_context_scope(const t_lua_desync_context *,uint32_t,bool,zapret_lua_context_scope_values *);
bool zapret_lua_context_cutoff(const t_lua_desync_context *,uint32_t);
bool zapret_lua_context_cancel(t_lua_desync_context *);
bool zapret_lua_context_cancelled(const t_lua_desync_context *);
bool zapret_lua_context_packet(const t_lua_desync_context *,zapret_lua_context_span *);
_Static_assert(sizeof(t_lua_desync_context)==56 && offsetof(t_lua_desync_context,func_n)==0 &&
    offsetof(t_lua_desync_context,func)==8 && offsetof(t_lua_desync_context,instance)==16 &&
    offsetof(t_lua_desync_context,dp)==24 && offsetof(t_lua_desync_context,dis)==32 &&
    offsetof(t_lua_desync_context,ctrack)==40 && offsetof(t_lua_desync_context,incoming)==48 &&
    offsetof(t_lua_desync_context,cancel)==49 && offsetof(t_lua_desync_context,valid)==50,
    "Rust Lua execution context ABI");
_Static_assert(sizeof(zapret_lua_context_scope_values)==24 && sizeof(zapret_lua_context_span)==16 &&
    offsetof(t_ctrack,lua_instance_cutoff)==224 && offsetof(t_ctrack,b_lua_in_cutoff)==197 &&
    offsetof(t_ctrack,b_lua_out_cutoff)==198 && offsetof(struct dissect,data_pkt)==0 &&
    offsetof(struct dissect,len_pkt)==8,"Rust Lua context input and output ABI");
