/* MIT. Win64 LuaJIT display entry points for decoded records. */
#pragma once
#include <stddef.h>

_Static_assert(LUA_VERSION_NUM == 501 && sizeof(lua_Integer) == 8 &&
    sizeof(zapret_lua_packet_projection_action) == 40 &&
    offsetof(zapret_lua_packet_projection_action, number) == 24 &&
    offsetof(zapret_lua_packet_projection_action, header) == 36,
    "Rust Lua header view action ABI");

void lua_pushf_tcphdr(lua_State *, const struct tcphdr *, size_t);
void lua_pushf_udphdr(lua_State *, const struct udphdr *, size_t);
void lua_pushf_icmphdr(lua_State *, const struct icmp46 *, size_t);
void lua_pushf_iphdr(lua_State *, const struct ip *, size_t);
void lua_pushf_ip6hdr(lua_State *, const struct ip6_hdr *, size_t);
void lua_push_dissect(lua_State *, const struct dissect *);
void lua_pushf_dissect(lua_State *, const struct dissect *);
