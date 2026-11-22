/* MIT. Packet reconstruction bound directly to the Rust LuaJIT entries. */
#pragma once
#include "packet_write_windows.h"
#include "windows_lua_header_decode_abi.h"

typedef struct {
    const char *name;
    const uint8_t *data;
    size_t length;
    int64_t number;
    uint32_t kind, header;
} zapret_lua_packet_projection_action;
#include "windows_lua_header_views_abi.h"

void lua_reconstruct_extract_options(lua_State *, int, bool *, bool *, bool *, uint8_t *);
void lua_rawsend_extract_options(lua_State *, int, int *, uint32_t *, const char **);
int luacall_reconstruct_tcphdr(lua_State *);
int luacall_reconstruct_udphdr(lua_State *);
int luacall_reconstruct_icmphdr(lua_State *);
int luacall_reconstruct_iphdr(lua_State *);
int luacall_reconstruct_ip6hdr(lua_State *);
int luacall_rawsend(lua_State *);
int luacall_rawsend_dissect(lua_State *);
int luacall_conntrack_feed(lua_State *);
int luacall_reconstruct_dissect(lua_State *);
int luacall_dissect(lua_State *);

_Static_assert(LUA_VERSION_NUM == 501 && LUA_TNIL == 0 && LUA_TBOOLEAN == 1 &&
    LUA_TNUMBER == 3 && LUA_TSTRING == 4 && LUA_TTABLE == 5 &&
    sizeof(lua_Integer) == 8 && sizeof(struct ip) == 20 &&
    sizeof(struct ip6_hdr) == 40 && sizeof(struct tcphdr) == 20 &&
    sizeof(struct udphdr) == 8 && sizeof(struct icmp46) == 8 &&
    sizeof(struct dissect) == 112 && _Alignof(struct dissect) == 8 &&
    sizeof(sockaddr_in46) == 32 && RECONSTRUCT_MAX_SIZE == 65536 && IPPROTO_NONE == 59,
    "Rust LuaJIT packet writer ABI");
