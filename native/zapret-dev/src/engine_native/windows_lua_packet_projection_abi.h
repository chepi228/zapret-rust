/* MIT. Win64 LuaJIT metadata projection ABI. */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef ZAPRET_LUA_PACKET_TYPES_DEFINED
#define ZAPRET_LUA_PACKET_TYPES_DEFINED
typedef struct {
    const uint8_t *data;
    size_t length, offset;
    uint8_t next, kind;
    bool stopped;
} zapret_lua_packet_cursor;

typedef struct {
    uint32_t values[10];
    const uint8_t *source, *destination;
    zapret_lua_packet_cursor cursor;
    uint8_t count, address_width, table_capacity;
} zapret_lua_packet_header_values;

typedef struct {
    const uint8_t *data;
    size_t length;
    uint8_t kind, next;
    bool has_data;
} zapret_lua_packet_item;
#endif

typedef struct {
    const char *name;
    const uint8_t *data;
    size_t length;
    int64_t number;
    uint32_t kind, reserved;
} zapret_lua_packet_metadata_action;

typedef struct {
    zapret_lua_packet_header_values header;
    uint32_t kind, index, phase, present;
} zapret_lua_packet_header_projection_state;

typedef struct {
    zapret_lua_packet_cursor *cursor;
    zapret_lua_packet_item item;
    int64_t index;
    uint32_t phase;
} zapret_lua_packet_items_state;

_Static_assert(LUA_VERSION_NUM == 501 && sizeof(lua_Integer) == 8 &&
    sizeof(zapret_lua_packet_cursor) == 32 && sizeof(zapret_lua_packet_header_values) == 96 &&
    sizeof(zapret_lua_packet_item) == 24 && sizeof(zapret_lua_packet_metadata_action) == 40 &&
    offsetof(zapret_lua_packet_metadata_action, kind) == 32 &&
    sizeof(zapret_lua_packet_header_projection_state) == 112 &&
    offsetof(zapret_lua_packet_header_projection_state, header.cursor) == 56 &&
    sizeof(zapret_lua_packet_items_state) == 48, "Rust metadata projection ABI");

bool zapret_lua_packet_header_projection_begin(uint32_t, const uint8_t *, size_t,
    zapret_lua_packet_header_projection_state *, zapret_lua_packet_metadata_action *);
bool zapret_lua_packet_header_projection_step(zapret_lua_packet_header_projection_state *,
    zapret_lua_packet_metadata_action *);
bool zapret_lua_packet_items_prepare(uint32_t, const uint8_t *, size_t,
    zapret_lua_packet_cursor *, const char **);
bool zapret_lua_packet_items_begin(const char *, zapret_lua_packet_cursor *,
    zapret_lua_packet_items_state *, zapret_lua_packet_metadata_action *);
bool zapret_lua_packet_items_step(zapret_lua_packet_items_state *, zapret_lua_packet_metadata_action *);

void native_lua_push_packet_items(lua_State *, const char *, zapret_lua_packet_cursor *);
void native_lua_push_packet_header(lua_State *, uint8_t, const uint8_t *, size_t);
void lua_pushf_tcphdr_options(lua_State *, const struct tcphdr *, size_t);
void lua_pushf_ip6exthdr(lua_State *, const struct ip6_hdr *, size_t);
void lua_push_tcphdr(lua_State *, const struct tcphdr *, size_t);
void lua_push_udphdr(lua_State *, const struct udphdr *, size_t);
void lua_push_icmphdr(lua_State *, const struct icmp46 *, size_t);
void lua_push_iphdr(lua_State *, const struct ip *, size_t);
void lua_push_ip6hdr(lua_State *, const struct ip6_hdr *, size_t);
