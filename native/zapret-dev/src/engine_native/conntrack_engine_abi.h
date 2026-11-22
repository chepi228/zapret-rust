/* MIT. Native record layout used by the Rust conntrack entries. */
#pragma once
#include "conntrack.h"
#include "helpers.h"
#include <lauxlib.h>

typedef struct {
    uint32_t entry, stage, status, reverse, reset, find_direction, protocol, queue_limit;
    uint32_t after_clear, after_init, after_new, after_feed;
    int32_t incoming;
    uint32_t tcp, udp, padding;
    uintptr_t track, element, out_track, out_reverse;
    uint64_t cursor;
    int64_t now, last, interval;
    uintptr_t result;
} zapret_conntrack_engine_state;

typedef struct {
    t_conntrack *table;
    const struct dissect *packet;
    t_conn key;
    zapret_conntrack_packet input;
} zapret_conntrack_engine_context;

uint32_t zapret_engine_conntrack_until_vm(zapret_conntrack_engine_state *, zapret_conntrack_engine_context *);

#define POINTER_BYTES sizeof(void *)
_Static_assert(sizeof(struct dissect) == 14 * POINTER_BYTES &&
    offsetof(struct dissect, ip) == 2 * POINTER_BYTES && offsetof(struct dissect, ip6) == 3 * POINTER_BYTES &&
    offsetof(struct dissect, tcp) == 6 * POINTER_BYTES && offsetof(struct dissect, udp) == 7 * POINTER_BYTES &&
    offsetof(struct dissect, len_l4) == 9 * POINTER_BYTES &&
    offsetof(struct dissect, len_payload) == 12 * POINTER_BYTES && offsetof(struct ip6_hdr, ip6_flow) == 0,
    "Rust conntrack packet projection ABI");
_Static_assert(sizeof(t_ctrack) == 216 + 8 * POINTER_BYTES && _Alignof(t_ctrack) == 8 &&
    offsetof(t_ctrack, t_start) == 8 && offsetof(t_ctrack, pos) == 24 &&
    offsetof(t_ctrack, b_cutoff) == 188 + POINTER_BYTES && offsetof(t_ctrack, l7proto) == 192 + POINTER_BYTES &&
    offsetof(t_ctrack, hostname) == 200 + POINTER_BYTES &&
    offsetof(t_ctrack, hostname_is_ip) == 200 + 2 * POINTER_BYTES &&
    offsetof(t_ctrack, lua_state) == 204 + 2 * POINTER_BYTES &&
    offsetof(t_ctrack, lua_instance_cutoff) == 208 + 2 * POINTER_BYTES &&
    offsetof(t_ctrack, reasm_client_payload) == 212 + 2 * POINTER_BYTES &&
    offsetof(t_ctrack, reasm_client) == 216 + 2 * POINTER_BYTES &&
    offsetof(t_ctrack, delayed) == 216 + 6 * POINTER_BYTES &&
    sizeof(t_reassemble) == 4 * POINTER_BYTES && _Alignof(t_reassemble) == _Alignof(void *) &&
    sizeof(struct rawpacket_queue) == 2 * POINTER_BYTES && _Alignof(struct rawpacket_queue) == _Alignof(void *),
    "Rust conntrack track projection ABI");
_Static_assert(sizeof(t_conntrack_pool) == sizeof(t_ctrack) + 40 && offsetof(t_conntrack_pool, track) == 0 &&
    offsetof(t_conntrack_pool, conn) == sizeof(t_ctrack) && sizeof(t_conntrack) == 40 &&
    offsetof(t_conntrack, timeout_syn) == 0 && offsetof(t_conntrack, timeout_established) == 4 &&
    offsetof(t_conntrack, timeout_fin) == 8 && offsetof(t_conntrack, timeout_udp) == 12 &&
    offsetof(t_conntrack, t_purge_interval) == 16 && offsetof(t_conntrack, t_last_purge) == 24 &&
    offsetof(t_conntrack, pool) == 32, "Rust conntrack table projection ABI");
_Static_assert(sizeof(time_t) == 8 && sizeof(struct timespec) == 16 &&
    offsetof(struct timespec, tv_sec) == 0 && offsetof(struct timespec, tv_nsec) == 8 &&
    offsetof(t_ctrack_positions, t_last) == 0 && sizeof(((t_ctrack_positions *)0)->ipproto) == 1 &&
    CLOCK_BOOT_OR_UPTIME == 1 && LUA_NOREF == -2 && L7_UNKNOWN == 1 && L7P_UNKNOWN == 1,
    "Rust conntrack times and constants ABI");
_Static_assert(sizeof(zapret_conntrack_engine_state) == 104 + 4 * POINTER_BYTES &&
    offsetof(zapret_conntrack_engine_state, track) == 64 &&
    offsetof(zapret_conntrack_engine_state, element) == 64 + POINTER_BYTES &&
    offsetof(zapret_conntrack_engine_state, cursor) == 64 + 4 * POINTER_BYTES &&
    offsetof(zapret_conntrack_engine_state, result) == 96 + 4 * POINTER_BYTES &&
    sizeof(zapret_conntrack_engine_context) == 48 + 5 * POINTER_BYTES &&
    offsetof(zapret_conntrack_engine_context, input) == 40 + 2 * POINTER_BYTES,
    "Rust conntrack lifecycle engine ABI");
#undef POINTER_BYTES
