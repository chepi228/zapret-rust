/* MIT. Option projection and text parser entry for the native profile. */
#pragma once
#include <stddef.h>
#include "params.h"

_Static_assert(sizeof(struct desync_profile) == 184 && _Alignof(struct desync_profile) == 8 &&
    offsetof(struct desync_profile, filter_ipv4) == 24 &&
    offsetof(struct desync_profile, filter_ipv6) == 25 &&
    offsetof(struct desync_profile, pf_tcp) == 32 && offsetof(struct desync_profile, pf_udp) == 40 &&
    offsetof(struct desync_profile, icf) == 48 && offsetof(struct desync_profile, ipf) == 56 &&
    offsetof(struct desync_profile, filter_l7) == 64 && offsetof(struct desync_profile, lua_desync) == 160 &&
    offsetof(struct desync_profile, b_filter_l3) == 176 && offsetof(struct desync_profile, b_filter_l7) == 177,
    "Rust profile option fields");
_Static_assert(offsetof(struct params_s, reasm_payload_disable) == 12728 &&
    offsetof(struct params_s, payload_disable) == 12736 && L7P_ALL == 0,
    "Rust global profile option fields");
_Static_assert(sizeof(struct packet_range) == 20 && offsetof(struct func_list, payload_type) == 8 &&
    offsetof(struct func_list, range_in) == 16 && offsetof(struct func_list, range_out) == 36,
    "Rust local profile record fields");

int engine_profile_filter(int index, const char *text, struct desync_profile *profile,
    uint64_t *payload, struct packet_range *incoming, struct packet_range *outgoing);
