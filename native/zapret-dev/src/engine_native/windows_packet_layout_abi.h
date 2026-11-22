/* MIT. Layout checks for Windows packet callbacks and borrowed state. */
#pragma once
#include "windows_lua_packet_run_abi.h"
#include "engine_list_exports_abi.h"
#include "engine_profile_exports_abi.h"
#include "windows_exports_abi.h"

_Static_assert(offsetof(struct params_s, debug) == 4252 && offsetof(struct params_s, desync_fwmark) == 4264 &&
    offsetof(struct params_s, desync_profiles) == 4272 && offsetof(struct params_s, hostlist_auto_debuglog) == 8528 &&
    offsetof(struct params_s, conntrack) == 12664 && offsetof(struct params_s, ctrack_disable) == 12704 &&
    offsetof(struct params_s, server) == 12705 && offsetof(struct params_s, cache_hostname) == 12706 &&
    offsetof(struct params_s, ipcache_lifetime) == 12708 && offsetof(struct params_s, ipcache) == 12712 &&
    offsetof(struct params_s, reasm_payload_disable) == 12728 && offsetof(struct params_s, payload_disable) == 12736,
    "Rust packet settings");
_Static_assert(offsetof(t_ctrack, bCheckDone) == 0 && offsetof(t_ctrack, bCheckResult) == 1 &&
    offsetof(t_ctrack, bCheckExcluded) == 2 && offsetof(t_ctrack, incoming_ttl) == 195 &&
    offsetof(t_ctrack, dp) == 184 && sizeof(t_ctrack) == 280 &&
    offsetof(t_ctrack, reasm_client_payload) == 228 && offsetof(t_ctrack, reasm_client) == 232 &&
    offsetof(t_ctrack, delayed) == 264, "Rust packet connection");
_Static_assert(offsetof(struct dissect, proto) == 40 && offsetof(struct dissect, tcp) == 48 &&
    offsetof(struct dissect, icmp) == 64 && offsetof(struct dissect, transport_len) == 80 &&
    offsetof(struct dissect, data_payload) == 88 && offsetof(struct dissect, frag_off) == 106 &&
    sizeof(struct dissect) == 112 && sizeof(t_ctrack_positions) == 160,
    "Rust packet projections");
_Static_assert(offsetof(struct rawpacket, ifin) == 128 && offsetof(struct rawpacket, ifout) == 172 &&
    offsetof(struct rawpacket, fwmark_orig) == 216 && offsetof(struct rawpacket, fwmark) == 220 &&
    offsetof(struct rawpacket, packet) == 240 && offsetof(struct rawpacket, tpos) == 248 &&
    offsetof(struct rawpacket, tpos_present) == 408 && offsetof(struct rawpacket, dst) == 0,
    "Rust replay snapshot");
_Static_assert(VERDICT_PASS == 0 && VERDICT_DROP == 2 && VERDICT_MODIFY == 1 && VERDICT_MASK == 3 &&
    VERDICT_NOCSUM == 8 && L7_UNKNOWN == 1 && L7P_UNKNOWN == 1 && INET6_ADDRSTRLEN == 65,
    "Rust packet verdict and protocol constants");
