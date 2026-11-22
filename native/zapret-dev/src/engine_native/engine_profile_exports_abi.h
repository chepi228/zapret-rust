/* MIT. Native engine profile records borrowed by the Rust configuration owner. */
#pragma once
#include <stddef.h>
#include "params.h"
#include "profile_flow_windows.h"

#ifdef HAS_FILTER_SSID
#error "The Windows profile layout has no per-profile SSID field"
#endif
#define ZAPRET_PROFILE_ABI(win32, win64) (sizeof(void *) == 4 ? (win32) : (win64))
#define ZAPRET_PROFILE_FIELD(field, win32, win64) \
    _Static_assert(offsetof(struct desync_profile, field) == ZAPRET_PROFILE_ABI(win32, win64), \
        "Rust profile configuration: " #field)
_Static_assert(sizeof(struct desync_profile) == ZAPRET_PROFILE_ABI(120, 184) &&
    _Alignof(struct desync_profile) == 8, "Rust profile configuration ABI");
ZAPRET_PROFILE_FIELD(name, 4, 8);
ZAPRET_PROFILE_FIELD(cookie, 8, 16);
ZAPRET_PROFILE_FIELD(filter_ipv4, 12, 24);
ZAPRET_PROFILE_FIELD(filter_ipv6, 13, 25);
ZAPRET_PROFILE_FIELD(pf_tcp, 16, 32);
ZAPRET_PROFILE_FIELD(pf_udp, 20, 40);
ZAPRET_PROFILE_FIELD(icf, 24, 48);
ZAPRET_PROFILE_FIELD(ipf, 28, 56);
ZAPRET_PROFILE_FIELD(filter_l7, 32, 64);
ZAPRET_PROFILE_FIELD(ips_collection, 40, 72);
ZAPRET_PROFILE_FIELD(ips_collection_exclude, 44, 80);
ZAPRET_PROFILE_FIELD(hl_collection, 48, 88);
ZAPRET_PROFILE_FIELD(hl_collection_exclude, 52, 96);
ZAPRET_PROFILE_FIELD(hostlist_auto, 56, 104);
ZAPRET_PROFILE_FIELD(hostlist_auto_fail_threshold, 60, 112);
ZAPRET_PROFILE_FIELD(hostlist_auto_retrans_reset, 88, 140);
ZAPRET_PROFILE_FIELD(hostlist_auto_fail_counters, 92, 144);
ZAPRET_PROFILE_FIELD(hostlist_auto_last_purge, 96, 152);
ZAPRET_PROFILE_FIELD(lua_desync, 104, 160);
ZAPRET_PROFILE_FIELD(b_hostlist_auto_fail_threshold, 108, 168);
ZAPRET_PROFILE_FIELD(b_filter_l3, 116, 176);
ZAPRET_PROFILE_FIELD(b_filter_l7, 117, 177);
_Static_assert(sizeof(struct desync_profile_list) == ZAPRET_PROFILE_ABI(128, 200) &&
    offsetof(struct desync_profile_list, dp) == 0 &&
    offsetof(struct desync_profile_list, next.le_next) == sizeof(struct desync_profile) &&
    offsetof(struct desync_profile_list, next.le_prev) == sizeof(struct desync_profile) + sizeof(void *) &&
    sizeof(struct desync_profile_list_head) == sizeof(void *) &&
    offsetof(struct desync_profile_list_head, lh_first) == 0 &&
    offsetof(struct port_filter_item, next.le_next) == 8 &&
    offsetof(struct func_list, next.le_next) == ZAPRET_PROFILE_ABI(60, 64),
    "Rust profile list ABI");
#undef ZAPRET_PROFILE_FIELD
#undef ZAPRET_PROFILE_ABI
_Static_assert(HOSTLIST_AUTO_FAIL_THRESHOLD_DEFAULT == 3 && HOSTLIST_AUTO_FAIL_TIME_DEFAULT == 60 &&
    HOSTLIST_AUTO_RETRANS_THRESHOLD_DEFAULT == 3 && HOSTLIST_AUTO_RETRANS_MAXSEQ == 32768 &&
    HOSTLIST_AUTO_INCOMING_MAXSEQ == 4096 && HOSTLIST_AUTO_UDP_OUT == 4 && HOSTLIST_AUTO_UDP_IN == 1,
    "Rust profile defaults");

void dp_init_dynamic(struct desync_profile *);
bool native_profile_add_default(struct desync_profile_list_head *);
