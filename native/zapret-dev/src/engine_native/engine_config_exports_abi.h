/* MIT. Layout used by the native Rust configuration entries. */
#pragma once
#include "windows_startup_params_abi.h"

_Static_assert(offsetof(struct params_s, wexp) == 0, "Rust configuration word storage");
#define ZAPRET_FILTER_SLOT(field, index) \
    _Static_assert(offsetof(struct params_s, field) == \
        offsetof(struct params_s, wf_pf_tcp_src_in) + (index) * sizeof(char *) && \
        sizeof(params.field) == sizeof(char *), "Rust filter slot " #field)
ZAPRET_FILTER_SLOT(wf_pf_tcp_dst_in, 1);
ZAPRET_FILTER_SLOT(wf_pf_udp_src_in, 2);
ZAPRET_FILTER_SLOT(wf_pf_udp_dst_in, 3);
ZAPRET_FILTER_SLOT(wf_pf_tcp_src_out, 4);
ZAPRET_FILTER_SLOT(wf_pf_tcp_dst_out, 5);
ZAPRET_FILTER_SLOT(wf_pf_udp_src_out, 6);
ZAPRET_FILTER_SLOT(wf_pf_udp_dst_out, 7);
ZAPRET_FILTER_SLOT(wf_icf_in, 8);
ZAPRET_FILTER_SLOT(wf_icf_out, 9);
ZAPRET_FILTER_SLOT(wf_ipf_in, 10);
ZAPRET_FILTER_SLOT(wf_ipf_out, 11);
ZAPRET_FILTER_SLOT(wf_raw_filter, 12);
#undef ZAPRET_FILTER_SLOT

_Static_assert(DPI_DESYNC_FWMARK_DEFAULT == 0 &&
    CTRACK_T_SYN == 60 && CTRACK_T_EST == 300 && CTRACK_T_FIN == 60 && CTRACK_T_UDP == 60 &&
    IPCACHE_LIFETIME == 7200 && LUA_GC_INTERVAL == 60 && L7P_NONE == 31, "Rust engine defaults");
