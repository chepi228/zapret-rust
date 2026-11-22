/* MIT. Native addresses only; bounds/types/scales/side effects belong to Rust. */
#include "native_cli_catalog_abi.h"

typedef struct {
    void *value;
    bool *explicit, *intercept;
    unsigned *timeouts[4];
} zapret_cli_numeric_target;
typedef struct {
    bool (*number)(const char *, const zapret_numeric_option *);
    bool (*timeouts)(const char *, unsigned *, unsigned *, unsigned *, unsigned *);
} zapret_cli_numeric_ops;
int32_t zapret_native_cli_apply_numeric(int32_t, const char *, const zapret_cli_numeric_target *, const zapret_cli_numeric_ops *);
_Static_assert(sizeof(zapret_cli_numeric_target) == 7 * sizeof(void *) &&
    sizeof(zapret_cli_numeric_ops) == 2 * sizeof(void *), "Rust numeric CLI ABI");

static int engine_numeric_option(int index,const char *text,struct desync_profile *dp)
{
    zapret_cli_numeric_target target = {
        .intercept = &params.intercept,
        .timeouts = {&params.ctrack_t_syn, &params.ctrack_t_est, &params.ctrack_t_fin, &params.ctrack_t_udp},
    };
    switch(index){
        case IDX_INTERCEPT:target.value=&params.intercept;break;
        case IDX_FUZZ:target.value=&params.fuzz;break;
        case IDX_DAEMON:target.value=&params.daemon;break;
        case IDX_CTRACK_DISABLE:target.value=&params.ctrack_disable;break;
        case IDX_SERVER:target.value=&params.server;break;
        case IDX_IPCACHE_HOSTNAME:target.value=&params.cache_hostname;break;
        case IDX_IPCACHE_LIFETIME:target.value=&params.ipcache_lifetime;break;
        case IDX_LUA_GC:target.value=&params.lua_gc;break;
        case IDX_HOSTLIST_AUTO_FAIL_THRESHOLD:target.value=&dp->hostlist_auto_fail_threshold;target.explicit=&dp->b_hostlist_auto_fail_threshold;break;
        case IDX_HOSTLIST_AUTO_FAIL_TIME:target.value=&dp->hostlist_auto_fail_time;target.explicit=&dp->b_hostlist_auto_fail_time;break;
        case IDX_HOSTLIST_AUTO_RETRANS_THRESHOLD:target.value=&dp->hostlist_auto_retrans_threshold;target.explicit=&dp->b_hostlist_auto_retrans_threshold;break;
        case IDX_HOSTLIST_AUTO_RETRANS_MAXSEQ:target.value=&dp->hostlist_auto_retrans_maxseq;target.explicit=&dp->b_hostlist_auto_retrans_maxseq;break;
        case IDX_HOSTLIST_AUTO_INCOMING_MAXSEQ:target.value=&dp->hostlist_auto_incoming_maxseq;target.explicit=&dp->b_hostlist_auto_incoming_maxseq;break;
        case IDX_HOSTLIST_AUTO_RETRANS_RESET:target.value=&dp->hostlist_auto_retrans_reset;target.explicit=&dp->b_hostlist_auto_retrans_reset;break;
        case IDX_HOSTLIST_AUTO_UDP_OUT:target.value=&dp->hostlist_auto_udp_out;target.explicit=&dp->b_hostlist_auto_udp_out;break;
        case IDX_HOSTLIST_AUTO_UDP_IN:target.value=&dp->hostlist_auto_udp_in;target.explicit=&dp->b_hostlist_auto_udp_in;break;
        case IDX_SSID_FILTER_NEG:target.value=&params.ssid_filter_neg;break;
        case IDX_NLM_FILTER_NEG:target.value=&params.nlm_filter_neg;break;
        default:break;
    }
    static const zapret_cli_numeric_ops ops = {zapret_cli_set_number, zapret_cli_timeouts};
    return zapret_native_cli_apply_numeric(index, text, &target, &ops);
}
