/* MIT. C supplies field addresses, Rust validates and commits numeric values. */
typedef struct {
    void *target;
    bool *explicit;
    int64_t lower, upper;
    uint32_t scale, kind;
    bool *disable;
} zapret_numeric_option;
_Static_assert(sizeof(zapret_numeric_option) == (sizeof(void *) == 4 ? 40 : 48) &&
    offsetof(zapret_numeric_option, kind) == 2 * sizeof(void *) + 20 &&
    sizeof(params.lua_gc) == 8 && sizeof(params.fuzz) == 4, "Rust scalar option ABI");
bool zapret_cli_set_number(const char *, const zapret_numeric_option *);
bool zapret_cli_timeouts(const char *, unsigned int *, unsigned int *, unsigned int *, unsigned int *);

// 0 delegates to an option with its own side effects, 1 has committed the
// value, and -1 rejects it before the prior value or explicit flag changes.
static int engine_numeric_option(int index, const char *text, struct desync_profile *dp)
{
    zapret_numeric_option option = {.lower = INT32_MIN, .upper = INT32_MAX, .scale = 1};
    switch (index) {
    case IDX_INTERCEPT: option.target = &params.intercept; break;
    case IDX_FUZZ: option.target = &params.fuzz; option.kind = 3; option.disable = &params.intercept; break;
    case IDX_DAEMON: option.target = &params.daemon; text = NULL; break;
    case IDX_CTRACK_DISABLE: option.target = &params.ctrack_disable; break;
    case IDX_SERVER: option.target = &params.server; break;
    case IDX_IPCACHE_HOSTNAME: option.target = &params.cache_hostname; break;
    case IDX_IPCACHE_LIFETIME:
        option.target = &params.ipcache_lifetime; option.kind = 2; option.lower = 0; option.upper = UINT32_MAX; break;
    case IDX_LUA_GC:
        option.target = &params.lua_gc; option.kind = 4; option.lower = 0; option.scale = 1000; break;
    case IDX_HOSTLIST_AUTO_FAIL_THRESHOLD:
        option.target = &dp->hostlist_auto_fail_threshold; option.explicit = &dp->b_hostlist_auto_fail_threshold;
        option.kind = 1; option.lower = 1; option.upper = 20; break;
    case IDX_HOSTLIST_AUTO_FAIL_TIME:
        option.target = &dp->hostlist_auto_fail_time; option.explicit = &dp->b_hostlist_auto_fail_time;
        option.kind = 1; option.lower = 1; break;
    case IDX_HOSTLIST_AUTO_RETRANS_THRESHOLD:
        option.target = &dp->hostlist_auto_retrans_threshold; option.explicit = &dp->b_hostlist_auto_retrans_threshold;
        option.kind = 1; option.lower = 2; option.upper = 10; break;
    case IDX_HOSTLIST_AUTO_RETRANS_MAXSEQ:
        option.target = &dp->hostlist_auto_retrans_maxseq; option.explicit = &dp->b_hostlist_auto_retrans_maxseq;
        option.kind = 3; option.upper = UINT32_MAX; break;
    case IDX_HOSTLIST_AUTO_INCOMING_MAXSEQ:
        option.target = &dp->hostlist_auto_incoming_maxseq; option.explicit = &dp->b_hostlist_auto_incoming_maxseq;
        option.kind = 3; option.upper = UINT32_MAX; break;
    case IDX_HOSTLIST_AUTO_RETRANS_RESET:
        option.target = &dp->hostlist_auto_retrans_reset; option.explicit = &dp->b_hostlist_auto_retrans_reset; break;
    case IDX_HOSTLIST_AUTO_UDP_OUT:
        option.target = &dp->hostlist_auto_udp_out; option.explicit = &dp->b_hostlist_auto_udp_out;
        option.kind = 1; break;
    case IDX_HOSTLIST_AUTO_UDP_IN:
        option.target = &dp->hostlist_auto_udp_in; option.explicit = &dp->b_hostlist_auto_udp_in;
        option.kind = 1; break;
    case IDX_SSID_FILTER_NEG: option.target = &params.ssid_filter_neg; break;
    case IDX_NLM_FILTER_NEG: option.target = &params.nlm_filter_neg; break;
    case IDX_CTRACK_TIMEOUTS:
        return zapret_cli_timeouts(text, &params.ctrack_t_syn, &params.ctrack_t_est,
            &params.ctrack_t_fin, &params.ctrack_t_udp) ? 1 : -1;
    default: return 0;
    }
    return zapret_cli_set_number(text, &option) ? 1 : -1;
}
