/* MIT. A failed Windows observation remains a failed observation in Rust. */
typedef struct {
    uint64_t second;
    uint32_t error;
    bool checked, allowed;
} zapret_network_snapshot;
typedef struct {
    uint32_t (*wlan)(void), (*network)(void);
} zapret_network_queries;
_Static_assert(sizeof(zapret_network_snapshot) == 16 && offsetof(zapret_network_snapshot, checked) == 12,
    "Rust logical network cache ABI");

bool zapret_network_gate(zapret_network_snapshot *, uint64_t, bool, bool, bool, uint32_t *,
    const zapret_network_queries *);
uint32_t zapret_network_observation(bool, bool, uint32_t);

static zapret_network_snapshot network_snapshot;
static void logical_net_filter_reset(void)
{
    network_snapshot = (zapret_network_snapshot){0};
}
static uint32_t observe_wlan(void)
{
    bool match = wlan_filter_match(wlan_filter_ssid);
    return zapret_network_observation(false, match, w_win32_error);
}
static uint32_t observe_network(void)
{
    bool match = nlm_filter_match(nlm_filter_net);
    return zapret_network_observation(true, match, w_win32_error);
}
static bool logical_net_filter_check(bool refresh)
{
    static const zapret_network_queries queries = {observe_wlan, observe_network};
    return zapret_network_gate(&network_snapshot, GetTickCount64(), refresh,
        wlan_filter_ssid_neg, nlm_filter_net_neg, &w_win32_error, &queries);
}
bool logical_net_filter_match(void) { return logical_net_filter_check(true); }
static bool logical_net_filter_match_rate_limited(void) { return logical_net_filter_check(false); }
