/* MIT. Exercise WLAN and NLM decisions without querying the host network. */
static const void *wlan_filter_ssid, *nlm_filter_net;
static bool wlan_filter_ssid_neg, nlm_filter_net_neg;
static unsigned wlan_state, nlm_state, wlan_queries, nlm_queries;
static uint64_t tick;

static bool wlan_filter_match(const void *list)
{
    (void)list;
    ++wlan_queries;
    w_win32_error = wlan_state == 2 ? ERROR_NOT_READY : ERROR_SUCCESS;
    return wlan_state == 1;
}
static bool nlm_filter_match(const void *list)
{
    (void)list;
    ++nlm_queries;
    w_win32_error = nlm_state == 2 ? (uint32_t)E_FAIL : nlm_state == 0 ? S_FALSE : S_OK;
    return nlm_state == 1;
}
static uint64_t fixture_ticks(void) { return tick; }
#define GetTickCount64 fixture_ticks
#include "network_gate_windows.inc"
#undef GetTickCount64

static void check_network_gate(void)
{
    unsigned checked = 0;
    for (wlan_state = 0; wlan_state < 3; ++wlan_state)
    for (nlm_state = 0; nlm_state < 3; ++nlm_state)
    for (unsigned flags = 0; flags < 4; ++flags) {
        wlan_filter_ssid_neg = (flags & 1) != 0;
        nlm_filter_net_neg = (flags & 2) != 0;
        bool allow_wlan = wlan_state < 2 && ((wlan_state == 1) != wlan_filter_ssid_neg);
        bool allow_nlm = nlm_state < 2 && ((nlm_state == 1) != nlm_filter_net_neg);
        logical_net_filter_reset();
        wlan_queries = nlm_queries = 0;
        CHECK(logical_net_filter_match() == (allow_wlan && allow_nlm));
        CHECK(wlan_queries == 1 && nlm_queries == (unsigned)allow_wlan);
        ++checked;
    }
    logical_net_filter_reset();
    wlan_filter_ssid_neg = nlm_filter_net_neg = false;
    wlan_queries = nlm_queries = 0;
    tick = 0;
    wlan_state = 2;
    CHECK(!logical_net_filter_match_rate_limited() && wlan_queries == 1);
    // Simulate an unrelated operation changing the diagnostic slot.
    w_win32_error = 0;
    wlan_state = nlm_state = 1;
    CHECK(!logical_net_filter_match_rate_limited() && wlan_queries == 1 && w_win32_error == ERROR_NOT_READY);
    tick = 1000;
    CHECK(logical_net_filter_match_rate_limited() && wlan_queries == 2 && nlm_queries == 1);
    wlan_state = 0;
    CHECK(!logical_net_filter_match() && !logical_net_filter_match_rate_limited() && wlan_queries == 3);
    printf("PASS network_gate cases=%u cache_cases=4\n", checked);
}
