/* MIT. Bind the native filter slots to the Rust-owned environment. */
struct zapret_network_environment;
static struct zapret_network_environment *network_environment;
typedef struct {
    struct zapret_network_environment **environment;
    const struct str_list_head **wlan, **network;
    bool *wlan_negated, *network_negated;
    uint32_t *error;
    void (*reset)(void);
} zapret_network_binding;
_Static_assert(sizeof(zapret_network_binding) == 7 * sizeof(void *) &&
    sizeof(struct str_list_head) == sizeof(void *),
    "Rust logical network binding ABI");
static const zapret_network_binding network_binding = {
    &network_environment, &wlan_filter_ssid, &nlm_filter_net,
    &wlan_filter_ssid_neg, &nlm_filter_net_neg, &w_win32_error, logical_net_filter_reset,
};
void zapret_network_unbind(const zapret_network_binding *);
bool zapret_network_bind(const zapret_network_binding *, const struct str_list_head *, bool,
    const struct str_list_head *, bool);
bool zapret_network_bind_present(const zapret_network_binding *);
bool zapret_network_environment_wlan(const struct zapret_network_environment *,
    const struct str_list_head *, uint32_t *);
bool zapret_network_environment_nlm(const struct zapret_network_environment *,
    const struct str_list_head *, uint32_t *);

void win_dark_deinit(void)
{
    zapret_network_unbind(&network_binding);
}
bool win_dark_init(const struct str_list_head *ssid, bool ssid_neg,
    const struct str_list_head *network, bool network_neg)
{
    return zapret_network_bind(&network_binding, ssid, ssid_neg, network, network_neg);
}
static bool wlan_filter_match(const struct str_list_head *list)
{
    return zapret_network_environment_wlan(network_environment, list, &w_win32_error);
}
static bool nlm_filter_match(const struct str_list_head *list)
{
    return zapret_network_environment_nlm(network_environment, list, &w_win32_error);
}
