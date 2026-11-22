/* Native profile views and the variadic sink used by the Rust reports. */
#include "runtime_log_windows.h"

_Static_assert(INET6_ADDRSTRLEN == 65, "Rust profile search address buffer ABI");
_Static_assert(offsetof(struct desync_profile, n) == 0 &&
    offsetof(struct desync_profile, name) == 8 &&
    offsetof(struct desync_profile, hostlist_auto) == 104, "Rust selected profile log ABI");
void zapret_profile_search_report(const struct zapret_profile_query *, const char *, uint32_t,
    bool, zapret_log_sink);
void zapret_profile_result_report(const struct desync_profile *, const struct zapret_profile_query *,
    zapret_log_sink);
