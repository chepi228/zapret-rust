/* MIT. Domain suffix traversal and strict matching execute in Rust. */
#include "pools_windows.h"

static void trace_host(const char *suffix, const char *host, int status)
{
    DLOG("hostlist check for %s : ", suffix);
    if (status == 0) DLOG("positive\n");
    else if (status == 1) DLOG("negative : strict_mismatch : %s != %s\n", suffix, host);
    else DLOG("negative\n");
}

static bool SearchHostList(hostlist_pool *pool, const char *host, bool no_match_subdomains)
{
    return zapret_host_match(pool, host, no_match_subdomains, params.debug ? trace_host : NULL) != 0;
}
