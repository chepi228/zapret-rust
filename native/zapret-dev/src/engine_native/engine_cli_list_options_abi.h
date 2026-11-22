/* MIT. CLI indices and profile/list storage borrowed by the Rust list entries. */
#pragma once
#include <stddef.h>
#include "engine_list_exports_abi.h"

_Static_assert(IDX_HOSTLIST == 20 && IDX_HOSTLIST_DOMAINS == 21 && IDX_HOSTLIST_EXCLUDE == 22 &&
    IDX_HOSTLIST_EXCLUDE_DOMAINS == 23 && IDX_HOSTLIST_AUTO == 24 && IDX_IPSET == 46 &&
    IDX_IPSET_IP == 47 && IDX_IPSET_EXCLUDE == 48 && IDX_IPSET_EXCLUDE_IP == 49,
    "Rust startup list indices ABI");
int engine_list_option(int, const char *, struct desync_profile *, bool,
    struct zapret_list_file **, struct zapret_list_file **, struct zapret_list_file **, struct zapret_list_file **);
