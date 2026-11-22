/* Supply C layout and callback addresses to the Rust list policy. */
#include "list_startup_abi.h"
bool NonEmptyHostlist(hostlist_pool **pool)
{
    return zapret_list_host_nonempty(pool, HostlistPoolAddStrLen);
}
static void list_startup_ensure_automatic(struct zapret_list_file *file)
{
    NonEmptyHostlist(&file->hostlist);
}
static void MakeAutolistsNonEmpty(void)
{
    zapret_profile_ensure_automatic_hosts(LIST_FIRST(&params.desync_profiles), list_startup_ensure_automatic);
}
