/* MIT. The engine passes ownership of each domain pool to Rust. */
#include "pools_windows.h"

bool HostlistPoolAddStrLen(hostlist_pool **pool, const char *name, size_t length, uint32_t flags)
{
    return zapret_host_add(pool, (const unsigned char *)name, length, flags) != 0;
}

bool HostlistPoolAddStr(hostlist_pool **pool, const char *name, uint32_t flags)
{
    return HostlistPoolAddStrLen(pool, name, strlen(name), flags);
}

bool HostlistPoolCheckStr(hostlist_pool *pool, const char *name)
{
    return zapret_host_has(pool, name) != 0;
}

void HostlistPoolDestroy(hostlist_pool **pool)
{
    zapret_host_destroy(pool);
}
