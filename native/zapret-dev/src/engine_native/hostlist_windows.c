/* MIT. Bind normalized Rust host tokens to the engine's existing pool. */
#include "list_windows.h"

static int insert_host(void *context, const unsigned char *token, size_t length, uint32_t flags)
{
    hostlist_pool **pool = context;
    if (HostlistPoolAddStrLen(pool, (const char *)token, length, flags)) return 1;
    HostlistPoolDestroy(pool);
    return -1;
}

bool AppendHostlistItem(hostlist_pool **hostlist, char *s)
{
    return zapret_list_item((unsigned char *)s, strlen(s), 1, insert_host, hostlist) != 0;
}

bool AppendHostList(hostlist_pool **hostlist, const char *filename)
{
    DLOG_CONDUP("Loading hostlist %s\n", filename);
    zapret_list_info info;
    int status = zapret_list_load(filename, 1, insert_host, hostlist, &info);
    if (status) {
        if (info.error) wf_error(info.error);
        switch (status) {
        case 1: DLOG_ERR("Could not open %s\n", filename); break;
        case 2: DLOG_PERROR("AppendHostList"); break;
        case 3: DLOG_ERR("zlib decompression failed : result -3\n"); break;
        case 4: DLOG_ERR("Not enough memory to store host list : %s\n", filename); break;
        }
        return false;
    }
    if (info.compressed)
        DLOG_CONDUP("zlib compression detected. uncompressed size : %zu\n", (size_t)info.decompressed_size);
    else
        DLOG_CONDUP("loading plain text list\n");
    DLOG_CONDUP("Loaded %d hosts from %s\n", (int)info.count, filename);
    return true;
}
