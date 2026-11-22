/* MIT. Bind Rust IP list tokens to the engine's existing CIDR pools. */
#include "list_windows.h"

static int insert_ip(void *context, const unsigned char *token, size_t length, uint32_t flags)
{
    (void)flags;
    ipset *pool = context;
    char cidr[128];
    if (length >= sizeof(cidr)) length = sizeof(cidr) - 1;
    memcpy(cidr, token, length);
    cidr[length] = 0;
    struct cidr4 ip4;
    struct cidr6 ip6;
    bool added;
    if (parse_cidr4(cidr, &ip4))
        added = ipset4AddCidr(&pool->ips4, &ip4);
    else if (parse_cidr6(cidr, &ip6))
        added = ipset6AddCidr(&pool->ips6, &ip6);
    else {
        DLOG_ERR("bad ip or subnet : %s\n", cidr);
        return 0;
    }
    if (added) return 1;
    ipsetDestroy(pool);
    return -1;
}

bool AppendIpsetItem(ipset *ips, char *text)
{
    return zapret_list_item((unsigned char *)text, strlen(text), 0, insert_ip, ips) != 0;
}

static bool AppendIpset(ipset *ips, const char *filename)
{
    DLOG_CONDUP("Loading ipset %s\n", filename);
    zapret_list_info info;
    int status = zapret_list_load(filename, 0, insert_ip, ips, &info);
    if (status) {
        if (info.error) wf_error(info.error);
        switch (status) {
        case 1: DLOG_ERR("Could not open %s\n", filename); break;
        case 2: DLOG_PERROR("AppendIpset"); break;
        case 3: DLOG_ERR("zlib decompression failed : result -3\n"); break;
        case 4: DLOG_ERR("Not enough memory to store ipset : %s\n", filename); break;
        }
        return false;
    }
    if (info.compressed)
        DLOG_CONDUP("zlib compression detected. uncompressed size : %zu\n", (size_t)info.decompressed_size);
    else
        DLOG_CONDUP("loading plain text list\n");
    DLOG_CONDUP("Loaded %d ip/subnets from %s\n", (int)info.count, filename);
    return true;
}
