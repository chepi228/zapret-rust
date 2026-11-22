/* MIT. The C API retains network-order addresses and its diagnostic format. */
#include "pools_windows.h"

bool ipset4Add(struct zapret_ip_pool **pool, const struct in_addr *address, uint8_t bits)
{
    return zapret_ip_add(pool, (const unsigned char *)address, 32, bits) != 0;
}

bool ipset4Check(const struct zapret_ip_pool *pool, const struct in_addr *address, uint8_t bits)
{
    return zapret_ip_check(pool, (const unsigned char *)address, bits) != 0;
}

bool ipset6Add(struct zapret_ip_pool **pool, const struct in6_addr *address, uint8_t bits)
{
    return zapret_ip_add(pool, (const unsigned char *)address, 128, bits) != 0;
}

bool ipset6Check(const struct zapret_ip_pool *pool, const struct in6_addr *address, uint8_t bits)
{
    return zapret_ip_check(pool, (const unsigned char *)address, bits) != 0;
}

void ipset4Print(struct zapret_ip_pool *pool)
{
    zapret_prefix_info entry;
    const unsigned char *after = NULL;
    while (zapret_ip_next(pool, after, &entry)) {
        struct cidr4 prefix;
        memcpy(&prefix.addr, entry.address, sizeof(prefix.addr));
        prefix.preflen = entry.bits;
        print_cidr4(&prefix);
        printf("\n");
        after = entry.address;
    }
}

void ipset6Print(struct zapret_ip_pool *pool)
{
    zapret_prefix_info entry;
    const unsigned char *after = NULL;
    while (zapret_ip_next(pool, after, &entry)) {
        struct cidr6 prefix;
        memcpy(&prefix.addr, entry.address, sizeof(prefix.addr));
        prefix.preflen = entry.bits;
        print_cidr6(&prefix);
        printf("\n");
        after = entry.address;
    }
}

void ipsetDestroy(ipset *pool)
{
    zapret_ip_destroy(&pool->ips4);
    zapret_ip_destroy(&pool->ips6);
}

void ipsetPrint(ipset *pool)
{
    ipset4Print(pool->ips4);
    ipset6Print(pool->ips6);
}
