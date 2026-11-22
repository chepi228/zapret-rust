/* MIT. Validate the native header layouts and publish the extension offset. */
_Static_assert(sizeof(struct ip) == 20 && sizeof(struct ip6_hdr) == 40 &&
    sizeof(struct tcphdr) == 20 && sizeof(struct udphdr) == 8 && sizeof(struct icmp46) == 8,
    "wire header sizes");

size_t zapret_ipv6_extension(const uint8_t *, size_t, uint8_t);

uint8_t *proto_find_ip6_exthdr(struct ip6_hdr *ip6, size_t len, uint8_t proto)
{
    uint8_t *data = (uint8_t *)ip6;
    size_t offset = zapret_ipv6_extension(data, len, proto);
    return offset ? data + offset : NULL;
}

