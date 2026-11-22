/* MIT. Wire layout is checked against the pinned native headers. */
#include "packet_read_views_abi.h"

uint32_t zapret_packet_net32_add(uint32_t, uint32_t);
uint16_t zapret_packet_net16_add(uint16_t, uint16_t);
uint8_t *zapret_packet_tcp_find_option(const void *, uint8_t);
bool zapret_packet_extract_dst(const uint8_t *, size_t, void *);
void zapret_packet_reverse_ip(void *, void *);
void zapret_packet_reverse_tcp(void *);
_Static_assert(sizeof(struct sockaddr_storage) == 128 && sizeof(struct sockaddr_in6) == 28 &&
    offsetof(struct sockaddr_in6, sin6_addr) == 8 && offsetof(struct sockaddr_in6, sin6_scope_id) == 24 &&
    offsetof(struct sockaddr_in, sin_addr) == 4 && AF_INET == 2 && AF_INET6 == 23 && IPPROTO_NONE == 59 && SCALE_NONE == 255,
    "Rust packet socket address ABI");
uint32_t net32_add(uint32_t value,uint32_t increment) { return zapret_packet_net32_add(value,increment); }
uint16_t net16_add(uint16_t value,uint16_t increment) { return zapret_packet_net16_add(value,increment); }
uint8_t *tcp_find_option(struct tcphdr *tcp,uint8_t kind) { return zapret_packet_tcp_find_option(tcp,kind); }
bool extract_dst(const uint8_t *data,size_t length,struct sockaddr *dst) { return zapret_packet_extract_dst(data,length,dst); }
void reverse_ip(struct ip *ip,struct ip6_hdr *ip6) { zapret_packet_reverse_ip(ip,ip6); }
void reverse_tcp(struct tcphdr *tcp) { zapret_packet_reverse_tcp(tcp); }
