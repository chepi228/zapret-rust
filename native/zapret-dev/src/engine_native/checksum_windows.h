/* MIT. Typed C entry points for Rust-owned wire checksum updates. */
#pragma once
#include "checksum.h"

void zapret_checksum_ip4(struct ip *);
void zapret_checksum_tcp4(struct tcphdr *, size_t, const struct in_addr *, const struct in_addr *);
void zapret_checksum_tcp6(struct tcphdr *, size_t, const struct in6_addr *, const struct in6_addr *);
void zapret_checksum_tcp(struct tcphdr *, size_t, const struct ip *, const struct ip6_hdr *);
void zapret_checksum_udp4(struct udphdr *, size_t, const struct in_addr *, const struct in_addr *);
void zapret_checksum_udp6(struct udphdr *, size_t, const struct in6_addr *, const struct in6_addr *);
void zapret_checksum_udp(struct udphdr *, size_t, const struct ip *, const struct ip6_hdr *);
void zapret_checksum_icmp4(struct icmp46 *, size_t);
void zapret_checksum_icmp6(struct icmp46 *, size_t, const struct ip6_hdr *);
void zapret_checksum_icmp(struct icmp46 *, size_t, const struct ip6_hdr *);

_Static_assert(offsetof(struct ip, ip_sum) == 10 && offsetof(struct tcphdr, th_sum) == 16 &&
    offsetof(struct udphdr, uh_sum) == 6 && offsetof(struct icmp46, icmp_cksum) == 2 &&
    offsetof(struct ip, ip_src) == 12 && offsetof(struct ip6_hdr, ip6_src) == 8 &&
    offsetof(struct ip, ip_dst) == 16 && offsetof(struct ip6_hdr, ip6_dst) == 24,
    "Rust checksum wire offsets");

#ifndef ZAPRET_CHECKSUM_FIXTURE_BRIDGE
#define ip4_fix_checksum zapret_checksum_ip4
#define tcp4_fix_checksum zapret_checksum_tcp4
#define tcp6_fix_checksum zapret_checksum_tcp6
#define tcp_fix_checksum zapret_checksum_tcp
#define udp4_fix_checksum zapret_checksum_udp4
#define udp6_fix_checksum zapret_checksum_udp6
#define udp_fix_checksum zapret_checksum_udp
#define icmp4_fix_checksum zapret_checksum_icmp4
#define icmp6_fix_checksum zapret_checksum_icmp6
#define icmp_fix_checksum zapret_checksum_icmp
#endif
