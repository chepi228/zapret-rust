/* MIT. Keep the pinned C signatures for the intermediate comparison gates. */
#define ZAPRET_CHECKSUM_FIXTURE_BRIDGE
#include "checksum_windows.h"
#undef ZAPRET_CHECKSUM_FIXTURE_BRIDGE
void ip4_fix_checksum(struct ip *ip) { zapret_checksum_ip4(ip); }
void tcp4_fix_checksum(struct tcphdr *tcp,size_t length,const struct in_addr *source,const struct in_addr *destination)
{ zapret_checksum_tcp4(tcp,length,source,destination); }
void tcp6_fix_checksum(struct tcphdr *tcp,size_t length,const struct in6_addr *source,const struct in6_addr *destination)
{ zapret_checksum_tcp6(tcp,length,source,destination); }
void tcp_fix_checksum(struct tcphdr *tcp,size_t length,const struct ip *ip,const struct ip6_hdr *ip6)
{ zapret_checksum_tcp(tcp,length,ip,ip6); }
void udp4_fix_checksum(struct udphdr *udp,size_t length,const struct in_addr *source,const struct in_addr *destination)
{ zapret_checksum_udp4(udp,length,source,destination); }
void udp6_fix_checksum(struct udphdr *udp,size_t length,const struct in6_addr *source,const struct in6_addr *destination)
{ zapret_checksum_udp6(udp,length,source,destination); }
void udp_fix_checksum(struct udphdr *udp,size_t length,const struct ip *ip,const struct ip6_hdr *ip6)
{ zapret_checksum_udp(udp,length,ip,ip6); }
void icmp4_fix_checksum(struct icmp46 *icmp,size_t length) { zapret_checksum_icmp4(icmp,length); }
void icmp6_fix_checksum(struct icmp46 *icmp,size_t length,const struct ip6_hdr *ip6) { zapret_checksum_icmp6(icmp,length,ip6); }
void icmp_fix_checksum(struct icmp46 *icmp,size_t length,const struct ip6_hdr *ip6) { zapret_checksum_icmp(icmp,length,ip6); }
