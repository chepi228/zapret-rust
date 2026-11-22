/* MIT. Symbols and pinned SDK layouts for the Rust packet host. */
#pragma once

extern __typeof__(net32_add) zapret_packet_net32_add;
extern __typeof__(net16_add) zapret_packet_net16_add;
extern __typeof__(tcp_find_option) zapret_packet_tcp_find_option;
extern __typeof__(extract_dst) zapret_packet_extract_dst;
extern __typeof__(reverse_ip) zapret_packet_reverse_ip;
extern __typeof__(reverse_tcp) zapret_packet_reverse_tcp;

#define net32_add zapret_packet_net32_add
#define net16_add zapret_packet_net16_add
#define tcp_find_option zapret_packet_tcp_find_option
#define extract_dst zapret_packet_extract_dst
#define reverse_ip zapret_packet_reverse_ip
#define reverse_tcp zapret_packet_reverse_tcp

_Static_assert(sizeof(struct sockaddr_storage) == 128 && _Alignof(struct sockaddr_storage) == 8 &&
    sizeof(struct sockaddr_in6) == 28 && offsetof(struct sockaddr_in6, sin6_addr) == 8 &&
    offsetof(struct sockaddr_in6, sin6_scope_id) == 24 && offsetof(struct sockaddr_in, sin_addr) == 4 &&
    AF_INET == 2 && AF_INET6 == 23 && IPPROTO_NONE == 59,
    "Rust packet socket address ABI");
