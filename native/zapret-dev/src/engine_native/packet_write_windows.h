/* MIT. Host-order field descriptors and native packet serialization ABI. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t source[4], destination[4];
    uint16_t length, identification, fragment;
    uint8_t service, hop_limit, protocol;
} zapret_ipv4_fields;

typedef struct {
    uint8_t source[16], destination[16];
    uint32_t flow;
    uint16_t payload_length;
    uint8_t next, hop_limit, has_payload_length;
} zapret_ipv6_fields;

typedef struct {
    uint32_t sequence, acknowledgement;
    uint16_t source, destination, window, checksum, urgent;
    uint8_t reserved, flags;
} zapret_tcp_fields;

typedef struct {
    uint16_t source, destination, length, checksum;
} zapret_udp_fields;

typedef struct {
    uint32_t data;
    uint16_t checksum;
    uint8_t kind, code;
} zapret_icmp_fields;

typedef struct {
    size_t ip_length;
    uint8_t version, transport;
    bool keep_checksum;
    uint16_t checksum_xor;
} zapret_packet_finish;

enum zapret_packet_finish_error {
    ZAPRET_FINISH_LAYOUT = 1,
    ZAPRET_FINISH_UDP_LENGTH,
    ZAPRET_FINISH_IPV4_FRAGMENT_LENGTH,
    ZAPRET_FINISH_IPV4_FRAGMENT_BOUNDS,
    ZAPRET_FINISH_IPV6_FRAGMENT_LENGTH,
    ZAPRET_FINISH_IPV6_FRAGMENT_BOUNDS,
};

_Static_assert(sizeof(zapret_ipv4_fields) == 18 && offsetof(zapret_ipv4_fields, protocol) == 16,
    "Rust IPv4 writer ABI");
_Static_assert(sizeof(zapret_ipv6_fields) == 44 && offsetof(zapret_ipv6_fields, has_payload_length) == 40,
    "Rust IPv6 writer ABI");
_Static_assert(sizeof(zapret_tcp_fields) == 20 && offsetof(zapret_tcp_fields, flags) == 19,
    "Rust TCP writer ABI");
_Static_assert(sizeof(zapret_udp_fields) == 8 && sizeof(zapret_icmp_fields) == 8,
    "Rust UDP and ICMP writer ABI");
_Static_assert(offsetof(zapret_packet_finish, checksum_xor) == sizeof(size_t) + 4,
    "Rust packet finish ABI");

size_t zapret_write_ipv4(uint8_t *, size_t, const zapret_ipv4_fields *, const uint8_t *, size_t);
void zapret_write_ipv6(uint8_t *, const zapret_ipv6_fields *);
size_t zapret_write_ipv6_extension(uint8_t *, size_t, uint8_t, uint8_t, const uint8_t *, size_t);
void zapret_finish_ipv6(uint8_t *, size_t, const zapret_ipv6_fields *, size_t, uint8_t, bool);
size_t zapret_write_tcp_option(uint8_t *, size_t, uint8_t, const uint8_t *, size_t);
size_t zapret_write_tcp(uint8_t *, size_t, const zapret_tcp_fields *, size_t);
void zapret_write_udp(uint8_t *, const zapret_udp_fields *);
void zapret_write_icmp(uint8_t *, const zapret_icmp_fields *);
int zapret_finish_packet(uint8_t *, size_t *, const zapret_packet_finish *);
