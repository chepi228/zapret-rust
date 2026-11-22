/* MIT. Shared startup filter ABI. */
#pragma once
#include <stddef.h>
#include "filter.h"

_Static_assert(sizeof(port_filter) == 6 && offsetof(port_filter, neg) == 4 &&
    sizeof(icmp_filter) == 4 && offsetof(icmp_filter, code_valid) == 3 && sizeof(ipp_filter) == 2 &&
    offsetof(struct packet_pos, pos) == 4 && sizeof(struct packet_range) == 20 &&
    offsetof(struct packet_range, upper_cutoff) == 16 &&
    FLTMODE_SKIP == 0 && FLTMODE_ANY == 1 && FLTMODE_FILTER == 2, "Rust startup filter ABI");
_Static_assert(sizeof(struct cidr4) == 8 && _Alignof(struct cidr4) == 4 &&
    offsetof(struct cidr4, addr) == 0 && offsetof(struct cidr4, preflen) == 4 &&
    sizeof(struct cidr6) == 18 && _Alignof(struct cidr6) == 2 &&
    offsetof(struct cidr6, addr) == 0 && offsetof(struct cidr6, preflen) == 16,
    "Rust CIDR ABI");

bool zapret_pf_parse(const char *, port_filter *);
bool zapret_pf_match(uint16_t, const port_filter *);
bool zapret_icf_parse(const char *, icmp_filter *);
bool zapret_icf_match(uint8_t, uint8_t, const icmp_filter *);
bool zapret_ipp_parse(const char *, ipp_filter *);
bool zapret_ipp_match(uint8_t, const ipp_filter *);
bool zapret_packet_range_parse(const char *, struct packet_range *);
bool zapret_parse_cidr4(char *, struct cidr4 *);
bool zapret_parse_cidr6(char *, struct cidr6 *);
void zapret_str_cidr4(char *, size_t, const struct cidr4 *);
void zapret_str_cidr6(char *, size_t, const struct cidr6 *);
bool zapret_parse_l7_list(const char *, uint64_t *);
bool zapret_parse_payload_list(const char *, uint64_t *);
