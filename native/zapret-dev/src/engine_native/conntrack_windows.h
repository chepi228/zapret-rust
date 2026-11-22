/* MIT. Rust connection indexing and accounting. Lua objects stay in C. */
#pragma once
#include <stddef.h>
#include <stdint.h>

struct zapret_conntrack_index;
typedef struct {
    const unsigned char *tcp;
    size_t tcp_size;
    size_t payload_size;
    uint32_t ipv6_flow;
    uint32_t ipv6;
} zapret_conntrack_packet;

_Static_assert(sizeof(t_conn) == 40 && offsetof(t_conn, l4proto) == 37, "Rust connection key ABI");
_Static_assert(sizeof(t_ctrack_position) == 64 && offsetof(t_ctrack_position, scale) == 56 &&
    offsetof(t_ctrack_position, seq_last) == 40 && offsetof(t_ctrack_position, winsize_calc) == 52,
    "Rust connection position ABI");
_Static_assert(sizeof(t_ctrack_positions) == 160 &&
    offsetof(t_ctrack_positions, client) == 24 && offsetof(t_ctrack_positions, server) == 88 &&
    offsetof(t_ctrack_positions, ipproto) == 152, "Rust connection positions ABI");
_Static_assert(sizeof(zapret_conntrack_packet) == 3 * sizeof(void *) + 8 &&
    offsetof(zapret_conntrack_packet, ipv6_flow) == 3 * sizeof(void *), "Rust packet descriptor ABI");
_Static_assert(sizeof(t_reassemble) == 4 * sizeof(void *) && offsetof(t_reassemble, seq) == sizeof(void *) &&
    offsetof(t_reassemble, size) == 2 * sizeof(void *) && offsetof(t_reassemble, size_present) == 3 * sizeof(void *),
    "Rust reassembly ABI");

int zapret_conntrack_key(t_conn *, const unsigned char *, const unsigned char *,
    const unsigned char *, const unsigned char *, int);
int zapret_conntrack_insert(struct zapret_conntrack_index **, const t_conn *, void *);
void *zapret_conntrack_find(const struct zapret_conntrack_index *, const t_conn *, int *);
void *zapret_conntrack_after(const struct zapret_conntrack_index *, uint64_t *);
void *zapret_conntrack_remove(struct zapret_conntrack_index **, const t_conn *);
int zapret_conntrack_start(const unsigned char *, int);
int zapret_conntrack_update(t_ctrack_positions *, const zapret_conntrack_packet *, int, int);
int zapret_conntrack_expired(const void *, const t_ctrack_positions *, uint8_t, int, int64_t);
