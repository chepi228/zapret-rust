/* MIT. Opaque Rust domain and IP prefix stores for the pinned engine. */
#pragma once
#include <stddef.h>
#include <stdint.h>

struct hostlist_pool;
struct zapret_ip_pool;

int zapret_host_add(struct hostlist_pool **, const unsigned char *, size_t, uint32_t);
typedef void (*zapret_host_trace)(const char *, const char *, int);
int zapret_host_match(const struct hostlist_pool *, const char *, int, zapret_host_trace);
int zapret_host_has(const struct hostlist_pool *, const char *);
void zapret_host_destroy(struct hostlist_pool **);

typedef struct {
    unsigned char address[16];
    unsigned char bits;
} zapret_prefix_info;
_Static_assert(sizeof(zapret_prefix_info) == 17, "Rust prefix descriptor ABI");

int zapret_ip_add(struct zapret_ip_pool **, const unsigned char *, uint8_t, uint8_t);
int zapret_ip_check(const struct zapret_ip_pool *, const unsigned char *, uint8_t);
int zapret_ip_next(const struct zapret_ip_pool *, const unsigned char *, zapret_prefix_info *);
void zapret_ip_destroy(struct zapret_ip_pool **);
