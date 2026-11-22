/* MIT. List input is parsed in Rust before each C pool insertion. */
#pragma once
#include <stddef.h>
#include <stdint.h>

typedef int (*zapret_list_insert)(void *, const unsigned char *, size_t, uint32_t);
typedef struct {
    uint64_t count;
    uint64_t decompressed_size;
    uint32_t compressed;
    uint32_t error;
} zapret_list_info;
_Static_assert(sizeof(zapret_list_info) == 24, "Rust list result ABI");

int zapret_list_load(const char *, int, zapret_list_insert, void *, zapret_list_info *);
int zapret_list_item(unsigned char *, size_t, int, zapret_list_insert, void *);
