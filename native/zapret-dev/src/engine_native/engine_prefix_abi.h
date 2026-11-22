/* Rust selects stages. All calls that can enter Lua run after it returns. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "runtime_log_windows.h"

struct blob_item;
typedef struct blob_item *(*zapret_publish_default_blob)(void *, const char *, const void *, size_t, size_t);
bool zapret_engine_default_blobs(void *, const uint8_t *, size_t, const char *const *, zapret_publish_default_blob);

typedef struct {
    bool (*open)(const char *);
    bool (*sandbox)(void);
    zapret_log_sink console, error;
} zapret_engine_activate_ops;
bool zapret_engine_activate_native(const char *, const bool *, const uint32_t *, uint32_t *, const zapret_engine_activate_ops *);

typedef struct { size_t maximum, reserve; } zapret_engine_blob_limit;
zapret_engine_blob_limit zapret_engine_blob_limits(int);
size_t zapret_engine_capture_capacity(void);
void zapret_engine_version(char *, size_t, bool, const char *, const char *, uint32_t, zapret_log_sink);
uint32_t zapret_engine_prefix_next(uint32_t, bool, int, uint8_t, zapret_log_sink);
uint32_t zapret_engine_parse_failure(bool);
uint32_t zapret_engine_activate_next(uint32_t, bool);
_Static_assert(sizeof(zapret_engine_blob_limit) == 2 * sizeof(size_t) &&
    sizeof(zapret_engine_activate_ops) == 4 * sizeof(void *),
    "Rust startup blob and capture ABI");
