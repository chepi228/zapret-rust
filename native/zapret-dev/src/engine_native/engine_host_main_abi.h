/* MIT. Rust owns the options and phase state in the native entry frame. */
#pragma once
#include "engine_main_bindings_abi.h"
#include "engine_main_prefix_abi.h"

typedef struct {
    zapret_engine_main_options options;
    unsigned hashes[WF_COUNT];
    native_profile_flow profiles;
    struct desync_profile_list *entry;
    struct desync_profile *profile;
    zapret_capture_cli capture;
    zapret_native_prefix_cursor prefix;
    zapret_native_finish_state finish;
    char **argv;
    int argc, exit_code;
    bool parsed;
} zapret_native_main_state;

typedef struct {
    size_t (*option_count)(void);
    char *(*environment)(const char *);
    bool (*read_blob)(const char *, size_t, size_t);
    uint32_t (*prefix)(zapret_native_prefix_cursor *, const zapret_native_prefix_slots *);
    zapret_native_finish_ops finish;
} zapret_native_main_ops;

enum { MAIN_ARGUMENT_HELP = 21, MAIN_ARGUMENT_EXIT = 22, MAIN_FINISH_BASE = 32 };

_Static_assert(sizeof(zapret_native_main_state) == (sizeof(void *) == 4 ? 520 : 616) &&
    _Alignof(zapret_native_main_state) == 8 &&
    offsetof(zapret_native_main_state, prefix) == (sizeof(void *) == 4 ? 476 : 560) &&
    offsetof(zapret_native_main_state, finish) == (sizeof(void *) == 4 ? 484 : 568) &&
    offsetof(zapret_native_main_state, argc) == (sizeof(void *) == 4 ? 508 : 600) &&
    sizeof(zapret_native_main_ops) == 10 * sizeof(void *) &&
    offsetof(zapret_native_main_ops, finish) == 4 * sizeof(void *) && NATIVE_PREFIX_READY == 20,
    "Rust main state and native operation ABI");

void zapret_native_main_begin(zapret_native_main_state *, int, char **);
uint32_t zapret_native_main_advance(zapret_native_main_state *, struct params_s *, const zapret_native_main_ops *);
