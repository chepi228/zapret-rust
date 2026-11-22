/* MIT. The caller retains the stack slots and performs host actions. */
#pragma once
#include "windows_startup_params_abi.h"
#include "profile_flow_windows.h"

typedef struct {
    uint32_t phase;
    bool available;
    uint8_t first;
} zapret_native_prefix_cursor;

typedef struct {
    int *argc;
    char ***argv;
    unsigned *hashes;
    native_profile_flow *profiles;
    struct desync_profile_list **entry;
    struct desync_profile **profile;
} zapret_native_prefix_slots;

enum {
    NATIVE_PREFIX_STOP = 0, NATIVE_PREFIX_SERVICE = 1, NATIVE_PREFIX_PARAMS = 4,
    NATIVE_PREFIX_BANNER = 5, NATIVE_PREFIX_HELP = 6, NATIVE_PREFIX_BLOBS = 13,
    NATIVE_PREFIX_PROFILE = 14, NATIVE_PREFIX_EXIT = 19, NATIVE_PREFIX_READY = 20,
};

uint32_t zapret_native_main_prefix_step(zapret_native_prefix_cursor *, const zapret_native_prefix_slots *);

_Static_assert(sizeof(zapret_native_prefix_cursor) == 8 &&
    offsetof(zapret_native_prefix_cursor, available) == 4 && offsetof(zapret_native_prefix_cursor, first) == 5 &&
    sizeof(zapret_native_prefix_slots) == 6 * sizeof(void *) &&
    offsetof(zapret_native_prefix_slots, profiles) == 3 * sizeof(void *) &&
    offsetof(zapret_native_prefix_slots, entry) == 4 * sizeof(void *) &&
    offsetof(zapret_native_prefix_slots, profile) == 5 * sizeof(void *) &&
    sizeof(time_t) == 8 && sizeof(unsigned) == 4 && sizeof(int) == 4 && WF_COUNT == 16,
    "Rust startup phase storage");

_Static_assert(offsetof(struct params_s, wexp.we_wordc) == 0 &&
    sizeof(params.wexp.we_wordc) == sizeof(size_t) &&
    offsetof(struct params_s, wexp.we_wordv) == sizeof(size_t) &&
    offsetof(native_profile_flow, profiles) == 0 &&
    offsetof(native_profile_flow, templates) == sizeof(void *) &&
    offsetof(native_profile_flow, current) == 2 * sizeof(void *) &&
    offsetof(native_profile_flow, count) == 3 * sizeof(void *) &&
    offsetof(native_profile_flow, template_count) == 3 * sizeof(void *) + 4 &&
    offsetof(native_profile_flow, template) == 3 * sizeof(void *) + 9 &&
    offsetof(struct desync_profile_list, dp) == 0, "Rust startup config and profile slots");
