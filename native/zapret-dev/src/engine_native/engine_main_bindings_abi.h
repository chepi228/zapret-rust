/* MIT. Slots for nonterminating main setup and finish operations. */
#pragma once

typedef struct {
    zapret_engine_finish flow;
    zapret_engine_finish_feedback feedback;
    HANDLE mutex;
} zapret_native_finish_state;

typedef struct {
    uint32_t (*profile)(native_profile_flow *);
    void (*arguments)(struct params_s *);
    bool (*validate)(unsigned, unsigned);
    uint32_t (*prepare)(struct params_s *, bool);
    void (*release)(HANDLE *);
    void (*close_stdio)(void);
} zapret_native_finish_ops;

_Static_assert(sizeof(struct packet_range) == 20 && _Alignof(struct packet_range) == 4 &&
    sizeof(zapret_capture_cli) == 11 * sizeof(void *) &&
    offsetof(zapret_capture_cli, hashes) == 10 * sizeof(void *) &&
    sizeof(zapret_native_finish_state) == 16 + sizeof(void *) &&
    sizeof(zapret_native_finish_ops) == 6 * sizeof(void *) &&
    offsetof(zapret_native_finish_state, feedback) == 8 &&
    offsetof(zapret_native_finish_state, mutex) == 16 &&
    FINISH_PROFILE == 1 && FINISH_ARGUMENTS == 2 && FINISH_VALIDATE == 3 &&
    FINISH_LIFECYCLE == 5 && FINISH_MUTEX == 8 && FINISH_STDIO == 9,
    "Rust main storage and finish ABI");

void zapret_native_main_bind(zapret_engine_main_options *, unsigned *, native_profile_flow *,
    struct desync_profile_list **, struct desync_profile **, zapret_capture_cli *, native_engine_cli *);
uint32_t zapret_native_finish_advance(zapret_native_finish_state *, struct params_s *,
    native_profile_flow *, const bool *, int *, char ***, const zapret_native_finish_ops *);
