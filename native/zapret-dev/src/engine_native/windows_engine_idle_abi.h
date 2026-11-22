/* MIT. Windows idle entry points and the pinned timer and sleep ABI. */
#pragma once
#include "windows_startup_params_abi.h"
#include "engine_loop_windows.h"
#include <pthread_time.h>

_Static_assert(sizeof(sig_atomic_t) == 4 && sizeof(_Atomic(sig_atomic_t)) == 4 &&
    _Alignof(_Atomic(sig_atomic_t)) == 4, "Rust engine idle quit ABI");
_Static_assert(WINPTHREADS_TIME_BITS == 64 && sizeof(time_t) == 8 && sizeof(long) == 4 &&
    sizeof(struct timespec) == 16 && offsetof(struct timespec, tv_nsec) == 8 &&
    sizeof(struct _timespec64) == 16 && offsetof(struct _timespec64, tv_nsec) == 8,
    "Rust engine idle sleep ABI");
_Static_assert(sizeof(zapret_loop_timers) == 5 * sizeof(void *) &&
    offsetof(zapret_loop_timers, run) == 4 * sizeof(void *),
    "Rust engine idle timer vtable ABI");

bool loop_quitting(void);
void loop_sleep_ms(uint64_t);
void loop_prepare(void);
void NoInterceptLoop(void);
