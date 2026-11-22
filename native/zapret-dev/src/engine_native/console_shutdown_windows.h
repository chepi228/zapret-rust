/* MIT. Native console and Lua actions use the result of a lock-free claim. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <signal.h>
#include <stdatomic.h>
#include <windows.h>
#include "runtime_log_windows.h"

typedef void (*zapret_console_signal)(int);
typedef struct {
    BOOL (WINAPI *console)(PHANDLER_ROUTINE, BOOL);
    uintptr_t (*signal)(int, zapret_console_signal);
} zapret_engine_console_ops;
typedef struct {
    const char *text;
    size_t length;
} zapret_shutdown_message;

_Static_assert(ATOMIC_INT_LOCK_FREE == 2 &&
    sizeof(_Atomic(sig_atomic_t)) == 4 && _Alignof(_Atomic(sig_atomic_t)) == 4 &&
    sizeof(zapret_shutdown_message) == 16, "Rust native shutdown ABI");
bool zapret_console_claim_shutdown(_Atomic(sig_atomic_t) *, int, zapret_shutdown_message *);
bool zapret_engine_console_register(zapret_console_signal, const zapret_engine_console_ops *,
    zapret_log_sink);
