/* MIT. Windows main state fields consumed by the Rust lifecycle bindings. */
#pragma once

#include "windows_startup_params_abi.h"

_Static_assert(sizeof(time_t) == 8, "Rust main lifecycle clock ABI");

uint32_t zapret_native_lifecycle_prepare(struct params_s *, bool);
void zapret_native_lifecycle_release_mutex(HANDLE *);
