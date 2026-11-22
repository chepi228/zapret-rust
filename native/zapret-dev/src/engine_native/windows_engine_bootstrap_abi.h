/* MIT. Pinned parameter slots and callbacks for the Rust bootstrap entry. */
#pragma once

#include "engine_bootstrap_local_abi.h"
#include <stddef.h>

int win_main(void);
bool native_boot_network(void);
int native_boot_capture(void);
