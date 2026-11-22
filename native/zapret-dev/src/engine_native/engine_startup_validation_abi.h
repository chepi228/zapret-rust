/* MIT. Live Windows slots observed by the Rust startup validation entry. */
#pragma once
#include "windows_startup_params_abi.h"
#include "engine_profile_exports_abi.h"

_Static_assert(LOG_TARGET_FILE == 1 && offsetof(struct desync_profile_list, dp) == 0 &&
    offsetof(struct zapret_list_file, filename) == 0, "Rust startup profile traversal");

bool native_startup_validate(unsigned profile_count, unsigned template_count);
