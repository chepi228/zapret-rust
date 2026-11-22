/* MIT. Read-only application startup and diagnostic entry points. */
#pragma once
#include "params.h"
#include <fcntl.h>

_Static_assert(offsetof(struct params_s, debug) == 4252 &&
    offsetof(struct params_s, hostlists) == 12624 &&
    offsetof(struct params_s, ipsets) == 12632 &&
    offsetof(struct params_s, blobs.lh_first) == 12640 &&
    O_RDONLY == 0, "Rust startup and diagnostic slots");

bool test_list_files(void);
void BlobDebug(void);
void LuaDesyncDebug(const struct desync_profile *, const char *);
_Noreturn void exithelp(void);
