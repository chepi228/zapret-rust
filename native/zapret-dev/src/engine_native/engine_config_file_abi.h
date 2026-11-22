/* MIT. A local config read returns before the native caller can terminate. */
#pragma once
#include "params.h"

_Static_assert(MAX_CONFIG_FILE_SIZE == 16384 && offsetof(struct params_s, wexp) == 0 &&
    sizeof(wordexp_t) == 24 && offsetof(wordexp_t, we_wordc) == 0 &&
    offsetof(wordexp_t, we_wordv) == 8 && offsetof(wordexp_t, we_offs) == 16,
    "Rust config word expansion storage");

bool zapret_config_from_file(const char *filename);
