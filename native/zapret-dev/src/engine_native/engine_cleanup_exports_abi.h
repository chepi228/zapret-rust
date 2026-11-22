/* MIT. Release the borrowed Windows parameter slots after Lua shuts down. */
#pragma once
#include "windows_startup_params_abi.h"

void zapret_cleanup_closed_params(struct params_s *);
