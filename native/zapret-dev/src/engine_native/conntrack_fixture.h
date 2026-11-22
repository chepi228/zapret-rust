/* MIT. In-memory conformance only; no WinDivert or network operations. */
#pragma once
#include "conntrack.h"
#include "params.h"
#include "helpers.h"
#include "lua.h"
#include <lauxlib.h>

int fixture_clock_gettime(clockid_t, struct timespec *);
