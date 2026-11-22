/* MIT. Cache conformance fixtures share only these public observations. */
#pragma once
#include "pools.h"
#include <stdarg.h>

typedef struct {
    const char *name;
    int counter;
    time_t expires;
} cache_fail_view;
int cache_oracle_printf(const char *, ...);
