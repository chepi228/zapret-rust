/* MIT. Reference C binding for the CLI comparisons. */
#pragma once
#include "runtime_log_windows.h"
#include <stdarg.h>

static inline int native_cli_stderr(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = vfprintf(stderr, format, args);
    va_end(args);
    return result;
}
