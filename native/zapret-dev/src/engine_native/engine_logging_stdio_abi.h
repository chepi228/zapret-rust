/* MIT. Layout of the live parameters read by the Rust engine logger. */
#pragma once
#include <stddef.h>
#include "windows_startup_params_abi.h"
#include "native_logging_stdio_abi.h"
#include "syslog.h"

_Static_assert(LOG_TARGET_CONSOLE == 0 && LOG_TARGET_FILE == 1 && LOG_TARGET_SYSLOG == 2,
    "Rust engine logging parameter slots");
_Static_assert(LOG_ERR == 3 && LOG_DEBUG == 7, "Windows logging entry priorities");
