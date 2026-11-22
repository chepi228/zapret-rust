/* MIT. Bind live engine configuration to the Rust logging entries. */
#include "native_logging_stdio_abi.h"

_Static_assert(sizeof(params.debug_target) == sizeof(int32_t) && LOG_TARGET_CONSOLE == 0 &&
    LOG_TARGET_FILE == 1 && LOG_TARGET_SYSLOG == 2, "Rust logging targets");

static void native_file_log(int32_t priority, const char *line)
{
    (void)priority;
    zapret_crt_log_line(params.debug_logfile, line, NULL);
}

static const zapret_log_route native_log_route = {
    &params.debug, (const int32_t *)&params.debug_target,
    zapret_crt_log_buffered, native_file_log, zapret_system_syslog,
};

#define DLOG_VA(format, priority, duplicate, args) \
    zapret_crt_log_dispatch((format), (priority), (duplicate), (args), &native_log_route, NULL)
#define LOG_APPEND(path, format, args) zapret_crt_log_path((path), (format), (args), true, NULL)
