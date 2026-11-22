/* MIT. Keep the variadic log entrances and Lua shutdown on the native frame. */
#include "params.h"
#include "syslog.h"
#include "native_logging_entry_abi.h"
#include "native_logging_stdio_windows.inc"

int DLOG(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = DLOG_VA(format, LOG_DEBUG, false, args);
    va_end(args);
    return result;
}

int DLOG_CONDUP(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = DLOG_VA(format, LOG_DEBUG, true, args);
    va_end(args);
    return result;
}

int DLOG_ERR(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = DLOG_VA(format, LOG_ERR, true, args);
    va_end(args);
    return result;
}

int HOSTLIST_DEBUGLOG_APPEND(const char *format, ...)
{
    if (!zapret_log_path_enabled(params.hostlist_auto_debuglog)) return 0;
    va_list args;
    va_start(args, format);
    int result = LOG_APPEND(params.hostlist_auto_debuglog, format, args);
    va_end(args);
    return result;
}

#undef DLOG_VA
#undef LOG_APPEND
#include "engine_cleanup_native_windows.inc"
