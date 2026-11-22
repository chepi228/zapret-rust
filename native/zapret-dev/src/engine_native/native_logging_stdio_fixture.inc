/* MIT. Keep native operation tracing for the complete logging entry oracle. */
#include "native_logging_stdio_abi.h"

static FILE *model_console_stream(unsigned int descriptor)
{
    CHECK(descriptor == 1 || descriptor == 2);
    return descriptor == 2 ? stderr : stdout;
}

static const zapret_log_io model_log_io = {
    model_console_stream, model_fopen, model_vfprintf, model_fprintf, fprint_localtime, model_fclose,
};

static void fixture_file_log(int32_t priority, const char *line)
{
    (void)priority;
    zapret_crt_log_line(params.debug_logfile, line, &model_log_io);
}

static void fixture_event_log(int32_t priority, const char *line)
{
    model_syslog(priority, "%s", line);
}

static int DLOG_FILE_VA(FILE *file, const char *format, va_list args)
{
    return zapret_crt_log_file(file, format, args, &model_log_io);
}

static int DLOG_CON_VA(const char *format, int priority, va_list args)
{
    return zapret_crt_log_console(format, priority, args, &model_log_io);
}

static int DLOG_FILENAME_VA(const char *path, const char *format, va_list args)
{
    return zapret_crt_log_path(path, format, args, false, &model_log_io);
}

static int LOG_APPEND(const char *path, const char *format, va_list args)
{
    return zapret_crt_log_path(path, format, args, true, &model_log_io);
}

static int DLOG_VA(const char *format, int priority, bool duplicate, va_list args)
{
    const zapret_log_route route = {
        &params.debug, &params.debug_target, log_buffered, fixture_file_log, fixture_event_log,
    };
    return zapret_crt_log_dispatch(format, priority, duplicate, args, &route, &model_log_io);
}
