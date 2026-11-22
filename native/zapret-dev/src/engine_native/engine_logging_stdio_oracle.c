/* MIT. Exercise both logging bindings over private Win32 files and UCRT streams. */
#include "params.h"
#include "syslog.h"
#include "native_logging_entry_abi.h"
#include "engine_logging_stdio_abi.h"
#undef main

struct params_s params;

#include "native_logging_stdio_windows.inc"

static int reference_dispatch(int priority, bool duplicate, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = DLOG_VA(format, priority, duplicate, args);
    va_end(args);
    return result;
}

static int reference_append(const char *format, ...)
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

enum fixture_case {
    FILE_LOG, FILE_DUPLICATE, LATE_FILE, DISABLE_AFTER_CONSOLE, FRAGMENT,
    APPEND, APPEND_DISABLED, APPEND_MISSING, APPEND_LOCKED, FILE_MISSING,
    FILE_DIRECTORY, CONSOLE_DUPLICATE, MOCK_EVENT, UNKNOWN_TARGET, MIXED_DOUBLES, CASES,
};

static const char debug_path[] = "движок-é-中.log";
static const char late_path[] = "поздний-é-中.log";
static const char host_path[] = "хостлист-é-中.log";
static const WCHAR wide_debug[] = L"движок-é-中.log";
static const WCHAR wide_late[] = L"поздний-é-中.log";
static const WCHAR wide_host[] = L"хостлист-é-中.log";
static const WCHAR wide_console[] = L"fixture-console.bin";
static const char timestamp[] = "07.01.2026 01:02:03";
static const char seeded_line[] = "seed\r\n";
static const char missing_path[] = "unused-log-fixture-directory/failure.log";

#define MIXED_FORMAT "%.*s|%lld|%#x|%.4f|%zu|%ls|%%"
#define MIXED_ARGS 8, "данные", -800000000000LL, 0xabcdefU, 3.125, (size_t)16000, L"wide"
static const char expected_body[] = "данн|-800000000000|0xabcdef|3.1250|16000|wide|%";
#define DOUBLES_FORMAT "%.2f|%lld|%.3f|%.*s\n"
#define DOUBLES_ARGS 1.25, -800000000000LL, -3.125, 3, "abcdef"
static const char expected_doubles_body[] = "1.25|-800000000000|-3.125|abc\r\n";

struct observations {
    int result, error, open_error;
    DWORD win32_error, open_win32_error;
    unsigned opens, closes, timestamps, stdout_writes, stderr_writes, events;
    char debug[512], late[512], host[512], console[512], event[512];
};

static enum fixture_case scenario;
static struct observations *active;
static FILE *console_file, *opened_log;

#define CHECK(value) do { \
    if (!(value)) { \
        fprintf(stderr, "FAIL engine logging case=%u line=%d: %s\n", scenario, __LINE__, #value); \
        exit(1); \
    } \
} while (0)

FILE *__real_wf_fopen(const char *, const char *);
FILE *__wrap_wf_fopen(const char *path, const char *mode)
{
    if (!active) return __real_wf_fopen(path, mode);
    bool host = scenario >= APPEND && scenario <= APPEND_LOCKED;
    CHECK(path == (host ? params.hostlist_auto_debuglog : params.debug_logfile));
    CHECK(!opened_log && !strcmp(mode, "at"));
    ++active->opens;
    opened_log = __real_wf_fopen(path, mode);
    if (!opened_log) {
        // Buffered dispatch can touch the thread's error state after the file callback returns.
        active->open_win32_error = GetLastError();
        active->open_error = errno;
    }
    return opened_log;
}

int __real_fclose(FILE *);
int __wrap_fclose(FILE *file)
{
    if (active) {
        CHECK(file == opened_log);
        ++active->closes;
        opened_log = NULL;
    }
    return __real_fclose(file);
}

int __real___mingw_vfprintf(FILE *, const char *, va_list);
int __wrap___mingw_vfprintf(FILE *file, const char *format, va_list args)
{
    if (!active || (file != stdout && file != stderr)) return __real___mingw_vfprintf(file, format, args);
    if (file == stdout) ++active->stdout_writes;
    else ++active->stderr_writes;
    int result = __real___mingw_vfprintf(console_file, format, args);
    if (scenario == LATE_FILE) {
        params.debug = true;
        params.debug_target = LOG_TARGET_FILE;
        strcpy(params.debug_logfile, late_path);
    } else if (scenario == DISABLE_AFTER_CONSOLE) {
        params.debug = false;
    }
    return result;
}

int __wrap_zapret_crt_fprint_localtime(FILE *file)
{
    CHECK(active && file == opened_log);
    ++active->timestamps;
    return fprintf(file, "%s", timestamp);
}

void __wrap_zapret_system_syslog(int priority, const char *line)
{
    CHECK(active && scenario == MOCK_EVENT && priority == LOG_DEBUG);
    CHECK(strlen(line) < sizeof(active->event));
    ++active->events;
    strcpy(active->event, line);
}

static void read_private_file(const WCHAR *path, char data[512])
{
    HANDLE file = CreateFileW(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        CHECK(GetLastError() == ERROR_FILE_NOT_FOUND);
        return;
    }
    DWORD read = 0;
    CHECK(ReadFile(file, data, 511, &read, NULL) && read < 511 && CloseHandle(file));
    data[read] = 0;
    CHECK(DeleteFileW(path));
}

static int invoke(bool direct)
{
    switch (scenario) {
        case APPEND_DISABLED:
            return direct ? HOSTLIST_DEBUGLOG_APPEND(NULL) : reference_append(NULL);
        case APPEND: case APPEND_MISSING: case APPEND_LOCKED:
            return direct ? HOSTLIST_DEBUGLOG_APPEND(MIXED_FORMAT, MIXED_ARGS) :
                reference_append(MIXED_FORMAT, MIXED_ARGS);
        case FILE_DUPLICATE: case LATE_FILE: case CONSOLE_DUPLICATE:
            return direct ? DLOG_CONDUP(MIXED_FORMAT "\n", MIXED_ARGS) :
                reference_dispatch(LOG_DEBUG, true, MIXED_FORMAT "\n", MIXED_ARGS);
        case DISABLE_AFTER_CONSOLE:
            return direct ? DLOG_ERR(MIXED_FORMAT "\n", MIXED_ARGS) :
                reference_dispatch(LOG_ERR, true, MIXED_FORMAT "\n", MIXED_ARGS);
        case FRAGMENT: {
            int before = direct ? DLOG("%s", "first %s literal ") :
                reference_dispatch(LOG_DEBUG, false, "%s", "first %s literal ");
            CHECK(before == 1 && !active->opens);
            strcpy(params.debug_logfile, late_path);
            return direct ? DLOG("%s\n", "second") : reference_dispatch(LOG_DEBUG, false, "%s\n", "second");
        }
        case MIXED_DOUBLES:
            return direct ? DLOG(DOUBLES_FORMAT, DOUBLES_ARGS) :
                reference_dispatch(LOG_DEBUG, false, DOUBLES_FORMAT, DOUBLES_ARGS);
        default:
            return direct ? DLOG(MIXED_FORMAT "\n", MIXED_ARGS) :
                reference_dispatch(LOG_DEBUG, false, MIXED_FORMAT "\n", MIXED_ARGS);
    }
}

static void run(bool direct, struct observations *result)
{
    memset(&params, 0, sizeof(params));
    params.debug = scenario != LATE_FILE;
    params.debug_target = LOG_TARGET_FILE;
    strcpy(params.debug_logfile, debug_path);
    strcpy(params.hostlist_auto_debuglog, host_path);
    HANDLE lock = INVALID_HANDLE_VALUE;
    switch (scenario) {
        case LATE_FILE: case CONSOLE_DUPLICATE:
            params.debug_target = LOG_TARGET_CONSOLE;
            break;
        case APPEND_DISABLED: params.hostlist_auto_debuglog[0] = 0; break;
        case APPEND_MISSING: strcpy(params.hostlist_auto_debuglog, missing_path); break;
        case APPEND: case APPEND_LOCKED: {
            HANDLE file = CreateFileW(wide_host, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
            CHECK(file != INVALID_HANDLE_VALUE);
            DWORD count = 0;
            CHECK(WriteFile(file, seeded_line, sizeof(seeded_line) - 1, &count, NULL) && count == sizeof(seeded_line) - 1);
            if (scenario == APPEND_LOCKED) lock = file;
            else CHECK(CloseHandle(file));
            break;
        }
        case FILE_MISSING: strcpy(params.debug_logfile, missing_path); break;
        case FILE_DIRECTORY: strcpy(params.debug_logfile, "."); break;
        case MOCK_EVENT: params.debug_target = LOG_TARGET_SYSLOG; break;
        case UNKNOWN_TARGET: params.debug_target = (enum log_target)-1; break;
        default: break;
    }

    console_file = fopen("fixture-console.bin", "w+b");
    CHECK(console_file);
    active = result;
    errno = EACCES;
    SetLastError(ERROR_BUSY);
    result->result = invoke(direct);
    result->win32_error = GetLastError();
    result->error = errno;
    CHECK(!opened_log);
    active = NULL;
    CHECK(!fclose(console_file));
    if (lock != INVALID_HANDLE_VALUE) CHECK(CloseHandle(lock));
    read_private_file(wide_debug, result->debug);
    read_private_file(wide_late, result->late);
    read_private_file(wide_host, result->host);
    read_private_file(wide_console, result->console);
}

static void check_expected(const struct observations *result)
{
    char log[512], console[512], host[512];
    snprintf(log, sizeof(log), "%s\r\n", expected_body);
    snprintf(console, sizeof(console), "%s\n", expected_body);
    snprintf(host, sizeof(host), "%s%s : %s\r\n", seeded_line, timestamp, expected_body);
    switch (scenario) {
        case FILE_LOG: case FILE_DUPLICATE:
            CHECK(result->result == 1 && result->opens == 1 && result->closes == 1);
            CHECK(!strcmp(result->debug, log));
            if (scenario == FILE_DUPLICATE) CHECK(result->stdout_writes == 1 && !strcmp(result->console, console));
            else CHECK(!result->stdout_writes && !*result->console);
            break;
        case LATE_FILE:
            CHECK(result->result == 1 && result->stdout_writes == 1 && !strcmp(result->console, console));
            CHECK(result->opens == 1 && result->closes == 1 && !*result->debug && !strcmp(result->late, log));
            break;
        case DISABLE_AFTER_CONSOLE:
            CHECK(!result->result && !result->opens && result->stderr_writes == 1 && !strcmp(result->console, console));
            break;
        case FRAGMENT:
            CHECK(result->result == 1 && result->opens == 1 && result->closes == 1);
            CHECK(!*result->debug && !strcmp(result->late, "first %s literal second\r\n"));
            break;
        case APPEND:
            CHECK(result->result == strlen(expected_body) && result->opens == 1 && result->closes == 1);
            CHECK(result->timestamps == 1 && !strcmp(result->host, host));
            break;
        case APPEND_DISABLED:
            CHECK(!result->result && !result->opens && !result->timestamps && !*result->host);
            CHECK(result->error == EACCES && result->win32_error == ERROR_BUSY);
            break;
        case APPEND_MISSING: case FILE_MISSING:
            CHECK(result->result == (scenario == APPEND_MISSING ? -1 : 1));
            CHECK(result->opens == 1 && !result->closes && !result->timestamps);
            CHECK(result->open_error == ENOENT && result->open_win32_error == ERROR_PATH_NOT_FOUND);
            if (scenario == APPEND_MISSING)
                CHECK(result->error == ENOENT && result->win32_error == ERROR_PATH_NOT_FOUND);
            break;
        case APPEND_LOCKED:
            CHECK(result->result == -1 && result->opens == 1 && !result->closes && !result->timestamps);
            CHECK(result->error == EACCES && result->win32_error == ERROR_SHARING_VIOLATION);
            CHECK(!strcmp(result->host, seeded_line));
            break;
        case FILE_DIRECTORY:
            CHECK(result->result == 1 && result->opens == 1 && !result->closes);
            CHECK(result->open_error == EACCES && result->open_win32_error == ERROR_ACCESS_DENIED);
            break;
        case CONSOLE_DUPLICATE:
            CHECK(result->result == strlen(console) && !result->opens);
            CHECK(result->stdout_writes == 1 && !strcmp(result->console, console));
            break;
        case MOCK_EVENT:
            CHECK(result->result == 1 && !result->opens && result->events == 1 && !strcmp(result->event, console));
            break;
        case UNKNOWN_TARGET:
            CHECK(!result->result && !result->opens && !result->events && !*result->console);
            break;
        case MIXED_DOUBLES:
            CHECK(result->result == 1 && result->opens == 1 && result->closes == 1);
            CHECK(!strcmp(result->debug, expected_doubles_body));
            break;
        default: CHECK(false); break;
    }
}

int main(void)
{
    for (scenario = FILE_LOG; scenario < CASES; ++scenario) {
        struct observations previous = {0}, direct = {0};
        run(false, &previous);
        run(true, &direct);
        CHECK(previous.result == direct.result && previous.error == direct.error && previous.win32_error == direct.win32_error);
        CHECK(previous.open_error == direct.open_error && previous.open_win32_error == direct.open_win32_error);
        CHECK(previous.opens == direct.opens && previous.closes == direct.closes && previous.timestamps == direct.timestamps);
        CHECK(previous.stdout_writes == direct.stdout_writes && previous.stderr_writes == direct.stderr_writes && previous.events == direct.events);
        CHECK(!strcmp(previous.debug, direct.debug) && !strcmp(previous.late, direct.late) &&
            !strcmp(previous.host, direct.host) && !strcmp(previous.console, direct.console) && !strcmp(previous.event, direct.event));
        check_expected(&direct);
    }
    printf("PASS engine_logging_stdio_direct cases=%u unicode=1 cursor_reused=1 deferred_route_and_path=1 "
        "disabled_untouched=1 timestamp_bytes=1 errno_and_win32=1 real_file_ownership=1 mock_event=1 "
        "mixed_variadic_arguments=1\n", CASES);
    return 0;
}
