/* MIT. Identity, UCRT calendar parity and private event-log handles. */
#include "win_platform.h"
#include "sys/utsname.h"
#include <string.h>
#include <wchar.h>
#include <stdatomic.h>
#undef main

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL system diagnostics line=%d: %s\n", __LINE__, #condition); ExitProcess(1); } \
} while (0)
static unsigned mode;
static LONG WINAPI version_query(OSVERSIONINFOW *version)
{
    CHECK(version->dwOSVersionInfoSize == sizeof(*version));
    if (mode == 1 || mode == 2) return -1;
    version->dwMajorVersion = mode == 9 ? UINT32_MAX : 10;
    version->dwMinorVersion = mode == 9 ? UINT32_MAX : 0;
    version->dwBuildNumber = mode == 9 ? UINT32_MAX : 26200;
    return 0;
}
static BOOL WINAPI computer_name(WCHAR *output, DWORD *length)
{
    CHECK(*length == 256);
    if (mode == 3) return FALSE;
    if (mode == 4) { output[0] = 0xd800; output[1] = 0; *length = 1; return TRUE; }
    if (mode == 5) { for (unsigned index = 0; index < 100; ++index) output[index] = 0x4e00; output[100] = 0; *length = 100; return TRUE; }
    const WCHAR *name = mode == 8 ? L"Компьютер" : L"DESKTOP-test";
    wcscpy(output, name);
    *length = (DWORD)wcslen(name);
    return TRUE;
}
static void WINAPI architecture(SYSTEM_INFO *system)
{
    memset(system, 0, sizeof(*system));
    system->wProcessorArchitecture = mode == 6 ? PROCESSOR_ARCHITECTURE_UNKNOWN : mode == 7 ? PROCESSOR_ARCHITECTURE_ARM64 : PROCESSOR_ARCHITECTURE_AMD64;
}
static HMODULE WINAPI module(LPCWSTR name) { (void)name; return (HMODULE)(uintptr_t)41; }
static FARPROC WINAPI symbol(HMODULE handle, LPCSTR name)
{
    CHECK(handle == (HMODULE)(uintptr_t)41 && !strcmp(name, "RtlGetVersion"));
    return mode == 1 ? NULL : (FARPROC)version_query;
}
#define uname reference_uname
#define GetModuleHandleW module
#define GetProcAddress symbol
#define GetComputerNameW computer_name
#define GetNativeSystemInfo architecture
#include "system_identity_reference.inc"
#undef uname
#undef GetModuleHandleW
#undef GetProcAddress
#undef GetComputerNameW
#undef GetNativeSystemInfo
#define uname actual_reference_uname
#include "system_identity_reference.inc"
#undef uname
static unsigned check_calendar(void)
{
    const struct {
        errno_t (*native)(struct tm *, const time_t *);
        struct tm *(*adapter)(const time_t *, struct tm *);
    } functions[] = {{localtime_s, zapret_localtime_r}, {gmtime_s, zapret_gmtime_r}};
    const time_t values[] = { INT64_MIN, -1, 0, 1, 1700000000, 32535215999LL, INT64_MAX };
    unsigned cases = 0;
    for (size_t function = 0; function < sizeof(functions) / sizeof(*functions); ++function) {
        for (size_t index = 0; index < sizeof(values) / sizeof(*values); ++index) {
            for (unsigned missing = 0; missing < 4; ++missing) {
                struct { uint8_t before[8]; struct tm value; uint8_t after[8]; } reference, actual;
                memset(&reference, 0x69, sizeof(reference));
                memcpy(&actual, &reference, sizeof(actual));
                const time_t *source = missing & 1 ? NULL : &values[index];
                struct tm *legacy_output = missing & 2 ? NULL : &reference.value;
                struct tm *actual_output = missing & 2 ? NULL : &actual.value;
                errno = EACCES;
                bool success = false;
                if (!source || !legacy_output) errno = EINVAL;
                else success = functions[function].native(legacy_output, source) == 0;
                int error = errno;
                errno = EACCES;
                struct tm *result = functions[function].adapter(source, actual_output);
                CHECK(result == (success ? actual_output : NULL));
                CHECK(errno == error);
                CHECK(!memcmp(&actual, &reference, sizeof(actual)));
                ++cases;
            }
        }
    }
    return cases;
}

typedef struct {
    LONG (WINAPI *version)(OSVERSIONINFOW *);
    BOOL (WINAPI *name)(WCHAR *, DWORD *);
    void (WINAPI *architecture)(SYSTEM_INFO *);
} identity_ops;
int zapret_system_uname(struct utsname *, const identity_ops *);
typedef struct {
    HANDLE (*register_source)(const WCHAR *);
    BOOL (*report)(HANDLE, WORD, const WCHAR *);
    BOOL (*release)(HANDLE);
    void (*debug)(const WCHAR *);
} event_ops;
bool zapret_system_openlog(const char *, const event_ops *);
void zapret_system_syslog(int, const char *);
void zapret_system_closelog(void);
int zapret_crt_fprint_localtime(FILE *);

static void check_timestamp_stream(void)
{
    WCHAR directory[MAX_PATH], path[MAX_PATH];
    DWORD length = GetTempPathW(MAX_PATH, directory);
    CHECK(length > 0 && length < MAX_PATH);
    CHECK(GetTempFileNameW(directory, L"zts", 0, path));
    FILE *stream = _wfopen(path, L"w+b");
    CHECK(stream);
    CHECK(zapret_crt_fprint_localtime(stream) == 19);
    rewind(stream);
    char text[20] = {0};
    CHECK(fread(text, 1, 19, stream) == 19 && fgetc(stream) == EOF);
    CHECK(text[2] == '.' && text[5] == '.' && text[10] == ' ' && text[13] == ':' && text[16] == ':');
    CHECK(!fclose(stream) && DeleteFileW(path));
}

static unsigned reports, debug_calls, releases, registrations;
static HANDLE active;
static WORD last_kind;
static WCHAR last_name[64], last_message[64], last_debug[64];
static bool registration_failure, blocking;
static HANDLE report_entered, report_release, close_started, close_done;
static HANDLE register_source(const WCHAR *name)
{
    CHECK(!active && wcslen(name) < 64);
    wcscpy(last_name, name);
    ++registrations;
    if (registration_failure) return NULL;
    return active = (HANDLE)(uintptr_t)(100 + registrations);
}
static BOOL report(HANDLE handle, WORD kind, const WCHAR *message)
{
    CHECK(handle && active == handle && wcslen(message) < 64);
    ++reports;
    last_kind = kind;
    wcscpy(last_message, message);
    if (blocking) {
        CHECK(SetEvent(report_entered));
        CHECK(WaitForSingleObject(report_release, 3000) == WAIT_OBJECT_0);
    }
    CHECK(active == handle);
    return TRUE;
}
static BOOL release(HANDLE handle)
{
    CHECK(handle && active == handle);
    active = NULL;
    ++releases;
    return TRUE;
}
static void debug(const WCHAR *message)
{
    CHECK(wcslen(message) < 64);
    wcscpy(last_debug, message);
    ++debug_calls;
}
static unsigned bounded_messages;
static void debug_bounded(const WCHAR *message)
{
    CHECK(wcslen(message) == 8191 && message[0] == L'x' && message[8189] == L'x');
    CHECK(message[8190] == 0xfffd && !message[8191]);
    ++bounded_messages;
}
static DWORD WINAPI write_log(void *unused) { (void)unused; zapret_system_syslog(3, "message"); return 0; }
static DWORD WINAPI close_log(void *unused)
{
    (void)unused;
    CHECK(SetEvent(close_started));
    zapret_system_closelog();
    CHECK(SetEvent(close_done));
    return 0;
}
static void join(HANDLE thread)
{
    CHECK(thread && WaitForSingleObject(thread, 3000) == WAIT_OBJECT_0);
    CHECK(CloseHandle(thread));
}
int main(void)
{
    const identity_ops identity = {version_query, computer_name, architecture};
    for (mode = 0; mode < 10; ++mode) {
        struct { uint8_t before[8]; struct utsname value; uint8_t after[8]; } legacy, rust;
        memset(&legacy, 0x69, sizeof(legacy));
        memcpy(&rust, &legacy, sizeof(rust));
        errno = 0;
        int result = reference_uname(&legacy.value), error = result ? errno : 0;
        CHECK(zapret_system_uname(&rust.value, &identity) == error);
        CHECK(!memcmp(rust.before, legacy.before, 8) && !memcmp(rust.after, legacy.after, 8));
        if (!result) CHECK(!memcmp(&rust.value, &legacy.value, sizeof(rust.value)));
        else for (size_t index = 0; index < sizeof(rust.value); ++index) CHECK(!((uint8_t *)&rust.value)[index]);
    }
    CHECK(zapret_system_uname(NULL, &identity) == EINVAL);
    struct utsname legacy, rust;
    CHECK(!actual_reference_uname(&legacy) && !zapret_system_uname(&rust, NULL));
    CHECK(!memcmp(&legacy, &rust, sizeof(rust)));
    memset(&rust, 0x69, sizeof(rust));
    CHECK(!uname(&rust) && !memcmp(&legacy, &rust, sizeof(rust)));
    errno = 0;
    CHECK(uname(NULL) == -1 && errno == EINVAL);

    const event_ops events = {register_source, report, release, debug};
    CHECK(zapret_system_openlog("source", &events));
    CHECK(zapret_system_openlog("источник", &events));
    CHECK(!wcscmp(last_name, L"источник") && releases == 1);
    for (int priority = -2; priority <= 9; ++priority) {
        zapret_system_syslog(priority, "сообщение");
        CHECK(last_kind == (priority <= 3 ? EVENTLOG_ERROR_TYPE : EVENTLOG_INFORMATION_TYPE));
        CHECK(!wcscmp(last_message, L"сообщение") && !wcscmp(last_debug, last_message));
    }
    zapret_system_syslog(7, "\xff");
    CHECK(last_message[0] == 0xfffd && !last_message[1]);
    registration_failure = true;
    CHECK(!zapret_system_openlog("unavailable", &events));
    CHECK(releases == 2 && !active);
    zapret_system_syslog(7, "debug only");
    CHECK(reports == 13 && !wcscmp(last_debug, L"debug only"));
    zapret_system_closelog();
    zapret_system_closelog();
    CHECK(releases == 2);
    registration_failure = false;
    CHECK(zapret_system_openlog("threaded", &events));
    report_entered = CreateEventW(NULL, TRUE, FALSE, NULL);
    report_release = CreateEventW(NULL, TRUE, FALSE, NULL);
    close_started = CreateEventW(NULL, TRUE, FALSE, NULL);
    close_done = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(report_entered && report_release && close_started && close_done);
    blocking = true;
    HANDLE writer = CreateThread(NULL, 0, write_log, NULL, 0, NULL);
    CHECK(writer && WaitForSingleObject(report_entered, 3000) == WAIT_OBJECT_0);
    HANDLE closer = CreateThread(NULL, 0, close_log, NULL, 0, NULL);
    CHECK(closer && WaitForSingleObject(close_started, 3000) == WAIT_OBJECT_0);
    CHECK(WaitForSingleObject(close_done, 50) == WAIT_TIMEOUT);
    CHECK(SetEvent(report_release));
    join(writer);
    join(closer);
    CHECK(!active && releases == 3);
    blocking = false;
    HANDLE threads[16];
    for (unsigned index = 0; index < 16; ++index) {
        threads[index] = CreateThread(NULL, 0, write_log, NULL, 0, NULL);
        CHECK(threads[index]);
    }
    for (unsigned index = 0; index < 16; ++index) join(threads[index]);
    CHECK(reports == 14 && debug_calls == 31);
    CHECK(CloseHandle(report_entered) && CloseHandle(report_release) && CloseHandle(close_started) && CloseHandle(close_done));
    event_ops bounded = events;
    bounded.debug = debug_bounded;
    registration_failure = true;
    CHECK(!zapret_system_openlog("unavailable", &bounded));
    char long_message[8194];
    memset(long_message, 'x', 8190);
    memcpy(long_message + 8190, "\xe4\xb8\xad", 4);
    zapret_system_syslog(7, long_message);
    CHECK(bounded_messages == 1);
    printf("PASS system_identity cases=14 unicode_cases=3 real_windows=1\n");
    printf("PASS system_eventlog reports=14 debug_calls=31 unicode_cases=3 releases=3 threaded_writes=16 guarded_closes=1 registration_failures=2 bounded_messages=1\n");
    unsigned calendar_cases = check_calendar();
    check_timestamp_stream();
    printf("PASS system_calendar cases=%u real_ucrt=1 timestamp_stream=1\n", calendar_cases);
    return 0;
}
