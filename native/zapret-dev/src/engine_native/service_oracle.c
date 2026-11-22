/* MIT. Private callbacks and threads exercise the ordinary service lifecycle. */
#include <windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static unsigned scenario, entries, registrations, dispatches, statuses;
static volatile LONG quitting;
static LPHANDLER_FUNCTION handler;
static SERVICE_STATUS observed[32];
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL engine service scenario=%u line=%d: %s\n", scenario, __LINE__, #condition); exit(1); } \
} while (0)

typedef struct {
    BOOL (WINAPI *dispatch)(const SERVICE_TABLE_ENTRYW *);
    SERVICE_STATUS_HANDLE (WINAPI *register_handler)(LPCWSTR, LPHANDLER_FUNCTION);
    BOOL (WINAPI *status)(SERVICE_STATUS_HANDLE, const SERVICE_STATUS *);
} service_ops;

bool zapret_engine_service_run(int, char **, int (*)(int, char **), void (*)(void), const service_ops *);
static int engine(int, char **);
static void quit(void) { InterlockedExchange(&quitting, 1); }
static char *args[] = {"fixture", "argument", NULL};
static const service_ops ops;

static BOOL WINAPI dispatch(const SERVICE_TABLE_ENTRYW *table)
{
    CHECK(++dispatches == 1);
    CHECK(!wcscmp(table[0].lpServiceName, L"winws2") && table[0].lpServiceProc);
    CHECK(!table[1].lpServiceName && !table[1].lpServiceProc);
    if (scenario == 0) return FALSE;
    table[0].lpServiceProc(0, NULL);
    return TRUE;
}
static SERVICE_STATUS_HANDLE WINAPI register_handler(LPCWSTR name, LPHANDLER_FUNCTION callback)
{
    CHECK(!wcscmp(name, L"winws2") && callback);
    ++registrations;
    handler = callback;
    if (scenario == 1) return NULL;
    if (scenario == 7) callback(SERVICE_CONTROL_STOP);
    return (SERVICE_STATUS_HANDLE)(uintptr_t)41;
}
static BOOL WINAPI publish(SERVICE_STATUS_HANDLE handle, const SERVICE_STATUS *status)
{
    CHECK(handle == (SERVICE_STATUS_HANDLE)(uintptr_t)41 && status->dwServiceType == SERVICE_WIN32_OWN_PROCESS);
    CHECK(statuses < sizeof(observed) / sizeof(*observed));
    if (statuses && observed[statuses - 1].dwCurrentState == SERVICE_STOP_PENDING)
        CHECK(status->dwCurrentState != SERVICE_RUNNING);
    observed[statuses++] = *status;
    return scenario == 6 ? FALSE : TRUE;
}
static DWORD WINAPI control_thread(void *context)
{
    CHECK(!context);
    for (unsigned index = 0; index < 16; ++index)
        handler(index & 1 ? SERVICE_CONTROL_INTERROGATE : SERVICE_CONTROL_STOP);
    return 0;
}
static int engine(int argc, char **argv)
{
    CHECK(argc == 2 && argv == args && !strcmp(argv[1], "argument"));
    ++entries;
    CHECK(statuses == 1 && observed[0].dwCurrentState == SERVICE_RUNNING &&
        observed[0].dwControlsAccepted == (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN));
    CHECK(!zapret_engine_service_run(argc, argv, engine, quit, &ops));
    if (scenario == 3) handler(SERVICE_CONTROL_STOP);
    if (scenario == 4) handler(SERVICE_CONTROL_SHUTDOWN);
    if (scenario == 5) { handler(SERVICE_CONTROL_INTERROGATE); CHECK(!quitting); handler(SERVICE_CONTROL_STOP); }
    if (scenario == 8) {
        HANDLE thread = CreateThread(NULL, 0, control_thread, NULL, 0, NULL);
        CHECK(thread && WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0);
        CloseHandle(thread);
    }
    return 37;
}
static const service_ops ops = {dispatch, register_handler, publish};

int main(void)
{
    for (scenario = 0; scenario < 9; ++scenario) {
        entries = registrations = dispatches = statuses = 0;
        quitting = 0;
        handler = NULL;
        CHECK(zapret_engine_service_run(2, args, engine, quit, &ops) == (scenario != 0));
        CHECK(dispatches == 1 && registrations == (scenario != 0));
        unsigned final_statuses = statuses;
        if (handler) handler(SERVICE_CONTROL_INTERROGATE);
        CHECK(statuses == final_statuses);
        if (scenario < 2) CHECK(!entries && !statuses && !quitting);
        else {
            CHECK(entries == (scenario != 7));
            const SERVICE_STATUS *last = &observed[statuses - 1];
            CHECK(last->dwCurrentState == SERVICE_STOPPED && !last->dwControlsAccepted && !last->dwCheckPoint);
            CHECK(last->dwWin32ExitCode == (scenario == 7 ? 0 : 37));
            CHECK(!!quitting == (scenario == 3 || scenario == 4 || scenario == 5 || scenario == 7 || scenario == 8));
            if (scenario == 7) CHECK(observed[0].dwCurrentState == SERVICE_STOP_PENDING);
        }
    }
    puts("PASS engine_service scenarios=9 threaded_controls=16 recursive_dispatches=0");
    return 0;
}
