/* MIT. Compare the actual Win64 bootstrap object using private callbacks. */
#include <iphlpapi.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "engine_loop_windows.h"
#undef main

enum step {
    DAEMON = 1, PID, ENVIRONMENT, SANDBOX, LUA, IDLE, NETWORK,
    CAPTURE, NETWORK_CLOSE, LUA_CLOSE, RAW_CLOSE, PID_REPORT, NETWORK_REPORT
};
enum failure { SUCCESS, PID_FAILURE, SANDBOX_FAILURE, LUA_FAILURE, NETWORK_FAILURE };
enum mutation { FROM_DAEMON = 1, FROM_ENVIRONMENT = 2 };

struct state {
    const char *environment;
    uint32_t error, report_error;
    int capture_result;
    enum failure failure;
    unsigned mutation, used;
    enum step trace[16];
    bool capture_intercept;
    char pid_path[32];
};

struct params_s params;
static struct state *active;
static uint32_t observed_error;
static const zapret_capture_ops capture_ops = {0};
static unsigned cases, changed_pid, changed_capture;

#define CHECK(value) do { if (!(value)) { \
    fprintf(stderr, "FAIL Rust bootstrap projection case=%u line=%d: %s\n", cases, __LINE__, #value); \
    exit(1); \
} } while (0)

static void trace(enum step operation)
{
    CHECK(active->used < sizeof(active->trace) / sizeof(*active->trace));
    active->trace[active->used++] = operation;
}

void __wrap_daemonize(void)
{
    trace(DAEMON);
    if (active->mutation & FROM_DAEMON) {
        strcpy(params.pidfile, params.pidfile[0] ? "changed.pid" : "new.pid");
        params.intercept = !params.intercept;
    }
}

static bool fixture_writepid(const char *path)
{
    CHECK(path == params.pidfile && strlen(path) < sizeof(active->pid_path));
    trace(PID);
    strcpy(active->pid_path, path);
    return active->failure != PID_FAILURE;
}

static const char *fixture_getenv(const char *name)
{
    CHECK(!strcmp(name, "ZAPRET_RING_SELFTEST"));
    trace(ENVIRONMENT);
    if (active->mutation & FROM_ENVIRONMENT) params.intercept = !params.intercept;
    return active->environment;
}

bool win_sandbox(void)
{
    trace(SANDBOX);
    return active->failure != SANDBOX_FAILURE;
}

bool lua_init(void)
{
    trace(LUA);
    return active->failure != LUA_FAILURE;
}

void NoInterceptLoop(void) { trace(IDLE); }

bool win_dark_init(const struct str_list_head *ssid, bool ssid_neg,
    const struct str_list_head *network, bool network_neg)
{
    CHECK(ssid == &params.ssid_filter && network == &params.nlm_filter);
    CHECK(ssid_neg == params.ssid_filter_neg && network_neg == params.nlm_filter_neg);
    trace(NETWORK);
    if (active->failure != NETWORK_FAILURE) return true;
    observed_error = active->error;
    return false;
}

static uint32_t fixture_capture(const zapret_capture_ops *ops, void *addresses, bool intercept)
{
    CHECK(ops == &capture_ops && addresses);
    trace(CAPTURE);
    active->capture_intercept = intercept;
    return (uint32_t)active->capture_result;
}

void win_dark_deinit(void) { trace(NETWORK_CLOSE); }
void lua_shutdown(void) { trace(LUA_CLOSE); }
void rawsend_cleanup(void) { trace(RAW_CLOSE); }

int DLOG_ERR(const char *format, ...)
{
    if (!strcmp(format, "could not write pidfile")) {
        trace(PID_REPORT);
        active->report_error = ERROR_TOO_MANY_OPEN_FILES;
        return 0;
    }
    CHECK(!strcmp(format, "win_dark_init failed. win32 error %u (0x%08X)\n"));
    trace(NETWORK_REPORT);
    va_list args;
    va_start(args, format);
    active->report_error = va_arg(args, unsigned);
    CHECK(va_arg(args, unsigned) == active->report_error);
    va_end(args);
    return 0;
}

#undef getenv
#define getenv fixture_getenv
#define writepid fixture_writepid
#define daemonize __wrap_daemonize
#define w_win32_error observed_error
#define zapret_capture_loop fixture_capture
#define win_main reference_win_main
#define native_boot_pid reference_boot_pid
#define native_boot_selftest reference_boot_selftest
#define native_boot_network reference_boot_network
#define native_boot_error reference_boot_error
#define native_boot_capture reference_boot_capture
#define native_boot_report reference_boot_report
#include "engine_bootstrap_windows.inc"
#undef native_boot_report
#undef native_boot_capture
#undef native_boot_error
#undef native_boot_network
#undef native_boot_selftest
#undef native_boot_pid
#undef win_main
#include "engine_bootstrap_entry_windows.inc"

bool native_boot_pid(void) { return reference_boot_pid(); }
bool native_boot_selftest(void) { return reference_boot_selftest(); }
uint32_t native_boot_error(void) { return reference_boot_error(); }
void native_boot_report(uint32_t event, uint32_t error) { reference_boot_report(event, error); }

static int run(int (*entry)(void), struct state *state, bool daemon, bool pid, bool intercept)
{
    params.daemon = daemon;
    strcpy(params.pidfile, pid ? "fixture.pid" : "");
    params.intercept = intercept;
    params.ssid_filter_neg = pid;
    params.nlm_filter_neg = intercept;
    observed_error = UINT32_MAX;
    active = state;
    return entry();
}

static void compare(struct state initial, bool daemon, bool pid, bool intercept)
{
    struct state before = initial, after = initial;
    int old_result = run(reference_win_main, &before, daemon, pid, intercept);
    int result = run(win_main, &after, daemon, pid, intercept);
    CHECK(result == old_result && after.used == before.used);
    CHECK(!memcmp(after.trace, before.trace, after.used * sizeof(after.trace[0])));
    CHECK(after.report_error == before.report_error && !strcmp(after.pid_path, before.pid_path));
    CHECK(after.capture_intercept == before.capture_intercept);
    CHECK(pid || !after.pid_path[0]);
    if (!strcmp(after.pid_path, "changed.pid")) ++changed_pid;
    for (unsigned i = 0; i < after.used; ++i)
        if (after.trace[i] == CAPTURE && after.capture_intercept != intercept) ++changed_capture;
    ++cases;
}

int main(void)
{
    static const char *const environments[] = {NULL, "", "1", "01", "true"};
    static const uint32_t errors[] = {0, ERROR_ACCESS_DENIED, ERROR_GEN_FAILURE, UINT32_MAX};
    static const int results[] = {0, 87, INT32_MIN, -1};
    for (unsigned daemon = 0; daemon < 2; ++daemon)
        for (unsigned pid = 0; pid < 2; ++pid)
            for (unsigned intercept = 0; intercept < 2; ++intercept)
                for (unsigned env = 0; env < sizeof(environments) / sizeof(environments[0]); ++env)
                    for (unsigned fail = SUCCESS; fail <= NETWORK_FAILURE; ++fail)
                        for (unsigned error = 0; error < sizeof(errors) / sizeof(errors[0]); ++error)
                            for (unsigned result = 0; result < sizeof(results) / sizeof(results[0]); ++result)
                                for (unsigned mutate = 0; mutate < 4; ++mutate)
                                    compare((struct state){
                                        .environment = environments[env], .error = errors[error],
                                        .capture_result = results[result], .failure = fail, .mutation = mutate,
                                    }, daemon, pid, intercept);
    CHECK(changed_pid && changed_capture);
    printf("PASS windows_engine_bootstrap cases=%u late_pid_paths=%u live_capture_flags=%u "
        "entry_flag_snapshot=1 exact_cleanup_order=1 exact_reports=1 private_callbacks=1\n",
        cases, changed_pid, changed_capture);
    return 0;
}
