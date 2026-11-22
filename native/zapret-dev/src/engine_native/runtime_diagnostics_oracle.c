/* Capture the full native log trace for the pinned C entries and Rust reporters. */
#include "darkmagic.h"
#include "params.h"
#include "protocol.h"
#include "engine_loop_windows.h"
#include "win_files.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef main

void __wrap_wf_error(DWORD error);
#define wf_error __wrap_wf_error
#define autolist_report reference_autolist_report
#define loop_idle_report reference_idle_report
#define loop_report reference_loop_report
#define native_capture_prepare_report reference_prepare_report
#define packet_cache_report reference_packet_cache_report
#define reassembly_report reference_reassembly_report
#include "runtime_diagnostics_reference.inc"
#undef autolist_report
#undef loop_idle_report
#undef loop_report
#undef native_capture_prepare_report
#undef packet_cache_report
#undef reassembly_report
#undef wf_error
#include "windows_engine_reports_abi.h"

void zapret_capture_idle_report(bool, zapret_log_sink, zapret_log_sink);

_Static_assert(offsetof(struct desync_profile, n) == 0 && offsetof(struct desync_profile, name) == 8 &&
    offsetof(struct desync_profile, hostlist_auto) == 104 && offsetof(t_ctrack, dp) == 184 &&
    offsetof(struct zapret_list_file, filename) == 0, "Automatic hostlist log field ABI");
_Static_assert(sizeof(zapret_autolist_context) == 64 && ZAPRET_INVALID_MODIFICATION == 13,
    "Runtime diagnostics ABI");

enum input { AUTOLIST, LOOP, IDLE, PREPARE, STATUS, PACKET_CACHE, REASSEMBLY, INPUTS };
struct row {
    char sink;
    int err;
    DWORD last_error, error_arg;
    char format[256], text[512];
};
struct trace {
    struct row rows[2];
    unsigned count;
    int err;
    DWORD last_error;
};
static struct trace results[2], *trace;
static struct desync_profile profile, other_profile, early_track_profile, late_track_profile;
static struct zapret_list_file file, late_file;
static t_ctrack track, other_track;
static zapret_autolist_context context;
struct params_s params;
static struct in_addr ipv4;
static struct in6_addr ipv6;
static zapret_packet_cache_context cache;
static ip_cache_item cache_item;
static bool debug_enabled;
static enum input input;
static uint32_t event, number;
static uint64_t values[4];
static unsigned layout, mutate, cases[INPUTS], late_reads, guards;
static void *guard;
static const char *text;
static const char binary[] = {'b', (char)0xff, (char)0x80, '%', 0, 'x', 0};
static const char *const strings[] = {"example.test", binary, NULL, "", "filter %s", "name with spaces"};
static const uint64_t numbers[] = {0, 1, INT32_MAX, UINT64_C(0x80000000), UINT32_MAX,
    UINT64_C(0x0102030405060708), UINT64_MAX};

#define LENGTH(array) (sizeof(array) / sizeof((array)[0]))
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL runtime_diagnostics input=%u event=%u layout=%u mutate=%u line=%d: %s\n", \
        (unsigned)input, event, layout, mutate, __LINE__, #condition); exit(1); \
} } while (0)

static void seed(void)
{
    profile.n = 51;
    profile.name = (char *)strings[layout];
    file.filename = (char *)strings[(layout + 1) % LENGTH(strings)];
    profile.hostlist_auto = &file;
    other_profile.n = 180;
    other_profile.name = "unrelated profile";
    other_profile.hostlist_auto = &file;
    early_track_profile.n = 859;
    late_track_profile.n = UINT32_MAX;
    track.dp = &early_track_profile;
    other_track.dp = &late_track_profile;
    context = (zapret_autolist_context){
        .profile = guard ? guard : &profile,
        .hostname = strings[(layout + 2) % LENGTH(strings)],
        .client_text = strings[(layout + 3) % LENGTH(strings)],
        .interface = strings[(layout + 4) % LENGTH(strings)],
        .track = guard ? guard : &track,
        .l7 = layout == 0 ? UINT32_MAX : layout,
    };
    params.debug = debug_enabled;
    cache = (zapret_packet_cache_context){
        .ipv4 = (layout & 1) ? &ipv4 : NULL,
        .ipv6 = (layout & 2) ? &ipv6 : NULL,
    };
    cache_item = (ip_cache_item){
        .hostname = (char *)strings[layout],
        .hostname_is_ip = (layout & 1) != 0,
        .ttl = layout ? (uint8_t)(layout * 64) : UINT8_MAX,
    };
}

static void after_debug(void)
{
    profile.n = 913;
    profile.name = profile.name ? NULL : (char *)binary;
    late_file.filename = "second hostlist";
    profile.hostlist_auto = &late_file;
    context.profile = &other_profile;
    context.hostname = "late % hostname";
    context.client_text = binary;
    context.l7 = 8;
    if (layout % 2)
        context.track = &other_track;
    else
        track.dp = &late_track_profile;
}

static struct row *next(char sink)
{
    const DWORD last_error = GetLastError();
    CHECK(trace->count < LENGTH(trace->rows));
    struct row *row = &trace->rows[trace->count++];
    row->sink = sink;
    row->err = errno;
    row->last_error = last_error;
    return row;
}

static int render(char sink, const char *format, va_list args)
{
    struct row *row = next(sink);
    CHECK(strlen(format) < sizeof(row->format));
    strcpy(row->format, format);
    int length = vsnprintf(row->text, sizeof(row->text), format, args);
    CHECK(length >= 0 && (size_t)length < sizeof(row->text));
    if (sink == 'D' && mutate && trace->count == 1) after_debug();
    errno = EDOM;
    SetLastError(ERROR_INVALID_HANDLE);
    return length;
}

#define SINK(name, sink) int name(const char *format, ...) { \
    va_list args; va_start(args, format); \
    int length = render(sink, format, args); va_end(args); return length; \
}
SINK(DLOG, 'D')
SINK(DLOG_ERR, 'E')
SINK(DLOG_CONDUP, 'C')
SINK(HOSTLIST_DEBUGLOG_APPEND, 'A')
#undef SINK

int DLOG_PERROR(const char *label)
{
    struct row *row = next('P');
    CHECK(strlen(label) < sizeof(row->text));
    strcpy(row->text, label);
    errno = EDOM;
    SetLastError(ERROR_INVALID_HANDLE);
    return (int)strlen(label);
}

void __wrap_wf_error(DWORD error)
{
    next('W')->error_arg = error;
    errno = ERANGE;
    SetLastError(error);
}

static void run(bool rust)
{
    trace = &results[rust];
    memset(trace, 0, sizeof(*trace));
    seed();
    errno = EACCES;
    SetLastError(ERROR_ACCESS_DENIED);
    switch (input) {
    case AUTOLIST:
        (rust ? autolist_report : reference_autolist_report)(event, &context, values[0], values[1], values[2], values[3]);
        break;
    case LOOP:
        (rust ? loop_report : reference_loop_report)(event, number, (size_t)values[0], (size_t)values[1]);
        break;
    case IDLE:
        if (rust)
            zapret_capture_idle_report(event != 0, DLOG, DLOG_CONDUP);
        else
            reference_idle_report(event != 0);
        break;
    case PREPARE:
        (rust ? native_capture_prepare_report : reference_prepare_report)(event, (size_t)values[0], text);
        break;
    case STATUS:
        (rust ? native_capture_prepare_status : capture_prepare_status)(event, number, text);
        break;
    case PACKET_CACHE:
        (rust ? packet_cache_report : reference_packet_cache_report)(
            guard ? guard : &cache, event, guard ? guard : &cache_item);
        break;
    case REASSEMBLY:
        (rust ? reassembly_report : reference_reassembly_report)(event, (size_t)values[0],
            (size_t)values[1], (size_t)values[2]);
        break;
    default:
        CHECK(false);
    }
    trace->last_error = GetLastError();
    trace->err = errno;
}

static void compare(void)
{
    run(false);
    run(true);
    const struct trace *old = &results[0], *rust = &results[1];
    CHECK(old->count == rust->count && old->err == rust->err && old->last_error == rust->last_error);
    for (unsigned i = 0; i < old->count; ++i) {
        const struct row *a = &old->rows[i], *b = &rust->rows[i];
        if (strcmp(a->text, b->text))
            fprintf(stderr, "row %u expected [%s], observed [%s]\n", i, a->text, b->text);
        CHECK(a->sink == b->sink && a->err == b->err && a->last_error == b->last_error &&
            a->error_arg == b->error_arg && !strcmp(a->format, b->format) && !strcmp(a->text, b->text));
    }
    ++cases[input];
    if (input == AUTOLIST && mutate && old->count == 2) ++late_reads;
}

int main(void)
{
    const uint8_t ipv4_bytes[4] = {192, 0, 2, 7};
    const uint8_t ipv6_bytes[16] = {0x20, 0x01, 0x0d, 0xb8, [15] = 7};
    memcpy(&ipv4, ipv4_bytes, sizeof(ipv4_bytes));
    memcpy(&ipv6, ipv6_bytes, sizeof(ipv6_bytes));
    input = AUTOLIST;
    for (unsigned i = 0; i <= 23; ++i) {
        event = i == 23 ? UINT32_MAX : i;
        for (layout = 0; layout < LENGTH(strings); ++layout)
            for (unsigned j = 0; j < LENGTH(numbers); ++j) {
                for (unsigned k = 0; k < LENGTH(values); ++k)
                    values[k] = numbers[(j + k) % LENGTH(numbers)];
                for (mutate = 0; mutate < 2; ++mutate) compare();
            }
    }
    mutate = layout = 0;
    input = LOOP;
    for (unsigned i = 0; i <= 15; ++i) {
        event = i == 15 ? UINT32_MAX : i;
        for (unsigned j = 0; j < LENGTH(numbers); ++j) {
            number = (uint32_t)numbers[j];
            values[0] = numbers[(j + 1) % LENGTH(numbers)];
            values[1] = numbers[(j + 3) % LENGTH(numbers)];
            compare();
        }
    }
    input = IDLE;
    for (event = 0; event <= 1; ++event) compare();
    input = PREPARE;
    for (unsigned i = 0; i <= 3; ++i) {
        event = i == 3 ? UINT32_MAX : i;
        for (unsigned j = 0; j < LENGTH(strings); ++j) {
            text = strings[j];
            for (unsigned k = 0; k < LENGTH(numbers); ++k) {
                values[0] = numbers[k];
                compare();
            }
        }
    }
    input = STATUS;
    for (unsigned i = 0; i <= 10; ++i) {
        event = i == 10 ? UINT32_MAX : i;
        for (unsigned j = 0; j < LENGTH(numbers); ++j) {
            number = (uint32_t)numbers[j];
            text = strings[j % LENGTH(strings)];
            compare();
        }
    }
    input = PACKET_CACHE;
    for (unsigned i = 0; i <= 7; ++i) {
        event = i == 7 ? UINT32_MAX : i;
        for (layout = 0; layout < LENGTH(strings); ++layout)
            for (unsigned debug = 0; debug < 2; ++debug) {
                debug_enabled = debug != 0;
                compare();
            }
    }
    input = REASSEMBLY;
    layout = 0;
    for (unsigned i = 0; i <= 12; ++i) {
        event = i == 12 ? UINT32_MAX : i;
        for (unsigned j = 0; j < LENGTH(numbers); ++j) {
            for (unsigned k = 0; k < 3; ++k)
                values[k] = numbers[(j + k) % LENGTH(numbers)];
            compare();
        }
    }
    guard = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
    CHECK(guard);
    input = AUTOLIST;
    for (event = 11; event <= 13; ++event) { compare(); ++guards; }
    input = STATUS;
    text = guard;
    for (event = 0; event <= 9; ++event)
        if (event != 5) { compare(); ++guards; }
    input = PACKET_CACHE;
    debug_enabled = false;
    for (event = 2; event <= 3; ++event) { compare(); ++guards; }
    debug_enabled = true;
    event = UINT32_MAX;
    compare();
    ++guards;
    CHECK(VirtualFree(guard, 0, MEM_RELEASE));
    printf("PASS runtime_diagnostics autohostlist=%u loop=%u idle=%u prepare=%u status=%u "
        "cache=%u reassembly=%u late_reads=%u guarded=%u ucrt_format=1 errno_order=1\n",
        cases[AUTOLIST], cases[LOOP], cases[IDLE], cases[PREPARE], cases[STATUS],
        cases[PACKET_CACHE], cases[REASSEMBLY], late_reads, guards);
    return 0;
}
