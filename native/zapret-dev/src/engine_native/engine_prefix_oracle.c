/* Compare the pinned startup and activation paths with entirely private stubs. */
#include "params.h"
#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "engine_entry_abi.h"
#undef main
#define ZAPRET_GH_VER v1.0.6-rust-native.1
#define ZAPRET_GH_HASH 221d7dff24bfec0cd5ac0a5070b8acef2008af3d
enum { WF_COUNT = 16, IDX_BLOB = 17 };
typedef struct {
    struct desync_profile_list_head *profiles, *templates;
    struct desync_profile_list *current;
} native_profile_flow;
struct params_s params;
const uint8_t fake_tls_clienthello_default[680] = {1, 2, 3, [679] = 5};
const char *fake_http_request_default;
static struct desync_profile_list native_entry;
static char *config_args[] = {"cfg", "--intercept=0", NULL};
static char *entry_args[] = {"engine", NULL, NULL};
static char allocation[16];
static jmp_buf exited;
static unsigned condition, mutation, cases, blobs, exit_code;
static char trace[4096];
static const uint32_t *published_error;
#define CHECK(p) do { if (!(p)) { \
    fprintf(stderr, "FAIL engine_prefix case=%u condition=%u mutation=%u line=%d: %s\n", \
        cases, condition, mutation, __LINE__, #p); exit(1); } } while (0)
static int record(const char *format, ...)
{
    if (published_error && !strcmp(format, "Cannot init Windows sandbox\n"))
        CHECK(*published_error == 62 + mutation);
    size_t used = strlen(trace);
    va_list args;
    va_start(args, format);
    int n = vsnprintf(trace + used, sizeof(trace) - used, format, args);
    va_end(args);
    CHECK(n >= 0 && (size_t)n < sizeof(trace) - used);
    return n;
}
static void stop(unsigned code) { exit_code = code; longjmp(exited, 1); }
static bool native_service(int argc, char **argv)
{
    record("service:%d:%s;", argc, argv[0]);
    return condition == 1;
}
static void icon(void) { record("icon;"); }
static void init(struct params_s *p) { CHECK(p == &params); record("params;"); }
static void help(void) { record("help;"); stop(21); }
static void help_clean(void) { record("help-clean;"); stop(22); }
static void clean(int code) { record("clean:%d;", code); stop(23); }
static time_t wall_time(time_t *out) { CHECK(!out); record("clock;"); return 987654; }
static void seed(unsigned value) { record("seed:%u;", value); }
static void exe_dir(const char *name) { record("exedir:%s;", name); }
static void buffering(void) { record("buffer;"); }
static void masks(void) { record("masks;"); }
static void appdata(void) { record("appdata;"); }
static bool inspect_blob(const char *name, const void *data, size_t length,
    struct blob_collection_head *target, size_t reserve)
{
    CHECK(target == &params.blobs);
    const uint8_t *bytes = data;
    uint64_t hash = 0;
    for (size_t i = 0; i < length; ++i) hash = hash * 131 + bytes[i];
    record("blob:%s:%zu:%zu:%llu;", name, length, reserve, (unsigned long long)hash);
    unsigned index = blobs++;
    bool success = condition != 2 + index;
    if (mutation && index == 0) {
        // A failed TLS call must return before the next source is read.
        fake_http_request_default = success ? "changed after TLS" : NULL;
    }
    return success;
}
static void default_blob(const char *name, const void *data, size_t length,
    struct blob_collection_head *target, size_t reserve)
{
    if (!inspect_blob(name, data, length, target, reserve)) clean(1);
}
static struct blob_item *selected_default_blob(void *target, const char *name, const void *data,
    size_t length, size_t reserve)
{
    static struct blob_item item;
    return inspect_blob(name, data, length, target, reserve) ? &item : NULL;
}
static unsigned profile_next(native_profile_flow *p, const char *name)
{
    CHECK(p->profiles == &params.desync_profiles && p->templates == &params.desync_templates && !name);
    record("profile;");
    p->current = &native_entry;
    return condition == 5 ? 4 : 0;
}
static void profile_exit(unsigned status, const char *name)
{
    CHECK(!name);
    record("profile-exit:%u;", status);
    if (status) stop(25);
}
static void from_file(const char *name)
{
    record("config:%s;", name);
    if (condition == 6) stop(26);
    params.wexp.we_wordv = config_args;
    params.wexp.we_wordc = mutation ? 1 : 2;
}
static void *capture_alloc(size_t count, size_t size)
{
    record("calloc:%zu:%zu;", count, size);
    return condition == 7 ? NULL : allocation;
}
static bool ports(struct params_s *p)
{
    CHECK(p == &params && p->windivert_filter == allocation);
    record("ports;");
    return condition != 8;
}
static void user_blob(const char *name, struct blob_collection_head *p, size_t maximum, size_t reserve)
{
    CHECK(p == &params.blobs);
    record("user:%s:%zu:%zu;", name, maximum, reserve);
}
uint32_t w_win32_error;
static bool driver(const char *filter)
{
    CHECK(filter == allocation);
    record("driver;");
    w_win32_error = 19 + mutation;
    if (mutation) params.intercept = !params.intercept;
    return condition != 1;
}
static bool sandbox(void)
{
    record("sandbox;");
    w_win32_error = 62 + mutation;
    if (mutation & 2) params.L = (lua_State *)(uintptr_t)1;
    return condition != 2;
}
static bool vm_init(void) { record("lua;"); if(condition==16) stop(27); return condition != 3; }
static void fuzz(void) { record("fuzz;"); }
#define service_run native_service
#define WinSetIcon icon
#define init_params init
#define printf record
#define exithelp help
#define exit_clean clean
#define exithelp_clean help_clean
#define time wall_time
#undef srandom
#define srandom seed
#define set_env_exedir exe_dir
#define set_console_io_buffering buffering
#define mask_from_bitcount6_prepare masks
#define prepare_low_appdata appdata
#define load_const_blob_to_collection default_blob
#define native_publish_const_blob selected_default_blob
#define native_profile_next profile_next
#define native_profile_exit profile_exit
#define config_from_file from_file
#define calloc capture_alloc
#define alloc_windivert_portfilters ports
#define load_blob_to_collection user_blob
#define DLOG_ERR record
#define DLOG_CONDUP record
#define windivert_init driver
#define win_sandbox sandbox
#define lua_init vm_init
#define do_fuzz fuzz
#define ApplyDefaultBlobs reference_blobs
#define loop_activate reference_activate
#include "engine_prefix_reference.inc"
#undef ApplyDefaultBlobs
#undef loop_activate
#include "engine_default_blobs_windows.inc"
#include "engine_prefix_windows.inc"
#include "engine_activate_windows.inc"
#undef printf

static bool same_range(const struct packet_range *a, const struct packet_range *b)
{
    return a->from.mode == b->from.mode && a->from.pos == b->from.pos &&
        a->to.mode == b->to.mode && a->to.pos == b->to.pos && a->upper_cutoff == b->upper_cutoff;
}

static void check_main_defaults(void)
{
    zapret_engine_main_options expected = reference_main_defaults(), actual;
    memset(&actual, 0xA5, sizeof(actual));
    zapret_engine_main_defaults(&actual);
    for (size_t i = 0; i < 4; ++i) CHECK(expected.anonymous[i] == actual.anonymous[i]);
    CHECK(expected.payload == actual.payload && same_range(&expected.incoming, &actual.incoming) &&
        same_range(&expected.outgoing, &actual.outgoing) && expected.index == actual.index &&
        expected.sub_index == actual.sub_index && expected.dry == actual.dry &&
        expected.duplicate == actual.duplicate && expected.ipv4 == actual.ipv4 && expected.ipv6 == actual.ipv6 &&
        expected.lan == actual.lan && expected.loopback == actual.loopback && expected.empty == actual.empty &&
        !memcmp(expected.save, actual.save, sizeof(actual.save)));
}

static unsigned check_version_buffers(void)
{
    const size_t capacities[] = {0, 1, 11, 128};
    unsigned compared = 0;
    for (size_t i = 0; i < sizeof(capacities) / sizeof(*capacities); ++i) {
        size_t capacity = capacities[i];
        for (unsigned pinned = 0; pinned < 2; ++pinned) {
            char output[128], expected[128], expected_trace[144];
            memset(output, 0xA5, sizeof(output));
            output[127] = 0;
            memcpy(expected, output, sizeof(expected));
            const char *version = "v1-\xff";
            const char *hash = "x987";
            snprintf(expected, capacity, pinned ? "github version %s (%s) lua_compat_ver %u" :
                "self-built version %s %s lua_compat_ver %u", version, hash, UINT32_MAX);
            snprintf(expected_trace, sizeof(expected_trace), "%s\n\n", expected);
            trace[0] = 0;
            zapret_engine_version(output, capacity, pinned, version, hash, UINT32_MAX, record);
            CHECK(!memcmp(expected, output, sizeof(expected)) && !strcmp(expected_trace, trace));
            ++compared;
        }
    }
    return compared;
}

static void selected_parse_error(bool dry)
{
    if (zapret_engine_parse_failure(dry) == 1) exit_clean(1);
    else exithelp_clean();
}

static void selected_residual(int index, char *text)
{
    zapret_engine_blob_limit limits = zapret_engine_blob_limits(index);
    if (limits.maximum)
        load_blob_to_collection(text, &params.blobs, limits.maximum, limits.reserve);
}

static int argc;
static char **argv;
static unsigned hashes[WF_COUNT];
static native_profile_flow flow;
static struct desync_profile_list *profile_entry;
static struct desync_profile *profile;
static unsigned run(bool selected, unsigned domain, unsigned shape)
{
    trace[0] = 0;
    published_error = NULL;
    blobs = exit_code = 0;
    memset(&params, 0, sizeof(params));
    memset(hashes, 0x51, sizeof(hashes));
    params.intercept = shape & 1;
    if (shape & 2) params.L = (lua_State *)(uintptr_t)1;
    fake_http_request_default = "constant HTTP";
    if (!setjmp(exited)) {
        switch (domain) {
        case 0: {
            static char *prefix[] = {NULL, "@absolute", "$relative", "--opt", ""};
            entry_args[1] = prefix[shape];
            argc = shape ? 2 : 1;
            argv = entry_args;
            bool proceed = (selected ? native_main_prefix : reference_prefix)(
                &argc, &argv, hashes, &flow, &profile_entry, &profile);
            record("proceed:%u;", proceed);
            if (proceed)
                record("result:%d:%s:%u:%u;", argc, argv[0], profile_entry == &native_entry,
                    profile == &native_entry.dp);
            break;
        }
        case 1: (selected ? selected_parse_error : reference_parse_error)(shape & 1); break;
        case 2: (selected ? selected_residual : reference_residual)(condition, "test blob"); break;
        case 3: {
            params.windivert_filter = allocation;
            uint32_t error = 111;
            published_error = &error;
            bool result = (selected ? loop_activate : reference_activate)(&error);
            record("result:%u:%u;", result, error);
            break;
        }
        }
    }
    published_error = NULL;
    if (domain == 0) {
        record("hashes:");
        for (unsigned i = 0; i < WF_COUNT; ++i) record("%u,", hashes[i]);
    }
    return exit_code;
}
int main(void)
{
    check_main_defaults();
    unsigned version_cases = check_version_buffers();
    for (unsigned domain = 0; domain < 4; ++domain)
        for (unsigned shape = 0; shape < 5; ++shape)
            for (condition = 0; condition < 20; ++condition)
                for (mutation = 0; mutation < 4; ++mutation) {
                    char before[sizeof(trace)];
                    unsigned expected = run(false, domain, shape);
                    strcpy(before, trace);
                    unsigned actual = run(true, domain, shape);
                    if (expected != actual || strcmp(before, trace))
                        fprintf(stderr, "expected %s\nactual %s\n", before, trace);
                    CHECK(expected == actual && !strcmp(before, trace));
                    ++cases;
                }
    printf("PASS engine_prefix cases=%u original_native_order=1 args_replaced=1 default_blob_bytes=1 "
        "deferred_observations=1 protected_activation=1 failed_tls_skips_http=1 "
        "win32_error_before_report=1 c_vm_exit=1 main_defaults=1 version_buffers=%u\n", cases, version_cases);
    return 0;
}
