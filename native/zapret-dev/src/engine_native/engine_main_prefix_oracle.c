/* MIT. Compare both prefix adapters using only fixture callbacks. */
#include "params.h"
#include <setjmp.h>
#include <stdarg.h>
#include <string.h>
#include "profile_flow_windows.h"
#include "engine_prefix_abi.h"
#undef main

enum { WF_COUNT = 16, IDX_BLOB = 17 };
#define ZAPRET_GH_VER fixture-version
#define ZAPRET_GH_HASH fixture-hash
#include "engine_main_prefix_abi.h"

enum failure { NONE, SERVICE, PARAMS, BLOBS, PROFILE, CONFIG, FILTER, PORTS };
enum variant { REENTER = 1, LATE_PROFILE = 2, LARGE_WORD_COUNT = 4, REPLACE_OPERAND = 8 };

static struct desync_profile_list initial_entry, selected_entry, late_entry;
struct params_s params;
static char *config_words[] = {"config", "--fixture", NULL};
static char *late_arguments[] = {"late", "$late-argument", NULL};
static char filter_storage;

struct call {
    jmp_buf exit_target;
    int argc;
    char **argv;
    struct {
        uint32_t before;
        unsigned words[WF_COUNT];
        uint32_t after;
    } hashes;
    native_profile_flow flow;
    struct desync_profile_list *entry;
    struct desync_profile *profile;
    unsigned exit_code;
    bool proceed, direct, nested;
    char trace[1024];
    size_t used;
};

static enum failure fault;
static unsigned variant, cases, reentries, nonlocal_exits, steps;
static struct call *active;
static unsigned step_depth;

#define CHECK(value) do { \
    if (!(value)) { \
        fprintf(stderr, "FAIL native prefix case=%u fault=%u variant=%u line=%d: %s\n", \
            cases, fault, variant, __LINE__, #value); \
        exit(1); \
    } \
} while (0)

static int record(const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    size_t available = sizeof(active->trace) - active->used;
    int length = vsnprintf(active->trace + active->used, available, format, arguments);
    va_end(arguments);
    CHECK(length >= 0 && (size_t)length < available);
    active->used += (size_t)length;
    return length;
}

static bool invoke_prefix(void);

static void host(void) { CHECK(step_depth == 0); }
static void local(void) { CHECK(step_depth == active->direct); }

static void stop(unsigned code)
{
    host();
    active->exit_code = code;
    ++nonlocal_exits;
    longjmp(active->exit_target, 1);
}

bool service_run(int argc, char **argv)
{
    host();
    CHECK(argc == active->argc && argv == active->argv);
    record("service:%d:%s;", argc, argv[0]);
    if (active->nested) return true;
    if (variant & REENTER) {
        struct call *outer = active;
        char *arguments[] = {"nested", NULL};
        struct call inner = {.argc = 1, .argv = arguments, .direct = outer->direct, .nested = true};
        active = &inner;
        CHECK(!invoke_prefix());
        active = outer;
        record("nested:%s", inner.trace);
        ++reentries;
    }
    return fault == SERVICE;
}

void WinSetIcon(void)
{
    local();
    record("icon;");
}

void init_params(struct params_s *state)
{
    host();
    CHECK(state == &params);
    record("init;");
    if (fault == PARAMS) stop(10);
}

static void exithelp(void)
{
    record("help;");
    stop(11);
}

static void exit_clean(int code)
{
    record("clean:%d;", code);
    stop(12);
}

__time64_t __wrap__time64(__time64_t *output)
{
    local();
    CHECK(!output);
    record("clock;");
    return -0x112233445566LL;
}

void __wrap_zapret_srandom(uint32_t seed)
{
    local();
    CHECK(seed == (uint32_t)-0x112233445566LL);
    record("seed:%u;", seed);
}

bool set_env_exedir(const char *name)
{
    local();
    CHECK(name == active->argv[0]);
    record("exedir:%s;", name);
    return false;
}

void __wrap_zapret_crt_set_console_io_buffering(void)
{
    local();
    record("buffer;");
}

void __wrap_zapret_prefix_prepare6(void)
{
    local();
    record("mask;");
}

bool prepare_low_appdata(void)
{
    local();
    for (size_t i = 0; i < WF_COUNT; ++i) CHECK(active->hashes.words[i] == 0);
    record("appdata;");
    return false;
}

static void ApplyDefaultBlobs(struct blob_collection_head *target)
{
    host();
    CHECK(target == &params.blobs);
    record("blobs;");
    if (fault == BLOBS) stop(13);
}

uint32_t native_profile_next(native_profile_flow *flow, const char *name)
{
    host();
    CHECK(flow == &active->flow && !name);
    CHECK(flow->profiles == &params.desync_profiles && flow->templates == &params.desync_templates);
    CHECK(!flow->current && !flow->count && !flow->template_count && !flow->skip && !flow->template);
    flow->current = &selected_entry;
    record("profile;");
    return fault == PROFILE ? 4 : 0;
}

static void native_profile_exit(uint32_t status, const char *name)
{
    host();
    CHECK(!name && active->entry == &initial_entry && active->profile == &initial_entry.dp);
    record("profile-result:%u;", status);
    if (status) stop(14);
    if (variant & LATE_PROFILE) active->flow.current = &late_entry;
    if (variant & REPLACE_OPERAND) {
        active->argv = late_arguments;
        active->argc = 2;
    }
}

bool zapret_config_from_file(const char *name)
{
    local();
    CHECK(name == active->argv[1] + 1);
    CHECK(active->entry == active->flow.current && active->profile == &active->entry->dp);
    record("config:%s;", name);
    if (fault == CONFIG) return false;
    params.wexp.we_wordv = config_words;
    params.wexp.we_wordc = (variant & LARGE_WORD_COUNT) ? (size_t)UINT64_C(0x100000002) : 2;
    return true;
}

static void config_from_file(const char *name)
{
    if (!zapret_config_from_file(name)) exit_clean(1);
}

void *__real_calloc(size_t count, size_t size);
void *__wrap_calloc(size_t count, size_t size)
{
    if (!active) return __real_calloc(count, size);
    local();
    CHECK(count == 1 && size == 65536);
    CHECK(active->entry == active->flow.current && active->profile == &active->entry->dp);
    if (params.wexp.we_wordv) {
        CHECK(active->argv == config_words && active->argc == 2);
    }
    record("allocate:%zu:%zu;", count, size);
    return fault == FILTER ? NULL : &filter_storage;
}

bool alloc_windivert_portfilters(struct params_s *state)
{
    local();
    CHECK(state == &params && state->windivert_filter == &filter_storage);
    record("ports;");
    return fault != PORTS;
}

int DLOG_ERR(const char *format, ...)
{
    local();
    CHECK(!strcmp(format, "out of memory\n"));
    return record("%s", format);
}

void zapret_native_main_version(bool pinned, const char *version, const char *revision, uint32_t lua_compat)
{
    host();
    zapret_engine_version(params.verstr, sizeof(params.verstr), pinned, version, revision, lua_compat, record);
}

uint32_t __real_zapret_native_main_prefix_step(zapret_native_prefix_cursor *, const zapret_native_prefix_slots *);
uint32_t __wrap_zapret_native_main_prefix_step(zapret_native_prefix_cursor *cursor, const zapret_native_prefix_slots *slots)
{
    CHECK(!step_depth && active->direct);
    ++step_depth;
    uint32_t result = __real_zapret_native_main_prefix_step(cursor, slots);
    --step_depth;
    ++steps;
    return result;
}

void zapret_crt_set_console_io_buffering(void);
void zapret_prefix_prepare6(void);
#undef set_console_io_buffering
#define set_console_io_buffering zapret_crt_set_console_io_buffering
#undef mask_from_bitcount6_prepare
#define mask_from_bitcount6_prepare zapret_prefix_prepare6

#define native_main_prefix previous_native_main_prefix
#define printf record
#include "engine_prefix_windows.inc"
#undef printf
#undef native_main_prefix
#include "engine_main_prefix_windows.inc"

static bool invoke_prefix(void)
{
    return (active->direct ? native_main_prefix : previous_native_main_prefix)(
        &active->argc, &active->argv, active->hashes.words, &active->flow, &active->entry, &active->profile);
}

static void run_prefix(struct call *value)
{
    active = value;
    memset(&params, 0, sizeof(params));
    value->hashes.before = value->hashes.after = UINT32_C(0xcafe6400);
    memset(value->hashes.words, 0x5a, sizeof(value->hashes.words));
    value->flow.count = value->flow.template_count = 99;
    value->flow.skip = value->flow.template = true;
    value->entry = &initial_entry;
    value->profile = &initial_entry.dp;
    if (!setjmp(value->exit_target)) value->proceed = invoke_prefix();
    CHECK(!step_depth && value->hashes.before == UINT32_C(0xcafe6400) &&
        value->hashes.after == UINT32_C(0xcafe6400));
    active = NULL;
}

int main(void)
{
    char *operands[] = {NULL, "--argument", "@file", "$file", "", "@", "$", "\xFF"};
    for (size_t operand = 0; operand < sizeof(operands) / sizeof(*operands); ++operand) {
        char *arguments[] = {"engine", operands[operand], NULL};
        for (fault = NONE; fault <= PORTS; ++fault) for (variant = 0; variant < 16; ++variant) {
            int argc = operand ? 2 : 1;
            struct call previous = {.argc = argc, .argv = arguments};
            struct call direct = {.argc = argc, .argv = arguments, .direct = true};
            run_prefix(&previous);
            struct params_s after_previous = params;
            run_prefix(&direct);
            if (strcmp(previous.trace, direct.trace))
                fprintf(stderr, "previous: %s\ndirect: %s\n", previous.trace, direct.trace);
            CHECK(!strcmp(previous.trace, direct.trace));
            CHECK(previous.exit_code == direct.exit_code && previous.proceed == direct.proceed);
            CHECK(previous.argc == direct.argc && previous.argv == direct.argv);
            CHECK(!memcmp(previous.hashes.words, direct.hashes.words, sizeof(previous.hashes.words)));
            CHECK(previous.flow.profiles == direct.flow.profiles && previous.flow.templates == direct.flow.templates &&
                previous.flow.current == direct.flow.current && previous.flow.count == direct.flow.count &&
                previous.flow.template_count == direct.flow.template_count && previous.flow.skip == direct.flow.skip &&
                previous.flow.template == direct.flow.template);
            CHECK(previous.entry == direct.entry && previous.profile == direct.profile);
            CHECK(after_previous.wexp.we_wordv == params.wexp.we_wordv &&
                after_previous.wexp.we_wordc == params.wexp.we_wordc &&
                after_previous.windivert_filter == params.windivert_filter &&
                !memcmp(after_previous.verstr, params.verstr, sizeof(params.verstr)));
            ++cases;
        }
    }
    fprintf(stdout, "PASS main_prefix_direct cases=%u reentries=%u c_longjmps=%u steps=%u "
        "deferred_profile=1 argc_truncation=1 hashes_guarded=1 exact_trace=1\n", cases, reentries, nonlocal_exits, steps);
    return 0;
}
