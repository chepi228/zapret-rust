/* MIT. Compare the previous and current main frames with local callbacks. */
#include "params.h"
#include "nfqws.h"
#include "profile_flow_windows.h"
#include "engine_entry_capture_type.inc"
#include "engine_entry_abi.h"
#include <setjmp.h>

#undef main
#undef getenv
#undef close_std
#define close_std fixture_close_std
enum { WF_COUNT = 16, IDX_BLOB = 17, IDX_DRY = 1, IDX_VERSION = 4 };
#include "engine_main_prefix_abi.h"

enum failure {
    NONE, SERVICE, INITIALIZE, CONFIG, PREFIX_PROFILE, BLOB_READ, PROFILE_FINISH,
    VALIDATE, PREPARE, RUN, REPLACE_ARGUMENTS
};
enum observation {
    SEEN_SERVICE, SEEN_INIT, SEEN_BANNER, SEEN_HELP, SEEN_BLOBS, SEEN_NEXT_PROFILE,
    SEEN_PROFILE_REPORT, SEEN_OPTIONS, SEEN_COUNT, SEEN_ENVIRONMENT, SEEN_DRY,
    SEEN_VERSION, SEEN_BLOB_READ, SEEN_FINISH_PROFILE, SEEN_ARGUMENTS_FREE,
    SEEN_VALIDATE, SEEN_CAPTURE, SEEN_PREPARE, SEEN_RUN, SEEN_CLEANUP,
    SEEN_MUTEX_RELEASE, SEEN_STDIO, SEEN_EXIT, SEEN_CONFIG_REPLACED
};

typedef struct {
    uint32_t trace[64];
    size_t count;
    int result;
    unsigned reads;
    int *argc;
    char ***argv;
    enum failure failure;
} trial;

static trial *active;
static jmp_buf escaped;
static unsigned advancing, cases, escapes;
static struct desync_profile_list entry;
struct params_s params;

#define CHECK(value) do { \
    if (!(value)) { \
        fprintf(stderr, "FAIL main frame case=%u fault=%u line=%d: %s\n", \
            cases, active ? active->failure : NONE, __LINE__, #value); \
        exit(1); \
    } \
} while (0)

static void note(enum observation event, unsigned value)
{
    CHECK(active->count < sizeof(active->trace) / sizeof(*active->trace) && value < 65536);
    active->trace[active->count++] = ((unsigned)event << 16) | value;
}

static void host(enum observation event, unsigned value)
{
    CHECK(!advancing);
    note(event, value);
}

static void leave(int code)
{
    host(SEEN_EXIT, code);
    active->result = code;
    ++escapes;
    longjmp(escaped, 1);
}

bool service_run(int argc, char **argv)
{
    CHECK(argc == *active->argc && argv == *active->argv);
    host(SEEN_SERVICE, argc);
    return active->failure == SERVICE;
}

void init_params(struct params_s *settings)
{
    CHECK(settings == &params);
    host(SEEN_INIT, 0);
    if (active->failure == INITIALIZE) leave(19);
}

void zapret_native_main_version(bool pinned, const char *version, const char *revision, uint32_t compat)
{
    CHECK(version && revision);
    host(SEEN_BANNER, compat);
}

static void exithelp(void) { host(SEEN_HELP, 0); leave(1); }
static void exithelp_clean(void) { host(SEEN_HELP, 1); leave(1); }
static void exit_clean(int code) { leave(code); }

static void ApplyDefaultBlobs(struct blob_collection_head *blobs)
{
    CHECK(blobs == &params.blobs);
    host(SEEN_BLOBS, 0);
}

uint32_t native_profile_next(native_profile_flow *flow, const char *name)
{
    CHECK(!name && !flow->current);
    host(SEEN_NEXT_PROFILE, 0);
    flow->current = &entry;
    flow->count = 1;
    return active->failure == PREFIX_PROFILE;
}

static void native_profile_exit(uint32_t status, const char *name)
{
    if (name) CHECK(!strcmp(name, "observed after finish"));
    host(SEEN_PROFILE_REPORT, status);
    if (status) leave(1);
}

uint32_t zapret_native_main_prefix_step(zapret_native_prefix_cursor *cursor, const zapret_native_prefix_slots *slots)
{
    static char *configured[] = {"configured", "--dry-run", "--blob=one", NULL};
    active->argc = slots->argc;
    active->argv = slots->argv;
    switch (cursor->phase) {
    case 0: return cursor->phase = NATIVE_PREFIX_SERVICE;
    case NATIVE_PREFIX_SERVICE:
        return cursor->phase = cursor->available ? NATIVE_PREFIX_STOP : NATIVE_PREFIX_PARAMS;
    case NATIVE_PREFIX_PARAMS: return cursor->phase = NATIVE_PREFIX_BANNER;
    case NATIVE_PREFIX_BANNER:
        return cursor->phase = *slots->argc < 2 ? NATIVE_PREFIX_HELP : NATIVE_PREFIX_BLOBS;
    case NATIVE_PREFIX_BLOBS:
        *slots->profiles = (native_profile_flow){0};
        return cursor->phase = NATIVE_PREFIX_PROFILE;
    case NATIVE_PREFIX_PROFILE:
        if (active->failure == CONFIG) return cursor->phase = NATIVE_PREFIX_EXIT;
        if (active->failure == REPLACE_ARGUMENTS) {
            *slots->argc = 3;
            *slots->argv = configured;
            note(SEEN_CONFIG_REPLACED, 0);
        }
        *slots->entry = slots->profiles->current;
        *slots->profile = &(*slots->entry)->dp;
        memset(slots->hashes, 0, WF_COUNT * sizeof(*slots->hashes));
        return cursor->phase = NATIVE_PREFIX_READY;
    default: CHECK(false); return NATIVE_PREFIX_STOP;
    }
}

static const struct option options[IDX_BLOB + 1] = {
    [IDX_DRY] = {"dry-run", no_argument, NULL, 0},
    [IDX_VERSION] = {"version", no_argument, NULL, 0},
    [IDX_BLOB] = {"blob", required_argument, NULL, 0},
};
static const struct option *zapret_native_cli_options(void)
{
    note(SEEN_OPTIONS, 0);
    return options;
}
#define long_options (zapret_native_cli_options())

static size_t zapret_native_cli_count(void)
{
    note(SEEN_COUNT, 0);
    return sizeof(options) / sizeof(*options);
}

static char *fixture_environment(const char *key)
{
    CHECK(!strcmp(key, "POSIXLY_CORRECT"));
    note(SEEN_ENVIRONMENT, 0);
    return NULL;
}

static bool zapret_native_cli_read_blob(const char *text, size_t maximum, size_t reserve)
{
    CHECK(maximum == 16384 && reserve == 128);
    CHECK(!strcmp(text, active->reads ? "two" : "one"));
    note(SEEN_BLOB_READ, ++active->reads);
    return active->failure != BLOB_READ;
}

static int engine_numeric_option(int index, const char *text, struct desync_profile *profile)
{ CHECK(profile == &entry.dp); return 0; }
static int engine_startup_option(int index, const char *text) { return 0; }
static int engine_list_option(int index, const char *text, struct desync_profile *profile, bool skip,
    struct zapret_list_file **a, struct zapret_list_file **b, struct zapret_list_file **c, struct zapret_list_file **d)
{ return 0; }
static int engine_profile_filter(int index, const char *text, struct desync_profile *profile, uint64_t *payload,
    struct packet_range *incoming, struct packet_range *outgoing) { return 0; }
static int engine_capture_option(int index, const char *text, zapret_capture_cli *capture) { return 0; }
static int engine_control_option(int index, const char *text, native_profile_flow *flow,
    struct desync_profile_list **selected, struct desync_profile **profile,
    struct zapret_list_file **a, struct zapret_list_file **b, struct zapret_list_file **c,
    struct zapret_list_file **d, uint64_t *payload, struct packet_range *incoming,
    struct packet_range *outgoing, bool *dry)
{
    CHECK(*selected == &entry && *profile == &entry.dp && flow->count == 1);
    if (index == IDX_DRY) {
        note(SEEN_DRY, *dry);
        *dry = true;
        return 1;
    }
    if (index == IDX_VERSION) {
        note(SEEN_VERSION, 0);
        return 2;
    }
    CHECK(index == IDX_BLOB);
    return 0;
}

int DLOG_ERR(const char *format, ...) { CHECK(false); return 0; }

uint32_t native_profile_finish(native_profile_flow *flow)
{
    CHECK(flow->current == &entry && flow->count == 1);
    note(SEEN_FINISH_PROFILE, flow->count);
    entry.dp.name = "observed after finish";
    return active->failure == PROFILE_FINISH;
}

void cleanup_args(struct params_s *settings)
{
    CHECK(settings == &params && *active->argc >= 2 && *active->argv);
    note(SEEN_ARGUMENTS_FREE, *active->argc);
}

static bool native_startup_validate(unsigned count, unsigned templates)
{
    CHECK(!*active->argc && !*active->argv && count == 1 && !templates);
    note(SEEN_VALIDATE, count);
    return active->failure != VALIDATE;
}

typedef struct { uint32_t status, error; } zapret_capture_prepare_result;
static zapret_capture_prepare_result native_capture_prepare(unsigned index, unsigned sub, bool ipv4,
    bool ipv6, bool lan, bool loopback, bool empty, bool duplicate, bool dry, const char *save,
    const unsigned *hashes, HANDLE *mutex)
{
    CHECK(!index && !sub && ipv4 && ipv6 && lan && loopback && !empty && duplicate);
    CHECK(!*save && !*mutex && !hashes[0] && !hashes[WF_COUNT - 1]);
    host(SEEN_CAPTURE, dry);
    *mutex = (HANDLE)(uintptr_t)1;
    return (zapret_capture_prepare_result){0};
}

static uint32_t zapret_native_lifecycle_prepare(struct params_s *settings, bool dry)
{
    CHECK(settings == &params);
    note(SEEN_PREPARE, dry);
    if (dry) return 8;
    return active->failure == PREPARE;
}

static int win_main(void)
{
    host(SEEN_RUN, 0);
    if (active->failure == RUN) leave(37);
    return 13;
}

void cleanup_params(struct params_s *settings)
{
    CHECK(settings == &params);
    host(SEEN_CLEANUP, 0);
}

static void zapret_native_lifecycle_release_mutex(HANDLE *mutex)
{
    note(SEEN_MUTEX_RELEASE, *mutex != NULL);
    *mutex = NULL;
}

void close_std(void) { note(SEEN_STDIO, 0); }

#define getenv fixture_environment
#include "engine_entry_rust.inc"
#include "engine_main_prefix_windows.inc"
#include "engine_arguments_reference.inc"
#define main current_main
#include "engine_host_main_windows.inc"
#undef main
#undef getenv

uint32_t __real_zapret_native_main_advance(zapret_native_main_state *, struct params_s *, const zapret_native_main_ops *);
uint32_t __wrap_zapret_native_main_advance(zapret_native_main_state *state, struct params_s *settings,
    const zapret_native_main_ops *ops)
{
    CHECK(!advancing);
    ++advancing;
    uint32_t result = __real_zapret_native_main_advance(state, settings, ops);
    --advancing;
    return result;
}

static void run(trial *value, bool current, int argc, char **argv)
{
    active = value;
    entry.dp.name = "original";
    if (!setjmp(escaped)) value->result = (current ? current_main : native_engine_main)(argc, argv);
    CHECK(!advancing);
}

int main(void)
{
    const struct {
        enum failure failure;
        int argc, result;
        char *arguments[5];
    } fixtures[] = {
        {NONE, 3, 13, {"fixture", "--blob=one", "--blob=two"}},
        {SERVICE, 3, 0, {"fixture", "--blob=one", "--blob=two"}},
        {INITIALIZE, 2, 19, {"fixture", "--version"}},
        {NONE, 1, 1, {"fixture"}},
        {CONFIG, 2, 1, {"fixture", "@fixture"}},
        {REPLACE_ARGUMENTS, 2, 0, {"fixture", "@fixture"}},
        {PREFIX_PROFILE, 2, 1, {"fixture", "--version"}},
        {NONE, 3, 0, {"fixture", "--version", "--blob=one"}},
        {NONE, 2, 1, {"fixture", "--unknown"}},
        {NONE, 3, 1, {"fixture", "--dry-run", "--unknown"}},
        {BLOB_READ, 3, 1, {"fixture", "--blob=one", "--blob=two"}},
        {PROFILE_FINISH, 2, 1, {"fixture", "--blob=one"}},
        {VALIDATE, 2, 1, {"fixture", "--blob=one"}},
        {NONE, 2, 0, {"fixture", "--dry-run"}},
        {PREPARE, 2, 1, {"fixture", "--blob=one"}},
        {RUN, 2, 37, {"fixture", "--blob=one"}},
    };
    for (size_t i = 0; i < sizeof(fixtures) / sizeof(*fixtures); ++i) {
        trial reference = {.failure = fixtures[i].failure}, current = reference;
        char *arguments[5];
        memcpy(arguments, fixtures[i].arguments, sizeof(arguments));
        run(&reference, false, fixtures[i].argc, arguments);
        run(&current, true, fixtures[i].argc, arguments);
        if (current.result != fixtures[i].result)
            fprintf(stderr, "status expected=%d previous=%d current=%d\n", fixtures[i].result, reference.result, current.result);
        CHECK(reference.result == current.result && current.result == fixtures[i].result);
        CHECK(reference.count == current.count && reference.reads == current.reads &&
            !memcmp(reference.trace, current.trace, current.count * sizeof(*current.trace)));
        ++cases;
    }
    printf("PASS engine_host_main cases=%u host_escapes=%u same_argv_replacement=1 exact_trace=1\n", cases, escapes);
    return 0;
}
