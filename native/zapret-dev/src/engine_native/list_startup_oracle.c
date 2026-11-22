/* Use actual list/profile layouts and a private in-memory registry. */
#include "params.h"
#include "helpers.h"
#include <stdarg.h>
#undef main
struct params_s params;
static struct zapret_list_file files[3], *failed_file;
static struct desync_profile_list profiles[4];
static struct zapret_list_files *alternate;
static char trace[2048];
static unsigned calls, fail, mutate, cases;
#define CHECK(p) do { if (!(p)) { \
    fprintf(stderr, "FAIL list_startup case=%u line=%d: %s\n", cases, __LINE__, #p); exit(1); \
} } while(0)
static int record(const char *format, ...)
{
    size_t used = strlen(trace);
    va_list args;
    va_start(args, format);
    int n = vsnprintf(trace + used, sizeof(trace) - used, format, args);
    va_end(args);
    CHECK(n >= 0 && (size_t)n < sizeof(trace) - used);
    return n;
}
static bool probe(const char *name, int flags)
{
    CHECK(flags == O_RDONLY);
    record("open:%s;", name);
    if (++calls == 1 && (mutate & 1) && alternate) params.hostlists = alternate;
    return calls != fail;
}
static int logged_errno(const char *origin)
{
    record("errno:%s;", origin);
    if ((mutate & 2) && failed_file) failed_file->filename = "after errno";
    return 0;
}
static bool size_probe(const char *name, off_t *length)
{
    CHECK(!length);
    record("stat:%s;", name);
    return ++calls != fail;
}
static struct zapret_list_file *register_path(struct zapret_list_files **registry,
    struct zapret_list_collection **collection, const char *name)
{
    struct desync_profile *p = &profiles[0].dp;
    unsigned target = collection == &p->hl_collection ? 0 :
        collection == &p->hl_collection_exclude ? 1 :
        collection == &p->ips_collection ? 2 :
        collection == &p->ips_collection_exclude ? 3 : 4;
    CHECK(target < 4);
    CHECK(registry == (target < 2 ? &params.hostlists : &params.ipsets));
    record("register:%u:%s;", target, name ? name : "<null>");
    return ++calls == fail ? NULL : &files[0];
}
static bool host_add(hostlist_pool **slot, const char *name, size_t length, uint32_t flags)
{
    unsigned index = slot == &files[0].hostlist ? 0 : slot == &files[1].hostlist ? 1 : 2;
    CHECK(slot == &files[index].hostlist);
    record("host:%u:%.*s:%u;", index, (int)length, name, flags);
    if (++calls == 1 && (mutate & 1)) profiles[0].next.le_next = &profiles[2];
    if (calls == fail) return false;
    *slot = (hostlist_pool *)(uintptr_t)(index + 1);
    return true;
}
#define DLOG_ERR record
#define DLOG_PERROR logged_errno
#define file_open_test probe
#define file_size size_probe
#define zapret_list_register_path register_path
#define HostlistPoolAddStrLen host_add
#define NonEmptyHostlist reference_nonempty
#define MakeAutolistsNonEmpty reference_automatic
#define RegisterHostlist reference_register_host
#define RegisterIpset reference_register_ip
#define test_list_files reference_probe
#include "list_startup_reference.inc"
#undef NonEmptyHostlist
#undef MakeAutolistsNonEmpty
#undef RegisterHostlist
#undef RegisterIpset
#undef test_list_files
#include "list_startup_probe_windows.inc"
#include "list_startup_sentinel_windows.inc"
#define ZAPRET_LIST_STARTUP_HOSTS 1
#include "list_startup_register_windows.inc"
#undef ZAPRET_LIST_STARTUP_HOSTS
#define ZAPRET_LIST_STARTUP_HOSTS 0
#include "list_startup_register_windows.inc"
#undef ZAPRET_LIST_STARTUP_HOSTS

static bool run(bool selected, unsigned operation, unsigned shape)
{
    memset(&params, 0, sizeof(params));
    memset(files, 0, sizeof(files));
    memset(profiles, 0, sizeof(profiles));
    calls = 0;
    trace[0] = 0;
    const char *name = shape == 0 ? NULL : shape == 1 ? "" : "x.txt";
    struct desync_profile *profile = &profiles[0].dp;
    if (name && fail == 1 && (mutate & 2)) profile = NULL;
    switch (operation) {
    case 0: return (selected ? RegisterHostlist : reference_register_host)(profile, shape & 1, name) != NULL;
    case 1: return (selected ? RegisterIpset : reference_register_ip)(profile, shape & 1, name) != NULL;
    case 2: {
        struct zapret_list_files *hosts = NULL;
        struct zapret_list_collection *collection = NULL;
        const char *names[] = {"first", NULL, "", "last"};
        for (size_t i = 0; i < sizeof(names) / sizeof(*names); ++i)
            CHECK(zapret_list_register(&hosts, &collection, names[i]));
        CHECK(zapret_list_register(&params.ipsets, &collection, "ip"));
        CHECK(zapret_list_register(&alternate, &collection, "replacement"));
        params.hostlists = hosts;
        failed_file = zapret_list_files_at(hosts, 0);
        bool result = (selected ? test_list_files : reference_probe)();
        zapret_list_collection_destroy(&collection);
        zapret_list_files_destroy(&hosts);
        zapret_list_files_destroy(&params.ipsets);
        zapret_list_files_destroy(&alternate);
        failed_file = NULL;
        return result;
    }
    case 3:
        if (shape & 1) files[0].hostlist = (hostlist_pool *)(uintptr_t)1;
        return (selected ? NonEmptyHostlist : reference_nonempty)(&files[0].hostlist);
    default:
        params.desync_profiles.lh_first = profiles;
        for (unsigned i = 0; i < 3; ++i) profiles[i].next.le_next = &profiles[i+1];
        profiles[0].dp.hostlist_auto = &files[0];
        profiles[1].dp.hostlist_auto = &files[1];
        profiles[2].dp.hostlist_auto = &files[0];
        profiles[3].dp.hostlist_auto = shape & 1 ? &files[2] : NULL;
        (selected ? MakeAutolistsNonEmpty : reference_automatic)();
        for (unsigned i = 0; i < 3; ++i) record("slot:%u;", files[i].hostlist != NULL);
        return true;
    }
}
int main(void)
{
    for (unsigned operation = 0; operation < 5; ++operation)
        for (unsigned shape = 0; shape < 4; ++shape)
            for (fail = 0; fail < 7; ++fail)
                for (mutate = 0; mutate < 4; ++mutate) {
                    char before[sizeof(trace)];
                    bool expected = run(false, operation, shape);
                    strcpy(before, trace);
                    bool actual = run(true, operation, shape);
                    CHECK(expected == actual && !strcmp(before, trace));
                    ++cases;
                }
    printf("PASS list_startup cases=%u preflight_order=1 deferred_registry_and_names=1 "
        "include_exclude=1 shared_auto_files=1\n", cases);
    return 0;
}
