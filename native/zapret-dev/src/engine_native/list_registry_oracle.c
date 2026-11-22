/* MIT. Deterministic list lifecycles through the original and native APIs. */
#include "pools.h"
#include "pools_windows.h"

static unsigned step, registration_checks, reference_checks, reload_checks;

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL list registry step %u line %d: %s\n", step, __LINE__, #condition); \
        exit(1); \
    } \
} while (0)

static file_mod_sig disk_stamp;
static bool have_file, readable, load_ok;
static unsigned revision;
static char calls[16];
static size_t call_count;

static void trace(char code)
{
    CHECK(call_count < sizeof(calls));
    calls[call_count++] = code;
}

bool file_mod_signature(const char *filename, file_mod_sig *stamp)
{
    CHECK(filename && *filename);
    trace('s');
    // The native comparison must ignore structure padding.
    memset(stamp, 0xa5, sizeof(*stamp));
    stamp->mod_time.tv_sec = disk_stamp.mod_time.tv_sec;
    stamp->mod_time.tv_nsec = disk_stamp.mod_time.tv_nsec;
    stamp->size = disk_stamp.size;
    return have_file;
}

bool file_open_test(const char *filename, int mode)
{
    CHECK(filename && *filename && mode == O_RDONLY);
    trace('p');
    return readable;
}

static char *fixture_realpath(const char *filename, char *canonical)
{
    if (!strcmp(filename, "missing")) return NULL;
    if (!strcmp(filename, "alias")) filename = "shared";
    return strcpy(canonical, filename);
}

static int DLOG_PERROR(const char *message)
{
    trace(!strcmp(message, "file_mod_signature") ? 'S' : 'P');
    return 0;
}

static int DLOG_ERR(const char *format, ...)
{
    CHECK(format && *format);
    trace('E');
    return 0;
}

static void domain(char name[20], unsigned number)
{
    snprintf(name, 20, "r%u.example", number);
}

static bool AppendHostList(hostlist_pool **pool, const char *filename)
{
    CHECK(filename && *filename);
    trace('a');
    char name[20];
    domain(name, revision);
    CHECK(zapret_host_add(pool, (const unsigned char *)name, strlen(name), 0));
    return load_ok;
}

static void ip_addresses(unsigned number, unsigned char v4[4], unsigned char v6[16])
{
    const unsigned char a4[] = {192, 0, 2, number};
    const unsigned char a6[] = {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, number};
    memcpy(v4, a4, sizeof(a4));
    memcpy(v6, a6, sizeof(a6));
}

static bool AppendIpset(ipset *set, const char *filename)
{
    CHECK(filename && *filename);
    trace('a');
    unsigned char a4[4], a6[16];
    ip_addresses(revision, a4, a6);
    CHECK(zapret_ip_add(&set->ips4, a4, 32, 32));
    CHECK(zapret_ip_add(&set->ips6, a6, 128, 128));
    return load_ok;
}

void HostlistPoolDestroy(hostlist_pool **pool) { zapret_host_destroy(pool); }
void ipsetDestroy(ipset *set)
{
    zapret_ip_destroy(&set->ips4);
    zapret_ip_destroy(&set->ips6);
}

#define wf_realpath fixture_realpath
#define LoadHostList ReferenceLoadHostList
#define LoadIpset ReferenceLoadIpset
#include "list_registry_reference.inc"
#undef LoadIpset
#undef LoadHostList

#include "list_registry_windows.c"
#undef wf_realpath
#define ZAPRET_RELOAD_HOSTS 1
#include "list_reload_windows.inc"
#define ZAPRET_RELOAD_HOSTS 0
#include "list_reload_windows.inc"

static void same_name(const char *a, const char *b)
{
    CHECK(!!a == !!b);
    if (a) CHECK(!strcmp(a, b));
}

static void same_contents(hostlist_pool *hosts, ipset *ips, struct zapret_list_file *file)
{
    CHECK(!!hosts == !!file->hostlist);
    CHECK((ips && ips->ips4) == !!file->ipset.ips4);
    CHECK((ips && ips->ips6) == !!file->ipset.ips6);
    for (unsigned number = 1; number <= 8; ++number) {
        char name[20];
        unsigned char a4[4], a6[16];
        domain(name, number);
        ip_addresses(number, a4, a6);
        CHECK(zapret_host_has(hosts, name) == zapret_host_has(file->hostlist, name));
        if (ips) {
            CHECK(zapret_ip_check(ips->ips4, a4, 32) == zapret_ip_check(file->ipset.ips4, a4, 32));
            CHECK(zapret_ip_check(ips->ips6, a6, 128) == zapret_ip_check(file->ipset.ips6, a6, 128));
        }
    }
}

static void check_reload(struct hostlist_file *hosts, struct ipset_file *ips,
    struct zapret_list_file *rust_hosts, struct zapret_list_file *rust_ips)
{
    static const struct {
        int64_t seconds, size;
        int32_t nanoseconds;
        bool exists, readable, valid, initial_changed;
    } scenarios[] = {
        {90, 50, 100, true, true, true, false},
        {90, 50, 100, true, true, true, true},
        {91, 50, 100, false, false, false, false},
        {90, 50, 101, true, false, true, false},
        {90, 50, 101, true, true, true, false},
        {90, 51, 101, true, true, false, false},
        {90, 51, 101, true, true, true, false},
        {91, 51, 101, true, true, true, false},
    };
    for (size_t i = 0; i < sizeof(scenarios) / sizeof(*scenarios); ++i) {
        ++step;
        disk_stamp.mod_time.tv_sec = scenarios[i].seconds;
        disk_stamp.mod_time.tv_nsec = scenarios[i].nanoseconds;
        disk_stamp.size = scenarios[i].size;
        have_file = scenarios[i].exists;
        readable = scenarios[i].readable;
        load_ok = scenarios[i].valid;
        revision = i + 1;
        bool changed_c = scenarios[i].initial_changed;
        bool changed_rust = changed_c;
        char expected[sizeof(calls)];
        call_count = 0;
        bool ok = ReferenceLoadHostList(hosts, &changed_c);
        size_t count = call_count;
        memcpy(expected, calls, count);
        call_count = 0;
        CHECK(LoadHostList(rust_hosts, &changed_rust) == ok);
        CHECK(call_count == count && !memcmp(expected, calls, count));
        CHECK(changed_rust == changed_c && FILE_MOD_COMPARE(&hosts->mod_sig, &rust_hosts->mod_sig));
        same_contents(hosts->hostlist, NULL, rust_hosts);
        ++reload_checks;

        call_count = 0;
        ok = ReferenceLoadIpset(ips);
        count = call_count;
        memcpy(expected, calls, count);
        call_count = 0;
        CHECK(LoadIpset(rust_ips) == ok);
        CHECK(call_count == count && !memcmp(expected, calls, count));
        CHECK(FILE_MOD_COMPARE(&ips->mod_sig, &rust_ips->mod_sig));
        same_contents(NULL, &ips->ipset, rust_ips);
        ++reload_checks;
    }
}

static void compare_host_order(const struct hostlist_files_head *files, const struct hostlist_collection_head *refs,
    const struct zapret_list_files *rust_files, const struct zapret_list_collection *rust_refs)
{
    struct hostlist_file *file;
    struct hostlist_item *item;
    size_t position = 0;
    LIST_FOREACH(file, files, next) {
        struct zapret_list_file *actual = zapret_list_files_at(rust_files, position++);
        CHECK(actual);
        same_name(file->filename, actual->filename);
        ++reference_checks;
    }
    CHECK(!zapret_list_files_at(rust_files, position));
    position = 0;
    LIST_FOREACH(item, refs, next) {
        struct zapret_list_file *actual = zapret_list_collection_at(rust_refs, position++);
        CHECK(actual);
        same_name(item->hfile->filename, actual->filename);
        ++reference_checks;
    }
    CHECK(!zapret_list_collection_at(rust_refs, position));
    CHECK(hostlist_collection_is_empty(refs) == zapret_list_collection_empty(rust_refs));
}

static void check_registration(void)
{
    struct hostlist_files_head c_files = {0};
    struct hostlist_collection_head c_base = {0}, c_template = {0};
    struct zapret_list_files *files = NULL;
    struct zapret_list_collection *base = NULL, *template = NULL;
    struct hostlist_file *c_shared = RegisterHostlist_(&c_files, &c_base, "shared");
    struct zapret_list_file *shared = zapret_list_register_path(&files, &base, "shared");
    CHECK(c_shared && shared);
    for (step = 1; step <= 520; ++step) {
        char generated[48];
        snprintf(generated, sizeof(generated), "groups/%u.example", step % 97);
        const char *name = step % 13 == 0 ? "missing" :
            step % 7 == 0 ? NULL : step % 3 == 0 ? "alias" : generated;
        bool use_template = step % 2 == 0;
        struct hostlist_collection_head *c_refs = use_template ? &c_template : &c_base;
        struct zapret_list_collection **refs = use_template ? &template : &base;
        struct hostlist_file *left = RegisterHostlist_(&c_files, c_refs, name);
        struct zapret_list_file *right = zapret_list_register_path(&files, refs, name);
        CHECK(!!left == !!right);
        if (left) {
            same_name(left->filename, right->filename);
            CHECK((left == c_shared) == (right == shared));
        }
        ++registration_checks;
        if (step % 47 == 0) {
            CHECK(hostlist_collection_copy(&c_base, &c_template));
            CHECK(zapret_list_collection_copy(&base, template));
        }
        if (step % 11 == 0) compare_host_order(&c_files, c_refs, files, *refs);
    }
    CHECK(RegisterHostlist_(&c_files, &c_template, "alias") == c_shared);
    CHECK(zapret_list_register_path(&files, &template, "alias") == shared);
    compare_host_order(&c_files, &c_base, files, base);
    compare_host_order(&c_files, &c_template, files, template);
    CHECK(zapret_list_collection_empty(base));

    struct ipset_files_head c_ips = {0};
    struct ipset_collection_head c_incl = {0}, c_excl = {0};
    struct zapret_list_files *ip_files = NULL;
    struct zapret_list_collection *incl = NULL, *excl = NULL;
    struct ipset_file *c_ip = RegisterIpset_(&c_ips, &c_incl, "shared");
    struct zapret_list_file *ip = zapret_list_register_path(&ip_files, &incl, "shared");
    CHECK(c_ip && ip && ip != shared);
    CHECK(RegisterIpset_(&c_ips, &c_excl, "alias") == c_ip);
    CHECK(zapret_list_register_path(&ip_files, &excl, "alias") == ip);
    struct ipset_file *c_fixed = RegisterIpset_(&c_ips, &c_excl, NULL);
    struct zapret_list_file *fixed = zapret_list_register_path(&ip_files, &excl, NULL);
    CHECK(c_fixed && fixed && ip != fixed);
    CHECK(ipset_collection_copy(&c_incl, &c_excl));
    CHECK(zapret_list_collection_copy(&incl, excl));
    struct ipset_item *item;
    size_t position = 0;
    LIST_FOREACH(item, &c_incl, next) {
        struct zapret_list_file *actual = zapret_list_collection_at(incl, position++);
        CHECK(actual == (item->hfile == c_ip ? ip : fixed));
        same_name(item->hfile->filename, actual->filename);
        ++reference_checks;
    }
    CHECK(!zapret_list_collection_at(incl, position));
    CHECK(zapret_list_files_at(ip_files, 0) == fixed && zapret_list_files_at(ip_files, 1) == ip);
    CHECK(!zapret_list_files_at(ip_files, 2));

    check_reload(c_shared, c_ip, shared, ip);
    CHECK(!zapret_list_collection_empty(base) && !zapret_list_collection_empty(template));
    CHECK(!ipset_collection_is_empty(&c_incl) && !zapret_list_collection_empty(incl));
    CHECK(!ipset_collection_is_empty(&c_excl) && !zapret_list_collection_empty(excl));
    call_count = 0;
    CHECK(ReferenceLoadIpset(c_fixed) && LoadIpset(fixed) && !call_count);

    hostlist_files_reset_modtime(&c_files);
    ipset_files_reset_modtime(&c_ips);
    zapret_list_files_reset(files);
    zapret_list_files_reset(ip_files);
    CHECK(FILE_MOD_COMPARE(&c_shared->mod_sig, &shared->mod_sig));
    CHECK(FILE_MOD_COMPARE(&c_ip->mod_sig, &ip->mod_sig));
    CHECK(!shared->mod_sig.size && !ip->mod_sig.size && !zapret_list_collection_empty(incl));
    call_count = 0;
    CHECK(LoadIpset(ip) && call_count == 3 && !memcmp(calls, "spa", 3));
    ++reload_checks;

    hostlist_collection_destroy(&c_base);
    hostlist_collection_destroy(&c_template);
    ipset_collection_destroy(&c_incl);
    ipset_collection_destroy(&c_excl);
    hostlist_files_destroy(&c_files);
    ipset_files_destroy(&c_ips);
    zapret_list_collection_destroy(&base);
    zapret_list_collection_destroy(&template);
    zapret_list_collection_destroy(&incl);
    zapret_list_collection_destroy(&excl);
    zapret_list_files_destroy(&files);
    zapret_list_files_destroy(&ip_files);
    CHECK(!base && !template && !incl && !excl && !files && !ip_files);
}

#undef main
int main(void)
{
    check_registration();
    printf("PASS %u registration cases, %u ordered references, %u reload cases against pinned C\n",
        registration_checks, reference_checks, reload_checks);
    return 0;
}
