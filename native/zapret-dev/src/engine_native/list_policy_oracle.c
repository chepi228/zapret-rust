/* MIT. Real Rust pools and registry; pinned C decisions and callback traces. */
#include "params.h"
#include "hostlist.h"
#include "ipset.h"
#include "helpers.h"
#include "pools_windows.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#undef main
struct params_s params;
static unsigned cases, mutation_checks;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL list policy case=%u line=%d: %s\n", cases, __LINE__, #condition); exit(1); } \
} while (0)
struct capture { unsigned reloads, automatic; size_t used; char bytes[16384]; };
static struct capture captured;
static bool recording = true, mutate;
static uint64_t failures, changes;
static struct zapret_list_file *files[12];
static void event(const char *format, ...)
{
    if (!recording) return;
    va_list arguments; va_start(arguments, format);
    int count = vsnprintf(captured.bytes + captured.used, sizeof(captured.bytes) - captured.used, format, arguments);
    va_end(arguments);
    CHECK(count >= 0 && (size_t)count < sizeof(captured.bytes) - captured.used);
    captured.used += (size_t)count;
}
static int log_message(const char *format, ...)
{
    if (!params.debug || !recording) return 0;
    va_list arguments; va_start(arguments, format);
    int count = vsnprintf(captured.bytes + captured.used, sizeof(captured.bytes) - captured.used, format, arguments);
    va_end(arguments);
    CHECK(count >= 0 && (size_t)count < sizeof(captured.bytes) - captured.used);
    captured.used += (size_t)count;
    return count;
}
#define DLOG log_message
static unsigned identity(struct zapret_list_file *file)
{
    for (unsigned index = 0; index < 12; ++index) if (files[index] == file) return index;
    CHECK(false); return 99;
}
static bool LoadHostList(struct zapret_list_file *file, bool *changed)
{
    unsigned id = identity(file);
    if (recording) ++captured.reloads;
    event("H%u;", id);
    if (changes & (UINT64_C(1) << id)) *changed = true;
    if (mutate && id == 0) {
        zapret_host_destroy(&file->hostlist);
        CHECK(zapret_host_add(&file->hostlist, (const uint8_t *)"example", 7, 0));
    }
    return !(failures & (UINT64_C(1) << id));
}
static bool LoadIpset(struct zapret_list_file *file)
{
    unsigned id = identity(file);
    if (recording) ++captured.reloads;
    event("I%u;", id);
    return !(failures & (UINT64_C(1) << id));
}
static void MakeAutolistsNonEmpty(void)
{
    if (recording) ++captured.automatic;
    event("A;");
}
bool ipset4Check(const struct zapret_ip_pool *pool, const struct in_addr *address, uint8_t bits)
{ return zapret_ip_check(pool, (const uint8_t *)address, bits) != 0; }
bool ipset6Check(const struct zapret_ip_pool *pool, const struct in6_addr *address, uint8_t bits)
{ return zapret_ip_check(pool, (const uint8_t *)address, bits) != 0; }
#include "host_search_windows.c"
#include "list_policy_reference.inc"
#include "host_policy_windows.inc"
#include "ip_policy_windows.inc"

struct result { bool value, excluded; struct capture trace; };
static void reset(void) { memset(&captured, 0, sizeof(captured)); }
static void equal(const struct result *expected, const struct result *actual)
{
    if (expected->value != actual->value || expected->excluded != actual->excluded || memcmp(&expected->trace, &actual->trace, sizeof(captured))) {
        fprintf(stderr, "expected value=%d excluded=%d trace=%s\nactual value=%d excluded=%d trace=%s\n",
            expected->value, expected->excluded, expected->trace.bytes, actual->value, actual->excluded, actual->trace.bytes);
        CHECK(false);
    }
    ++cases;
}
static void compare_host(const struct desync_profile *profile, const char *host, bool exact, bool skip, bool output)
{
    struct result expected = {.excluded = true}, actual = {.excluded = true};
    reset(); expected.value = reference_HostlistCheck(profile, host, exact, output ? &expected.excluded : NULL, skip); expected.trace = captured;
    reset(); actual.value = HostlistCheck(profile, host, exact, output ? &actual.excluded : NULL, skip); actual.trace = captured;
    equal(&expected, &actual);
}
static void compare_ip(const struct desync_profile *profile, const struct in_addr *v4, const struct in6_addr *v6,
    const struct in_addr *reverse4, const struct in6_addr *reverse6)
{
    struct result expected = {0}, actual = {0};
    reset(); expected.value = reference_IpsetCheck(profile, v4, v6, reverse4, reverse6); expected.trace = captured;
    reset(); actual.value = IpsetCheck(profile, v4, v6, reverse4, reverse6); actual.trace = captured;
    equal(&expected, &actual);
}
static void compare_reload(const struct desync_profile *profile, bool ips)
{
    struct result expected = {0}, actual = {0};
    reset(); expected.value = ips ? reference_IpsetsReloadCheckForProfile(profile) : reference_HostlistsReloadCheckForProfile(profile); expected.trace = captured;
    reset(); actual.value = ips ? IpsetsReloadCheckForProfile(profile) : HostlistsReloadCheckForProfile(profile); actual.trace = captured;
    equal(&expected, &actual);
}
static void compare_global(bool ips)
{
    struct result expected = {0}, actual = {0};
    reset(); expected.value = ips ? reference_LoadAllIpsets() : reference_LoadAllHostLists(); expected.trace = captured;
    reset(); actual.value = ips ? LoadAllIpsets() : LoadAllHostLists(); actual.trace = captured;
    equal(&expected, &actual);
}
static volatile unsigned sink;
static double measure(const struct desync_profile *profile, bool rust, bool ips, const struct in_addr *address)
{
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency); QueryPerformanceCounter(&start);
    for (unsigned index = 0; index < 65536; ++index) {
        if (ips) sink ^= rust ? IpsetCheck(profile, address, NULL, NULL, NULL) : reference_IpsetCheck(profile, address, NULL, NULL, NULL);
        else sink ^= rust ? HostlistCheck(profile, "sub.only.example", false, NULL, true) : reference_HostlistCheck(profile, "sub.only.example", false, NULL, true);
    }
    QueryPerformanceCounter(&end);
    return (double)(end.QuadPart - start.QuadPart) * 1e9 / frequency.QuadPart / 65536;
}
static void benchmark(const char *name, const struct desync_profile *profile, bool ips, const struct in_addr *address)
{
    double c[9], r[9];
    for (unsigned round = 0; round < 9; ++round) {
        if (round % 2) { r[round] = measure(profile, true, ips, address); c[round] = measure(profile, false, ips, address); }
        else { c[round] = measure(profile, false, ips, address); r[round] = measure(profile, true, ips, address); }
    }
    for (unsigned i = 0; i < 9; ++i) for (unsigned j = i + 1; j < 9; ++j) {
        if (c[i] > c[j]) { double swap = c[i]; c[i] = c[j]; c[j] = swap; }
        if (r[i] > r[j]) { double swap = r[i]; r[i] = r[j]; r[j] = swap; }
    }
    printf("BENCH list_policy %s c_ns=%.2f rust_ns=%.2f rounds=9 calls_per_round=65536\n", name, c[4], r[4]);
}
int main(void)
{
    WSADATA winsock; CHECK(!WSAStartup(MAKEWORD(2, 2), &winsock));
    struct zapret_list_collection *hosts[5] = {0}, *ips[5] = {0};
    static const char *const domains[6] = {"example", "only.example", NULL, "other.test", NULL, "autotest"};
    for (unsigned index = 0; index < 6; ++index) {
        char name[16]; snprintf(name, sizeof(name), "h%u", index);
        files[index] = zapret_list_register(&params.hostlists, &hosts[1], index == 5 ? NULL : name); CHECK(files[index]);
        if (domains[index]) CHECK(zapret_host_add(&files[index]->hostlist, (const uint8_t *)domains[index], strlen(domains[index]), index == 1));
        if (index < 5 && index % 2 == 0) CHECK(zapret_list_register(&params.hostlists, &hosts[2], name) == files[index]);
        if (index == 2 || index == 4) CHECK(zapret_list_register(&params.hostlists, &hosts[3], name) == files[index]);
        snprintf(name, sizeof(name), "i%u", index);
        files[index + 6] = zapret_list_register(&params.ipsets, &ips[1], index == 5 ? NULL : name); CHECK(files[index + 6]);
        if (index < 5 && index % 2 == 0) CHECK(zapret_list_register(&params.ipsets, &ips[2], name) == files[index + 6]);
        if (index == 2 || index == 4) CHECK(zapret_list_register(&params.ipsets, &ips[3], name) == files[index + 6]);
    }
    CHECK(zapret_list_collection_copy(&hosts[4], hosts[2]) && zapret_list_collection_copy(&hosts[4], hosts[2]));
    CHECK(zapret_list_collection_copy(&ips[4], ips[2]) && zapret_list_collection_copy(&ips[4], ips[2]));
    const uint8_t a4[] = {10,0,0,0}, b4[] = {192,0,2,0}, a6[] = {0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0};
    CHECK(zapret_ip_add(&files[6]->ipset.ips4, a4, 32, 8));
    CHECK(zapret_ip_add(&files[7]->ipset.ips4, b4, 32, 24));
    CHECK(zapret_ip_add(&files[9]->ipset.ips6, a6, 128, 32));
    CHECK(zapret_ip_add(&files[11]->ipset.ips4, b4, 32, 32) && zapret_ip_add(&files[11]->ipset.ips6, a6, 128, 128));
    static const char *const names[] = {"example", "a.example", "only.example", "sub.only.example", "other.test", "absent", "EXAMPLE", "autotest"};
    struct in_addr v4, reverse4; struct in6_addr v6, reverse6;
    for (unsigned round = 0; round < 4096; ++round) {
        struct desync_profile profile = {0}; profile.n = 7;
        profile.hl_collection = hosts[round % 5]; profile.hl_collection_exclude = hosts[(round / 5) % 5];
        profile.ips_collection = ips[(round / 7) % 5]; profile.ips_collection_exclude = ips[(round / 11) % 5];
        params.debug = round % 2; failures = round % 7 ? 0 : UINT64_C(1) << (round % 12);
        changes = round % 5 ? 0 : UINT64_C(1) << (round % 6); mutate = round % 31 == 0;
        compare_host(&profile, names[(round / 3) % 8], round % 3 == 0, round % 4 == 0, round % 7 != 0);
        if (mutate) ++mutation_checks;
        uint8_t primary4[] = {(uint8_t)(round % 2 ? 10 : 192), 0, 2, (uint8_t)round}; memcpy(&v4, primary4, 4);
        memcpy(&reverse4, b4, 4); memcpy(&v6, a6, 16); memcpy(&reverse6, a6, 16);
        v6.s6_addr[0] = round % 3 ? 0x20 : 0x30;
        compare_ip(&profile, round % 4 == 0 || round % 4 == 3 ? &v4 : NULL, round % 4 == 1 || round % 4 == 3 ? &v6 : NULL,
            round % 5 == 0 || round % 5 == 3 ? &reverse4 : NULL, round % 5 == 1 || round % 5 == 3 ? &reverse6 : NULL);
        if (!(round % 16)) {
            compare_reload(&profile, false); compare_reload(&profile, true); compare_global(false); compare_global(true);
        }
    }
    CHECK(cases == 9216);
    printf("PASS list_policy functions=13 cases=%u callback_mutations=%u empty_and_duplicate_references=1 error_order=1\n", cases, mutation_checks);
    params.debug = false; failures = changes = 0; mutate = false; recording = false;
    struct desync_profile profile = {0}; profile.n = 7; profile.hl_collection = hosts[1]; profile.ips_collection = ips[1];
    benchmark("hosts6", &profile, false, &v4); benchmark("ips6", &profile, true, &v4);
    for (unsigned index = 0; index < 5; ++index) { zapret_list_collection_destroy(&hosts[index]); zapret_list_collection_destroy(&ips[index]); }
    zapret_list_files_destroy(&params.hostlists); zapret_list_files_destroy(&params.ipsets);
    CHECK(!params.hostlists && !params.ipsets); WSACleanup();
    return 0;
}
