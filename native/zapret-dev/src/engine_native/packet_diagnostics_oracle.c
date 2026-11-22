/* Compare the pinned C entries and their actual Rust replacements in memory. */
#include "darkmagic.h"
#include "helpers.h"
#include "hostlist.h"
#include "ipset.h"
#include "params.h"
#include "protocol.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef main
#define PKTDATA_MAXDUMP 32

struct params_s params;
static struct dissect packet;
static struct desync_profile_list selected;
static struct zapret_list_file automatic;
static uint8_t ipv4[20], ipv6[40], tcp[20], udp[8], icmp[8];
static uint8_t data[64], alternate_data[64];
static char long_text[4097];
static const char binary_text[] = {'n', (char)0xff, (char)0x80, 0, 'x', 0};
static const char moved_name[] = "updated name";
static unsigned mutation, selection, mutations, packet_cases, profile_cases, guards;
static unsigned late_payloads, late_names;
static struct {
    uint64_t bytes;
    unsigned writes, dumps, lookups;
} trace;

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL packet_diagnostics packet=%u profile=%u mutation=%u line=%d: %s\n", \
        packet_cases, profile_cases, mutation, __LINE__, #condition); exit(1); \
} } while (0)

static void record(const void *data, size_t length)
{
    const uint8_t *bytes = data;
    for (size_t i = 0; i < length; ++i)
        trace.bytes = (trace.bytes ^ bytes[i]) * UINT64_C(1099511628211);
}

static void record_number(size_t value) { record(&value, sizeof(value)); }

int DLOG(const char *format, ...)
{
    char output[10000];
    va_list args;
    va_start(args, format);
    int length = vsnprintf(output, sizeof(output), format, args);
    va_end(args);
    CHECK(length >= 0 && (size_t)length < sizeof(output));
    record(format, strlen(format) + 1);
    record_number(length);
    record(output, length);
    ++trace.writes;
    if (mutation == 1 && !strcmp(format, "REPLAY ")) {
        params.debug = false;
        packet.ip = NULL;
        packet.ip6 = (const struct ip6_hdr *)ipv6;
        packet.proto = 255;
        ++mutations;
    }
    if (mutation == 2 && (!strncmp(format, "IP4: ", 5) || !strncmp(format, "IP6: ", 5))) {
        packet.tcp = NULL;
        packet.udp = (const struct udphdr *)udp;
        ++mutations;
    }
    if (mutation == 3 && !strcmp(format, " %s\n")) {
        packet.len_payload = packet.len_payload ? 0 : 14;
        ++mutations;
    }
    if (mutation == 4 && strstr(format, "len=%zu")) {
        packet.len_payload = 19;
        packet.data_payload = alternate_data;
        ++mutations;
    }
    if (mutation == 5 && !strncmp(format, "autohostlist profile", 20)) {
        selected.dp.n = 513;
        selected.dp.name = selected.dp.name ? NULL : (char *)moved_name;
        ++mutations;
    }
    if (mutation == 5 && strstr(output, "profile 513 (")) ++late_names;
    return length;
}

int DLOG_ERR(const char *format, ...)
{
    (void)format;
    CHECK(false);
    return 0;
}

void hexdump_limited_dlog(const uint8_t *payload, size_t length, size_t limit)
{
    CHECK(limit == PKTDATA_MAXDUMP);
    CHECK(payload == data || payload == alternate_data);
    record_number(length);
    record_number(limit);
    record_number(payload == alternate_data);
    record(payload, length < limit ? length : limit);
    ++trace.dumps;
    if (payload == alternate_data && length == 19) ++late_payloads;
}

bool HostlistsReloadCheckForProfile(const struct desync_profile *profile) { return profile != NULL; }
bool IpsetCheck(const struct desync_profile *profile, const struct in_addr *a,
    const struct in6_addr *b, const struct in_addr *c, const struct in6_addr *d)
{
    (void)a; (void)b; (void)c; (void)d;
    return profile != NULL;
}
bool HostlistCheck(const struct desync_profile *profile, const char *name,
    bool no_subdomains, bool *excluded, bool skip_reload)
{
    (void)name; (void)no_subdomains; (void)excluded; (void)skip_reload;
    return profile != NULL;
}

/* Reuse the exact formatters that both versions of the Windows engine use. */
#include "packet_describe_windows.inc"

#define zapret_profile_find fixture_find
#include "packet_diagnostics_selector.inc"
#include "packet_diagnostics_find.inc"
#include "packet_debug_windows.inc"
#define packet_debug reference_packet_debug
#define profile_find_windows reference_profile_find_windows
#define dp_find reference_dp_find
#include "packet_diagnostics_reference.inc"
#undef dp_find
#undef profile_find_windows
#undef packet_debug
#undef zapret_profile_find

struct desync_profile *fixture_find(struct desync_profile_list *head, size_t filters, size_t next,
    const struct zapret_profile_query *query, const struct zapret_profile_list_checks *checks)
{
    CHECK(head == &selected && filters == offsetof(struct desync_profile, filter_ipv4));
    CHECK(next == offsetof(struct desync_profile_list, next.le_next) && checks->check_host && checks->check_ips);
    record_number(query->ipv4 != NULL);
    record_number(query->ipv6 != NULL);
    record_number(query->reverse_ipv4 != NULL);
    record_number(query->reverse_ipv6 != NULL);
    record_number(query->hostname != NULL);
    record_number(query->l7);
    record_number(query->port);
    record_number(query->icmp_type);
    record_number(query->icmp_code);
    record_number(query->no_subdomains);
    record_number(query->protocol);
    *query->check_done = true;
    *query->check_result = selection != 0;
    *query->excluded = selection == 2;
    ++trace.lookups;
    return selection ? &selected.dp : NULL;
}

struct result { uint64_t digest; unsigned writes, dumps, lookups; };
static void begin(void)
{
    trace.bytes = UINT64_C(14695981039346656037);
    trace.writes = trace.dumps = trace.lookups = 0;
}
static struct result end(void)
{
    return (struct result){trace.bytes, trace.writes, trace.dumps, trace.lookups};
}
static bool same(struct result left, struct result right)
{
    return left.digest == right.digest && left.writes == right.writes && left.dumps == right.dumps &&
        left.lookups == right.lookups;
}

static struct result packet_sample(bool rust, unsigned flags, unsigned network, unsigned transport,
    size_t size, bool fragment)
{
    params.debug = flags & 1;
    packet = (struct dissect){
        .ip = network & 1 ? (const struct ip *)ipv4 : NULL,
        .ip6 = network & 2 ? (const struct ip6_hdr *)ipv6 : NULL,
        .tcp = transport & 1 ? (const struct tcphdr *)tcp : NULL,
        .udp = transport & 2 ? (const struct udphdr *)udp : NULL,
        .icmp = transport & 4 ? (const struct icmp46 *)icmp : NULL,
        .proto = transport & 1 ? 6 : transport & 2 ? 17 : 255,
        .data_payload = data, .len_payload = size, .frag = fragment, .frag_off = UINT16_MAX,
    };
    begin();
    (rust ? packet_debug : reference_packet_debug)((flags & 2) != 0, &packet);
    return end();
}

static struct result profile_sample(bool rust, bool debug, unsigned addresses, unsigned kind,
    unsigned text_shape, const void *guard)
{
    const struct in_addr a = { .S_un.S_addr = 0x0100007f };
    struct in6_addr b;
    memset(&b, 0, sizeof(b));
    ((uint8_t *)&b)[15] = 1;
    const char *names[] = {NULL, "", "visible", binary_text, long_text};
    const uint8_t protocols[] = {1, 6, 17, 58, 255};
    params.debug = debug;
    selected = (struct desync_profile_list){0};
    selected.dp.n = UINT32_MAX;
    selected.dp.name = (char *)names[(text_shape + 2) % 5];
    selected.dp.hostlist_auto = selection == 2 ? &automatic : NULL;
    struct desync_profile_list_head head = LIST_HEAD_INITIALIZER(head);
    LIST_INSERT_HEAD(&head, &selected, next);
    bool done = false, matched = false, excluded = false;
    begin();
    struct desync_profile *profile = (rust ? dp_find : reference_dp_find)(
        &head, protocols[kind],
        guard ? guard : addresses & 1 ? &a : NULL, addresses & 2 ? &b : NULL,
        addresses & 4 ? &a : NULL, addresses & 8 ? &b : NULL,
        UINT16_MAX, UINT8_MAX, kind, names[text_shape], text_shape & 1, (t_l7proto)(kind * 9),
        names[(text_shape + 3) % 5], UINT32_MAX, &done, &matched, &excluded);
    CHECK(profile == (selection ? &selected.dp : NULL));
    CHECK(done && matched == (selection != 0) && excluded == (selection == 2));
    return end();
}

int main(void)
{
    ipv4[0] = 0x45; ipv4[8] = 64; ipv4[9] = 6; ipv4[12] = 10; ipv4[16] = 127;
    ipv6[0] = 0x60; ipv6[7] = 63; ipv6[23] = 2; ipv6[39] = 5;
    tcp[12] = 0x50; tcp[13] = 0x12; udp[5] = 8; icmp[0] = 129;
    memset(data, 0xa5, sizeof(data));
    memset(alternate_data, 0xc1, sizeof(alternate_data));
    memset(long_text, 'x', sizeof(long_text) - 1);
    long_text[4095] = (char)0xfe;
    const size_t sizes[] = {0, 1, 32, 33, 64, SIZE_MAX};
    for (mutation = 0; mutation < 5; ++mutation)
        for (unsigned flags = 0; flags < 4; ++flags)
            for (unsigned network = 0; network < 4; ++network)
                for (unsigned transport = 0; transport < 8; ++transport)
                    for (unsigned size = 0; size < sizeof(sizes) / sizeof(*sizes); ++size)
                        for (unsigned fragment = 0; fragment < 2; ++fragment) {
                            const struct result a = packet_sample(false, flags, network, transport, sizes[size], fragment);
                            const struct result b = packet_sample(true, flags, network, transport, sizes[size], fragment);
                            CHECK(same(a, b));
                            ++packet_cases;
                        }
    for (mutation = 0; mutation <= 5; mutation += 5)
        for (selection = 0; selection < 3; ++selection)
            for (unsigned debug = 0; debug < 2; ++debug)
                for (unsigned addresses = 0; addresses < 16; ++addresses)
                    for (unsigned kind = 0; kind < 5; ++kind)
                        for (unsigned text = 0; text < 5; ++text) {
                            const struct result a = profile_sample(false, debug, addresses, kind, text, NULL);
                            const struct result b = profile_sample(true, debug, addresses, kind, text, NULL);
                            CHECK(same(a, b));
                            ++profile_cases;
                        }
    void *inaccessible = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    CHECK(inaccessible);
    params.debug = 0;
    begin();
    reference_packet_debug(true, inaccessible);
    packet_debug(true, inaccessible);
    CHECK(!trace.writes && !trace.dumps);
    ++guards;
    const struct result a = profile_sample(false, false, 0, 0, 0, inaccessible);
    const struct result b = profile_sample(true, false, 0, 0, 0, inaccessible);
    CHECK(same(a, b));
    CHECK(VirtualFree(inaccessible, 0, MEM_RELEASE));
    ++guards;
    CHECK(late_payloads > 0 && late_names > 0);
    printf("PASS packet_diagnostics packet_cases=%u profile_cases=%u mutations=%u guarded=%u "
        "late_payloads=%u late_names=%u exact_fragments=1 native_bytes=1 selector_order=1\n",
        packet_cases, profile_cases, mutations, guards, late_payloads, late_names);
    return 0;
}
