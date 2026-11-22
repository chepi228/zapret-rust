/* MIT. Deterministic failure decisions, exact reset bytes and publication failures. */
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "hostlist.h"
#include "checksum.h"
#include "pools_windows.h"
#undef main

struct params_s params;
static unsigned cases, boundaries;
static unsigned reset4_checks, reset6_checks;
static char trace[16384], effects[128];
static size_t trace_len, effect_count;
static bool counter_fail, append_ok = true, stamp_ok = true, send_ok = true;
static unsigned host_mode, writes, sends;
static uint8_t sent_packet[60];
static size_t sent_length;
static char written_host[256];

#define CHECK(condition) do { \
    if (!(condition)) { fprintf(stderr, "FAIL auto hostlist case %u line %d: %s\n", cases, __LINE__, #condition); exit(1); } \
} while (0)

static void effect(char code)
{
    CHECK(effect_count + 1 < sizeof(effects));
    effects[effect_count++] = code;
    effects[effect_count] = 0;
}
static int record(char category, const char *format, va_list args)
{
    CHECK(trace_len + 2 < sizeof(trace));
    trace[trace_len++] = category;
    int n = vsnprintf(trace + trace_len, sizeof(trace) - trace_len, format, args);
    CHECK(n >= 0 && (size_t)n + 2 < sizeof(trace) - trace_len);
    trace_len += n;
    trace[trace_len++] = '|';
    trace[trace_len] = 0;
    return n;
}
#define LOG_FUNCTION(name, category, enabled) \
    int name(const char *format, ...) { \
        if (!(enabled)) return 0; \
        va_list args; va_start(args, format); \
        int n = record(category, format, args); va_end(args); return n; \
    }
LOG_FUNCTION(DLOG, 'D', params.debug)
LOG_FUNCTION(DLOG_ERR, 'E', true)
LOG_FUNCTION(DLOG_CONDUP, 'C', params.debug)
LOG_FUNCTION(HOSTLIST_DEBUGLOG_APPEND, 'H', *params.hostlist_auto_debuglog)
int DLOG_PERROR(const char *name) { return DLOG_ERR("%s", name); }
struct tm *zapret_localtime_r(const time_t *value, struct tm *output)
{
    return localtime_s(output, value) ? NULL : output;
}

static hostfail_pool *fixture_counter_add(hostfail_index **pool, const char *host, int timeout)
{
    effect('c');
    if (counter_fail) return NULL;
    hostfail_pool *entry = HostFailPoolAdd(pool, host, timeout);
    CHECK(entry);
    entry->expire = 1000 + timeout;
    return entry;
}
bool HostlistCheck(const struct desync_profile *profile, const char *host, bool exact,
    bool *excluded, bool skip_reload)
{
    CHECK(host && !skip_reload);
    (void)exact;
    effect('h');
    if (excluded) *excluded = host_mode == 2;
    return host_mode == 1 || (host_mode == 0 &&
        zapret_host_match(profile->hostlist_auto->hostlist, host, exact, NULL));
}
static bool fixture_append(const char *filename, const char *host)
{
    CHECK(filename && host);
    effect('w');
    if (!append_ok) return false;
    ++writes;
    snprintf(written_host, sizeof(written_host), "%s", host);
    return true;
}
static bool fixture_stamp(const char *filename, file_mod_sig *stamp)
{
    CHECK(filename && stamp);
    effect('m');
    memset(stamp, 0, sizeof(*stamp));
    if (stamp_ok) {
        stamp->mod_time.tv_sec = 123;
        stamp->mod_time.tv_nsec = 4;
        stamp->size = 19;
    }
    return stamp_ok;
}
static bool fixture_send(const struct sockaddr *client, uint32_t mark, const char *interface,
    const void *packet, size_t length)
{
    CHECK(client && mark == 0 && (length == 40 || length == 60));
    CHECK(!interface || !strcmp(interface, "Wi-Fi"));
    effect('s');
    ++sends;
    sent_length = length;
    memcpy(sent_packet, packet, length);
    return send_ok;
}

#include "auto_packet_reference.inc"
#define HostFailPoolAdd fixture_counter_add
#define append_to_list_file fixture_append
#define file_mod_signature fixture_stamp
#define rawsend fixture_send
#define ctrack_stop_retrans_counter reference_stop
#define auto_hostlist_reset_fail_counter reference_reset
#define is_retransmission reference_retransmission
#define auto_hostlist_retrans reference_retrans
#define auto_hostlist_failed reference_failed
#define fill_client_ip_port reference_client_text
#define process_retrans_fail reference_tcp
#define process_udp_fail reference_udp
#include "auto_hostlist_reference.inc"

static void reference_incoming(t_ctrack *track, struct desync_profile *profile,
    const struct dissect *dis, t_l7payload payload, t_l7proto l7, const struct sockaddr *client)
{
    struct {
        t_ctrack *ctrack;
        struct desync_profile *dp;
        const struct dissect *dis;
        t_l7payload l7payload;
        t_l7proto l7proto;
        struct sockaddr_storage dst;
    } ps = {.ctrack = track, .dp = profile, .dis = dis, .l7payload = payload, .l7proto = l7};
    memcpy(&ps.dst, client, sizeof(ps.dst));
#include "auto_incoming_reference.inc"
}
#undef ctrack_stop_retrans_counter
#undef auto_hostlist_reset_fail_counter
#undef is_retransmission
#undef auto_hostlist_retrans
#undef auto_hostlist_failed
#undef fill_client_ip_port
#undef process_retrans_fail
#undef process_udp_fail
#include "auto_hostlist_windows.inc"
#undef rawsend
#undef file_mod_signature
#undef append_to_list_file
#undef HostFailPoolAdd

void zapret_autolist_reset(const zapret_autolist_context *, const zapret_autolist_ops *);
void zapret_autolist_failed(const zapret_autolist_context *, const zapret_autolist_ops *);
bool zapret_is_retransmission(const t_ctrack_position *);

static struct sockaddr_storage client;
static struct ip ip4;
static struct ip6_hdr ip6;
static struct tcphdr tcp;
static struct dissect packet;
static t_ctrack_positions replay_positions;
static t_l7payload payload_kind;

static void observe_reset(void)
{
    trace_len = effect_count = writes = sends = sent_length = 0;
    trace[0] = effects[0] = written_host[0] = 0;
    memset(sent_packet, 0, sizeof(sent_packet));
}
static void run(bool actual, unsigned operation, t_ctrack *track,
    struct desync_profile *profile, const t_ctrack_positions *snapshot)
{
    if (actual && operation < 2) {
        const zapret_autolist_context context = {
            .profile = profile, .hostname = track->hostname, .client_text = "192.0.2.1:40000",
            .l7 = track->l7proto, .no_subdomains = operation == 1 && track->hostname_is_ip,
            .flags = (params.server ? 1u : 0u) | ((params.debug || *params.hostlist_auto_debuglog) ? 2u : 0u),
        };
        if (operation == 0) zapret_autolist_reset(&context, &autolist_ops);
        else zapret_autolist_failed(&context, &autolist_ops);
        return;
    }
    switch (operation) {
    case 0:
        reference_reset(profile, track->hostname, "192.0.2.1:40000", track->l7proto);
        break;
    case 1:
        reference_failed(profile, track->hostname, track->hostname_is_ip, "192.0.2.1:40000", track->l7proto);
        break;
    case 2:
        if (actual) process_retrans_fail(track, &packet, (struct sockaddr *)&client, "Wi-Fi");
        else reference_tcp(track, &packet, (struct sockaddr *)&client, "Wi-Fi");
        break;
    case 3:
        if (actual) process_udp_fail(track, snapshot, (struct sockaddr *)&client);
        else reference_udp(track, snapshot, (struct sockaddr *)&client);
        break;
    case 4:
        if (actual) process_incoming_fail(track, profile, &packet, payload_kind, track->l7proto, (struct sockaddr *)&client);
        else reference_incoming(track, profile, &packet, payload_kind, track->l7proto, (struct sockaddr *)&client);
        break;
    }
}

static void same_pool(struct desync_profile *left, struct desync_profile *right)
{
    const char *names[] = {"example.com", "other.example", "keep.example"};
    for (unsigned i = 0; i < 3; ++i) {
        hostfail_pool *a = HostFailPoolFind(left->hostlist_auto_fail_counters, names[i]);
        hostfail_pool *b = HostFailPoolFind(right->hostlist_auto_fail_counters, names[i]);
        CHECK(!!a == !!b);
        if (a) CHECK(a->counter == b->counter && a->expire == b->expire);
        CHECK(zapret_host_has(left->hostlist_auto->hostlist, names[i]) ==
            zapret_host_has(right->hostlist_auto->hostlist, names[i]));
    }
    CHECK(!memcmp(&left->hostlist_auto->mod_sig, &right->hostlist_auto->mod_sig, sizeof(file_mod_sig)));
}

static void compare(unsigned operation, t_ctrack *left, t_ctrack *right,
    struct desync_profile *lp, struct desync_profile *rp, const t_ctrack_positions *snapshot)
{
    ++cases;
    observe_reset();
    run(false, operation, left, lp, snapshot);
    char expected_trace[sizeof(trace)], expected_effects[sizeof(effects)], expected_host[256];
    uint8_t expected_packet[60];
    strcpy(expected_trace, trace);
    strcpy(expected_effects, effects);
    strcpy(expected_host, written_host);
    memcpy(expected_packet, sent_packet, sizeof(sent_packet));
    unsigned expected_writes = writes, expected_sends = sends;
    size_t expected_length = sent_length;
    observe_reset();
    run(true, operation, right, rp, snapshot);
    if (strcmp(expected_trace, trace) || strcmp(expected_effects, effects)) {
        fprintf(stderr, "operation=%u C effects=%s Rust effects=%s\nC %s\nRust %s\n",
            operation, expected_effects, effects, expected_trace, trace);
        CHECK(false);
    }
    CHECK(expected_writes == writes && expected_sends == sends && expected_length == sent_length);
    CHECK(!strcmp(expected_host, written_host));
    CHECK(!memcmp(expected_packet, sent_packet, sizeof(sent_packet)));
    if (sent_length == 40) ++reset4_checks;
    if (sent_length == 60) ++reset6_checks;
    unsigned char a[sizeof(*left)], b[sizeof(*right)];
    memcpy(a, left, sizeof(a));
    memcpy(b, right, sizeof(b));
    memset(a + offsetof(t_ctrack, dp), 0, sizeof(left->dp));
    memset(b + offsetof(t_ctrack, dp), 0, sizeof(right->dp));
    CHECK(!memcmp(a, b, sizeof(a)));
    same_pool(lp, rp);
}

static void initialize(struct desync_profile *profile, struct zapret_list_file *file, t_ctrack *track)
{
    memset(profile, 0, sizeof(*profile));
    memset(file, 0, sizeof(*file));
    memset(track, 0, sizeof(*track));
    profile->n = 3;
    profile->name = "automatic";
    profile->hostlist_auto = file;
    profile->hostlist_auto_fail_threshold = 3;
    profile->hostlist_auto_fail_time = 60;
    profile->hostlist_auto_retrans_threshold = 3;
    profile->hostlist_auto_retrans_maxseq = 32;
    profile->hostlist_auto_incoming_maxseq = 16;
    profile->hostlist_auto_retrans_reset = true;
    profile->hostlist_auto_udp_in = 1;
    profile->hostlist_auto_udp_out = 4;
    file->filename = "autolist-fixture.txt";
    track->dp = profile;
    track->hostname = "example.com";
    track->hostname_ah_check = true;
    track->l7proto = L7_TLS;
    track->pos.state = ESTABLISHED;
    track->pos.client.seq0 = UINT32_MAX - 5;
    track->pos.client.seq_last = 2;
    track->pos.client.pos = 9;
    track->pos.client.uppos_prev = 9;
    track->pos.server.seq0 = UINT32_MAX - 7;
    track->pos.server.seq_last = 1;
    track->pos.server.winsize = 0x1234;
    track->pos.server.ip6flow = 0x6ab12345;
    CHECK(HostlistPoolAddStr(&file->hostlist, "keep.example", HOSTLIST_POOL_FLAG_STRICT_MATCH));
}
static void destroy(struct desync_profile *profile)
{
    HostFailPoolDestroy(&profile->hostlist_auto_fail_counters);
    HostlistPoolDestroy(&profile->hostlist_auto->hostlist);
}
static void seed(struct desync_profile *profile, unsigned count)
{
    if (!count) return;
    hostfail_pool *item = HostFailPoolAdd(&profile->hostlist_auto_fail_counters, "example.com", 60);
    CHECK(item);
    item->expire = 1060;
    item->counter = count;
}

static void combinations(void)
{
    static const uint32_t sequences[] = {UINT32_MAX - 6, UINT32_MAX - 5, 0, 2, 26, 27};
    static const char *const replies[] = {
        "HTTP/1.1 200 OK\r\n\r\n", "HTTP/1.1 302 Found\r\nLocation: https://example.com/a\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: https://other.test/a\r\n\r\n",
        "HTTP/1.1 307 Redirect\r\nLocation: /same\r\n\r\n"
    };
    for (unsigned i = 0; i < 20000; ++i) {
        struct desync_profile lp, rp;
        struct zapret_list_file lf, rf;
        t_ctrack left, right;
        initialize(&lp, &lf, &left);
        initialize(&rp, &rf, &right);
        unsigned operation = i % 5;
        lp.hostlist_auto_fail_threshold = rp.hostlist_auto_fail_threshold = 1 + i / 7 % 20;
        lp.hostlist_auto_retrans_threshold = rp.hostlist_auto_retrans_threshold = 2 + i / 11 % 9;
        lp.hostlist_auto_retrans_maxseq = rp.hostlist_auto_retrans_maxseq = i % 13 ? 32 : 0;
        lp.hostlist_auto_incoming_maxseq = rp.hostlist_auto_incoming_maxseq = i % 17 ? 16 : 0;
        lp.hostlist_auto_retrans_reset = rp.hostlist_auto_retrans_reset = i / 2 % 2;
        lp.hostlist_auto_udp_in = rp.hostlist_auto_udp_in = i / 19 % 5;
        lp.hostlist_auto_udp_out = rp.hostlist_auto_udp_out = i / 23 % 7;
        left.req_retrans_counter = right.req_retrans_counter = i % 29 ? i / 29 % 10 : 255;
        left.failure_detect_finalized = right.failure_detect_finalized = i % 31 == 0;
        left.hostname_ah_check = right.hostname_ah_check = i % 37 != 0;
        left.pos.state = right.pos.state = i % 3;
        left.pos.client.seq_last = right.pos.client.seq_last = sequences[i / 3 % 6];
        left.pos.server.seq_last = right.pos.server.seq_last = sequences[i / 5 % 6];
        left.pos.client.pos = right.pos.client.pos = i % 2 ? 9 : 10;
        left.pos.client.uppos_prev = right.pos.client.uppos_prev = 9;
        left.pos.server.ip6flow = right.pos.server.ip6flow = i % 3 ? 0x6ab12345 : 0;
        left.pos.client.pcounter = right.pos.client.pcounter = i / 41 % 9;
        left.pos.server.pcounter = right.pos.server.pcounter = i / 43 % 8;
        replay_positions = left.pos;
        replay_positions.client.pcounter += 3;
        replay_positions.server.pcounter += 1;
        seed(&lp, i / 47 % 4);
        seed(&rp, i / 47 % 4);
        host_mode = i / 53 % 3;
        counter_fail = i % 59 == 0;
        stamp_ok = i % 61 != 0;
        send_ok = i % 67 != 0;
        append_ok = true;
        params.server = i % 71 == 0;
        params.debug = i % 7 == 0;
        strcpy(params.hostlist_auto_debuglog, i % 11 == 0 ? "fixture-debug" : "");
        packet.ip = i & 1 ? &ip4 : NULL;
        packet.ip6 = i & 1 ? NULL : &ip6;
        memset(&client, 0, sizeof(client));
        if (packet.ip6) {
            ((struct sockaddr_in6 *)&client)->sin6_family = AF_INET6;
            ((struct sockaddr_in6 *)&client)->sin6_port = htons(40000);
            ((struct sockaddr_in6 *)&client)->sin6_addr = ip6.ip6_src;
        } else {
            ((struct sockaddr_in *)&client)->sin_family = AF_INET;
            ((struct sockaddr_in *)&client)->sin_port = htons(40000);
            ((struct sockaddr_in *)&client)->sin_addr = ip4.ip_src;
        }
        packet.tcp = i % 73 ? &tcp : NULL;
        packet.proto = operation == 3 ? IPPROTO_UDP : IPPROTO_TCP;
        if (operation == 4) packet.tcp = &tcp;
        tcp.th_flags = i % 4 ? TH_ACK : TH_RST;
        packet.data_payload = (const uint8_t *)replies[i / 79 % 4];
        packet.len_payload = strlen((const char *)packet.data_payload);
        payload_kind = i % 83 ? L7P_HTTP_REPLY : L7P_UNKNOWN;
        compare(operation, &left, &right, &lp, &rp, i % 2 ? &replay_positions : NULL);
        destroy(&lp);
        destroy(&rp);
    }
}

static void publication_failure(void)
{
    struct desync_profile lp, rp;
    struct zapret_list_file lf, rf;
    t_ctrack left, right;
    initialize(&lp, &lf, &left);
    initialize(&rp, &rf, &right);
    lp.hostlist_auto_fail_threshold = rp.hostlist_auto_fail_threshold = 1;
    params.server = false;
    params.debug = true;
    *params.hostlist_auto_debuglog = 0;
    host_mode = 0;
    counter_fail = false;
    stamp_ok = true;
    append_ok = false;
    observe_reset();
    run(false, 1, &left, &lp, NULL);
    CHECK(zapret_host_has(lf.hostlist, "example.com"));
    observe_reset();
    run(true, 1, &right, &rp, NULL);
    CHECK(!zapret_host_has(rf.hostlist, "example.com") && zapret_host_has(rf.hostlist, "keep.example"));
    CHECK(!writes && !rf.mod_sig.size);
    ++boundaries;
    HostlistPoolDestroy(&lf.hostlist);
    CHECK(HostlistPoolAddStr(&lf.hostlist, "keep.example", HOSTLIST_POOL_FLAG_STRICT_MATCH));
    append_ok = true;
    compare(1, &left, &right, &lp, &rp, NULL);
    CHECK(writes == 1 && zapret_host_has(rf.hostlist, "example.com"));
    ++boundaries;
    destroy(&lp);
    destroy(&rp);
}

static void state_boundaries(void)
{
    const uint32_t values[] = {0, 1, UINT32_MAX, UINT32_MAX - 1, 0x7fffffff, 0x80000000, 0x80000001};
    t_ctrack_position position = {0};
    for (unsigned a = 0; a < 7; ++a) {
        for (unsigned b = 0; b < 7; ++b) {
            position.pos = values[a];
            position.uppos_prev = values[b];
            CHECK(reference_retransmission(&position) == zapret_is_retransmission(&position));
            ++boundaries;
        }
    }
    struct desync_profile lp, rp;
    struct zapret_list_file lf, rf;
    t_ctrack left, right;
    initialize(&lp, &lf, &left);
    initialize(&rp, &rf, &right);
    params.server = false;
    params.debug = true;
    strcpy(params.hostlist_auto_debuglog, "fixture-debug");
    host_mode = 0;
    counter_fail = false;
    append_ok = stamp_ok = send_ok = true;
    packet.ip = &ip4;
    packet.ip6 = NULL;
    packet.tcp = &tcp;
    packet.proto = IPPROTO_TCP;
    left.req_retrans_counter = right.req_retrans_counter = 2;
    compare(2, &left, &right, &lp, &rp, NULL);
    CHECK(right.failure_detect_finalized && right.req_retrans_counter == RETRANS_COUNTER_STOP);
    CHECK(sends == 1);
    ++boundaries;
    compare(2, &left, &right, &lp, &rp, NULL);
    CHECK(!sends && !effect_count && !trace_len);
    ++boundaries;
    left.failure_detect_finalized = right.failure_detect_finalized = false;
    left.pos.server.pcounter = right.pos.server.pcounter = UINT64_MAX;
    compare(3, &left, &right, &lp, &rp, NULL);
    CHECK(right.failure_detect_finalized);
    ++boundaries;
    left.hostname = right.hostname = NULL;
    compare(0, &left, &right, &lp, &rp, NULL);
    CHECK(!effect_count);
    ++boundaries;
    destroy(&lp);
    destroy(&rp);
    CHECK(reset4_checks && reset6_checks);
}

static bool mock_open_ok, mock_print_ok, mock_flush_ok, mock_close_ok;
static unsigned mock_closes;
static FILE *mock_open(const char *name, const char *mode)
{
    CHECK(name && !strcmp(mode, "at"));
    return mock_open_ok ? (FILE *)(uintptr_t)1 : NULL;
}
static int mock_print(FILE *stream, const char *format, ...)
{
    CHECK(stream && !strcmp(format, "%s\n"));
    return mock_print_ok ? 2 : -1;
}
static int mock_flush(FILE *stream) { CHECK(stream); return mock_flush_ok ? 0 : EOF; }
static int mock_close(FILE *stream) { CHECK(stream); ++mock_closes; return mock_close_ok ? 0 : EOF; }
#pragma push_macro("fopen")
#pragma push_macro("fprintf")
#pragma push_macro("fflush")
#pragma push_macro("fclose")
#undef fopen
#undef fprintf
#undef fflush
#undef fclose
#define fopen mock_open
#define fprintf mock_print
#define fflush mock_flush
#define fclose mock_close
#define append_to_list_file checked_buffered_append
#include "auto_writer_actual.inc"
#undef append_to_list_file
#pragma pop_macro("fclose")
#pragma pop_macro("fflush")
#pragma pop_macro("fprintf")
#pragma pop_macro("fopen")

static void writer_failures(void)
{
    for (unsigned i = 0; i < 16; ++i) {
        mock_open_ok = i & 1;
        mock_print_ok = i & 2;
        mock_flush_ok = i & 4;
        mock_close_ok = i & 8;
        mock_closes = 0;
        CHECK(checked_buffered_append("fixture", "x") == (i == 15));
        CHECK(mock_closes == !!mock_open_ok);
        ++boundaries;
    }
}

enum { BENCH_ROUNDS = 9, BENCH_CALLS = 131072 };
static __attribute__((noinline)) double time_detection(bool actual, unsigned operation,
    t_ctrack *track, struct desync_profile *profile)
{
    LARGE_INTEGER frequency, first, last;
    CHECK(QueryPerformanceFrequency(&frequency));
    CHECK(QueryPerformanceCounter(&first));
    for (unsigned i = 0; i < BENCH_CALLS; ++i) run(actual, operation, track, profile, NULL);
    CHECK(QueryPerformanceCounter(&last));
    return (double)(last.QuadPart - first.QuadPart) * 1e9 / frequency.QuadPart / BENCH_CALLS;
}
static int compare_time(const void *left, const void *right)
{
    double a = *(const double *)left, b = *(const double *)right;
    return (a > b) - (a < b);
}
static void benchmark(const char *name, unsigned operation, bool active)
{
    struct desync_profile lp, rp;
    struct zapret_list_file lf, rf;
    t_ctrack left, right;
    initialize(&lp, &lf, &left);
    initialize(&rp, &rf, &right);
    left.hostname_ah_check = right.hostname_ah_check = active;
    left.pos.client.pos = right.pos.client.pos = 10; // New data, not a retransmission.
    params.server = params.debug = false;
    *params.hostlist_auto_debuglog = 0;
    observe_reset();
    double reference[BENCH_ROUNDS], actual[BENCH_ROUNDS];
    for (unsigned i = 0; i < BENCH_ROUNDS; ++i) {
        if (i % 2 == 0) {
            reference[i] = time_detection(false, operation, &left, &lp);
            actual[i] = time_detection(true, operation, &right, &rp);
        } else {
            actual[i] = time_detection(true, operation, &right, &rp);
            reference[i] = time_detection(false, operation, &left, &lp);
        }
    }
    CHECK(!effect_count && !trace_len && !sends && !writes);
    qsort(reference, BENCH_ROUNDS, sizeof(reference[0]), compare_time);
    qsort(actual, BENCH_ROUNDS, sizeof(actual[0]), compare_time);
    printf("BENCH auto_hostlist %s c_ns=%.2f rust_ns=%.2f rounds=%u calls_per_round=%u\n",
        name, reference[BENCH_ROUNDS / 2], actual[BENCH_ROUNDS / 2], BENCH_ROUNDS, BENCH_CALLS);
    destroy(&lp);
    destroy(&rp);
}

int main(void)
{
    memset(&client, 0, sizeof(client));
    ((struct sockaddr_in *)&client)->sin_family = AF_INET;
    ((struct sockaddr_in *)&client)->sin_port = htons(40000);
    CHECK(inet_pton(AF_INET, "192.0.2.1", &((struct sockaddr_in *)&client)->sin_addr) == 1);
    memset(&ip4, 0, sizeof(ip4));
    ip4.ip_v = 4; ip4.ip_hl = 7; ip4.ip_ttl = 64; ip4.ip_p = IPPROTO_TCP;
    ip4.ip_len = htons(200); ip4.ip_id = htons(1234);
    CHECK(inet_pton(AF_INET, "192.0.2.1", &ip4.ip_src) == 1);
    CHECK(inet_pton(AF_INET, "198.51.100.2", &ip4.ip_dst) == 1);
    memset(&ip6, 0, sizeof(ip6));
    ip6.ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x6ab12345);
    ip6.ip6_plen = htons(200); ip6.ip6_nxt = 0; ip6.ip6_hlim = 77;
    CHECK(inet_pton(AF_INET6, "2001:db8::1", &ip6.ip6_src) == 1);
    CHECK(inet_pton(AF_INET6, "2001:db8::2", &ip6.ip6_dst) == 1);
    memset(&tcp, 0, sizeof(tcp));
    tcp.th_sport = htons(40000); tcp.th_dport = htons(443);
    tcp.th_seq = htonl(0x12345678); tcp.th_ack = htonl(0xfedcba98);
    tcp.th_off = 8; tcp.th_win = htons(4096); tcp.th_urp = htons(2);
    combinations();
    publication_failure();
    state_boundaries();
    writer_failures();
    printf("PASS auto_hostlist cases=%u boundary_cases=%u reset4=%u reset6=%u publication_fixes=2\n",
        cases, boundaries, reset4_checks, reset6_checks);
    benchmark("tcp-inactive", 2, false);
    benchmark("tcp-new-data", 2, true);
    benchmark("udp-waiting", 3, true);
    return 0;
}
