/* MIT. Compare packet payloads, diagnostics, reassembly and queue effects in memory. */
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "protocol.h"
#include "checksum.h"
#include "quic_vectors.h"
#undef main

#define TCP_MAX_REASM 16384
#define UDP_MAX_REASM 16384
struct params_s params;
#include "packet_play_state.inc"

static unsigned test_case, test_flags;
#define CHECK(condition) do { \
    if (!(condition)) { fprintf(stderr, "FAIL packet play case %u flags %u line %d: %s\n", \
        test_case, test_flags, __LINE__, #condition); exit(1); } \
} while (0)

struct trace {
    char log[4096], effects[48], hostname[256];
    size_t tcp_len, quic_len, present, wanted;
    uint64_t tcp_bytes, quic_bytes, queued_bytes, buffered_bytes;
    uint32_t payload, l7, tracked_l7, assembly_kind;
    unsigned queued, sends, replays, dns;
    bool have_host, from_peer;
    uint8_t verdict;
};
static struct trace trace;
static size_t log_at, effect_at;
static t_ctrack track;
static struct desync_profile profile;
static bool tracked, reverse, rediscover, fail_prolog;
static uint8_t verdict;
static uint8_t *checksum_log_byte;

static uint64_t digest(const uint8_t *data, size_t length)
{
    uint64_t value = 14695981039346656037ull;
    for (size_t i = 0; i < length; ++i)
        value = (value ^ data[i]) * 1099511628211ull;
    return value;
}
static void effect(char code)
{
    CHECK(effect_at + 1 < sizeof(trace.effects));
    trace.effects[effect_at++] = code;
}
static int log_message(const char *format, va_list args)
{
    int n = vsnprintf(trace.log + log_at, sizeof(trace.log) - log_at, format, args);
    CHECK(n >= 0 && (size_t)n < sizeof(trace.log) - log_at);
    log_at += n;
    return n;
}
int DLOG(const char *format, ...)
{
    if (!params.debug) return 0;
    if (checksum_log_byte && (!strcmp(format, "fixing tcp checksum\n") ||
        !strcmp(format, "fixing udp checksum\n") || !strcmp(format, "fixing icmp checksum\n"))) {
        *checksum_log_byte ^= 0xa7;
        checksum_log_byte = NULL;
    }
    va_list args;
    va_start(args, format);
    int n = log_message(format, args);
    va_end(args);
    return n;
}
int DLOG_ERR(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int n = log_message(format, args);
    va_end(args);
    return n;
}
bool rawsend(const struct sockaddr *destination, uint32_t mark, const char *ifout,
    const void *data, size_t length)
{
    effect('S');
    ++trace.sends;
    CHECK(destination->sa_family == AF_INET && mark == 0x21);
    CHECK(ifout && !strcmp(ifout, "out") && data && length);
    return true;
}
static bool replay_queue(struct rawpacket_queue *queue)
{
    effect('R');
    ++trace.replays;
    CHECK(track.reasm_client.packet);
    trace.buffered_bytes = digest(track.reasm_client.packet, track.reasm_client.size_present);
    struct rawpacket *packet;
    while ((packet = rawpacket_dequeue(queue))) {
        CHECK(packet->fwmark_orig == 1 && packet->fwmark == 0x21 && packet->tpos_present);
        trace.queued_bytes ^= digest(packet->packet, packet->len);
        rawpacket_free(packet);
    }
    return true;
}
static bool play_prolog(struct play_state *ps, const struct dissect *packet,
    const t_ctrack_positions *positions, bool replay, const char *ifin, const char *ifout, uint32_t mark)
{
    CHECK(ifin && ifout && mark == 1);
    memset(ps, 0, sizeof(*ps));
    ps->dis = packet;
    ps->tpos = positions ? positions : tracked ? &track.pos : NULL;
    ps->dp = &profile;
    ps->l7proto = tracked ? track.l7proto : L7_UNKNOWN;
    ps->l7payload = packet->len_payload ? L7P_UNKNOWN : L7P_EMPTY;
    ps->bReverse = reverse;
    ps->bReverseFixed = reverse;
    ps->ctrack_replay = tracked ? &track : NULL;
    ps->ctrack = replay ? NULL : ps->ctrack_replay;
    ps->src.ss_family = ps->dst.ss_family = AF_INET;
    return !fail_prolog;
}
static bool dp_rediscovery(struct play_state *ps)
{
    effect('P');
    trace.payload = ps->l7payload;
    trace.l7 = ps->l7proto;
    trace.have_host = ps->bHaveHost;
    if (ps->bHaveHost)
        strcpy(trace.hostname, ps->host);
    return rediscover;
}
static uint8_t desync(struct desync_profile *dp, uint32_t mark, const char *ifin, const char *ifout,
    bool from_peer, t_ctrack *connection, const t_ctrack_positions *positions, t_l7payload payload,
    t_l7proto protocol, const struct dissect *packet, const struct in_addr *ipv4,
    const struct in6_addr *ipv6, uint16_t port, uint8_t *modified, size_t *modified_len,
    unsigned int piece, unsigned int count, size_t offset, const uint8_t *tcp, size_t tcp_len,
    const uint8_t *quic, size_t quic_len)
{
    effect('L');
    CHECK(dp == &profile && mark == 1 && !strcmp(ifin, "in") && !strcmp(ifout, "out"));
    CHECK(connection == (tracked ? &track : NULL) && !positions && !ipv4 && !ipv6 && !port);
    CHECK(packet && payload == trace.payload && protocol == trace.l7 && modified && *modified_len == 8);
    CHECK(piece == 0 && count <= 1 && offset == 7);
    trace.from_peer = from_peer;
    trace.tcp_len = tcp_len;
    trace.quic_len = quic_len;
    trace.tcp_bytes = digest(tcp, tcp_len);
    trace.quic_bytes = digest(quic, quic_len);
    return verdict;
}
static uint8_t ct_new_postnat_fix(const t_ctrack *connection, const struct dissect *packet,
    uint8_t *modified, size_t *modified_len)
{
    CHECK((!connection || connection == &track) && packet && modified && modified_len);
    effect('F');
    return VERDICT_DROP;
}
static void TLSDebug(const uint8_t *data, size_t length)
{
    DLOG("tls record %zu %llu\n", length, (unsigned long long)digest(data, length));
}
static void TLSDebugHandshake(const uint8_t *data, size_t length)
{
    DLOG("tls handshake %zu %llu\n", length, (unsigned long long)digest(data, length));
}
static void process_retrans_fail(t_ctrack *connection, const struct dissect *packet,
    struct sockaddr *source, const char *ifin)
{
    CHECK(connection == &track || !connection);
    CHECK(packet && source->sa_family == AF_INET && !strcmp(ifin, "in"));
    effect('T');
}
static void process_incoming_fail(t_ctrack *connection, struct desync_profile *dp, const struct dissect *packet,
    t_l7payload payload, t_l7proto protocol, const struct sockaddr *dest)
{
    CHECK((connection == &track || !connection) && dp == &profile && packet);
    CHECK(payload < L7P_LAST && protocol < L7_LAST && dest->sa_family == AF_INET);
    effect('I');
}
bool zapret_is_retransmission(const t_ctrack_position *);
static bool is_retransmission(const t_ctrack_position *position) { return zapret_is_retransmission(position); }
static bool feed_dns_response(const uint8_t *data, size_t length)
{
    CHECK(IsDNSResponse(data, length));
    effect('D');
    ++trace.dns;
    return true;
}
#include "protocol_probe_descriptor.inc"
#include "protocol_probe_windows.inc"
#include "reassembly_windows.inc"
#define dpi_desync_tcp_packet_play reference_tcp
#define dpi_desync_udp_packet_play reference_udp
#include "packet_play_reference.inc"
#undef dpi_desync_tcp_packet_play
#undef dpi_desync_udp_packet_play
#include "packet_play_windows.inc"

struct fixture {
    const uint8_t *packet, *seed;
    size_t length, seed_length;
    uint8_t protocol;
    bool replay;
};
static void run(struct trace *out, const struct fixture *input, bool actual, unsigned flags)
{
    memset(&track, 0, sizeof(track));
    memset(&trace, 0, sizeof(trace));
    log_at = effect_at = 0;
    reverse = (flags & 1) != 0 && !input->replay;
    params.debug = (flags & 2) != 0;
    tracked = (flags & 4) != 0 || input->seed_length || input->replay;
    params.payload_disable = flags & 8 ? 0 : 1;
    // The C input parser uses bit 0 for an empty disable list.
    params.reasm_payload_disable = flags & 16 ? 0 : 1;
    rediscover = !(flags & 32);
    verdict = flags & 64 ? VERDICT_DROP : VERDICT_PASS;
    fail_prolog = (flags & 128) != 0;
    params.desync_fwmark = 0x20;
    track.l7proto = L7_UNKNOWN;
    track.reasm_client_payload = L7P_UNKNOWN;
    track.pos.ipproto = input->protocol;
    track.pos.client.seq_last = 101;
    track.pos.client.seq0 = 100;
    track.pos.client.pos = 102;
    track.pos.client.uppos_prev = 101;
    if (flags & 256) track.pos.client.uppos_prev = 103;
    rawpacket_queue_init(&track.delayed, flags & 512 ? 1 : 64);
    if (input->seed_length) {
        // Install the same partial assembly for both paths. The first queued
        // packet lets a successful replay and a rejected enqueue diverge.
        CHECK(reasm_client_start(&track, input->protocol,
            input->protocol == IPPROTO_TCP ? L7P_TLS_CLIENT_HELLO : L7P_QUIC_INITIAL,
            input->protocol == IPPROTO_TCP ? TLSRecordLen(input->seed) : UDP_MAX_REASM,
            UDP_MAX_REASM, input->seed, input->seed_length));
        track.pos.client.seq_last += (uint32_t)input->seed_length;
        struct sockaddr_storage dst = {.ss_family = AF_INET};
        CHECK(rawpacket_queue(&track.delayed, &dst, 1, 0x21, "in", "out",
            input->seed, input->seed_length, input->seed_length, &track.pos, false));
    }
    memset(&trace, 0, sizeof(trace));
    log_at = effect_at = 0;
    struct tcphdr tcp = {.th_flags = flags & 1024 ? TH_SYN : TH_ACK};
    struct udphdr udp = {0};
    struct dissect packet = {
        .data_pkt = input->packet, .len_pkt = input->length,
        .data_payload = input->packet, .len_payload = input->length,
        .proto = input->protocol, .tcp = input->protocol == IPPROTO_TCP ? &tcp : NULL,
        .udp = input->protocol == IPPROTO_UDP ? &udp : NULL,
    };
    uint8_t modified[8];
    size_t mod_len = sizeof(modified);
    if (input->protocol == IPPROTO_TCP) {
        trace.verdict = (actual ? dpi_desync_tcp_packet_play : reference_tcp)(
            0, input->replay, 7, 1, "in", "out", NULL, &packet, modified, &mod_len);
    } else {
        trace.verdict = (actual ? dpi_desync_udp_packet_play : reference_udp)(
            0, input->replay, 7, 1, "in", "out", NULL, &packet, modified, &mod_len);
    }
    trace.assembly_kind = track.reasm_client_payload;
    trace.tracked_l7 = track.l7proto;
    trace.present = track.reasm_client.size_present;
    trace.wanted = track.reasm_client.size;
    trace.queued = rawpacket_queue_count(&track.delayed);
    if (trace.present)
        trace.buffered_bytes ^= digest(track.reasm_client.packet, trace.present);
    struct rawpacket *queued;
    while ((queued = rawpacket_dequeue(&track.delayed))) {
        CHECK(queued->fwmark_orig == 1 && queued->fwmark == 0x21);
        trace.queued_bytes ^= digest(queued->packet, queued->len);
        rawpacket_free(queued);
    }
    rawpacket_queue_destroy(&track.delayed);
    ReasmClear(&track.reasm_client);
    memcpy(out, &trace, sizeof(trace));
}

#include "packet_route_oracle.inc"
#include "lua_rules_oracle.inc"

int main(void)
{
    static const uint8_t http[] = "GET / HTTP/1.1\r\nHost: TeSt.Example\r\n\r\n";
    static const uint8_t reply[] = "HTTP/1.1 200 OK\r\n\r\n";
    static const uint8_t dns[12] = {0, 1, 0x81, 0x80, 0, 1, 0, 1};
    uint8_t decoded[UDP_MAX_REASM], defrag[UDP_MAX_REASM], tls[TCP_MAX_REASM];
    size_t decoded_length = sizeof(decoded), defrag_length = sizeof(defrag), hello_offset, hello_length;
    bool full;
    CHECK(QUICDecryptInitial(quic_v1, sizeof(quic_v1), decoded, &decoded_length));
    CHECK(QUICDefragCrypto(decoded, decoded_length, defrag, &defrag_length, &full) && full);
    CHECK(IsQUICCryptoHello(defrag, defrag_length, &hello_offset, &hello_length));
    CHECK(hello_length > 50 && hello_length <= sizeof(tls) - 5);
    tls[0] = 22;
    tls[1] = 3;
    tls[2] = 1;
    tls[3] = (uint8_t)(hello_length >> 8);
    tls[4] = (uint8_t)hello_length;
    memcpy(tls + 5, defrag + hello_offset, hello_length);
    size_t tls_len = hello_length + 5;
    uint8_t corrupt[sizeof(quic_v1)];
    memcpy(corrupt, quic_v1, sizeof(corrupt));
    corrupt[sizeof(corrupt) - 1] ^= 1;
    enum { PREFIX = 32 };
    struct fixture inputs[] = {
        {NULL, NULL, 0, 0, IPPROTO_TCP, false},
        {http, NULL, sizeof(http) - 1, 0, IPPROTO_TCP, false},
        {reply, NULL, sizeof(reply) - 1, 0, IPPROTO_TCP, false},
        {tls, NULL, tls_len, 0, IPPROTO_TCP, false},
        {tls, NULL, PREFIX, 0, IPPROTO_TCP, false},
        {tls + PREFIX, tls, tls_len - PREFIX, PREFIX, IPPROTO_TCP, false},
        {tls + PREFIX, tls, tls_len - PREFIX, PREFIX, IPPROTO_TCP, true},
        {NULL, NULL, 0, 0, IPPROTO_UDP, false},
        {dns, NULL, sizeof(dns), 0, IPPROTO_UDP, false},
        {quic_v1, NULL, sizeof(quic_v1), 0, IPPROTO_UDP, false},
        {quic_v2, NULL, sizeof(quic_v2), 0, IPPROTO_UDP, false},
        {corrupt, NULL, sizeof(corrupt), 0, IPPROTO_UDP, false},
        {quic_v1, decoded, sizeof(quic_v1), decoded_length, IPPROTO_UDP, false},
        {quic_v1, decoded, sizeof(quic_v1), decoded_length, IPPROTO_UDP, true},
    };
    unsigned tcp_cases = 0, udp_cases = 0, replays = 0, queued = 0;
    for (test_case = 0; test_case < sizeof(inputs) / sizeof(*inputs); ++test_case)
    for (test_flags = 0; test_flags < 2048; ++test_flags) {
        struct trace before, after;
        const struct fixture *input = &inputs[test_case];
        run(&before, input, false, test_flags);
        run(&after, input, true, test_flags);
        if (memcmp(&before, &after, sizeof(trace))) {
            fprintf(stderr, "reference %s / %s, actual %s / %s\n", before.effects, before.log,
                after.effects, after.log);
        }
        CHECK(!memcmp(&before, &after, sizeof(trace)));
        if (input->protocol == IPPROTO_TCP) ++tcp_cases; else ++udp_cases;
        replays += after.replays;
        queued += after.queued;
    }
    CHECK(replays && queued);
    printf("PASS packet_play tcp_cases=%u udp_cases=%u replays=%u queued=%u\n",
        tcp_cases, udp_cases, replays, queued);
    check_routes();
    check_lua_rules();
    return 0;
}
