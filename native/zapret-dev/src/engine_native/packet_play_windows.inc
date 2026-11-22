/* MIT. Packet preparation finishes before profile rediscovery and Lua run. */
#include "runtime_log_windows.h"

typedef struct {
    const uint8_t *data;
    size_t length;
} zapret_play_payload;

typedef struct {
    const char *ifin, *ifout;
    uint64_t payload_disable, reassembly_disable;
    uint32_t mark, desync_mark;
    bool replay, debug;
} zapret_payload_input;

typedef struct {
    const zapret_reassembly_ops *reassembly;
    void (*tcp_reply)(struct play_state *);
    void (*tcp_retransmit)(struct play_state *, const char *);
    bool (*dns_response)(const uint8_t *, size_t);
    zapret_log_sink log;
    void (*tls_record)(const uint8_t *, size_t);
    void (*tls_handshake)(const uint8_t *, size_t);
} zapret_payload_ops;

_Static_assert(offsetof(t_ctrack, pos) == 24 && offsetof(t_ctrack, l7proto) == 200 &&
    offsetof(t_ctrack, reasm_client_payload) == 228 && offsetof(t_ctrack, reasm_client) == 232 &&
    offsetof(t_ctrack, delayed) == 264, "Rust packet preparation track ABI");
_Static_assert(offsetof(struct tcphdr, th_flags) == 13 && TH_SYN == 2 &&
    sizeof(zapret_payload_input) == 48 && offsetof(zapret_payload_input, replay) == 40 &&
    sizeof(zapret_payload_ops) == 56 && offsetof(zapret_payload_ops, log) == 32 &&
    sizeof(zapret_play_payload) == 16,
    "Rust packet preparation input ABI");
_Static_assert(TCP_MAX_REASM == 16384 && UDP_MAX_REASM == 16384 &&
    L7P_TLS_CLIENT_HELLO == 9 && L7P_TLS_SERVER_HELLO == 10 && L7P_QUIC_INITIAL == 13 &&
    L7P_DNS_RESPONSE == 27 && IPPROTO_TCP == 6 && IPPROTO_UDP == 17,
    "Rust payload preparation constants");

bool zapret_prepare_tcp(struct play_state *, const zapret_payload_input *,
    const zapret_payload_ops *, zapret_play_payload *);
bool zapret_prepare_udp(struct play_state *, const zapret_payload_input *, const zapret_payload_ops *);
bool zapret_prepare_quic(struct play_state *, const zapret_payload_input *, const zapret_payload_ops *,
    uint8_t *, zapret_play_payload *);

static void packet_play_reply(struct play_state *ps)
{
    process_incoming_fail(ps->ctrack, ps->dp, ps->dis, ps->l7payload, ps->l7proto,
        (struct sockaddr *)&ps->dst);
}
static void packet_play_retransmit(struct play_state *ps, const char *ifin)
{
    process_retrans_fail(ps->ctrack, ps->dis, (struct sockaddr *)&ps->src, ifin);
}
static const zapret_payload_ops payload_ops = {
    .reassembly = &reassembly_ops, .tcp_reply = packet_play_reply, .tcp_retransmit = packet_play_retransmit,
    .dns_response = feed_dns_response, .log = DLOG,
    .tls_record = TLSDebug, .tls_handshake = TLSDebugHandshake,
};

static zapret_payload_input payload_input(const char *ifin, const char *ifout, uint32_t mark, bool replay)
{
    return (zapret_payload_input){
        .ifin = ifin, .ifout = ifout, .payload_disable = params.payload_disable,
        .reassembly_disable = params.reasm_payload_disable, .mark = mark,
        .desync_mark = params.desync_fwmark, .replay = replay, .debug = params.debug,
    };
}

struct packet_play_call {
    const zapret_payload_input *input;
    unsigned int replay_piece, replay_count;
    size_t reasm_offset;
    const t_ctrack_positions *positions;
    uint8_t *modified;
    size_t *modified_length;
};

static uint8_t packet_play_finish(struct play_state *ps, const struct packet_play_call *call,
    zapret_play_payload tcp, zapret_play_payload decrypted)
{
    const zapret_payload_input *in = call->input;
    if (dp_rediscovery(ps)) {
        ps->verdict = desync(ps->dp, in->mark, in->ifin, in->ifout, ps->bReverseFixed,
            ps->ctrack_replay, call->positions, ps->l7payload, ps->l7proto, ps->dis,
            ps->sdip4, ps->sdip6, ps->sdport, call->modified, call->modified_length,
            call->replay_piece, call->replay_count, call->reasm_offset, tcp.data, tcp.length,
            decrypted.data, decrypted.length);
    } else if (ps->dis->tcp) {
        reasm_client_cancel(ps->ctrack);
    }
    if (!ps->bReverseFixed && (ps->verdict & VERDICT_MASK) == VERDICT_DROP)
        return ct_new_postnat_fix(ps->ctrack, ps->dis, call->modified, call->modified_length);
    return ps->verdict;
}

static uint8_t dpi_desync_tcp_packet_play(
    unsigned int replay_piece, unsigned int replay_count, size_t reasm_offset, uint32_t mark,
    const char *ifin, const char *ifout, const t_ctrack_positions *positions,
    const struct dissect *packet, uint8_t *modified, size_t *modified_length)
{
    struct play_state ps;
    if (!play_prolog(&ps, packet, positions, !!replay_count, ifin, ifout, mark))
        return ps.verdict;
    const zapret_payload_input input = payload_input(ifin, ifout, mark, !!replay_count);
    zapret_play_payload payload;
    if (zapret_prepare_tcp(&ps, &input, &payload_ops, &payload))
        return VERDICT_DROP;
    const struct packet_play_call call = {
        &input, replay_piece, replay_count, reasm_offset, positions, modified, modified_length,
    };
    return packet_play_finish(&ps, &call, payload, (zapret_play_payload){0});
}

// Keep the 16 KiB defragmentation buffer off the ordinary UDP path. It
// stays alive through the Lua call that consumes the returned handshake.
static __attribute__((noinline)) uint8_t packet_play_quic(struct play_state *ps, const struct packet_play_call *call)
{
    uint8_t buffer[UDP_MAX_REASM];
    zapret_play_payload payload;
    if (zapret_prepare_quic(ps, call->input, &payload_ops, buffer, &payload))
        return ct_new_postnat_fix(ps->ctrack, ps->dis, call->modified, call->modified_length);
    return packet_play_finish(ps, call, (zapret_play_payload){0}, payload);
}

static uint8_t dpi_desync_udp_packet_play(
    unsigned int replay_piece, unsigned int replay_count, size_t reasm_offset, uint32_t mark,
    const char *ifin, const char *ifout, const t_ctrack_positions *positions,
    const struct dissect *packet, uint8_t *modified, size_t *modified_length)
{
    struct play_state ps;
    if (!play_prolog(&ps, packet, positions, !!replay_count, ifin, ifout, mark))
        return ps.verdict;
    const zapret_payload_input input = payload_input(ifin, ifout, mark, !!replay_count);
    const struct packet_play_call call = {
        &input, replay_piece, replay_count, reasm_offset, positions, modified, modified_length,
    };
    if (zapret_prepare_udp(&ps, &input, &payload_ops))
        return packet_play_quic(&ps, &call);
    return packet_play_finish(&ps, &call, (zapret_play_payload){0}, (zapret_play_payload){0});
}
