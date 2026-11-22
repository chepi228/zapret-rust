/* MIT. Compare client reassembly and queue release without calling the driver. */
struct session_trace {
    uint8_t sent[4];
    uint8_t replayed[4];
    unsigned sent_count;
    unsigned replayed_count;
};

static t_ctrack *session_track;
static struct session_trace session_trace;
static bool replay_stops_early;

int DLOG(const char *format, ...)
{
    (void)format;
    return 0;
}

int DLOG_ERR(const char *format, ...)
{
    (void)format;
    return 0;
}

static void check_deferred_packet(const struct rawpacket *packet)
{
    REQUIRE(packet->len == 4 && packet->len_payload == 2 && packet->tpos_present);
    REQUIRE(!strcmp(packet->ifin, "incoming") && !strcmp(packet->ifout, "outgoing"));
    REQUIRE(packet->fwmark_orig == 0x22 && packet->fwmark == 0x44);
    REQUIRE(packet->dst.ss_family == AF_INET && !packet->server_side);
}

bool rawsend(const struct sockaddr *destination, uint32_t mark, const char *interface,
    const void *data, size_t length)
{
    REQUIRE(!session_track->reasm_client.packet && !session_track->reasm_client.size);
    REQUIRE(destination->sa_family == AF_INET && mark == 0x44);
    REQUIRE(!strcmp(interface, "outgoing") && data && length == 4);
    REQUIRE(session_trace.sent_count < sizeof(session_trace.sent));
    session_trace.sent[session_trace.sent_count++] = ((const uint8_t *)data)[0];
    // Simulate failure of the first send. More queued packets must still drain.
    return session_trace.sent_count != 1;
}

bool rawsend_queue(struct rawpacket_queue *queue)
{
    bool success = true;
    struct rawpacket *packet;
    while ((packet = rawpacket_dequeue(queue))) {
        check_deferred_packet(packet);
        success &= rawsend((const struct sockaddr *)&packet->dst, packet->fwmark,
            packet->ifout, packet->packet, packet->len);
        rawpacket_free(packet);
    }
    return success;
}

static bool replay_queue(struct rawpacket_queue *queue)
{
    REQUIRE(session_track->reasm_client.packet && session_track->reasm_client.size_present);
    const t_l7payload kind = session_track->reasm_client_payload;
    REQUIRE(kind == L7P_TLS_CLIENT_HELLO || kind == L7P_QUIC_INITIAL);
    struct rawpacket *packet;
    while ((packet = rawpacket_dequeue(queue))) {
        check_deferred_packet(packet);
        REQUIRE(session_trace.replayed_count < sizeof(session_trace.replayed));
        session_trace.replayed[session_trace.replayed_count++] = packet->packet[0];
        rawpacket_free(packet);
        if (replay_stops_early) return false;
    }
    return true;
}

#define reasm_client_start reference_client_start
#define reasm_client_feed reference_client_feed
#define reasm_client_cancel reference_client_cancel
#define reasm_client_fin reference_client_fin
#define ReasmInit reference_ReasmInit
#define ReasmFeed reference_ReasmFeed
#define ReasmClear reference_ReasmClear
#include "reassembly_session_reference.inc"
#undef ReasmClear
#undef ReasmFeed
#undef ReasmInit
#undef reasm_client_fin
#undef reasm_client_cancel
#undef reasm_client_feed
#undef reasm_client_start

#include "reassembly_windows.inc"

static void init_session(t_ctrack *track, uint8_t protocol, unsigned queue_limit)
{
    memset(track, 0, sizeof(*track));
    track->pos.ipproto = protocol;
    track->reasm_client_payload = L7P_UNKNOWN;
    rawpacket_queue_init(&track->delayed, queue_limit);
    session_track = track;
    memset(&session_trace, 0, sizeof(session_trace));
}

static bool defer_piece(t_ctrack *track, uint8_t id, bool complete, bool original)
{
    const struct sockaddr_storage destination = {.ss_family = AF_INET};
    const uint8_t bytes[] = {id, 0x33, 0x44, 0x55};
    const struct dissect packet = {.data_pkt = bytes, .len_pkt = sizeof(bytes), .len_payload = 2};
    if (!original) {
        return reasm_client_defer(track, &destination, 0x22, 0x44, "incoming", "outgoing", &packet, complete);
    }
    if (!rawpacket_queue(&track->delayed, &destination, 0x22, 0x44, "incoming", "outgoing", bytes,
        sizeof(bytes), 2, &track->pos, false)) {
        reference_client_cancel(track);
        return false;
    }
    if (complete) {
        replay_queue(&track->delayed);
        reference_client_fin(track);
    }
    return true;
}

static void require_idle(const t_ctrack *track)
{
    REQUIRE(!track->reasm_client.packet && !track->reasm_client.size && !track->reasm_client.size_present);
    REQUIRE(track->reasm_client_payload == L7P_UNKNOWN && rawpacket_queue_empty(&track->delayed));
}

enum session_outcome { COMPLETE, CANCEL, QUEUE_FULL, REPLAY_INTERRUPTED };

static struct session_trace complete_session(uint8_t protocol, unsigned length,
    enum session_outcome outcome, bool original, bool known_window)
{
    t_ctrack track;
    init_session(&track, protocol, outcome == QUEUE_FULL ? 1 : 4);
    replay_stops_early = outcome == REPLAY_INTERRUPTED;
    const size_t size = protocol == IPPROTO_TCP ? 2 * length : 16384;
    const t_l7payload kind = protocol == IPPROTO_TCP ? L7P_TLS_CLIENT_HELLO : L7P_QUIC_INITIAL;
    track.pos.client.seq_last = UINT32_MAX - length / 2;
    track.pos.server.pcounter = known_window;
    track.pos.server.winsize_calc = known_window ? size : 0;
    uint8_t first[64], second[64];
    memset(first, 0x61, sizeof(first));
    memset(second, 0x62, sizeof(second));
    bool (*start)(t_ctrack *, uint8_t, t_l7payload, size_t, size_t, const uint8_t *, size_t) =
        original ? reference_client_start : reasm_client_start;
    bool (*append)(t_ctrack *, uint8_t, const uint8_t *, size_t) =
        original ? reference_client_feed : reasm_client_feed;
    REQUIRE(start(&track, protocol, kind, size, 16384, first, length));
    REQUIRE(track.reasm_client_payload == kind && track.reasm_client.size_present == length);
    REQUIRE(defer_piece(&track, 1, false, original));
    track.pos.client.seq_last += length;
    REQUIRE(append(&track, protocol, second, length));
    REQUIRE(track.reasm_client.size_present == 2 * length);
    REQUIRE(!memcmp(track.reasm_client.packet, first, length));
    REQUIRE(!memcmp(track.reasm_client.packet + length, second, length));

    const bool complete = outcome == COMPLETE || outcome == REPLAY_INTERRUPTED;
    REQUIRE(defer_piece(&track, 2, complete, original) == (outcome != QUEUE_FULL));
    if (outcome == CANCEL) {
        if (original) reference_client_cancel(&track);
        else reasm_client_cancel(&track);
    }
    require_idle(&track);
    rawpacket_queue_destroy(&track.delayed);
    replay_stops_early = false;
    return session_trace;
}

static void check_reassembly_lifecycle(void)
{
    uint64_t sessions = 0, sent = 0, replayed = 0;
    for (step = 0; step < 2400; ++step) {
        uint8_t protocol = (step & 1) ? IPPROTO_TCP : IPPROTO_UDP;
        enum session_outcome outcome = (step / 2) % 4;
        unsigned length = 1 + random32() % 64;
        bool known_window = (step / 8) & 1;
        struct session_trace original = complete_session(protocol, length, outcome, true, known_window);
        struct session_trace rust = complete_session(protocol, length, outcome, false, known_window);
        REQUIRE(original.sent_count == rust.sent_count && original.replayed_count == rust.replayed_count);
        REQUIRE(!memcmp(original.sent, rust.sent, sizeof(rust.sent)));
        REQUIRE(!memcmp(original.replayed, rust.replayed, sizeof(rust.replayed)));
        ++sessions;
        sent += rust.sent_count;
        replayed += rust.replayed_count;
    }

    const uint8_t bytes[9] = {0};
    t_ctrack track;
    init_session(&track, IPPROTO_TCP, 4);
    REQUIRE(reference_client_start(&track, IPPROTO_TCP, L7P_TLS_CLIENT_HELLO, 8, 16, bytes, sizeof(bytes)));
    REQUIRE(track.reasm_client.size_present == 0);
    reference_client_cancel(&track);
    REQUIRE(!reasm_client_start(&track, IPPROTO_TCP, L7P_TLS_CLIENT_HELLO, 8, 16, bytes, sizeof(bytes)));
    require_idle(&track);

    REQUIRE(!reasm_client_start(&track, IPPROTO_TCP, L7P_TLS_CLIENT_HELLO, 17, 16, bytes, sizeof(bytes)));
    require_idle(&track);
    REQUIRE(!reasm_client_start(&track, IPPROTO_UDP, L7P_QUIC_INITIAL, SIZE_MAX, SIZE_MAX, bytes, 1));
    require_idle(&track);
    REQUIRE(!reasm_client_start(&track, IPPROTO_TCP, L7P_TLS_CLIENT_HELLO, 0, 16, bytes, 0));
    require_idle(&track);

    track.pos.server.pcounter = 1;
    track.pos.server.winsize_calc = 7;
    REQUIRE(!reference_client_start(&track, IPPROTO_TCP, L7P_TLS_CLIENT_HELLO, 8, 16, bytes, 2));
    REQUIRE(!reasm_client_start(&track, IPPROTO_TCP, L7P_TLS_CLIENT_HELLO, 8, 16, bytes, 2));
    require_idle(&track);
    track.pos.server.pcounter = 0;
    REQUIRE(reasm_client_start(&track, IPPROTO_TCP, L7P_TLS_CLIENT_HELLO, 8, 16, bytes, 2));
    REQUIRE(defer_piece(&track, 1, false, false) && defer_piece(&track, 2, false, false));
    track.pos.client.seq_last = 3;
    REQUIRE(!reasm_client_feed(&track, IPPROTO_TCP, bytes, 1));
    require_idle(&track);
    REQUIRE(session_trace.sent_count == 2 && session_trace.sent[0] == 1 && session_trace.sent[1] == 2);

    track.pos.ipproto = IPPROTO_UDP;
    REQUIRE(reasm_client_start(&track, IPPROTO_UDP, L7P_QUIC_INITIAL, 4, 4, bytes, 3));
    REQUIRE(defer_piece(&track, 3, false, false));
    REQUIRE(!reasm_client_feed(&track, IPPROTO_UDP, bytes, 2));
    require_idle(&track);
    REQUIRE(session_trace.sent_count == 3 && session_trace.sent[2] == 3);
    reasm_client_cancel(&track);
    REQUIRE(session_trace.sent_count == 3);
    rawpacket_queue_destroy(&track.delayed);

    printf("PASS %" PRIu64 " reassembly sessions matched pinned C, %" PRIu64
        " original sends and %" PRIu64 " replays compared, plus 7 boundary checks\n",
        sessions, sent, replayed);
}
