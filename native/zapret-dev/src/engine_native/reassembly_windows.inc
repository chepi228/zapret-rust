/* MIT. Supply connection fields, logging, and send callbacks to Rust reassembly. */
typedef struct {
    t_reassemble *buffer;
    t_l7payload *kind;
    const t_ctrack_positions *positions;
    struct rawpacket_queue *delayed;
} zapret_reassembly_session;

typedef struct {
    bool (*send)(const struct sockaddr *, uint32_t, const char *, const void *, size_t);
    bool (*replay)(struct rawpacket_queue *);
    void (*report)(uint32_t, size_t, size_t, size_t);
} zapret_reassembly_ops;

typedef struct {
    const struct sockaddr_storage *destination;
    const char *interface_in, *interface_out;
    const uint8_t *data;
    size_t length, payload_length;
    uint32_t original_mark, mark;
} zapret_deferred_packet;

_Static_assert(sizeof(t_l7payload) == sizeof(uint32_t) && L7P_UNKNOWN == 1,
    "Rust reassembly payload kind ABI");
_Static_assert(IPPROTO_TCP == 6, "Rust reassembly protocol ABI");

extern bool zapret_reassembly_start(const zapret_reassembly_session *, const zapret_reassembly_ops *,
    uint8_t, uint32_t, size_t, size_t, const uint8_t *, size_t);
extern bool zapret_reassembly_append(const zapret_reassembly_session *, const zapret_reassembly_ops *,
    uint8_t, const uint8_t *, size_t);
extern void zapret_reassembly_cancel(const zapret_reassembly_session *, const zapret_reassembly_ops *);
extern bool zapret_reassembly_defer(const zapret_reassembly_session *, const zapret_reassembly_ops *,
    const zapret_deferred_packet *, bool);

static bool replay_queue(struct rawpacket_queue *queue);

#include "runtime_log_windows.h"
void zapret_reassembly_report(uint32_t, size_t, size_t, size_t, zapret_log_sink, zapret_log_sink);

static void reassembly_report(uint32_t event, size_t first, size_t second, size_t third)
{
    zapret_reassembly_report(event, first, second, third, DLOG, DLOG_ERR);
}

static const zapret_reassembly_ops reassembly_ops = {
    .send = rawsend,
    .replay = replay_queue,
    .report = reassembly_report,
};

static zapret_reassembly_session reassembly_session(t_ctrack *track)
{
    return (zapret_reassembly_session){
        .buffer = &track->reasm_client,
        .kind = &track->reasm_client_payload,
        .positions = &track->pos,
        .delayed = &track->delayed,
    };
}

static bool reasm_client_start(t_ctrack *track, uint8_t protocol, t_l7payload kind,
    size_t size, size_t maximum, const uint8_t *data, size_t length)
{
    if (!track) return false;
    const zapret_reassembly_session session = reassembly_session(track);
    return zapret_reassembly_start(&session, &reassembly_ops, protocol, kind, size, maximum, data, length);
}

static bool reasm_client_feed(t_ctrack *track, uint8_t protocol, const uint8_t *data, size_t length)
{
    if (!track) return false;
    const zapret_reassembly_session session = reassembly_session(track);
    return zapret_reassembly_append(&session, &reassembly_ops, protocol, data, length);
}

static void reasm_client_cancel(t_ctrack *track)
{
    if (track) {
        const zapret_reassembly_session session = reassembly_session(track);
        zapret_reassembly_cancel(&session, &reassembly_ops);
    }
}

static bool reasm_client_defer(t_ctrack *track, const struct sockaddr_storage *destination,
    uint32_t original_mark, uint32_t mark, const char *ifin, const char *ifout,
    const struct dissect *packet, bool complete)
{
    const zapret_reassembly_session session = reassembly_session(track);
    const zapret_deferred_packet input = {
        .destination = destination, .interface_in = ifin, .interface_out = ifout,
        .data = packet->data_pkt, .length = packet->len_pkt, .payload_length = packet->len_payload,
        .original_mark = original_mark, .mark = mark,
    };
    return zapret_reassembly_defer(&session, &reassembly_ops, &input, complete);
}
