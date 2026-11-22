/* MIT. Bind replay to the engine's packet processing, sending and logging. */
#include "runtime_log_windows.h"

struct zapret_replay_ops {
    uint8_t (*process)(uint32_t, uint32_t, size_t, uint32_t, const char *, const char *,
        const t_ctrack_positions *, const uint8_t *, size_t, uint8_t *, size_t *);
    bool (*send)(const struct sockaddr *, uint32_t, const char *, const void *, size_t);
    zapret_log_sink debug;
    zapret_log_sink error;
};

_Static_assert(RECONSTRUCT_MAX_SIZE == 65536, "Rust replay buffer capacity");
_Static_assert(VERDICT_PASS == 0 && VERDICT_MODIFY == 1 && VERDICT_DROP == 2 && VERDICT_MASK == 3,
    "Rust replay verdict ABI");
_Static_assert(offsetof(t_ctrack_position, seq_last) == 40, "Rust replay sequence ABI");
_Static_assert(offsetof(struct rawpacket, dst) == 0 &&
    offsetof(struct rawpacket, ifin) == 128 && offsetof(struct rawpacket, ifout) == 172 &&
    offsetof(struct rawpacket, fwmark_orig) == 216 && offsetof(struct rawpacket, fwmark) == 220 &&
    offsetof(struct rawpacket, len) == 224 && offsetof(struct rawpacket, packet) == 224 + 2 * sizeof(void *) &&
    offsetof(struct rawpacket, tpos) == 232 + 2 * sizeof(void *) &&
    offsetof(struct rawpacket, tpos_present) == 392 + 2 * sizeof(void *),
    "Rust queued packet send ABI");

extern bool zapret_replay_queue(struct rawpacket_queue *, const struct zapret_replay_ops *);

static bool replay_queue(struct rawpacket_queue *queue)
{
    static const struct zapret_replay_ops ops = {
        .process = dpi_desync_packet_play,
        .send = rawsend,
        .debug = DLOG,
        .error = DLOG_ERR,
    };
    return zapret_replay_queue(queue, &ops);
}
