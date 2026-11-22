/* MIT. Run the real replay adapter against the pinned loop on the same Rust FIFO. */
#include <stdarg.h>

#define VERDICT_PASS 0
#define VERDICT_MODIFY 1
#define VERDICT_DROP 2
#define VERDICT_MASK 3
#define RECONSTRUCT_MAX_SIZE 65536
#define MAX_REPLAY_PIECES 64
#define INPUT_SIZE 16

struct replay_piece {
    bool has_position;
    bool server_side;
    bool send_fails;
    uint8_t protocol;
    uint8_t verdict;
    uint32_t sequence;
    size_t payload_length;
    size_t modified_length;
};

struct replay_trace {
    size_t offsets[MAX_REPLAY_PIECES];
    unsigned sent_indexes[MAX_REPLAY_PIECES];
    char outcomes[MAX_REPLAY_PIECES];
    size_t announced_offset;
    unsigned announced;
    unsigned processed;
    unsigned sent;
    unsigned invalid_lengths;
};

static const struct replay_piece *replay_fixture;
static unsigned replay_fixture_count;
static struct replay_trace replay_trace;

static int DLOG(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    unsigned number = va_arg(args, unsigned);
    if (!strcmp(format, "REPLAYING delayed packet #%u offset %zu\n")) {
        CHECK(number == replay_trace.processed + 1 && number <= replay_fixture_count);
        CHECK(++replay_trace.announced == number);
        replay_trace.announced_offset = va_arg(args, size_t);
    } else {
        CHECK(number && number == replay_trace.processed);
        char outcome;
        if (!strcmp(format, "SENDING delayed packet #%u unmodified\n"))
            outcome = 'P';
        else if (!strcmp(format, "SENDING delayed packet #%u modified\n"))
            outcome = 'M';
        else {
            CHECK(!strcmp(format, "DROPPING delayed packet #%u\n"));
            outcome = 'D';
        }
        CHECK(!replay_trace.outcomes[number - 1]);
        replay_trace.outcomes[number - 1] = outcome;
    }
    va_end(args);
    return 0;
}

static int DLOG_ERR(const char *format, ...)
{
    CHECK(!strcmp(format, "delayed packet #%u has invalid modified length %zu\n"));
    va_list args;
    va_start(args, format);
    unsigned number = va_arg(args, unsigned);
    size_t length = va_arg(args, size_t);
    va_end(args);
    CHECK(number && number == replay_trace.processed);
    CHECK(length == replay_fixture[number - 1].modified_length);
    CHECK(!replay_trace.outcomes[number - 1]);
    replay_trace.outcomes[number - 1] = 'E';
    ++replay_trace.invalid_lengths;
    return 0;
}

static uint8_t dpi_desync_packet_play(unsigned index, unsigned count, size_t offset,
    uint32_t mark, const char *ifin, const char *ifout, const t_ctrack_positions *positions,
    const uint8_t *data, size_t data_length, uint8_t *modified, size_t *modified_length)
{
    CHECK(index == replay_trace.processed && index < replay_fixture_count);
    CHECK(replay_trace.announced == index + 1 && replay_trace.announced_offset == offset);
    CHECK(count == replay_fixture_count && data_length == INPUT_SIZE);
    CHECK(mark == 0x1000 + index && !strcmp(ifin, "input") && !strcmp(ifout, "output"));
    CHECK(*modified_length == RECONSTRUCT_MAX_SIZE && data[0] == index);
    const struct replay_piece *piece = &replay_fixture[index];
    CHECK(!!positions == piece->has_position);
    if (positions) {
        CHECK(positions->ipproto == piece->protocol);
        CHECK(positions->client.seq_last == piece->sequence + (piece->server_side ? 31u : 0u));
        CHECK(positions->server.seq_last == piece->sequence + (piece->server_side ? 0u : 47u));
    }
    replay_trace.offsets[replay_trace.processed++] = offset;
    // The production callback can fix the original packet's checksum in place.
    ((uint8_t *)data)[INPUT_SIZE - 1] = 0x72;
    if ((piece->verdict & VERDICT_MASK) == VERDICT_MODIFY) {
        *modified_length = piece->modified_length;
        if (*modified_length <= RECONSTRUCT_MAX_SIZE) {
            memset(modified, 0xc7, *modified_length);
        }
    }
    return piece->verdict;
}

static bool rawsend(const struct sockaddr *destination, uint32_t mark, const char *ifout,
    const void *data, size_t length)
{
    CHECK(replay_trace.processed != 0 && replay_trace.sent < MAX_REPLAY_PIECES);
    unsigned index = replay_trace.processed - 1;
    const struct replay_piece *piece = &replay_fixture[index];
    const uint8_t *bytes = data;
    CHECK(destination->sa_family == ((index & 1) ? AF_INET6 : AF_INET));
    CHECK(mark == 0x3000 + index && !strcmp(ifout, "output"));
    if ((piece->verdict & VERDICT_MASK) == VERDICT_MODIFY) {
        CHECK(replay_trace.outcomes[index] == 'M');
        CHECK(length == piece->modified_length && length <= RECONSTRUCT_MAX_SIZE);
        if (length != 0) CHECK(bytes[0] == 0xc7 && bytes[length - 1] == 0xc7);
    } else {
        CHECK((piece->verdict & VERDICT_MASK) == VERDICT_PASS);
        CHECK(replay_trace.outcomes[index] == 'P');
        CHECK(length == INPUT_SIZE && bytes[0] == index && bytes[length - 1] == 0x72);
    }
    replay_trace.sent_indexes[replay_trace.sent++] = index;
    return !piece->send_fails;
}

static bool rawsend_rp(const struct rawpacket *packet)
{
    return rawsend((const struct sockaddr *)&packet->dst, packet->fwmark, packet->ifout,
        packet->packet, packet->len);
}

#include "packet_replay_reference.inc"
#include "replay_windows.inc"

static struct replay_trace run_replay(const struct replay_piece *pieces, unsigned count,
    bool (*replay)(struct rawpacket_queue *), bool expected_success)
{
    struct rawpacket_queue queue;
    rawpacket_queue_init(&queue, MAX_REPLAY_PIECES);
    for (unsigned index = 0; index < count; ++index) {
        const struct replay_piece *piece = &pieces[index];
        struct sockaddr_storage destination = {0};
        destination.ss_family = (index & 1) ? AF_INET6 : AF_INET;
        t_ctrack_positions positions = {0};
        positions.ipproto = piece->protocol;
        positions.client.seq_last = piece->sequence + (piece->server_side ? 31u : 0u);
        positions.server.seq_last = piece->sequence + (piece->server_side ? 0u : 47u);
        uint8_t data[INPUT_SIZE] = {0};
        data[0] = index;
        CHECK(rawpacket_queue(&queue, &destination, 0x1000 + index, 0x3000 + index,
            "input", "output", data, sizeof(data), piece->payload_length,
            piece->has_position ? &positions : NULL, piece->server_side));
    }
    struct zapret_packet_entries *storage = queue.entries;
    replay_fixture = pieces;
    replay_fixture_count = count;
    memset(&replay_trace, 0, sizeof(replay_trace));
    CHECK(replay(&queue) == expected_success);
    CHECK(rawpacket_queue_empty(&queue) && queue.entries == storage);
    CHECK(replay_trace.processed == count);
    rawpacket_queue_destroy(&queue);
    return replay_trace;
}

static uint64_t replay_cases, replay_pieces, replay_failed_sends;

static void compare_replay(const struct replay_piece *pieces, unsigned count)
{
    bool success = true;
    for (unsigned index = 0; index < count; ++index) {
        unsigned verdict = pieces[index].verdict & VERDICT_MASK;
        if (verdict <= VERDICT_MODIFY && pieces[index].send_fails) {
            success = false;
            ++replay_failed_sends;
        }
    }
    struct replay_trace original = run_replay(pieces, count, reference_replay_queue, success);
    struct replay_trace rust = run_replay(pieces, count, replay_queue, success);
    CHECK(original.sent == rust.sent && rust.invalid_lengths == 0);
    CHECK(!memcmp(original.offsets, rust.offsets, count * sizeof(rust.offsets[0])));
    CHECK(!memcmp(original.outcomes, rust.outcomes, count));
    CHECK(!memcmp(original.sent_indexes, rust.sent_indexes, rust.sent * sizeof(rust.sent_indexes[0])));
    ++replay_cases;
    replay_pieces += count;
}

static void test_replay(void)
{
    const struct replay_piece wrapped[] = {
        {.has_position = true, .protocol = IPPROTO_TCP, .sequence = UINT32_MAX - 3,
            .send_fails = true},
        {.has_position = true, .protocol = IPPROTO_TCP, .server_side = true, .sequence = 3,
            .verdict = VERDICT_MODIFY | 4, .modified_length = RECONSTRUCT_MAX_SIZE},
        {.payload_length = 9, .verdict = VERDICT_DROP | 8},
        {.verdict = VERDICT_PASS},
    };
    compare_replay(wrapped, sizeof(wrapped) / sizeof(*wrapped));
    CHECK(replay_trace.offsets[1] == 7 && replay_trace.offsets[3] == 16);
    CHECK(replay_trace.sent == 3 && replay_trace.sent_indexes[2] == 3);

    for (unsigned round = 0; round < 2400; ++round) {
        ++step;
        struct replay_piece pieces[MAX_REPLAY_PIECES] = {0};
        unsigned count = round % (MAX_REPLAY_PIECES + 1);
        for (unsigned index = 0; index < count; ++index) {
            struct replay_piece *piece = &pieces[index];
            piece->has_position = !(round & 1) && (index == 0 || random32() % 4 != 0);
            piece->protocol = ((round & 1) && random32() % 2) ? IPPROTO_UDP : IPPROTO_TCP;
            if (round & 1) piece->has_position = piece->protocol == IPPROTO_UDP;
            piece->server_side = random32() & 1;
            piece->sequence = UINT32_MAX - 1024 + index * 113;
            piece->verdict = random32() & 15;
            piece->send_fails = random32() % 5 == 0;
            piece->payload_length = random32() % INPUT_SIZE;
            piece->modified_length = 1 + random32() % 64;
        }
        compare_replay(pieces, count);
    }

    // These inputs exercise behavior that is undefined or unchecked in the C loop.
    const struct replay_piece missing[] = {
        {.payload_length = 9},
        {.has_position = true, .protocol = IPPROTO_TCP, .sequence = UINT32_MAX - 3},
        {.has_position = true, .protocol = IPPROTO_TCP, .sequence = 3},
    };
    struct replay_trace trace = run_replay(missing, 3, replay_queue, true);
    CHECK(trace.offsets[0] == 0 && trace.offsets[1] == 9 && trace.offsets[2] == 16);

    const struct replay_piece overflow[] = {
        {.payload_length = SIZE_MAX},
        {.payload_length = 8},
        {.verdict = VERDICT_DROP},
    };
    trace = run_replay(overflow, 3, replay_queue, true);
    CHECK(trace.offsets[1] == SIZE_MAX && trace.offsets[2] == SIZE_MAX);

    const struct replay_piece oversized[] = {
        {.verdict = VERDICT_MODIFY, .modified_length = RECONSTRUCT_MAX_SIZE + 1},
        {.verdict = VERDICT_PASS},
    };
    trace = run_replay(oversized, 2, replay_queue, false);
    CHECK(trace.invalid_lengths == 1 && trace.sent == 1 && trace.sent_indexes[0] == 1);

    printf("PASS %" PRIu64 " replay queues, %" PRIu64 " replayed packets, %" PRIu64
        " simulated send failures matched pinned C, plus 3 replay boundary regressions\n",
        replay_cases, replay_pieces, replay_failed_sends);
}
