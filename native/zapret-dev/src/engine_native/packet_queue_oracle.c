/* MIT. In-memory comparison of the original queue and the Rust FIFO. */
#include "packet_queue.h"
#include "packet_queue_reference.inc"

_Static_assert(sizeof(struct sockaddr_storage) == 128 &&
    _Alignof(struct sockaddr_storage) == 8 && IFNAMSIZ == 44, "Rust packet address ABI");
_Static_assert(sizeof(t_ctrack_positions) == 160 && _Alignof(t_ctrack_positions) == 8,
    "Rust packet positions ABI");
_Static_assert(offsetof(struct rawpacket_queue, max_packets) == sizeof(void *),
    "Rust packet queue ABI");
_Static_assert(offsetof(struct rawpacket, fwmark_orig) == 216 &&
    offsetof(struct rawpacket, len) == 224 && offsetof(struct rawpacket, packet) == 224 + 2 * sizeof(void *) &&
    offsetof(struct rawpacket, tpos) == 232 + 2 * sizeof(void *) &&
    offsetof(struct rawpacket, tpos_present) == 392 + 2 * sizeof(void *) &&
    offsetof(struct rawpacket, server_side) == 393 + 2 * sizeof(void *) &&
    sizeof(struct rawpacket) == 400 + 2 * sizeof(void *),
    "Rust packet record ABI");

static uint64_t pushes, rejected, popped, resets;
static unsigned step;
static uint32_t random_state = 0xecf6197a;

#define CHECK(value) do { \
    if (!(value)) { \
        fprintf(stderr, "FAIL packet queue step %u line %d: %s\n", step, __LINE__, #value); \
        exit(1); \
    } \
} while (0)

static uint32_t random32(void)
{
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return random_state;
}

static void compare_packet(const struct reference_rawpacket *left, const struct rawpacket *right)
{
    CHECK(left && right);
    CHECK(!memcmp(&left->dst, &right->dst, sizeof(left->dst)));
    CHECK(!strcmp(left->ifin, right->ifin) && !strcmp(left->ifout, right->ifout));
    CHECK(left->fwmark_orig == right->fwmark_orig && left->fwmark == right->fwmark);
    CHECK(left->len == right->len && left->len_payload == right->len_payload);
    CHECK(!memcmp(left->packet, right->packet, left->len));
    CHECK(left->tpos_present == right->tpos_present && left->server_side == right->server_side);
    if (left->tpos_present) CHECK(!memcmp(&left->tpos, &right->tpos, sizeof(left->tpos)));
}

static void compare_queue(const struct reference_rawpacket_queue *left, const struct rawpacket_queue *right)
{
    CHECK(left->max_packets == right->max_packets);
    CHECK(reference_rawpacket_queue_count(left) == rawpacket_queue_count(right));
    CHECK(reference_rawpacket_queue_empty(left) == rawpacket_queue_empty(right));
}

static struct rawpacket *enqueue(struct reference_rawpacket_queue *left, struct rawpacket_queue *right)
{
    unsigned char bytes[512];
    for (size_t i = 0; i < sizeof(bytes); ++i) bytes[i] = (unsigned char)random32();
    char iface[96];
    memset(iface, 'A' + step % 26, sizeof(iface) - 1);
    iface[sizeof(iface) - 1] = 0;
    const char *in = step % 7 == 0 ? NULL : step % 7 == 1 ? "" : step % 7 == 2 ? iface : "3.1";
    const char *out = step % 3 == 0 ? NULL : step % 3 == 1 ? "Wi-Fi" : iface;
    struct sockaddr_storage destination;
    memset(&destination, 0, sizeof(destination));
    destination.ss_family = step & 1 ? AF_INET : AF_INET6;
    t_ctrack_positions positions;
    memset(&positions, 0, sizeof(positions));
    positions.state = step % 3;
    positions.client.pcounter = step;
    positions.server.seq_last = random32();
    positions.t_last.tv_sec = random32();
    positions.t_last.tv_nsec = 1234567;
    positions.ipproto = step & 1 ? IPPROTO_TCP : IPPROTO_UDP;
    const t_ctrack_positions *snapshot = step % 7 == 0 ? NULL : &positions;
    const size_t length = step % 19 == 0 ? 0 : random32() % (sizeof(bytes) + 1);
    const size_t payload_length = random32() % (length + 1);
    const uint32_t mark = random32();
    const bool server = step % 3 == 0;
    struct reference_rawpacket *a = reference_rawpacket_queue(left, &destination,
        step, mark, in, out, bytes, length, payload_length, snapshot, server);
    struct rawpacket *b = rawpacket_queue(right, &destination, step, mark, in, out,
        bytes, length, payload_length, snapshot, server);
    CHECK(!!a == !!b);
    if (a) {
        // The queue must own its inputs. Change every reusable source buffer.
        memset(bytes, 0x5a, sizeof(bytes));
        memset(iface, '?', sizeof(iface) - 1);
        memset(&destination, 0, sizeof(destination));
        memset(&positions, 0, sizeof(positions));
        compare_packet(a, b);
        CHECK(a->packet != bytes && b->packet != bytes);
        ++pushes;
    } else {
        ++rejected;
    }
    compare_queue(left, right);
    ++step;
    return b;
}

static void dequeue(struct reference_rawpacket_queue *left, struct rawpacket_queue *right)
{
    struct reference_rawpacket *a = reference_rawpacket_dequeue(left);
    struct rawpacket *b = rawpacket_dequeue(right);
    CHECK(!!a == !!b);
    if (a) {
        compare_packet(a, b);
        reference_rawpacket_free(a);
        rawpacket_free(b);
        ++popped;
    }
    compare_queue(left, right);
    ++step;
}

static void clear_queues(struct reference_rawpacket_queue *left, struct rawpacket_queue *right)
{
    struct reference_rawpacket *a = reference_rawpacket_dequeue(left);
    struct rawpacket *b = rawpacket_dequeue(right);
    CHECK(!!a == !!b);
    reference_rawpacket_queue_destroy(left);
    rawpacket_queue_destroy(right);
    compare_queue(left, right);
    CHECK(rawpacket_queue_empty(right) && !right->entries);
    if (a) {
        // Popped packets outlive the queue and must be freed independently.
        compare_packet(a, b);
        reference_rawpacket_free(a);
        rawpacket_free(b);
        ++popped;
    }
    ++resets;
}

static void test_limit(unsigned maximum)
{
    struct reference_rawpacket_queue left;
    struct rawpacket_queue right;
    reference_rawpacket_queue_init(&left, maximum);
    rawpacket_queue_init(&right, maximum);
    dequeue(&left, &right);
    struct rawpacket *first = enqueue(&left, &right);
    CHECK(first);
    const unsigned fill = maximum ? maximum : 257;
    for (unsigned i = 1; i <= fill; ++i) {
        struct rawpacket *entry = enqueue(&left, &right);
        CHECK(!!entry == (!maximum || i < maximum));
    }
    struct reference_rawpacket *a = reference_rawpacket_dequeue(&left);
    struct rawpacket *b = rawpacket_dequeue(&right);
    CHECK(b == first);
    compare_packet(a, b);
    reference_rawpacket_free(a);
    rawpacket_free(b);
    ++popped;
    CHECK(enqueue(&left, &right));
    for (unsigned i = 0; i < 20000; ++i) {
        unsigned action = random32() % 100;
        if (action < 64) enqueue(&left, &right);
        else if (action < 99) dequeue(&left, &right);
        else clear_queues(&left, &right);
    }
    while (!reference_rawpacket_queue_empty(&left)) dequeue(&left, &right);
    CHECK(rawpacket_queue_empty(&right));
    struct zapret_packet_entries *retained = right.entries;
    dequeue(&left, &right);
    CHECK(right.entries == retained);
    clear_queues(&left, &right);
    clear_queues(&left, &right);
}

#include "packet_replay_oracle.inc"

#undef main
int main(void)
{
    struct rawpacket_queue partial = {0};
    rawpacket_queue_destroy(&partial);
    CHECK(rawpacket_queue_empty(&partial));
    rawpacket_free(NULL);
    for (unsigned i = 0; i < 5; ++i) {
        static const unsigned limits[] = {0, 1, 7, 64, 129};
        test_limit(limits[i]);
    }
    printf("PASS %" PRIu64 " enqueued, %" PRIu64 " rejected, %" PRIu64
        " dequeued, %" PRIu64 " cleared queues matched pinned C\n", pushes, rejected, popped, resets);
    test_replay();
    return 0;
}
