/* MIT. Pinned C versus Rust-backed conntrack, entirely in process memory. */
#include "conntrack_fixture.h"
#include <inttypes.h>

void *reference_create(time_t, uint32_t, uint32_t, uint32_t, uint32_t);
void reference_destroy(void *);
bool reference_feed(void *, const struct dissect *, t_ctrack **, bool *);
bool reference_search(void *, const struct dissect *, t_ctrack **, bool *);
bool reference_drop(void *, const struct dissect *);
void reference_purge(void *);
t_ctrack *reference_after(void *, size_t *, t_conn *);
time_t reference_last_purge(void *);
bool reference_ConntrackExtractConn(t_conn *, bool, const struct dissect *);
bool reference_ReasmInit(t_reassemble *, size_t, uint32_t);
void reference_ReasmClear(t_reassemble *);
bool reference_ReasmFeed(t_reassemble *, uint32_t, const void *, size_t);
bool reference_ReasmHasSpace(t_reassemble *, size_t);

struct params_s params;
static time_t fake_time = 100;
static uint32_t random_state = 0x9813fa72;
static unsigned allocations, releases, next_ref;
static unsigned char refs[2000000];
static uint64_t feeds, snapshots, reassemblies, keys, purges;
static unsigned step;

#define REQUIRE(value) do { if (!(value)) { \
    fprintf(stderr, "FAIL conntrack step %u at line %d: %s\n", step, __LINE__, #value); \
    exit(1); } } while (0)

static uint32_t random32(void)
{
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return random_state;
}
time_t boottime(void) { return fake_time; }
int fixture_clock_gettime(clockid_t clock, struct timespec *out)
{
    (void)clock;
    memset(out, 0, sizeof(*out));
    out->tv_sec = fake_time;
    out->tv_nsec = 1234567;
    return 0;
}
void lua_createtable(lua_State *L, int a, int b) { (void)L; (void)a; (void)b; }
int luaL_ref(lua_State *L, int index)
{
    (void)L; (void)index;
    REQUIRE(++next_ref < sizeof(refs));
    refs[next_ref] = 1;
    ++allocations;
    return next_ref;
}
void luaL_unref(lua_State *L, int index, int ref)
{
    (void)L; (void)index;
    if (ref < 0) return;
    REQUIRE(ref > 0 && (unsigned)ref <= next_ref && refs[ref]);
    refs[ref] = 0;
    ++releases;
}
uint16_t pntoh16(const uint8_t *p) { return ((uint16_t)p[0] << 8) | p[1]; }
#include "tcp_helpers.inc"

static void same_track(const t_ctrack *a, const t_ctrack *b)
{
    REQUIRE(!memcmp(&a->pos, &b->pos, sizeof(a->pos)));
    REQUIRE(!memcmp(&a->t_start, &b->t_start, sizeof(a->t_start)));
    REQUIRE(a->bCheckDone == b->bCheckDone && a->bCheckResult == b->bCheckResult &&
        a->bCheckExcluded == b->bCheckExcluded && a->dp == b->dp &&
        a->dp_search_complete == b->dp_search_complete &&
        a->req_retrans_counter == b->req_retrans_counter &&
        a->failure_detect_finalized == b->failure_detect_finalized &&
        a->incoming_ttl == b->incoming_ttl && a->b_cutoff == b->b_cutoff &&
        a->b_lua_in_cutoff == b->b_lua_in_cutoff && a->b_lua_out_cutoff == b->b_lua_out_cutoff);
    REQUIRE(a->l7proto == b->l7proto && a->l7proto_discovered == b->l7proto_discovered &&
        a->hostname_is_ip == b->hostname_is_ip && a->hostname_discovered == b->hostname_discovered &&
        a->hostname_ah_check == b->hostname_ah_check &&
        a->reasm_client_payload == b->reasm_client_payload);
    REQUIRE(!!a->hostname == !!b->hostname);
    if (a->hostname) REQUIRE(!strcmp(a->hostname, b->hostname));
    REQUIRE(refs[a->lua_state] && refs[b->lua_state] &&
        refs[a->lua_instance_cutoff] && refs[b->lua_instance_cutoff]);
    REQUIRE(a->delayed.max_packets == b->delayed.max_packets &&
        rawpacket_queue_count(&a->delayed) == rawpacket_queue_count(&b->delayed));
    REQUIRE(a->reasm_client.size == b->reasm_client.size &&
        a->reasm_client.size_present == b->reasm_client.size_present &&
        a->reasm_client.seq == b->reasm_client.seq);
    if (a->reasm_client.size_present)
        REQUIRE(!memcmp(a->reasm_client.packet, b->reasm_client.packet, a->reasm_client.size_present));
    ++snapshots;
}
static void same_table(void *reference, t_conntrack *actual)
{
    size_t left = 0;
    uint64_t right = 0;
    t_conn key;
    t_ctrack *a;
    t_conntrack_pool *b;
    for (;;) {
        a = reference_after(reference, &left, &key);
        b = zapret_conntrack_after(actual->pool, &right);
        REQUIRE(!!a == !!b);
        if (!a) break;
        REQUIRE(!memcmp(&key, &b->conn, sizeof(key)));
        same_track(a, &b->track);
    }
    REQUIRE(reference_last_purge(reference) == actual->t_last_purge);
}

typedef struct {
    struct ip ip;
    struct ip6_hdr ip6;
    union { uint64_t align; unsigned char bytes[60]; } transport;
    struct dissect dis;
} test_packet;

static void make_packet(test_packet *p, unsigned tuple, bool reverse, unsigned flags,
    uint32_t sequence, uint32_t ack, size_t payload)
{
    memset(p, 0, sizeof(*p));
    bool ipv6 = tuple & 1, udp = tuple & 2;
    uint32_t source = htonl(0xc0000201 + tuple * 2), destination = htonl(0xc6336401 + tuple * 2);
    p->ip.ip_src.s_addr = reverse ? destination : source;
    p->ip.ip_dst.s_addr = reverse ? source : destination;
    memcpy((unsigned char *)&p->ip6.ip6_src + 12, &p->ip.ip_src, 4);
    memcpy((unsigned char *)&p->ip6.ip6_dst + 12, &p->ip.ip_dst, 4);
    ((unsigned char *)&p->ip6.ip6_src)[0] = 0x20;
    ((unsigned char *)&p->ip6.ip6_dst)[0] = 0x20;
    p->ip6.ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000 | (tuple << 10));
    p->dis.ip = ipv6 ? NULL : &p->ip;
    p->dis.ip6 = ipv6 ? &p->ip6 : NULL;
    p->dis.len_payload = payload;
    uint16_t sport = 20000 + tuple, dport = 443;
    struct tcphdr *tcp = (struct tcphdr *)p->transport.bytes;
    tcp->th_sport = htons(reverse ? dport : sport);
    tcp->th_dport = htons(reverse ? sport : dport);
    if (udp) {
        p->dis.udp = (struct udphdr *)tcp;
        p->dis.len_l4 = 8;
    } else {
        p->dis.tcp = tcp;
        tcp->th_seq = htonl(sequence);
        tcp->th_ack = htonl(ack);
        tcp->th_flags = flags;
        tcp->th_win = htons(sequence & 0xffff);
        tcp->th_off = 8;
        memcpy(p->transport.bytes + 20, (unsigned char[]){1,2,4,5,180,3,3,14,0,0,0,0}, 12);
        p->dis.len_l4 = 32;
    }
}
static bool feed_pair(void *reference, t_conntrack *actual, test_packet *packet,
    t_ctrack **out_a, t_ctrack **out_b)
{
    bool ar = true, br = true;
    t_ctrack *a = NULL, *b = NULL;
    unsigned allocated = allocations, freed = releases;
    bool av = reference_feed(reference, &packet->dis, &a, &ar);
    unsigned delta_allocated = allocations - allocated, delta_freed = releases - freed;
    allocated = allocations; freed = releases;
    bool bv = ConntrackPoolFeed(actual, &packet->dis, &b, &br);
    REQUIRE(av == bv && ar == br && !!a == !!b);
    REQUIRE(allocations - allocated == delta_allocated && releases - freed == delta_freed);
    if (av) {
        same_track(a, b);
        t_ctrack *as = NULL, *bs = NULL;
        bool ars = !ar, brs = !br;
        REQUIRE(reference_search(reference, &packet->dis, &as, &ars));
        REQUIRE(ConntrackPoolDoubleSearch(actual, &packet->dis, &bs, &brs));
        REQUIRE(as == a && bs == b && ars == ar && brs == br);
    }
    if (out_a) *out_a = a;
    if (out_b) *out_b = b;
    ++feeds;
    return av;
}
static void purge_pair(void *reference, t_conntrack *actual)
{
    unsigned allocated = allocations, freed = releases;
    reference_purge(reference);
    unsigned delta_allocated = allocations - allocated, delta_freed = releases - freed;
    allocated = allocations; freed = releases;
    ConntrackPoolPurge(actual);
    REQUIRE(allocations - allocated == delta_allocated && releases - freed == delta_freed);
    same_table(reference, actual);
    ++purges;
}
static void owned_buffers(t_ctrack *track, bool reference)
{
    track->hostname = strdup("example.test");
    REQUIRE(track->hostname);
    track->hostname_discovered = track->hostname_is_ip = true;
    if (reference) {
        REQUIRE(reference_ReasmInit(&track->reasm_client, 32, 123));
        REQUIRE(reference_ReasmFeed(&track->reasm_client, 123, "hello", 5));
    } else {
        REQUIRE(ReasmInit(&track->reasm_client, 32, 123));
        REQUIRE(ReasmFeed(&track->reasm_client, 123, "hello", 5));
    }
    struct sockaddr_storage address = {0};
    REQUIRE(rawpacket_queue(&track->delayed, &address, 0, 0, NULL, NULL,
        "queued", 6, 6, &track->pos, false));
}

static void check_connections(void)
{
    t_conntrack actual;
    ConntrackPoolInit(&actual, 3, 7, 11, 5, 9);
    void *reference = reference_create(3, 7, 11, 5, 9);
    test_packet p;
    t_ctrack *a, *b;
    // Exercise every TCP flags value and all option scale bytes, including
    // SCALE_NONE=255 and malformed option lengths, with independent tuples.
    for (step = 0; step < 256; ++step) {
        make_packet(&p, step * 4, false, step, step, 1, 0);
        feed_pair(reference, &actual, &p, NULL, NULL);
        make_packet(&p, 2048 + step * 4, false, 2, step, 1, 0);
        p.transport.bytes[27] = step;
        feed_pair(reference, &actual, &p, NULL, NULL);
    }
    same_table(reference, &actual);
    // Explicit tuple reuse must free hostname, reassembly, queued packets and
    // both Lua references. Counters on the resetting SYN remain zero.
    make_packet(&p, 4096, false, 2, 100, 0, 0);
    REQUIRE(feed_pair(reference, &actual, &p, &a, &b));
    owned_buffers(a, true); owned_buffers(b, false);
    make_packet(&p, 4096, true, 0x12, 900, 101, 0);
    feed_pair(reference, &actual, &p, NULL, NULL);
    make_packet(&p, 4096, false, 0x10, 101, 901, 4);
    feed_pair(reference, &actual, &p, NULL, NULL);
    make_packet(&p, 4096, true, 0x11, 901, 105, 0);
    feed_pair(reference, &actual, &p, NULL, NULL);
    make_packet(&p, 4096, false, 2, 10000, 0, 0);
    REQUIRE(feed_pair(reference, &actual, &p, &a, &b));
    REQUIRE(!b->hostname && !b->reasm_client.packet && rawpacket_queue_empty(&b->delayed));
    REQUIRE(!b->pos.client.pcounter);
    for (step = 0; step < 40000; ++step) {
        unsigned tuple = random32() & 511, flags = random32() & 255;
        make_packet(&p, tuple, random32() & 1, flags, random32(), random32(), random32() % 3001);
        if (p.dis.tcp) {
            unsigned size = 20 + (random32() % 11) * 4;
            ((struct tcphdr *)p.transport.bytes)->th_off = size / 4;
            p.dis.len_l4 = size;
            for (unsigned i = 20; i < size; ++i) p.transport.bytes[i] = random32();
        }
        feed_pair(reference, &actual, &p, &a, &b);
        if ((step % 29) == 0) REQUIRE(reference_drop(reference, &p.dis) == ConntrackPoolDrop(&actual, &p.dis));
        if ((step % 131) == 0) same_table(reference, &actual);
        if ((step % 997) == 0) { ++fake_time; purge_pair(reference, &actual); }
    }
    // Extraction zeroes unused IPv4 bytes and padding; no-IP/no-L4 keys fail.
    for (step = 0; step < 10000; ++step) {
        make_packet(&p, random32() & 511, random32() & 1, 2, 1, 2, 0);
        if (step % 5 == 0) p.dis.ip = NULL, p.dis.ip6 = NULL;
        if (step % 7 == 0) p.dis.tcp = NULL, p.dis.udp = NULL;
        for (unsigned reverse = 0; reverse < 2; ++reverse) {
            t_conn ka, kb;
            memset(&ka, 0xa5, sizeof(ka)); memset(&kb, 0xa5, sizeof(kb));
            bool ra = reference_ConntrackExtractConn(&ka, reverse, &p.dis);
            bool rb = ConntrackExtractConn(&kb, reverse, &p.dis);
            REQUIRE(ra == rb && !memcmp(&ka, &kb, sizeof(ka)));
            ++keys;
        }
    }
    // Time zero, backwards clock, purge interval boundary and cutoff entries.
    fake_time = 0; purge_pair(reference, &actual);
    fake_time = 1; purge_pair(reference, &actual);
    fake_time = 200; purge_pair(reference, &actual);
    for (step = 0; step < 32; ++step) {
        make_packet(&p, step, false, 2, 1, 0, 0);
        REQUIRE(feed_pair(reference, &actual, &p, &a, &b));
        a->pos.state = b->pos.state = step % 4;
        a->b_cutoff = b->b_cutoff = step % 5 == 0;
        a->pos.t_last.tv_sec = b->pos.t_last.tv_sec = 198 + (step % 13);
    }
    for (step = 0; step < 30; ++step) {
        fake_time = 201 + step;
        purge_pair(reference, &actual);
    }
    reference_destroy(reference); ConntrackPoolDestroy(&actual);
    same_table(reference, &actual);
    reference_destroy(reference); ConntrackPoolDestroy(&actual);
    REQUIRE(!actual.pool);
    free(reference);
}
static void check_reassembly(void)
{
    unsigned char payload[256];
    for (step = 0; step < 160000; ++step) {
        size_t size = 1 + random32() % 256;
        uint32_t start = random32();
        t_reassemble a = {0}, b = {0};
        REQUIRE(reference_ReasmInit(&a, size, start) == ReasmInit(&b, size, start));
        memset(a.packet, 0x5a, size); memset(b.packet, 0x5a, size);
        for (unsigned part = 0; part < 6; ++part) {
            size_t length = random32() % 256;
            uint32_t sequence;
            switch (part) {
                case 0: sequence = start; break;
                case 1: sequence = a.seq; break;
                case 2: sequence = a.seq - (random32() % 128); break;
                case 3: sequence = a.seq + 1; break;
                case 4: sequence = a.seq - 0x100000; break;
                default: sequence = a.seq - 0x100001; break;
            }
            for (unsigned i = 0; i < sizeof(payload); ++i) payload[i] = random32();
            REQUIRE(reference_ReasmFeed(&a, sequence, payload, length) == ReasmFeed(&b, sequence, payload, length));
            REQUIRE(a.seq == b.seq && a.size == b.size && a.size_present == b.size_present);
            REQUIRE(!memcmp(a.packet, b.packet, size));
            REQUIRE(reference_ReasmHasSpace(&a, length) == ReasmHasSpace(&b, length));
            /* Oversized requests must fail even when the original addition wraps. */
            REQUIRE(!ReasmHasSpace(&b, SIZE_MAX - length));
            ++reassemblies;
        }
        reference_ReasmClear(&a); ReasmClear(&b);
        reference_ReasmClear(&a); ReasmClear(&b);
        REQUIRE(!a.packet && !b.packet && !a.size && !b.size && !a.size_present && !b.size_present);
    }
}
#include "reassembly_session_oracle.inc"

#undef main
int main(void)
{
    check_connections();
    check_reassembly();
    REQUIRE(allocations == releases);
    printf("PASS %" PRIu64 " connection feeds, %" PRIu64 " state snapshots, %" PRIu64
        " keys, %" PRIu64 " purges, %" PRIu64 " reassembly decisions; %u Lua references released\n",
        feeds, snapshots, keys, purges, reassemblies, releases);
    check_reassembly_lifecycle();
    return 0;
}
