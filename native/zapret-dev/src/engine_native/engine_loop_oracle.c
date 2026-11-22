/* MIT. Run the pinned and Rust batch dispatchers with identical in-memory inputs. */
#include "darkmagic.h"
#include "engine_loop_windows.h"
#include <assert.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#undef main

#define RECONSTRUCT_MAX_SIZE 65536
#define BATCHES 4096
#define HASH_START UINT64_C(14695981039346656037)

static struct {
    bool intercept, timers_dirty;
    void *timers, *L;
    const char *windivert_filter;
} params = { .intercept = true };
volatile sig_atomic_t bQuit;
static bool compare_pending;
static uint64_t trace, expected;
static unsigned batches, id_cursor, activations, closes, sleeps, oversize;
static unsigned registered, initializations, preparations, collections, fuzzes;
static unsigned processed, sent, ipv4_errors, ipv6_errors, send_errors;
static uint32_t seed = 17;
uint32_t w_win32_error;

static void hash_bytes(const void *data, size_t length)
{
    const uint8_t *bytes = data;
    for (size_t i = 0; i < length; ++i)
        trace = (trace ^ bytes[i]) * UINT64_C(1099511628211);
}

static int log_message(const char *format, ...)
{
    char message[256];
    va_list args;
    va_start(args, format);
    int length = vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    assert(length >= 0 && (size_t)length < sizeof(message));
    hash_bytes(message, length + 1);
    if (!compare_pending) return length;
    ipv4_errors += !strcmp(format, "invalid ipv4 packet\n");
    ipv6_errors += !strcmp(format, "invalid ipv6 packet\n");
    send_errors += !strcmp(format, "windivert: reinject of packet id=%u failed\n");
    return length;
}

#define DLOG log_message
#define DLOG_ERR log_message
#define DLOG_CONDUP log_message

static void catch_signals(void) { ++registered; }
static void ReloadCheck(void) { ++preparations; }
static void lua_do_gc(void) { ++collections; }
static void do_fuzz(void) { ++fuzzes; }
uint64_t boottime_ms(void) { return 0; }
static uint64_t TimerPoolNext(const void *pool, bool *dirty) { return 0; }
static uint64_t TimerPoolRun(void **pool, bool *dirty, uint64_t now) { return 0; }
bool win_sandbox(void) { return true; }
bool windivert_init(const char *filter) { ++activations; return true; }
void rawsend_cleanup(void) { ++closes; }
bool logical_net_filter_match(void) { return !closes || sleeps >= 2; }
static bool lua_init(void) { ++initializations; params.L = &params; return true; }

static uint8_t processPacketData(uint32_t *mark, const char *ifin, const char *ifout,
    const uint8_t *packet, size_t length, uint8_t *modified, size_t *modified_length)
{
    assert(*mark == 0 && *modified_length == RECONSTRUCT_MAX_SIZE);
    assert((!*ifin) != (!*ifout));
    unsigned int index, subindex;
    assert(sscanf(*ifin ? ifin : ifout, "%u.%u", &index, &subindex) == 2);
    hash_bytes(ifin, strlen(ifin) + 1);
    hash_bytes(ifout, strlen(ifout) + 1);
    hash_bytes(&length, sizeof(length));
    hash_bytes(packet, length);
    if (compare_pending) ++processed;
    if ((index & VERDICT_MASK) == VERDICT_MODIFY) {
        for (size_t i = 0; i < length; ++i)
            modified[i] = packet[length - 1 - i];
        modified[length] = subindex;
        *modified_length = length + 1;
    }
    return index & VERDICT_MASK_VALID;
}

bool windivert_send(const uint8_t *packet, size_t length, const WINDIVERT_ADDRESS *address)
{
    hash_bytes(&length, sizeof(length));
    hash_bytes(packet, length);
    hash_bytes(address, sizeof(*address));
    if (compare_pending) ++sent;
    return address->Network.SubIfIdx % 7 != 0;
}

#include "engine_loop_windows.inc"

static void reference_batch(uint8_t *packets, size_t len, WINDIVERT_ADDRESS *wa, unsigned wa_count)
{
    uint8_t modified[RECONSTRUCT_MAX_SIZE];
    uint8_t *packet, *mod = modified, verdict;
    size_t left, packet_len, modlen;
    unsigned n, id = id_cursor;
    uint32_t mark;
    char ifname[IFNAMSIZ];
#include "engine_loop_reference.inc"
    id_cursor = id;
}

static uint32_t random_word(void)
{
    seed = seed * UINT32_C(1664525) + UINT32_C(1013904223);
    return seed ^ (seed >> 16);
}

static void fill_batch(uint8_t *data, WINDIVERT_ADDRESS *addresses, zapret_capture_batch *batch)
{
    size_t capacity = batch->length;
    unsigned count = 1 + random_word() % batch->count;
    batch->count = count;
    batch->length = 0;
    memset(addresses, 0, count * sizeof(*addresses));
    for (unsigned i = 0; i < count; ++i) {
        uint32_t flags = random_word();
        WINDIVERT_ADDRESS *wa = addresses + i;
        wa->Timestamp = batches;
        wa->Outbound = !!(flags & 1);
        wa->IPv6 = !!(flags & 2);
        wa->IPChecksum = !!(flags & 4);
        wa->TCPChecksum = !!(flags & 8);
        wa->UDPChecksum = !!(flags & 16);
        wa->Impostor = (flags & 96) == 96;
        wa->Network.IfIdx = random_word();
        wa->Network.SubIfIdx = random_word();
        unsigned header = wa->IPv6 ? 40 : 20;
        unsigned length = header + random_word() % 193;
        uint8_t *packet = data + batch->length;
        assert(batch->length + length <= capacity);
        memset(packet, flags >> 8, length);
        packet[0] = wa->IPv6 ? 0x60 : 0x45;
        unsigned field = wa->IPv6 ? 4 : 2;
        unsigned declared = wa->IPv6 ? length - header : length;
        if (i == count - 1) {
            switch (batches % 13) {
            case 0: length = header - 1; break;
            case 1: declared = 65535; break;
            case 2: if (!wa->IPv6) declared = 0; break;
            }
        }
        packet[field] = declared >> 8;
        packet[field + 1] = declared;
        batch->length += length;
    }
}

uint32_t zapret_capture_receive(void *addresses, uint8_t *packet,
    zapret_capture_batch *batch, uint64_t *deadline)
{
    if (compare_pending) {
        assert(trace == expected);
        compare_pending = false;
    }
    if (batches == BATCHES) return ZAPRET_QUIT;
    if (batches == BATCHES / 2 && activations == 1) {
        id_cursor = 0;
        *deadline = 42;
        return ZAPRET_RECONNECT;
    }
    if (batches % 128 == 0 && oversize == batches / 128) {
        ++oversize;
        return ZAPRET_OVERSIZE;
    }
    assert(*deadline == 0 && batch->length == 196608 && batch->count == 128);
    fill_batch(packet, addresses, batch);
    ++batches;
    trace = HASH_START;
    reference_batch(packet, batch->length, addresses, batch->count);
    expected = trace;
    trace = HASH_START;
    compare_pending = true;
    return ZAPRET_BATCH;
}

static void fake_sleep(uint64_t millis)
{
    assert(millis == 500);
    ++sleeps;
}

void check_overlapped_receive(void);

int main(void)
{
    zapret_capture_ops ops = capture_ops;
    ops.sleep_ms = fake_sleep;
    WINDIVERT_ADDRESS addresses[ZAPRET_CAPTURE_ADDRESS_COUNT];
    assert(zapret_capture_loop(&ops, addresses, true) == 0);
    assert(batches == BATCHES && preparations == batches && collections == batches);
    assert(activations == 2 && initializations == 1 && fuzzes == 2);
    assert(closes == 1 && registered == 1 && sleeps == 2 && oversize == BATCHES / 128);
    assert(processed && sent && ipv4_errors && ipv6_errors && send_errors);
    printf("PASS %u batches, %u processed packets, %u sends, %u malformed frames and %u failed sends matched pinned C\n",
        batches, processed, sent, ipv4_errors + ipv6_errors, send_errors);
    check_overlapped_receive();
    return 0;
}
