/* Verify the existing diagnostic sequence with a processor that only records. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#define RECONSTRUCT_MAX_SIZE 65536
#define FUZZ_MAX_PACKET_SIZE (RECONSTRUCT_MAX_SIZE + 4096)
static struct { unsigned fuzz; } params;
static bool bQuit;
static unsigned cases, pattern, stop_after, fail_allocation, change_count;
static unsigned draws, allocations, releases, processed, asymmetric, large, empty;
static uint64_t trace;
static uint8_t data[FUZZ_MAX_PACKET_SIZE];
#define CHECK(p) do { if (!(p)) { \
    fprintf(stderr, "FAIL engine_fuzz case=%u line=%d: %s\n", cases, __LINE__, #p); exit(1); \
} } while(0)
static void record(uint64_t value) { trace = (trace ^ value) * 1099511628211ULL; }
static long mock_random(void)
{
    const long samples[] = {0, 1, 2, 3, 69632, 69633, 255, 17, 8, 99, 88};
    long value = samples[(draws++ + pattern) % (sizeof(samples) / sizeof(*samples))];
    record(200000 + value);
    return value;
}
static void *mock_malloc(size_t bytes)
{
    CHECK(bytes <= sizeof(data));
    record(300000 + bytes);
    ++allocations;
    return fail_allocation == allocations ? NULL : data;
}
static void mock_free(void *buffer)
{
    CHECK(buffer == data);
    record(400000);
    ++releases;
}
static void fill_random_bytes(uint8_t *buffer, size_t length)
{
    CHECK(buffer == data);
    record(500000 + length);
    if (length) {
        buffer[length - 1] = 0xa5;
        buffer[0] = (allocations + pattern) % 5;
    }
}
static uint8_t processPacketData(uint32_t *mark, const char *in, const char *out, const uint8_t *packet,
    size_t length, uint8_t *modified, size_t *capacity)
{
    CHECK(packet == data && *mark == processed && *capacity <= sizeof(data) && modified);
    CHECK(!in || !strcmp(in, "ifin"));
    CHECK(!out || !strcmp(out, "ifout"));
    record(600000 + length);
    record(*capacity);
    record((in ? 1 : 0) | (out ? 2 : 0));
    record(length ? packet[0] : 0);
    if (length) record(packet[length - 1]);
    asymmetric += (in != NULL) != (out != NULL);
    large += length == sizeof(data);
    empty += length == 0;
    ++*mark;
    bQuit = ++processed == stop_after;
    *capacity = 0;
    return 7;
}
static void log_line(const char *format, ...)
{
    char text[96];
    va_list args;
    va_start(args, format);
    int count = vsnprintf(text, sizeof(text), format, args);
    va_end(args);
    CHECK(count >= 0 && (size_t)count < sizeof(text));
    for (int i = 0; i < count; ++i) record((unsigned char)text[i]);
    if (change_count && !strncmp(text, "fuzz packet data", 16)) params.fuzz = change_count;
}
#define DLOG_CONDUP log_line
#define random mock_random
#define malloc mock_malloc
#define free mock_free
#define fuzzPacketData reference_packets
#define do_fuzz reference_fuzz
#include "engine_fuzz_reference.inc"
#undef fuzzPacketData
#undef do_fuzz
#include "engine_fuzz_windows.inc"

struct observation { uint64_t trace; unsigned draws, allocations, releases, processed; };
static struct observation run(bool selected, unsigned count, bool quit)
{
    params.fuzz = count;
    bQuit = quit;
    draws = allocations = releases = processed = 0;
    trace = 14695981039346656037ULL;
    if (selected) do_fuzz(); else reference_fuzz();
    CHECK(releases == processed && allocations >= releases && allocations - releases <= 1);
    return (struct observation){trace, draws, allocations, releases, processed};
}
int main(void)
{
    const unsigned counts[] = {0, 1, 6, 1001};
    for (size_t index = 0; index < sizeof(counts) / sizeof(*counts); ++index)
        for (pattern = 0; pattern < 11; ++pattern)
            for (stop_after = 0; stop_after < 4; ++stop_after)
                for (fail_allocation = 0; fail_allocation < 4; ++fail_allocation)
                    for (change_count = 0; change_count < 2; ++change_count)
                        for (unsigned quit = 0; quit < 2; ++quit) {
                            struct observation a = run(false, counts[index], quit);
                            struct observation b = run(true, counts[index], quit);
                            CHECK(a.trace == b.trace && a.draws == b.draws && a.allocations == b.allocations
                                && a.releases == b.releases && a.processed == b.processed);
                            ++cases;
                        }
    CHECK(asymmetric && large && empty);
    printf("PASS engine_fuzz cases=%u exact_rng_order=1 allocation_and_release=1 deferred_count=1 "
        "zero_and_max_sizes=1 synthetic_only=1\n", cases);
    return 0;
}
