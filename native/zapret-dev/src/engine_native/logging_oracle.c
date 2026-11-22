/* MIT. Private writers exercise original formatting and Rust buffer ownership. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <windows.h>
typedef void (*f_log_function)(int, const char *);
static unsigned calls, hex_cases;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL engine logging calls=%u hex=%u line=%d: %s\n", calls, hex_cases, __LINE__, #condition); ExitProcess(1); } \
} while (0)
static char log_buf[4096];
static size_t log_buf_sz;
static int capture_hex(const char *, ...);
static char hex_digit(uint8_t value) { return value <= 9 ? '0' + value : value <= 15 ? value + 'A' - 10 : '?'; }
#define log_buffered reference_log_buffered
#define hexdump_limited_dlog reference_hexdump_limited_dlog
#define DLOG capture_hex
#include "logging_reference.inc"
#undef log_buffered
#undef hexdump_limited_dlog
#undef DLOG
#include "logging_windows.inc"
bool zapret_log_hex(const uint8_t *, size_t, size_t, void (*)(const char *));

struct capture { unsigned count; int priority; char bytes[4096]; };
static struct capture captured[2];
static unsigned current;
static void writer(int priority, const char *text)
{
    struct capture *capture = &captured[current];
    CHECK(strlen(text) < sizeof(capture->bytes));
    ++capture->count;
    capture->priority = priority;
    strcpy(capture->bytes, text);
}
static void compare(int priority, const char *format, ...)
{
    va_list legacy, rust;
    va_start(legacy, format);
    va_copy(rust, legacy);
    memset(captured, 0, sizeof(captured));
    current = 0;
    reference_log_buffered(writer, priority, format, legacy);
    current = 1;
    log_buffered(writer, priority, format, rust);
    va_end(rust);
    va_end(legacy);
    CHECK(!memcmp(&captured[0], &captured[1], sizeof(captured[0])));
    ++calls;
}
struct hex_capture { unsigned count; char bytes[300000]; };
static struct hex_capture hex_captured[2];
static void hex_writer(const char *text)
{
    struct hex_capture *capture = &hex_captured[current];
    CHECK(strlen(text) < sizeof(capture->bytes));
    ++capture->count;
    strcpy(capture->bytes, text);
}
static int capture_hex(const char *format, ...)
{
    CHECK(!strcmp(format, "%s"));
    va_list arguments;
    va_start(arguments, format);
    hex_writer(va_arg(arguments, const char *));
    va_end(arguments);
    return 1;
}
static void compare_hex(const uint8_t *data, size_t size, size_t limit)
{
    memset(hex_captured, 0, sizeof(hex_captured));
    current = 0;
    reference_hexdump_limited_dlog(data, size, limit);
    current = 1;
    CHECK(zapret_log_hex(data, size, limit, hex_writer));
    CHECK(!memcmp(&hex_captured[0], &hex_captured[1], sizeof(hex_captured[0])));
    ++hex_cases;
}
static _Atomic unsigned seen, thread_lines;
static void thread_writer(int priority, const char *text)
{
    unsigned index;
    CHECK(priority == 7 && sscanf(text, "thread=%u", &index) == 1 && index < 16);
    char expected[32];
    snprintf(expected, sizeof(expected), "thread=%u\n", index);
    CHECK(!strcmp(text, expected));
    unsigned previous = atomic_fetch_or(&seen, 1u << index);
    CHECK(!(previous & (1u << index)));
    atomic_fetch_add(&thread_lines, 1);
}
static DWORD WINAPI thread(void *argument)
{
    char message[32];
    snprintf(message, sizeof(message), "thread=%u\n", (unsigned)(uintptr_t)argument);
    CHECK(zapret_log_buffer(message, strlen(message), 7, thread_writer));
    return 0;
}
static unsigned reentrant_lines;
static void reentrant_writer(int priority, const char *text)
{
    CHECK(priority == 3);
    ++reentrant_lines;
    if (reentrant_lines == 1) {
        CHECK(!strcmp(text, "outer\n"));
        CHECK(zapret_log_buffer("inner", 5, 3, reentrant_writer));
    } else {
        CHECK(reentrant_lines == 2 && !strcmp(text, "inner\n"));
        CHECK(!zapret_log_buffer("deeper\n", 7, 3, reentrant_writer));
    }
}
static uint64_t random_state = 0x6c6f6767696e675fULL;
static uint64_t next(void) { random_state ^= random_state << 13; random_state ^= random_state >> 7; random_state ^= random_state << 17; return random_state; }
static volatile unsigned sink;
static void discard(int priority, const char *text) { sink ^= (unsigned)priority + (unsigned char)*text; }
static void formatted(bool rust, const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    if (rust) log_buffered(discard, 7, format, arguments);
    else reference_log_buffered(discard, 7, format, arguments);
    va_end(arguments);
}
static double measure(bool rust, bool complete)
{
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency);
    formatted(rust, "\n");
    QueryPerformanceCounter(&start);
    for (unsigned round = 0; round < 16384; ++round)
        if (complete) formatted(rust, "message %08x\n", round);
        else formatted(rust, "data");
    QueryPerformanceCounter(&end);
    formatted(rust, "\n");
    return (double)(end.QuadPart - start.QuadPart) * 1e9 / frequency.QuadPart / 16384;
}
static void benchmark(const char *name, bool complete)
{
    double c[9], r[9];
    for (unsigned round = 0; round < 9; ++round) {
        if (round % 2) { r[round] = measure(true, complete); c[round] = measure(false, complete); }
        else { c[round] = measure(false, complete); r[round] = measure(true, complete); }
    }
    for (unsigned i = 0; i < 9; ++i) for (unsigned j = i + 1; j < 9; ++j) {
        if (c[i] > c[j]) { double swap = c[i]; c[i] = c[j]; c[j] = swap; }
        if (r[i] > r[j]) { double swap = r[i]; r[i] = r[j]; r[j] = swap; }
    }
    printf("BENCH engine_logging %s c_ns=%.2f rust_ns=%.2f rounds=9 calls_per_round=16384\n", name, c[4], r[4]);
}
int main(void)
{
    char message[4096];
    for (unsigned round = 0; round < 8192; ++round) {
        size_t length = next() % 4094;
        for (size_t index = 0; index < length; ++index) message[index] = (char)('a' + next() % 26);
        message[length] = 0;
        int priority = round % 11 - 2;
        switch (round % 8) {
            case 0: compare(priority, "%s", message); break;
            case 1: compare(priority, "%04u:%s", round, message); break;
            case 2: compare(priority, "%.*s", (int)(next() % 4096), message); break;
            case 3: compare(priority, "%c%s", round % 3 ? 0 : 'X', message); break;
            case 4: compare(priority, "%8192s", message); break;
            case 5: compare(priority, "%c", '\n'); break;
            case 6: compare(priority, "[%08x]", round); break;
            case 7: compare(priority, "%s\n", message); break;
        }
    }
    compare(7, "\n");
    CHECK(zapret_log_buffer("outer\n", 6, 3, reentrant_writer) && reentrant_lines == 2);
    HANDLE threads[16];
    for (unsigned index = 0; index < 16; ++index) {
        threads[index] = CreateThread(NULL, 0, thread, (void *)(uintptr_t)index, 0, NULL);
        CHECK(threads[index]);
    }
    for (unsigned index = 0; index < 16; ++index) {
        CHECK(WaitForSingleObject(threads[index], 3000) == WAIT_OBJECT_0);
        CHECK(CloseHandle(threads[index]));
    }
    CHECK(atomic_load(&seen) == 0xffff && atomic_load(&thread_lines) == 16);
    CHECK(zapret_log_buffer(NULL, 0, 7, writer));
    CHECK(!zapret_log_buffer(NULL, 1, 7, writer));
    uint8_t data[65535];
    for (unsigned index = 0; index < sizeof(data); ++index) data[index] = (uint8_t)next();
    for (unsigned round = 0; round < 4096; ++round) compare_hex(data, round % 1024, next() % 1400);
    const size_t lengths[] = {0,1,15,16,17,255,256,4096,65535};
    for (unsigned index = 0; index < sizeof(lengths) / sizeof(*lengths); ++index) {
        compare_hex(data, lengths[index], lengths[index]);
        compare_hex(data, lengths[index], lengths[index] / 2);
    }
    const uint8_t edges[] = {0,0x1f,0x20,0x7e,0x7f,0x80,0xff};
    compare_hex(edges, sizeof(edges), sizeof(edges));
    CHECK(!strcmp(hex_captured[1].bytes, "00 1F 20 7E 7F 80 FF : .. ~\x7f.."));
    unsigned before = hex_captured[1].count;
    CHECK(!zapret_log_hex(NULL, 1, 1, hex_writer));
    CHECK(!zapret_log_hex(data, SIZE_MAX, SIZE_MAX, hex_writer));
    CHECK(!zapret_log_hex(data, SIZE_MAX / 4, SIZE_MAX / 4, hex_writer));
    CHECK(zapret_log_hex(NULL, 0, 0, hex_writer) && hex_captured[1].count == before);
    printf("PASS engine_logging calls=%u threaded_lines=16 reentrant_lines=2 reentrant_drops=1 hex_cases=%u rejected_inputs=4\n", calls, hex_cases);
    benchmark("fragments4", false);
    benchmark("complete_lines", true);
    return 0;
}
