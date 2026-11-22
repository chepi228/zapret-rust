/* MIT. Pinned helper bodies, exact outputs, guards, overlap and RNG state. */
#include <ctype.h>
#include <strings.h>
#include "helpers_windows.inc"
#include "helpers.h"
#undef main
#include "helpers_reference.inc"

static unsigned cases, scenario, group;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL engine helpers group=%u scenario=%u case=%u line=%d: %s\n", group, scenario, cases, __LINE__, #condition); exit(1); } } while (0)
static uint64_t state = 0x7465737468656c70ULL;
static uint64_t next(void) { state ^= state << 13; state ^= state >> 7; state ^= state << 17; return state; }
static void fill(uint8_t *data, size_t count) { for (size_t i = 0; i < count; ++i) data[i] = (uint8_t)next(); }
typedef void (*binary_op)(const uint8_t *, const uint8_t *, uint8_t *, size_t);
static void binary_checks(void)
{
    binary_op c[] = {reference_bxor, reference_bor, reference_band};
    binary_op r[] = {zapret_helper_bxor, zapret_helper_bor, zapret_helper_band};
    uint8_t a[1024], b[1024];
    for (unsigned op = 0; op < 3; ++op) for (unsigned offset = 0; offset < 8; ++offset)
        for (unsigned size = 0; size < 256; ++size) for (unsigned alias = 0; alias < 6; ++alias) {
            fill(a, sizeof(a)); memcpy(b, a, sizeof(a));
            unsigned left = 64 + offset, right = 384 + (offset * 3 % 8);
            unsigned out = alias == 0 ? 716 : alias == 1 ? left : alias == 2 ? right : alias == 3 ? left + 1 : alias == 4 ? right - 3 : left;
            if (alias == 5) right = left + 3;
            c[op](a + left, a + right, a + out, size);
            r[op](b + left, b + right, b + out, size);
            CHECK(!memcmp(a, b, sizeof(a))); ++cases;
        }
}
static void endian_checks(void)
{
    uint8_t a[32], b[32], source[32];
#define ENDIAN(bits, type) do { \
    memset(a, 0x6d, sizeof(a)); memcpy(b, a, sizeof(a)); \
    reference_phton##bits(a + offset, (type)value); zapret_helper_phton##bits(b + offset, (type)value); \
    CHECK(!memcmp(a, b, sizeof(a))); \
    CHECK(reference_pntoh##bits(source + offset) == zapret_helper_pntoh##bits(source + offset)); ++cases; \
} while (0)
    for (scenario = 0; scenario < 4096; ++scenario) {
        fill(source, sizeof(source)); unsigned offset = scenario % 8; uint64_t value = next();
        ENDIAN(16, uint16_t); ENDIAN(24, uint32_t); ENDIAN(32, uint32_t); ENDIAN(48, uint64_t); ENDIAN(64, uint64_t);
        CHECK(reference_bswap16(value) == zapret_helper_bswap16(value));
        CHECK(reference_bswap24(value) == zapret_helper_bswap24(value));
        CHECK(reference_bswap48(value) == zapret_helper_bswap48(value));
        uint32_t first = next(), last = next(), current = scenario % 3 ? next() : scenario % 2 ? first : last;
        CHECK(reference_seq_within(current, first, last) == zapret_helper_seq_within(current, first, last));
        if (!(scenario % 17)) memset(source + offset, 0, 16);
        CHECK(reference_ipv6_addr_is_zero((const struct in6_addr *)(source + offset)) == zapret_helper_ipv6_addr_is_zero((const struct in6_addr *)(source + offset)));
    }
#undef ENDIAN
}
static void hex_checks(void)
{
    char text[7] = {0, 0, 'A', 'f', 0, 0, 0}; uint8_t a[8], b[8];
    for (unsigned high = 0; high < 256; ++high) for (unsigned low = 0; low < 256; ++low) {
        text[0] = high; text[1] = low;
        for (unsigned capacity = 0; capacity < 4; ++capacity) {
            memset(a, 0x5c, sizeof(a)); memcpy(b, a, sizeof(a)); size_t ac = capacity, bc = capacity;
            CHECK(reference_parse_hex_str(text, a, &ac) == zapret_helper_parse_hex_str(text, b, &bc));
            CHECK(ac == bc && !memcmp(a, b, sizeof(a))); ++cases;
        }
        CHECK(reference_hex_digit(high) == zapret_helper_hex_digit(high));
    }
    for (scenario = 0; scenario < 32; ++scenario) {
        char in_place_a[] = "Ab12cD34ef567890", in_place_b[] = "Ab12cD34ef567890";
        size_t ac = scenario % 10, bc = ac;
        CHECK(reference_parse_hex_str(in_place_a, (uint8_t *)in_place_a, &ac) == zapret_helper_parse_hex_str(in_place_b, (uint8_t *)in_place_b, &bc));
        CHECK(ac == bc && !memcmp(in_place_a, in_place_b, sizeof(in_place_a))); ++cases;
    }
}
static void random_checks(void)
{
    typedef void (*random_op)(uint8_t *, size_t);
    random_op c[] = {reference_fill_random_bytes, reference_fill_random_az, reference_fill_random_az09};
    random_op r[] = {zapret_helper_fill_random_bytes, zapret_helper_fill_random_az, zapret_helper_fill_random_az09};
    uint8_t a[160] __attribute__((aligned(8))), b[160] __attribute__((aligned(8)));
    for (unsigned op = 0; op < 3; ++op) for (unsigned offset = 0; offset < 8; ++offset) for (scenario = 0; scenario < 130; ++scenario) {
        memset(a, 0x6b, sizeof(a)); memcpy(b, a, sizeof(a));
        zapret_srandom(scenario); c[op](a + offset, scenario); int32_t after = zapret_random();
        zapret_srandom(scenario); r[op](b + offset, scenario);
        CHECK(after == zapret_random() && !memcmp(a, b, sizeof(a))); ++cases;
    }
}
static void string_checks(void)
{
    char text[130], a[130], b[130], needle[16];
    for (scenario = 0; scenario < 8192; ++scenario) {
        fill((uint8_t *)text, 128); text[128] = 0; text[129] = 0;
        unsigned length = scenario % 129;
        unsigned search = scenario % 13;
        memcpy(needle, text + (next() % (128 - search)), search); needle[search] = 0;
        const char *c = reference_strncasestr(text, needle, length), *r = zapret_helper_strncasestr(text, needle, length);
        CHECK((!c && !r) || (c && r && c - text == r - text));
        text[length] = 0;
        CHECK(reference_is_identifier(text) == zapret_helper_is_identifier(text));
        memcpy(a, text, sizeof(a)); memcpy(b, text, sizeof(b));
        reference_rtrim(a); zapret_helper_rtrim(b); CHECK(!memcmp(a, b, sizeof(a)));
        char from = text[0], to = scenario % 5 ? (char)next() : 0;
        reference_replace_char(a, from, to); zapret_helper_replace_char(b, from, to); CHECK(!memcmp(a, b, sizeof(a)));
        const char *strings[] = {"", "name", "NAmE", "_name_7", "name"};
        const char *query = scenario % 6 == 5 ? "absent" : strings[scenario % 5];
        CHECK(reference_str_index(strings, scenario % 6, query) == zapret_helper_str_index(strings, scenario % 6, query));
        ++cases;
    }
    static const char *const ends[] = {"", "\n", "\r\n", "name\r\n\r", "name \r\n", "name\r\ninside", "name"};
    for (scenario = 0; scenario < sizeof(ends) / sizeof(*ends); ++scenario) {
        memset(a, 0x2a, sizeof(a)); memcpy(b, a, sizeof(a)); strcpy(a, ends[scenario]); strcpy(b, ends[scenario]);
        reference_rtrim(a); zapret_helper_rtrim(b); CHECK(!memcmp(a, b, sizeof(a))); ++cases;
    }
    zapret_helper_rtrim(NULL);
    CHECK(zapret_helper_str_index(NULL, 0, NULL) == -1);
}
static void array_checks(void)
{
    size_t a[96], b[96]; ssize_t sa[96], sb[96];
    for (scenario = 0; scenario < 4096; ++scenario) {
        unsigned count = scenario % 97;
        for (unsigned i = 0; i < 96; ++i) { a[i] = b[i] = next() % 31; sa[i] = sb[i] = (ssize_t)next(); }
        if (scenario % 2) { reference_qsort_size_t(a, count); zapret_helper_qsort_size_t(b, count); }
        CHECK(!memcmp(a, b, sizeof(a)));
        CHECK(reference_unique_size_t(a, count) == zapret_helper_unique_size_t(b, count)); CHECK(!memcmp(a, b, sizeof(a)));
        reference_qsort_ssize_t(sa, count); zapret_helper_qsort_ssize_t(sb, count); CHECK(!memcmp(sa, sb, sizeof(sa)));
        CHECK(reference_unique_ssize_t(sa, count) == zapret_helper_unique_ssize_t(sb, count)); CHECK(!memcmp(sa, sb, sizeof(sa))); ++cases;
    }
    zapret_helper_qsort_size_t(NULL, 0); zapret_helper_qsort_ssize_t(NULL, -1);
    CHECK(zapret_helper_unique_size_t(NULL, 0) == 0 && zapret_helper_unique_ssize_t(NULL, -1) == 0);
}
static void expand_checks(void)
{
    uint8_t source[32], a[40], b[40];
    for (unsigned bytes = 0; bytes <= 32; ++bytes) for (unsigned bits = 0; bits <= 256; ++bits) {
        fill(source, sizeof(source)); memset(a, 0x5e, sizeof(a)); memcpy(b, a, sizeof(a));
        reference_expand_bits(a, source, bits, bytes); zapret_helper_expand_bits(b, source, bits, bytes);
        CHECK(!memcmp(a, b, sizeof(a))); ++cases;
    }
    memset(a, 0xff, sizeof(a)); zapret_helper_expand_bits(a, a, 13, 4);
    CHECK(a[0] == 0xff && a[1] == 0xf8 && !a[2] && !a[3] && a[4] == 0xff);
}
static volatile uint64_t sink;
static double measure_sort(bool rust)
{
    size_t input[64], copy[64]; for (unsigned i = 0; i < 64; ++i) input[i] = (i * 37) % 31;
    LARGE_INTEGER frequency, start, end; QueryPerformanceFrequency(&frequency); QueryPerformanceCounter(&start);
    for (unsigned i = 0; i < 16384; ++i) { memcpy(copy, input, sizeof(copy)); if (rust) zapret_helper_qsort_size_t(copy, 64); else reference_qsort_size_t(copy, 64); sink ^= copy[i % 64]; }
    QueryPerformanceCounter(&end);
    return (double)(end.QuadPart - start.QuadPart) * 1e9 / frequency.QuadPart / 16384;
}
int main(void)
{
    group = 1; binary_checks(); group = 2; endian_checks(); group = 3; hex_checks(); group = 4; random_checks();
    group = 5; string_checks(); group = 6; array_checks(); group = 7; expand_checks();
    printf("PASS engine_helpers functions=33 cases=%u boundary_improvements=3\n", cases);
    double c[9], r[9];
    for (unsigned i = 0; i < 9; ++i) { if (i % 2) { r[i] = measure_sort(true); c[i] = measure_sort(false); } else { c[i] = measure_sort(false); r[i] = measure_sort(true); } }
    for (unsigned i = 0; i < 9; ++i) for (unsigned j = i + 1; j < 9; ++j) {
        if (c[i] > c[j]) { double swap = c[i]; c[i] = c[j]; c[j] = swap; }
        if (r[i] > r[j]) { double swap = r[i]; r[i] = r[j]; r[j] = swap; }
    }
    printf("BENCH engine_helpers sort64 c_ns=%.2f rust_ns=%.2f rounds=9 calls_per_round=16384\n", c[4], r[4]);
    return 0;
}
