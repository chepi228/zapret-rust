/* MIT. Packet-filter list parity, rollback, self-copy and inline match costs. */
#include "pools.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include "filters_windows.inc"
#undef main

static unsigned cases, matches, allocation_faults;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL filter collections case=%u matches=%u faults=%u line=%d: %s\n", cases, matches, allocation_faults, __LINE__, #condition); exit(1); } \
} while (0)
typedef union { long double alignment; struct { size_t size; uint64_t guard; } value; } header;
static size_t allocations, live, fail_at;
static void *allocate(size_t size)
{
    if (++allocations == fail_at) return NULL;
    header *block = malloc(sizeof(*block) + size + 16);
    CHECK(block);
    block->value.size = size; block->value.guard = UINT64_C(0x46494c5445524c53);
    void *body = block + 1;
    memset(body, 0xcd, size); memset((uint8_t *)body + size, 0xa5, 16);
    ++live; return body;
}
static void release(void *body)
{
    if (!body) return;
    header *block = (header *)body - 1;
    CHECK(live && block->value.guard == UINT64_C(0x46494c5445524c53));
    for (unsigned index = 0; index < 16; ++index) CHECK(((uint8_t *)body)[block->value.size + index] == 0xa5);
    --live; block->value.guard = 0; free(block);
}
#define malloc allocate
#define free release
#define port_filter_add reference_port_filter_add
#define port_filters_copy reference_port_filters_copy
#define port_filters_destroy reference_port_filters_destroy
#define port_filters_match reference_port_filters_match
#define port_filters_deny_if_empty reference_port_filters_deny_if_empty
#define icmp_filter_add reference_icmp_filter_add
#define icmp_filters_copy reference_icmp_filters_copy
#define icmp_filters_destroy reference_icmp_filters_destroy
#define icmp_filters_match reference_icmp_filters_match
#define icmp_filters_deny_if_empty reference_icmp_filters_deny_if_empty
#define ipp_filter_add reference_ipp_filter_add
#define ipp_filters_copy reference_ipp_filters_copy
#define ipp_filters_destroy reference_ipp_filters_destroy
#define ipp_filters_match reference_ipp_filters_match
#define ipp_filters_deny_if_empty reference_ipp_filters_deny_if_empty
#include "filter_collections_reference.inc"
#undef port_filter_add
#undef port_filters_copy
#undef port_filters_destroy
#undef port_filters_match
#undef port_filters_deny_if_empty
#undef icmp_filter_add
#undef icmp_filters_copy
#undef icmp_filters_destroy
#undef icmp_filters_match
#undef icmp_filters_deny_if_empty
#undef ipp_filter_add
#undef ipp_filters_copy
#undef ipp_filters_destroy
#undef ipp_filters_match
#undef ipp_filters_deny_if_empty
typedef struct { void *(*allocate)(size_t); void (*release)(void *); } zapret_collection_allocator;
static const zapret_collection_allocator native_collection_allocator = {malloc, free};
#include "filter_collections_windows.inc"
#undef malloc
#undef free

union head { struct port_filters_head ports; struct icmp_filters_head icmp; struct ipp_filters_head ip; };
union value { port_filter port; icmp_filter icmp; ipp_filter ip; };
static bool add(unsigned kind, union head *head, const union value *value, bool legacy)
{
    if (kind == 0) return legacy ? reference_port_filter_add(&head->ports, &value->port) : port_filter_add(&head->ports, &value->port);
    if (kind == 1) return legacy ? reference_icmp_filter_add(&head->icmp, &value->icmp) : icmp_filter_add(&head->icmp, &value->icmp);
    return legacy ? reference_ipp_filter_add(&head->ip, &value->ip) : ipp_filter_add(&head->ip, &value->ip);
}
static bool copy(unsigned kind, union head *target, const union head *source, bool legacy)
{
    if (kind == 0) return legacy ? reference_port_filters_copy(&target->ports, &source->ports) : port_filters_copy(&target->ports, &source->ports);
    if (kind == 1) return legacy ? reference_icmp_filters_copy(&target->icmp, &source->icmp) : icmp_filters_copy(&target->icmp, &source->icmp);
    return legacy ? reference_ipp_filters_copy(&target->ip, &source->ip) : ipp_filters_copy(&target->ip, &source->ip);
}
static void clear(unsigned kind, union head *head, bool legacy)
{
    if (kind == 0) { if (legacy) reference_port_filters_destroy(&head->ports); else port_filters_destroy(&head->ports); }
    else if (kind == 1) { if (legacy) reference_icmp_filters_destroy(&head->icmp); else icmp_filters_destroy(&head->icmp); }
    else { if (legacy) reference_ipp_filters_destroy(&head->ip); else ipp_filters_destroy(&head->ip); }
}
static bool deny(unsigned kind, union head *head, bool legacy)
{
    if (kind == 0) return legacy ? reference_port_filters_deny_if_empty(&head->ports) : port_filters_deny_if_empty(&head->ports);
    if (kind == 1) return legacy ? reference_icmp_filters_deny_if_empty(&head->icmp) : icmp_filters_deny_if_empty(&head->icmp);
    return legacy ? reference_ipp_filters_deny_if_empty(&head->ip) : ipp_filters_deny_if_empty(&head->ip);
}
static bool match(unsigned kind, const union head *head, uint16_t first, uint8_t second, bool legacy)
{
    if (kind == 0) return legacy ? reference_port_filters_match(&head->ports, first) : port_filters_match(&head->ports, first);
    if (kind == 1) return legacy ? reference_icmp_filters_match(&head->icmp, (uint8_t)first, second) : icmp_filters_match(&head->icmp, (uint8_t)first, second);
    return legacy ? reference_ipp_filters_match(&head->ip, (uint8_t)first) : ipp_filters_match(&head->ip, (uint8_t)first);
}
static void equal(unsigned kind, const union head *left, const union head *right)
{
    const void *a, *b, *previous_a = left, *previous_b = right;
    memcpy(&a, left, sizeof(a)); memcpy(&b, right, sizeof(b));
    while (a && b) {
        if (kind == 0) {
            const struct port_filter_item *x = a, *y = b;
            CHECK(x->pf.from == y->pf.from && x->pf.to == y->pf.to && x->pf.neg == y->pf.neg);
            CHECK(x->next.le_prev == previous_a && y->next.le_prev == previous_b);
            previous_a = &x->next.le_next; previous_b = &y->next.le_next;
            a = x->next.le_next; b = y->next.le_next;
        } else if (kind == 1) {
            const struct icmp_filter_item *x = a, *y = b;
            CHECK(x->icf.mode == y->icf.mode && x->icf.type == y->icf.type && x->icf.code == y->icf.code && x->icf.code_valid == y->icf.code_valid);
            CHECK(x->next.le_prev == previous_a && y->next.le_prev == previous_b);
            previous_a = &x->next.le_next; previous_b = &y->next.le_next;
            a = x->next.le_next; b = y->next.le_next;
        } else {
            const struct ipp_filter_item *x = a, *y = b;
            CHECK(x->ipp.mode == y->ipp.mode && x->ipp.proto == y->ipp.proto);
            CHECK(x->next.le_prev == previous_a && y->next.le_prev == previous_b);
            previous_a = &x->next.le_next; previous_b = &y->next.le_next;
            a = x->next.le_next; b = y->next.le_next;
        }
    }
    CHECK(!a && !b);
}
static uint64_t random_state = UINT64_C(0x66696c7465725f6c);
static uint64_t next_random(void) { random_state ^= random_state << 13; random_state ^= random_state >> 7; random_state ^= random_state << 17; return random_state; }
static union value value(unsigned kind, unsigned id)
{
    union value value = {0};
    if (kind == 0) { value.port.from = id * 131; value.port.to = value.port.from + (id % 257); value.port.neg = id % 3 == 0; }
    else if (kind == 1) value.icmp = (icmp_filter){id % 4, id, id >> 8, id % 2};
    else value.ip = (ipp_filter){id % 4, id};
    return value;
}
static volatile unsigned sink;
static double measure(const union head *head, bool legacy)
{
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency); QueryPerformanceCounter(&start);
    for (unsigned index = 0; index < 262144; ++index) sink ^= match(0, head, (uint16_t)index, 0, legacy);
    QueryPerformanceCounter(&end);
    return (double)(end.QuadPart - start.QuadPart) * 1e9 / frequency.QuadPart / 262144;
}
int main(void)
{
    for (unsigned kind = 0; kind < 3; ++kind) {
        for (unsigned round = 0; round < 4096; ++round) {
            union head source[2] = {{0},{0}}, target[2] = {{0},{0}};
            for (unsigned side = 0; side < 2; ++side) {
                for (unsigned index = 0; index < round % 7; ++index) { union value v = value(kind, round * 13 + index); CHECK(add(kind, &source[side], &v, !side)); }
                for (unsigned index = 0; index < round % 3; ++index) { union value v = value(kind, round * 7 + index); CHECK(add(kind, &target[side], &v, !side)); }
                CHECK(copy(kind, &target[side], &source[side], !side));
            }
            equal(kind, &source[0], &source[1]); equal(kind, &target[0], &target[1]);
            for (unsigned index = 0; index < 64; ++index) {
                uint16_t first = index == 0 ? 0 : index == 1 ? 65535 : (uint16_t)next_random();
                uint8_t second = (uint8_t)next_random();
                CHECK(match(kind, &target[0], first, second, true) == match(kind, &target[1], first, second, false));
                ++matches;
            }
            for (unsigned side = 0; side < 2; ++side) CHECK(deny(kind, &target[side], !side));
            equal(kind, &target[0], &target[1]);
            for (unsigned side = 0; side < 2; ++side) { clear(kind, &source[side], !side); clear(kind, &target[side], !side); }
            CHECK(!live); ++cases;
        }
        union head source = {0}, target = {0}, expected = {0}, doubled = {0};
        for (unsigned index = 0; index < 5; ++index) { union value v = value(kind, index + 41); CHECK(add(kind, &source, &v, false)); }
        union value existing = value(kind, 99);
        CHECK(add(kind, &target, &existing, false) && add(kind, &expected, &existing, true));
        for (unsigned failure = 1; failure <= 5; ++failure) {
            size_t baseline = live;
            fail_at = allocations + failure;
            CHECK(!copy(kind, &target, &source, false));
            fail_at = 0;
            CHECK(live == baseline); equal(kind, &target, &expected);
            ++allocation_faults;
        }
        CHECK(copy(kind, &doubled, &source, true) && copy(kind, &doubled, &source, true));
        CHECK(copy(kind, &source, &source, false)); equal(kind, &doubled, &source);
        clear(kind, &source, false); clear(kind, &target, false); clear(kind, &expected, true); clear(kind, &doubled, true);
        fail_at = allocations + 1;
        CHECK(!deny(kind, &target, false)); fail_at = 0;
        CHECK(!live); ++allocation_faults;
        CHECK(deny(kind, &target, false));
        size_t old_allocations = allocations;
        CHECK(deny(kind, &target, false) && allocations == old_allocations);
        clear(kind, &target, false); CHECK(!live);
    }
    union head head = {0}; union value filter = value(0, 123);
    CHECK(!zapret_filter_collection_add(3, &head, &filter, &native_collection_allocator));
    CHECK(!zapret_filter_collection_add(0, NULL, &filter, &native_collection_allocator));
    CHECK(!zapret_filter_collection_add(0, &head, NULL, &native_collection_allocator));
    CHECK(!zapret_filter_collection_copy(3, &head, &head, &native_collection_allocator));
    CHECK(!zapret_filter_collection_matches(3, &head, 0, 0));
    CHECK(!zapret_filter_collection_matches(0, NULL, 0, 0));
    CHECK(!zapret_filter_collection_deny_empty(3, &head, &native_collection_allocator));
    CHECK(!live);
    printf("PASS filter_collections functions=15 cases=%u match_cases=%u allocation_faults=%u self_copies=3 boundary_cases=7\n", cases, matches, allocation_faults);
    union head benchmark[2] = {{0},{0}};
    for (unsigned side = 0; side < 2; ++side) for (unsigned index = 0; index < 8; ++index) {
        union value v = {.port = {1000 + index * 100, 1010 + index * 100, false}};
        CHECK(add(0, &benchmark[side], &v, !side));
    }
    double c[9], r[9];
    for (unsigned round = 0; round < 9; ++round) {
        if (round % 2) { r[round] = measure(&benchmark[1], false); c[round] = measure(&benchmark[0], true); }
        else { c[round] = measure(&benchmark[0], true); r[round] = measure(&benchmark[1], false); }
    }
    for (unsigned i = 0; i < 9; ++i) for (unsigned j = i + 1; j < 9; ++j) {
        if (c[i] > c[j]) { double swap = c[i]; c[i] = c[j]; c[j] = swap; }
        if (r[i] > r[j]) { double swap = r[i]; r[i] = r[j]; r[j] = swap; }
    }
    printf("BENCH filter_collections port8 c_ns=%.2f rust_ns=%.2f rounds=9 calls_per_round=262144\n", c[4], r[4]);
    clear(0, &benchmark[0], true); clear(0, &benchmark[1], false); CHECK(!live);
    return 0;
}
