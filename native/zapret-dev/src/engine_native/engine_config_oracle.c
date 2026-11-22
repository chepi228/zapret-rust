/* MIT. Pinned default bytes and independent allocation-failure checks. */
#include "params.h"
#include "desync.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#undef main

static unsigned defaults, invalid_layouts, filter_cases;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL engine config defaults=%u invalid=%u filters=%u line=%d: %s\n", defaults, invalid_layouts, filter_cases, __LINE__, #condition); exit(1); } \
} while (0)
typedef union { long double alignment; struct { size_t size; uint64_t guard; } value; } header;
static size_t allocations, live, fail_at;
static void *allocate(size_t size)
{
    if (++allocations == fail_at) return NULL;
    header *block = malloc(sizeof(*block) + size + 16);
    CHECK(block);
    block->value.size = size; block->value.guard = UINT64_C(0x454e47434f4e4647);
    void *body = block + 1;
    memset(body, 0xcd, size); memset((uint8_t *)body + size, 0xa5, 16);
    ++live;
    return body;
}
static void release(void *body)
{
    if (!body) return;
    header *block = (header *)body - 1;
    CHECK(live && block->value.guard == UINT64_C(0x454e47434f4e4647));
    for (unsigned index = 0; index < 16; ++index) CHECK(((uint8_t *)body)[block->value.size + index] == 0xa5);
    block->value.guard = 0; --live; free(block);
}
void strlist_destroy(struct str_list_head *head) { CHECK(!head->lh_first); }
#define malloc allocate
#define free release
#define init_params reference_init_params
#define alloc_windivert_portfilters reference_alloc_windivert_portfilters
#define cleanup_windivert_portfilters reference_cleanup_windivert_portfilters
#include "engine_config_reference.inc"
#undef init_params
#undef alloc_windivert_portfilters
#undef cleanup_windivert_portfilters
#include "engine_config_windows.inc"
#undef malloc
#undef free

static char **slot(struct params_s *params, unsigned index)
{
    char **slots[] = NATIVE_FILTER_SLOTS(params);
    CHECK(index < 13);
    return slots[index];
}
static void filter_valid(struct params_s *params)
{
    for (unsigned index = 0; index < 13; ++index) {
        char *pointer = *slot(params, index);
        CHECK(pointer && !*pointer);
        CHECK(((header *)pointer - 1)->value.size == (index == 12 ? 65536 : 4096));
    }
}
int main(void)
{
    for (unsigned round = 0; round < 4096; ++round) {
        struct { uint8_t before[8]; struct params_s params; uint8_t after[8]; } left, right;
        memset(&left, (int)(round * 131), sizeof(left)); memcpy(&right, &left, sizeof(left));
        reference_init_params(&left.params); init_params(&right.params);
        CHECK(!memcmp(&left, &right, sizeof(left)));
        ++defaults;
    }
    uint8_t unchanged[sizeof(struct params_s)], output[sizeof(struct params_s)];
    memset(unchanged, 0x69, sizeof(unchanged));
    for (unsigned fault = 0; fault < 24; ++fault) {
        zapret_engine_config_layout layout = native_engine_config_layout;
        size_t capacity = sizeof(output);
        memcpy(output, unchanged, sizeof(output));
        if (fault < 10) layout.offsets[fault] = sizeof(output);
        else if (fault < 20) layout.offsets[fault - 10] = SIZE_MAX;
        else if (fault == 20) layout.offsets[1] = layout.offsets[0];
        else if (fault == 21) layout.offsets[1] = layout.offsets[2] + 1;
        else if (fault == 22) capacity--;
        else layout.size++;
        CHECK(!zapret_engine_config_init(output, capacity, &layout));
        CHECK(!memcmp(output, unchanged, sizeof(output)));
        ++invalid_layouts;
    }
    CHECK(!zapret_engine_config_init(NULL, sizeof(output), &native_engine_config_layout));
    CHECK(!zapret_engine_config_init(output, sizeof(output), NULL));
    invalid_layouts += 2;
    for (unsigned round = 0; round < 128; ++round) {
        struct params_s left = {0}, right = {0};
        CHECK(reference_alloc_windivert_portfilters(&left) && alloc_windivert_portfilters(&right));
        filter_valid(&left); filter_valid(&right);
        reference_cleanup_windivert_portfilters(&left); cleanup_windivert_portfilters(&right);
        cleanup_windivert_portfilters(&right);
        for (unsigned index = 0; index < 13; ++index) CHECK(!*slot(&left, index) && !*slot(&right, index));
        CHECK(!live); ++filter_cases;
    }
    struct params_s params = {0};
    CHECK(alloc_windivert_portfilters(&params));
    char *before[13];
    for (unsigned index = 0; index < 13; ++index) { before[index] = *slot(&params, index); strcpy(before[index], "preserved"); }
    for (unsigned failure = 1; failure <= 13; ++failure) {
        size_t baseline = live;
        fail_at = allocations + failure;
        CHECK(!alloc_windivert_portfilters(&params));
        fail_at = 0;
        CHECK(live == baseline);
        for (unsigned index = 0; index < 13; ++index) CHECK(*slot(&params, index) == before[index] && !strcmp(before[index], "preserved"));
        ++filter_cases;
    }
    CHECK(alloc_windivert_portfilters(&params) && live == 13);
    filter_valid(&params);
    for (unsigned index = 0; index < 13; ++index) CHECK(*slot(&params, index) != before[index]);
    ++filter_cases;
    cleanup_windivert_portfilters(&params);
    CHECK(!live);
    for (unsigned failure = 1; failure <= 13; ++failure) {
        fail_at = allocations + failure;
        CHECK(!alloc_windivert_portfilters(&params));
        fail_at = 0;
        for (unsigned index = 0; index < 13; ++index) CHECK(!*slot(&params, index));
        CHECK(!live); ++filter_cases;
    }
    char **slots[] = NATIVE_FILTER_SLOTS(&params);
    CHECK(!zapret_engine_filter_buffers(slots, 12, &native_engine_config_allocator));
    CHECK(!zapret_engine_filter_buffers(NULL, 13, &native_engine_config_allocator));
    CHECK(!zapret_engine_filter_buffers(slots, 13, NULL));
    slots[1] = slots[0];
    CHECK(!zapret_engine_filter_buffers(slots, 13, &native_engine_config_allocator));
    CHECK(!zapret_engine_filter_clear(slots, 13, &native_engine_config_allocator));
    slots[1] = NULL;
    CHECK(!zapret_engine_filter_buffers(slots, 13, &native_engine_config_allocator));
    CHECK(!live);
    printf("PASS engine_config defaults=%u invalid_layouts=%u filter_cases=%u allocation_faults=26 invalid_slots=6\n", defaults, invalid_layouts, filter_cases);
    return 0;
}
