/* MIT. Legacy list parity and allocation-failure ownership with guard bytes. */
#include "pools.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#undef main

static unsigned cases, allocation_faults;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL collections case=%u faults=%u line=%d: %s\n", cases, allocation_faults, __LINE__, #condition); exit(1); } \
} while (0)
typedef union {
    long double alignment;
    struct { size_t size; uint64_t guard; } value;
} header;
static size_t allocations, live, fail_at;
static void *allocate(size_t size)
{
    if (++allocations == fail_at) return NULL;
    header *block = malloc(sizeof(*block) + size + 16);
    CHECK(block);
    block->value.size = size;
    block->value.guard = 0x434f4c4c45435453ULL;
    void *body = block + 1;
    memset(body, 0xcd, size);
    memset((uint8_t *)body + size, 0xa5, 16);
    ++live;
    return body;
}
static void release(void *body)
{
    if (!body) return;
    header *block = (header *)body - 1;
    CHECK(block->value.guard == 0x434f4c4c45435453ULL && live);
    for (unsigned index = 0; index < 16; ++index) CHECK(((uint8_t *)body)[block->value.size + index] == 0xa5);
    memset(body, 0xdd, block->value.size);
    block->value.guard = 0;
    --live;
    free(block);
}
static void *zero_allocate(size_t count, size_t size)
{
    CHECK(!size || count <= SIZE_MAX / size);
    void *body = allocate(count * size);
    if (body) memset(body, 0, count * size);
    return body;
}
static char *duplicate(const char *text)
{
    if (!text) return NULL;
    size_t size = strlen(text) + 1;
    char *copy = allocate(size);
    if (copy) memcpy(copy, text, size);
    return copy;
}
#define malloc allocate
#define free release
#define calloc zero_allocate
#define strdup duplicate
#define strlist_add reference_strlist_add
#define strlist_add_tail reference_strlist_add_tail
#define strlist_copy reference_strlist_copy
#define strlist_destroy reference_strlist_destroy
#define strlist_search reference_strlist_search
#define str2list_add reference_str2list_add
#define str2list_copy reference_str2list_copy
#define str2list_destroy reference_str2list_destroy
#define funclist_add_tail reference_funclist_add_tail
#define funclist_copy reference_funclist_copy
#define funclist_destroy reference_funclist_destroy
#include "collections_reference.inc"
#undef strlist_add
#undef strlist_add_tail
#undef strlist_copy
#undef strlist_destroy
#undef strlist_search
#undef str2list_add
#undef str2list_copy
#undef str2list_destroy
#undef funclist_add_tail
#undef funclist_copy
#undef funclist_destroy
#include "collections_windows.inc"
#undef malloc
#undef free
#undef calloc
#undef strdup

union head { struct str_list_head strings; struct str2_list_head pairs; struct func_list_head calls; };
static void *first(unsigned kind, const union head *head)
{
    return kind == 0 ? (void *)head->strings.lh_first : kind == 1 ? (void *)head->pairs.lh_first : (void *)head->calls.lh_first;
}
static void *next(unsigned kind, const void *node)
{
    return kind == 0 ? (void *)((const struct str_list *)node)->next.le_next :
        kind == 1 ? (void *)((const struct str2_list *)node)->next.le_next : (void *)((const struct func_list *)node)->next.le_next;
}
static void clear(unsigned kind, union head *head, bool legacy)
{
    if (kind == 0) { if (legacy) reference_strlist_destroy(&head->strings); else strlist_destroy(&head->strings); }
    else if (kind == 1) { if (legacy) reference_str2list_destroy(&head->pairs); else str2list_destroy(&head->pairs); }
    else { if (legacy) reference_funclist_destroy(&head->calls); else funclist_destroy(&head->calls); }
}
static bool copy(unsigned kind, union head *target, const union head *source, bool legacy)
{
    if (kind == 0) return legacy ? reference_strlist_copy(&target->strings, &source->strings) : strlist_copy(&target->strings, &source->strings);
    if (kind == 1) return legacy ? reference_str2list_copy(&target->pairs, &source->pairs) : str2list_copy(&target->pairs, &source->pairs);
    return legacy ? reference_funclist_copy(&target->calls, &source->calls) : funclist_copy(&target->calls, &source->calls);
}
static void *add(unsigned kind, union head *head, const char *name, bool legacy, bool tail)
{
    if (kind == 0) {
        bool result = legacy ? (tail ? reference_strlist_add_tail(&head->strings, name) : reference_strlist_add(&head->strings, name)) :
            (tail ? strlist_add_tail(&head->strings, name) : strlist_add(&head->strings, name));
        if (!result) return NULL;
        struct str_list *node = head->strings.lh_first;
        if (tail) while (node->next.le_next) node = node->next.le_next;
        return node;
    }
    if (kind == 1) return legacy ? reference_str2list_add(&head->pairs) : str2list_add(&head->pairs);
    return legacy ? reference_funclist_add_tail(&head->calls, name) : funclist_add_tail(&head->calls, name);
}
static bool same_text(const char *left, const char *right)
{
    return left ? right && !strcmp(left, right) : !right;
}
static void equal_pairs(const struct str2_list_head *left, const struct str2_list_head *right)
{
    const struct str2_list *a = left->lh_first, *b = right->lh_first;
    while (a && b) {
        CHECK(same_text(a->str1, b->str1) && same_text(a->str2, b->str2));
        a = a->next.le_next; b = b->next.le_next;
    }
    CHECK(!a && !b);
}
static void pair_links(const struct str2_list_head *head)
{
    const void *slot = &head->lh_first;
    for (const struct str2_list *node = head->lh_first; node; node = node->next.le_next) {
        CHECK((const void *)node->next.le_prev == slot);
        slot = &node->next.le_next;
    }
}
static bool same_range(const struct packet_range *a, const struct packet_range *b)
{
    return a->from.mode == b->from.mode && a->from.pos == b->from.pos && a->to.mode == b->to.mode &&
        a->to.pos == b->to.pos && a->upper_cutoff == b->upper_cutoff;
}
static void links(unsigned kind, const union head *head)
{
    const void *slot = head;
    unsigned count = 0;
    for (const void *node = first(kind, head); node; node = next(kind, node)) {
        CHECK(++count < 128);
        if (kind == 0) {
            const struct str_list *value = node;
            CHECK((const void *)value->next.le_prev == slot); slot = &value->next.le_next;
        } else if (kind == 1) {
            const struct str2_list *value = node;
            CHECK((const void *)value->next.le_prev == slot); slot = &value->next.le_next;
        } else {
            const struct func_list *value = node;
            CHECK((const void *)value->next.le_prev == slot); slot = &value->next.le_next;
            pair_links(&value->args);
        }
    }
}
static void equal(unsigned kind, const union head *left, const union head *right)
{
    links(kind, left); links(kind, right);
    const void *a = first(kind, left), *b = first(kind, right);
    while (a && b) {
        if (kind == 0) CHECK(same_text(((const struct str_list *)a)->str, ((const struct str_list *)b)->str));
        else if (kind == 1) {
            const struct str2_list *x = a, *y = b;
            CHECK(same_text(x->str1, y->str1) && same_text(x->str2, y->str2));
        } else {
            const struct func_list *x = a, *y = b;
            CHECK(same_text(x->func, y->func) && x->payload_type == y->payload_type);
            CHECK(same_range(&x->range_in, &y->range_in) && same_range(&x->range_out, &y->range_out));
            equal_pairs(&x->args, &y->args);
        }
        a = next(kind, a); b = next(kind, b);
    }
    CHECK(!a && !b);
}
static void fill_pair(struct str2_list *node, unsigned id)
{
    char text[48];
    snprintf(text, sizeof(text), "key_%u", id);
    node->str1 = id % 4 ? duplicate(text) : NULL;
    snprintf(text, sizeof(text), "значение_%u", id);
    node->str2 = id % 3 ? duplicate(text) : NULL;
}
static void fill(unsigned kind, union head *head, unsigned id, bool legacy)
{
    char name[48];
    snprintf(name, sizeof(name), id % 7 ? "name_%u" : "A\xff" "B_%u", id);
    void *node = add(kind, head, kind == 0 && !(id % 5) ? NULL : name, legacy, id % 2);
    CHECK(node);
    if (kind == 1) fill_pair(node, id);
    if (kind == 2) {
        struct func_list *call = node;
        struct packet_range always = PACKET_RANGE_ALWAYS;
        CHECK(!call->payload_type && !call->args.lh_first && same_range(&call->range_in, &always) && same_range(&call->range_out, &always));
        call->payload_type = UINT64_C(0x13579bdf01234567) ^ id;
        call->range_in = (struct packet_range){{'n', id * 11}, {'n', id * 11 + 7}, id % 2};
        call->range_out = (struct packet_range){{'s', id * 17}, {'d', id * 19}, !(id % 2)};
        for (unsigned index = 0; index < id % 3; ++index) {
            struct str2_list *pair = legacy ? reference_str2list_add(&call->args) : str2list_add(&call->args);
            CHECK(pair); fill_pair(pair, id * 4 + index);
        }
    }
}
static void faults(unsigned kind)
{
    union head source = {0}, target = {0}, expected = {0}, source_reference = {0}, probe = {0};
    for (unsigned index = 0; index < 3; ++index) { fill(kind, &source, 27 + index, false); fill(kind, &source_reference, 27 + index, true); }
    fill(kind, &target, 11, false); fill(kind, &expected, 11, true);
    size_t start = allocations;
    CHECK(copy(kind, &probe, &source, false));
    size_t needed = allocations - start;
    clear(kind, &probe, false);
    const void *identity = first(kind, &target);
    size_t baseline = live;
    for (size_t failure = 1; failure <= needed; ++failure) {
        fail_at = allocations + failure;
        CHECK(!copy(kind, &target, &source, false));
        fail_at = 0;
        CHECK(first(kind, &target) == identity && live == baseline);
        equal(kind, &target, &expected); equal(kind, &source, &source_reference);
        ++allocation_faults;
    }
    start = allocations;
    CHECK(add(kind, &probe, "new", false, true));
    needed = allocations - start;
    clear(kind, &probe, false);
    for (size_t failure = 1; failure <= needed; ++failure) {
        fail_at = allocations + failure;
        CHECK(!add(kind, &target, "new", false, true));
        fail_at = 0;
        CHECK(first(kind, &target) == identity && live == baseline);
        equal(kind, &target, &expected);
        ++allocation_faults;
    }
    clear(kind, &source, false); clear(kind, &source_reference, true);
    clear(kind, &target, false); clear(kind, &expected, true);
    CHECK(!live);
}
int main(void)
{
    for (unsigned kind = 0; kind < 3; ++kind) {
        for (unsigned round = 0; round < 2048; ++round) {
            union head source[2] = {{0},{0}}, target[2] = {{0},{0}};
            for (unsigned side = 0; side < 2; ++side) {
                bool legacy = !side;
                for (unsigned index = 0; index < round % 6; ++index) fill(kind, &source[side], round + index, legacy);
                for (unsigned index = 0; index < round % 3; ++index) fill(kind, &target[side], round + index + 101, legacy);
                CHECK(copy(kind, &target[side], &source[side], legacy));
            }
            equal(kind, &source[0], &source[1]); equal(kind, &target[0], &target[1]);
            clear(kind, &source[0], true); clear(kind, &source[1], false);
            equal(kind, &target[0], &target[1]);
            clear(kind, &target[0], true); clear(kind, &target[1], false);
            CHECK(!live);
            ++cases;
        }
        union head source = {0}, doubled = {0}, self = {0};
        for (unsigned index = 0; index < 3; ++index) { fill(kind, &source, 31 + index, true); fill(kind, &self, 31 + index, false); }
        CHECK(copy(kind, &doubled, &source, true) && copy(kind, &doubled, &source, true));
        CHECK(copy(kind, &self, &self, false));
        equal(kind, &doubled, &self);
        clear(kind, &source, true); clear(kind, &doubled, true); clear(kind, &self, false);
        CHECK(!live);
        faults(kind);
    }
    struct str_list_head nullable = {0};
    CHECK(strlist_add(&nullable, NULL));
    CHECK(!strlist_search(&nullable, "missing"));
    CHECK(!strlist_search(&nullable, NULL));
    CHECK(strlist_add_tail(&nullable, "present") && strlist_search(&nullable, "present"));
    strlist_destroy(&nullable);
    union head empty = {0};
    CHECK(!zapret_collection_copy(0, NULL, &empty, &native_collection_allocator));
    CHECK(!zapret_collection_copy(0, &empty, NULL, &native_collection_allocator));
    CHECK(!zapret_collection_copy(0, &empty, &empty, NULL));
    CHECK(!zapret_collection_copy(99, &empty, &empty, &native_collection_allocator));
    CHECK(!zapret_collection_add(99, &empty, "x", true, &native_collection_allocator));
    CHECK(!funclist_add_tail(&empty.calls, NULL));
    zapret_collection_destroy(99, &empty, &native_collection_allocator);
    zapret_collection_destroy(0, NULL, &native_collection_allocator);
    CHECK(!live);
    printf("PASS engine_collections functions=11 cases=%u allocation_faults=%u self_copies=3 null_searches=3 boundary_cases=8\n", cases, allocation_faults);
    return 0;
}
