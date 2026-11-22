/* MIT. Mutable pool callbacks and original CSV parsing without live lists. */
#include "pools.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#undef main
static unsigned calls, callback_failures;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL config lists calls=%u failures=%u line=%d: %s\n", calls, callback_failures, __LINE__, #condition); exit(1); } \
} while (0)
typedef union { long double alignment; struct { size_t size; uint64_t guard; } value; } header;
static size_t allocations, live, fail_at;
static void *allocate(size_t size)
{
    if (++allocations == fail_at) return NULL;
    header *block = malloc(sizeof(*block) + size + 16);
    CHECK(block);
    block->value.size = size; block->value.guard = UINT64_C(0x434f4e464c495354);
    void *body = block + 1;
    memset(body, 0xcd, size); memset((uint8_t *)body + size, 0xa5, 16);
    ++live; return body;
}
static void release(void *body)
{
    if (!body) return;
    header *block = (header *)body - 1;
    CHECK(live && block->value.guard == UINT64_C(0x434f4e464c495354));
    for (unsigned index = 0; index < 16; ++index) CHECK(((uint8_t *)body)[block->value.size + index] == 0xa5);
    --live; block->value.guard = 0; free(block);
}
#define malloc allocate
#define free release
bool AppendHostlistItem(hostlist_pool **, char *);
bool AppendIpsetItem(ipset *, char *);
#include "collections_windows.inc"
#include "config_lists_windows.inc"
#undef malloc
#undef free

struct capture { unsigned count, fail_at; size_t used; char bytes[16384]; };
static bool record(struct capture *capture, char *token)
{
    CHECK(capture->count < 1000);
    ++capture->count;
    if (capture->count == capture->fail_at) return false;
    size_t length = strlen(token);
    CHECK(capture->used + length + 1 < sizeof(capture->bytes));
    memcpy(capture->bytes + capture->used, token, length);
    capture->used += length;
    capture->bytes[capture->used++] = '\n';
    /* The actual pool normalizer can mutate this temporary token. */
    for (size_t index = 0; index < length; ++index) if (token[index] >= 'A' && token[index] <= 'Z') token[index] += 'a' - 'A';
    return true;
}
bool AppendHostlistItem(hostlist_pool **head, char *text) { return record((void *)head, text); }
bool AppendIpsetItem(ipset *head, char *text) { return record((void *)head, text); }
#define parse_domain_list reference_parse_domain_list
#define parse_ip_list reference_parse_ip_list
#define parse_strlist reference_parse_strlist
#include "config_lists_reference.inc"
#undef parse_domain_list
#undef parse_ip_list
#undef parse_strlist

static void compare_pool(bool ip, const char *text, unsigned failure)
{
    char left[8192], right[8192];
    CHECK(!text || strlen(text) < sizeof(left));
    if (text) { strcpy(left, text); strcpy(right, text); }
    struct capture expected = {.fail_at = failure}, actual = {.fail_at = failure};
    bool c = ip ? reference_parse_ip_list(text ? left : NULL, (void *)&expected) : reference_parse_domain_list(text ? left : NULL, (void *)&expected);
    bool r = ip ? parse_ip_list(text ? right : NULL, (void *)&actual) : parse_domain_list(text ? right : NULL, (void *)&actual);
    CHECK(c == r && !memcmp(&expected, &actual, sizeof(actual)));
    CHECK(!text || !strcmp(right, text));
    if (!r) ++callback_failures;
    ++calls;
}
static void equal(const struct str_list_head *left, const struct str_list_head *right)
{
    const struct str_list *a = left->lh_first, *b = right->lh_first;
    const void *previous_a = &left->lh_first, *previous_b = &right->lh_first;
    while (a && b) {
        CHECK(a->next.le_prev == previous_a && b->next.le_prev == previous_b);
        CHECK(a->str && b->str && !strcmp(a->str, b->str));
        previous_a = &a->next.le_next; previous_b = &b->next.le_next;
        a = a->next.le_next; b = b->next.le_next;
    }
    CHECK(!a && !b);
}
static void compare_strings(const char *text)
{
    char left[8192], right[8192];
    CHECK(!text || strlen(text) < sizeof(left));
    if (text) { strcpy(left, text); strcpy(right, text); }
    struct str_list_head expected = {0}, actual = {0};
    CHECK(strlist_add(&expected, "existing") && strlist_add(&actual, "existing"));
    CHECK(reference_parse_strlist(text ? left : NULL, &expected) == parse_strlist(text ? right : NULL, &actual));
    CHECK(!text || !strcmp(right, text)); equal(&expected, &actual);
    strlist_destroy(&expected); strlist_destroy(&actual); CHECK(!live); ++calls;
}
static uint64_t random_state = UINT64_C(0x636f6e6669675f6c);
static uint64_t next(void) { random_state ^= random_state << 13; random_state ^= random_state >> 7; random_state ^= random_state << 17; return random_state; }
int main(void)
{
    for (unsigned round = 0; round < 4096; ++round) {
        char text[1025]; size_t length = next() % 1024;
        static const char alphabet[] = "abcXYZ09/.:,% \t";
        for (size_t index = 0; index < length; ++index) text[index] = alphabet[next() % (sizeof(alphabet) - 1)];
        text[length] = 0;
        compare_pool(false, text, 0); compare_pool(true, text, 0); compare_strings(text);
    }
    static const char *const boundaries[] = {NULL, "", ",", ",,", "a", "a,", ",a", "a,,b", "  ,\t", "один,ДВА", "A\xff" "B,c", "1.2.3.4/32,::1/128", "A.example,,B.EXAMPLE,"};
    for (unsigned index = 0; index < sizeof(boundaries) / sizeof(*boundaries); ++index) {
        compare_pool(false, boundaries[index], 0); compare_pool(true, boundaries[index], 0); compare_strings(boundaries[index]);
    }
    for (unsigned failure = 1; failure <= 8; ++failure) {
        compare_pool(false, "A,,B,C,,D,E,F,G,H", failure); compare_pool(true, "A,,B,C,,D,E,F,G,H", failure);
    }
    char long_text[4096];
    memset(long_text, 'X', sizeof(long_text)); long_text[1024] = ','; long_text[3072] = ','; long_text[4095] = 0;
    compare_pool(false, long_text, 0); compare_pool(true, long_text, 0); compare_strings(long_text);
    struct str_list_head list = {0}, expected = {0};
    CHECK(strlist_add(&list, "preserved") && strlist_add(&expected, "preserved"));
    struct str_list *original = list.lh_first;
    size_t baseline = live;
    for (unsigned failure = 1; failure <= 8; ++failure) {
        char text[] = "a,b,c,d";
        fail_at = allocations + failure;
        CHECK(!parse_strlist(text, &list)); fail_at = 0;
        CHECK(list.lh_first == original && live == baseline && !strcmp(text, "a,b,c,d")); equal(&expected, &list);
    }
    strlist_destroy(&list); strlist_destroy(&expected); CHECK(!live);
    CHECK(!zapret_config_list("a", NULL, native_add_domain));
    CHECK(!zapret_config_list("a", &list, NULL));
    CHECK(!zapret_collection_parse_strings(NULL, "a", &native_config_list_allocator));
    CHECK(!zapret_collection_parse_strings(&list, "a", NULL));
    printf("PASS config_lists functions=3 cases=%u callback_failures=%u atomic_string_failures=8 long_tokens=3 boundary_cases=4\n", calls, callback_failures);
    return 0;
}
