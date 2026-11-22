/* MIT. Startup option list rollback and 64-bit file offsets. */
static unsigned additions, fail_add, released;
static void counted_free(void *memory)
{
    ++released;
    free(memory);
}
#define DEFINE_ADD(function, head_type, item_type, filter_type, field) \
bool function(struct head_type *head, const filter_type *value) \
{ \
    if (++additions == fail_add) return false; \
    struct item_type *item = calloc(1, sizeof(*item)); \
    CHECK(item); \
    item->field = *value; \
    LIST_INSERT_HEAD(head, item, next); \
    return true; \
}
DEFINE_ADD(port_filter_add, port_filters_head, port_filter_item, port_filter, pf)
DEFINE_ADD(icmp_filter_add, icmp_filters_head, icmp_filter_item, icmp_filter, icf)
DEFINE_ADD(ipp_filter_add, ipp_filters_head, ipp_filter_item, ipp_filter, ipp)
#undef DEFINE_ADD

#define parse_pf_list reference_parse_pf_list
#define parse_icf_list reference_parse_icf_list
#define parse_ipp_list reference_parse_ipp_list
#include "filter_list_reference.inc"
#undef parse_pf_list
#undef parse_icf_list
#undef parse_ipp_list
#define free counted_free
#include "filter_lists_windows.inc"
#undef free

int DLOG(const char *format, ...) { (void)format; return 0; }
#define parse_filespec reference_parse_filespec
#include "filespec_reference.inc"
#undef parse_filespec
#include "filespec_windows.inc"

static bool same_port(port_filter a, port_filter b)
{ return a.from == b.from && a.to == b.to && a.neg == b.neg; }
static bool same_icmp(icmp_filter a, icmp_filter b)
{ return a.mode == b.mode && a.type == b.type && a.code == b.code && a.code_valid == b.code_valid; }
static bool same_ip(ipp_filter a, ipp_filter b)
{ return a.mode == b.mode && a.proto == b.proto; }

static void check_startup_arguments(void)
{
    static const char *const files[] = {"name", "", "@name", "@@name", "+1@name", "+0",
        "+123", "+  0123@name", "++1@name", "+-0@name", "+bad", "+", "+1extra@name",
        "+18446744073709551615@name"};
    for (unsigned i = 0; i < sizeof(files) / sizeof(*files); ++i) {
        const char *ref = files[i], *rust = files[i];
        unsigned long long a = 42, b = 42;
        bool ok = reference_parse_filespec(&ref, &a);
        input = files[i];
        CHECK(parse_filespec(&rust, &b) == ok);
        CHECK(ok ? (ref == rust && a == b) : (rust == files[i] && b == 42));
    }
    static const char *const oversized[] = {"+18446744073709551616@name", "+-18446744073709551615@name"};
    for (unsigned i = 0; i < sizeof(oversized) / sizeof(*oversized); ++i) {
        const char *name = oversized[i];
        unsigned long long offset = 42;
        input = name;
        CHECK(!parse_filespec(&name, &offset) && name == oversized[i] && offset == 42);
    }
    // Verify the resulting list order, including an existing entry.
#define CHECK_LIST(fn, ref_fn, head_type, item_type, field, same, valid) \
    do { \
        struct head_type left = LIST_HEAD_INITIALIZER(left), right = LIST_HEAD_INITIALIZER(right); \
        struct item_type old_left = {0}, old_right = {0}; \
        LIST_INSERT_HEAD(&left, &old_left, next); \
        LIST_INSERT_HEAD(&right, &old_right, next); \
        char text[] = valid; \
        input = text; \
        CHECK(ref_fn(text, &left) && fn(text, &right) && !strcmp(text, valid)); \
        while (LIST_FIRST(&left) != &old_left) { \
            struct item_type *a = LIST_FIRST(&left), *b = LIST_FIRST(&right); \
            CHECK(b != &old_right && same(a->field, b->field)); \
            LIST_REMOVE(a, next); LIST_REMOVE(b, next); \
            free(a); free(b); \
        } \
        CHECK(LIST_FIRST(&right) == &old_right); \
        additions = released = 0; \
        CHECK(!fn(valid ",bogus", &right) && LIST_FIRST(&right) == &old_right && additions == released); \
        additions = released = 0; fail_add = 2; \
        CHECK(!fn(valid, &right) && LIST_FIRST(&right) == &old_right && released == 1); \
        fail_add = 0; \
    } while (0)
    CHECK_LIST(parse_pf_list, reference_parse_pf_list, port_filters_head, port_filter_item, pf, same_port, "80,443,~20");
    CHECK_LIST(parse_icf_list, reference_parse_icf_list, icmp_filters_head, icmp_filter_item, icf, same_icmp, "8:0,1,*");
    CHECK_LIST(parse_ipp_list, reference_parse_ipp_list, ipp_filters_head, ipp_filter_item, ipp, same_ip, "6,17,-");
#undef CHECK_LIST
    printf("PASS startup_arguments filespecs=%zu list_cases=9\n",
        (sizeof(files) / sizeof(*files)) + (sizeof(oversized) / sizeof(*oversized)));
}
