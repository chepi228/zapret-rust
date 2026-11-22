/* MIT. The pinned parser may modify its copy. The Rust parser keeps argv intact. */
#include "params.h"
#include "helpers.h"
#undef main
#undef DLOG_ERR
#define DLOG_ERR(...) ((void)0)

#include "lua_arguments_pools.inc"
#define lua_call_param_add reference_lua_call_param_add
#define parse_lua_call reference_parse_lua_call
#include "lua_arguments_reference.inc"
#undef lua_call_param_add
#undef parse_lua_call
#include "lua_arguments_windows.inc"

static unsigned cases, rejected;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL lua arguments case=%u line=%d: %s\n", cases, __LINE__, #condition); exit(1); } \
} while (0)

static void compare(const char *text)
{
    struct func_list_head legacy = {0}, rust = {0};
    struct func_list *existing = funclist_add_tail(&rust, "existing");
    char *left = strdup(text), *right = strdup(text);
    CHECK(existing && left && right);
    const struct func_list *a = reference_parse_lua_call(left, &legacy);
    const struct func_list *b = parse_lua_call(right, &rust);
    if (!!a != !!b) fprintf(stderr, "input: %s\n", text);
    CHECK(!!a == !!b && !strcmp(text, right));
    CHECK(LIST_FIRST(&rust) == existing && LIST_NEXT(existing, next) == b);
    if (a) {
        CHECK(!strcmp(a->func, b->func) && b->next.le_prev == &existing->next.le_next && !LIST_NEXT(b, next));
        CHECK(a->payload_type == b->payload_type && a->range_in.from.mode == b->range_in.from.mode &&
            a->range_out.to.mode == b->range_out.to.mode);
        const struct str2_list *x = LIST_FIRST(&a->args), *y = LIST_FIRST(&b->args);
        for (; x && y; x = LIST_NEXT(x, next), y = LIST_NEXT(y, next)) {
            CHECK(!strcmp(x->str1, y->str1));
            CHECK((!x->str2 && !y->str2) || (x->str2 && y->str2 && !strcmp(x->str2, y->str2)));
        }
        CHECK(!x && !y);
    } else {
        ++rejected;
    }
    ++cases;
    funclist_destroy(&legacy);
    funclist_destroy(&rust);
    free(left);
    free(right);
}

int main(void)
{
    const char *parts[] = {"", "flag", "flag=", "flag=one", "flag=one=two", "a=one\\:two", "a=\\:",
        "a=\\\\:", "a=\\\\\\:", "_=имя", "a=one\\", "a=\\:mid\\:here", "9bad=1", "a\\:b=1", "a==", "a= "};
    const size_t count = sizeof(parts) / sizeof(*parts);
    char text[160];
    for (size_t a = 0; a < count; ++a) for (size_t b = 0; b < count; ++b) for (size_t c = 0; c < count; ++c) {
        CHECK(snprintf(text, sizeof(text), "call:%s:%s:%s", parts[a], parts[b], parts[c]) > 0);
        compare(text);
    }
    compare("bare");
    compare("_bare:");
    compare(":flag");
    compare("9name:flag");
    compare("with space:flag");
    compare("name:repeat=one:repeat=two");
    struct str2_list_head legacy = {0}, rust = {0};
    char left[] = "name=", right[] = "name=";
    CHECK(reference_lua_call_param_add(left, &legacy) && lua_call_param_add(right, &rust));
    CHECK(!strcmp(left, right) && !strcmp(LIST_FIRST(&rust)->str1, "name") && !strcmp(LIST_FIRST(&rust)->str2, ""));
    str2list_destroy(&legacy);
    str2list_destroy(&rust);
    printf("PASS lua_arguments calls=%u rejected_without_insert=%u\n", cases, rejected);
    return 0;
}
