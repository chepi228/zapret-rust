/* Exercise complete Lua helpers, including a moving global VM pointer. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <lua.h>
#include <lauxlib.h>

static struct { lua_State *L; int ref_desync_ctx; } params;
struct report {
    char text[512];
    int operations[16], used, exited, unrefed, ref, primary_top, other_top;
};
static struct report report;
static lua_State *primary, *other;
static unsigned mutation, comparisons;
#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "FAIL lua_aux case=%u line=%d: %s\n", comparisons, __LINE__, #c); \
    exit(1); } } while(0)

static void record(lua_State *L, int operation)
{
    CHECK(report.used < 16);
    CHECK(L == primary || L == other);
    report.operations[report.used++] = operation * 2 + (L == other);
}
static int observed_isstring(lua_State *L, int index)
{
    record(L, 1);
    int result = lua_isstring(L, index);
    if (mutation & 1) params.L = other;
    return result;
}
static const char *observed_tostring(lua_State *L, int index)
{
    record(L, 2);
    const char *result = lua_tostring(L, index);
    if (mutation & 2) params.L = primary;
    return result;
}
static void observed_pop(lua_State *L, int n)
{
    record(L, 3);
    lua_pop(L, n);
}
static void observed_unref(lua_State *L, int index, int ref)
{
    record(L, 4);
    report.unrefed = ref;
    luaL_unref(L, index, ref);
    params.ref_desync_ctx = -9;
}
static void log_error(const char *format, ...)
{
    size_t used = strlen(report.text);
    va_list args;
    va_start(args, format);
    int result = vsnprintf(report.text + used, sizeof(report.text) - used, format, args);
    va_end(args);
    CHECK(result >= 0 && (size_t)result < sizeof(report.text) - used);
    if (mutation & 4) params.L = other;
}
static void observed_exit(int status) { report.exited = status; }
#define DLOG_ERR log_error
#define lua_isstring observed_isstring
#undef lua_tostring
#define lua_tostring observed_tostring
#undef lua_pop
#define lua_pop observed_pop
#define luaL_unref observed_unref
#define exit observed_exit
#define lua_check_argc old_check_argc
#define lua_check_argc_range old_check_argc_range
#define lua_desync_ctx_destroy old_context_destroy
#define lua_perror old_perror
#define lua_panic old_panic
#define lua_dlog_error old_dlog_error
#include "lua_aux_reference.inc"
#undef lua_check_argc
#undef lua_check_argc_range
#undef lua_desync_ctx_destroy
#undef lua_perror
#undef lua_panic
#undef lua_dlog_error
#include "lua_aux_arity_windows.inc"
#include "lua_aux_context_windows.inc"
#include "lua_aux_error_windows.inc"
#undef exit
#undef lua_isstring
#undef lua_tostring
#define lua_tostring(L,i) lua_tolstring(L,i,NULL)
#undef lua_pop
#define lua_pop(L,n) lua_settop(L, -(n)-1)

static bool ranged;
static int lower, upper;
static int reference_arity(lua_State *L)
{
    if (ranged) old_check_argc_range(L, "oracle", lower, upper);
    else old_check_argc(L, "oracle", lower);
    return 0;
}
static int selected_arity(lua_State *L)
{
    if (ranged) lua_check_argc_range(L, "oracle", lower, upper);
    else lua_check_argc(L, "oracle", lower);
    return 0;
}
static void compare_arity(lua_State *L)
{
    char expected[256];
    for (unsigned mode = 0; mode < 2; ++mode) {
        ranged = mode;
        for (lower = -1; lower < 5; ++lower)
            for (upper = -1; upper < 5; ++upper)
                for (int count = 0; count < 6; ++count) {
                    int status = 0;
                    for (unsigned side = 0; side < 2; ++side) {
                        lua_settop(L, 0);
                        lua_pushcfunction(L, side ? selected_arity : reference_arity);
                        for (int i = 0; i < count; ++i) lua_pushnil(L);
                        int current = lua_pcall(L, count, LUA_MULTRET, 0);
                        const char *message = current ? lua_tostring(L, -1) : "";
                        if (!side) {
                            status = current;
                            CHECK(strlen(message) < sizeof(expected));
                            strcpy(expected, message);
                        } else CHECK(current == status && !strcmp(message, expected));
                    }
                    ++comparisons;
                }
    }
}
static void push_value(lua_State *L, unsigned variant)
{
    switch (variant) {
    case 0: lua_pushnil(L); break;
    case 1: lua_pushboolean(L, 1); break;
    case 2: lua_pushnumber(L, -1349.5); break;
    case 3: lua_pushlstring(L, "primary\0hidden", 14); break;
    case 4: lua_newtable(L); break;
    }
}
static struct report run_error(bool selected, unsigned kind, unsigned variant)
{
    memset(&report, 0, sizeof(report));
    lua_settop(primary, 0);
    lua_settop(other, 0);
    params.L = primary;
    push_value(primary, variant);
    lua_pushliteral(other, "other VM");
    if (kind == 0) { if (selected) lua_perror(primary); else old_perror(primary); }
    if (kind == 1) CHECK((selected ? lua_panic(primary) : old_panic(primary)) == 0);
    if (kind == 2) { if (selected) lua_dlog_error(); else old_dlog_error(); }
    report.primary_top = lua_gettop(primary);
    report.other_top = lua_gettop(other);
    CHECK(report.exited == (kind == 1 ? 100 : 0));
    return report;
}
static struct report run_context(bool selected, int value)
{
    memset(&report, 0, sizeof(report));
    params.ref_desync_ctx = value;
    if (selected) lua_desync_ctx_destroy(primary);
    else old_context_destroy(primary);
    report.ref = params.ref_desync_ctx;
    return report;
}
int main(void)
{
    primary = luaL_newstate();
    other = luaL_newstate();
    CHECK(primary && other);
    compare_arity(primary);
    for (unsigned kind = 0; kind < 3; ++kind)
        for (unsigned variant = 0; variant < 5; ++variant)
            for (mutation = 0; mutation < 8; ++mutation) {
                struct report a = run_error(false, kind, variant), b = run_error(true, kind, variant);
                CHECK(!memcmp(&a, &b, sizeof(a)));
                ++comparisons;
            }
    for (int ref = -2; ref <= 1; ++ref) {
        if (ref > 0) {
            lua_pushliteral(primary, "registry value");
            int first = luaL_ref(primary, LUA_REGISTRYINDEX);
            struct report a = run_context(false, first);
            lua_pushliteral(primary, "registry value");
            int second = luaL_ref(primary, LUA_REGISTRYINDEX);
            struct report b = run_context(true, second);
            CHECK(first == second && !memcmp(&a, &b, sizeof(a)) && b.ref == 0);
        } else {
            struct report a = run_context(false, ref), b = run_context(true, ref);
            CHECK(!memcmp(&a, &b, sizeof(a)) && b.ref == 0);
        }
        ++comparisons;
    }
    lua_close(other);
    lua_close(primary);
    printf("PASS lua_aux cases=%u real_luajit=1 exact_errors=1 deferred_vm_reads=1 "
        "registry_unref_order=1 panic_exit_code=100\n", comparisons);
    return 0;
}
