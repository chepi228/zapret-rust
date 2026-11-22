/* MIT. Direct LuaJIT comparison of the Win64 Rust field writers. */
#include "engine_lua.h"
#include "windows_lua_fields_abi.h"
#include "lj_prng.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#undef main

#include "lua_fields_reference.inc"

/* Pair hash-table allocation budgets with the same seed inside this fixture. */
int LJ_FASTCALL __wrap_lj_prng_seed_secure(PRNGState *state)
{
    lj_prng_seed_fixed(state);
    return 1;
}

static unsigned variant, side, nested, cases, oom_pairs;

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL Lua fields variant=%u side=%u line=%d: %s\n", \
        variant, side, __LINE__, #condition); exit(1); \
} } while (0)

#define CALL(name, ...) do { \
    (side ? name : reference_##name)(__VA_ARGS__); \
    CHECK(lua_gettop(L) == 1); \
} while (0)

struct allocator {
    unsigned budget, attempts, denied, live;
    bool armed;
};

static void *allocate(void *context, void *pointer, size_t previous, size_t size)
{
    struct allocator *state = context;
    if (!size) {
        if (pointer) { CHECK(state->live); --state->live; }
        free(pointer);
        return NULL;
    }
    if (state->armed && size > previous && state->attempts++ >= state->budget) {
        ++state->denied;
        return NULL;
    }
    bool is_new = pointer == NULL;
    void *result = realloc(pointer, size);
    if (is_new && result) ++state->live;
    return result;
}

static int reject_set(lua_State *L)
{
    return luaL_error(L, "unexpected __newindex from field helper");
}

static int global_value(lua_State *L)
{
    ++nested;
    lua_newtable(L);
    (side ? lua_pushf_int : reference_lua_pushf_int)(L, "nested value", 19);
    if (variant % 7 == 0) return luaL_error(L, "global lookup refused");
    return 1;
}

static int publish(lua_State *L)
{
    const lua_Integer integers[] = {0, -1, INT64_MIN, INT64_MAX, INT64_C(9007199254740993)};
    const lua_Number numbers[] = {0.0, -0.0, 1.75, -16777217.125};
    const lua_Integer value = integers[variant % 5];
    const lua_Integer first = 100 * (lua_Integer)(variant & 1 ? -1 : 1);
    const lua_Number number = numbers[variant % 4];
    const char sample[] = "root\0\xff value which requires a separate Lua string";
    const char *text = variant & 2 ? NULL : "ordinary field value";
    const void *raw = variant & 4 ? NULL : sample;
    bool enabled = (variant & 8) != 0;
    CHECK(lua_gettop(L) == 1);
    CALL(lua_pushf_nil, L, "remove this field");
    CALL(lua_pushi_nil, L, first);
    CALL(lua_pushf_int, L, "integer field", value);
    CALL(lua_pushi_int, L, first + 1, value);
    CALL(lua_pushf_lint, L, "lint field", value);
    CALL(lua_pushi_lint, L, first + 2, value);
    CALL(lua_pushf_number, L, "number field", number);
    CALL(lua_pushi_number, L, first + 3, number);
    CALL(lua_pushf_bool, L, "boolean field", enabled);
    CALL(lua_pushi_bool, L, first + 4, enabled);
    CALL(lua_pushf_str, L, "string field", text);
    CALL(lua_pushi_str, L, first + 5, text);
    CALL(lua_pushf_lstr, L, "binary string", sample, sizeof(sample));
    CALL(lua_pushi_lstr, L, first + 6, sample, variant % sizeof(sample));
    CALL(lua_pushf_raw, L, "raw bytes", raw, sizeof(sample));
    CALL(lua_pushi_raw, L, first + 7, raw, sizeof(sample));
    CALL(lua_pushf_reg, L, "registry entry", 3189);
    CALL(lua_pushf_lud, L, "light userdata", (void *)(uintptr_t)(23 + variant));
    CALL(lua_pushf_table, L, "nested table");
    CALL(lua_pushi_table, L, first + 8);
    (side ? lua_push_raw : reference_lua_push_raw)(L, raw, sizeof(sample));
    CHECK(lua_gettop(L) == 2);
    lua_rawseti(L, 1, first + 9);
    CALL(lua_pushf_global, L, "global lookup result", "lookup target");
    if (variant == 63) CALL(lua_pushf_nil, L, NULL);
    return 0;
}

static uint64_t digest(const void *input, size_t length)
{
    const unsigned char *bytes = input;
    uint64_t value = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < length; ++i) {
        value = (value ^ bytes[i]) * UINT64_C(1099511628211);
    }
    return value;
}

static uint64_t value_hash(lua_State *L, int index)
{
    int kind = lua_type(L, index);
    uint64_t value = (unsigned)kind * UINT64_C(0x9e3779b185ebca87);
    switch (kind) {
    case LUA_TBOOLEAN: return value ^ (unsigned)lua_toboolean(L, index);
    case LUA_TLIGHTUSERDATA: return value ^ (uintptr_t)lua_touserdata(L, index);
    case LUA_TNUMBER: {
        lua_Number number = lua_tonumber(L, index);
        return value ^ digest(&number, sizeof(number));
    }
    case LUA_TSTRING: {
        size_t length;
        const char *text = lua_tolstring(L, index, &length);
        return value ^ digest(text, length);
    }
    case LUA_TTABLE:
        lua_getfield(L, index, "nested value");
        value ^= (uint64_t)lua_tointeger(L, -1);
        lua_pop(L, 1);
        return value;
    default: return value;
    }
}

struct sample {
    int status, top;
    unsigned nested, fields, attempts, denied;
    uint64_t table;
    char error[256];
};

static void run(struct sample *result, unsigned budget)
{
    struct allocator state = {.budget = budget};
    lua_State *L = lua_newstate(allocate, &state);
    CHECK(L);
    lua_pushliteral(L, "existing registry string");
    lua_rawseti(L, LUA_REGISTRYINDEX, 3189);
    lua_pushvalue(L, LUA_GLOBALSINDEX);
    lua_newtable(L);
    lua_pushcfunction(L, global_value);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -2);
    lua_pop(L, 1);

    lua_newtable(L);
    lua_pushliteral(L, "remove this field");
    lua_pushboolean(L, true);
    lua_rawset(L, -3);
    lua_pushboolean(L, true);
    lua_rawseti(L, -2, (variant & 1) ? -100 : 100);
    lua_newtable(L);
    lua_pushcfunction(L, reject_set);
    lua_setfield(L, -2, "__newindex");
    lua_setmetatable(L, -2);
    int table = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_pushcfunction(L, publish);
    lua_rawgeti(L, LUA_REGISTRYINDEX, table);
    nested = 0;
    state.armed = budget != UINT_MAX;
    result->status = lua_pcall(L, 1, 0, 0);
    state.armed = false;
    result->nested = nested;
    result->top = lua_gettop(L);
    result->attempts = state.attempts;
    result->denied = state.denied;
    if (result->status)
        snprintf(result->error, sizeof(result->error), "%s", lua_tostring(L, -1));

    lua_rawgeti(L, LUA_REGISTRYINDEX, table);
    lua_pushnil(L);
    while (lua_next(L, -2)) {
        ++result->fields;
        result->table ^= value_hash(L, -2) * UINT64_C(0x9e3779b185ebca87) + value_hash(L, -1);
        lua_pop(L, 1);
    }
    lua_close(L);
    CHECK(state.live == 0);
}

static void compare(unsigned budget)
{
    struct sample old = {0}, rust = {0};
    side = 0;
    run(&old, budget);
    side = 1;
    run(&rust, budget);
    CHECK(old.status == rust.status && old.top == rust.top && old.nested == rust.nested);
    if (old.fields != rust.fields || old.table != rust.table || strcmp(old.error, rust.error)) {
        fprintf(stderr, "budget=%u old=%u/%016llx/%s new=%u/%016llx/%s\n", budget,
            old.fields, (unsigned long long)old.table, old.error,
            rust.fields, (unsigned long long)rust.table, rust.error);
    }
    CHECK(old.fields == rust.fields && old.table == rust.table && !strcmp(old.error, rust.error));
    CHECK(old.attempts == rust.attempts && old.denied == rust.denied);
    if (rust.status == LUA_ERRMEM) { CHECK(rust.denied); ++oom_pairs; }
    if (budget == UINT_MAX) CHECK(rust.nested == 1 && rust.fields >= 13);
    ++cases;
}

int main(void)
{
    for (variant = 0; variant < 64; ++variant) {
        compare(UINT_MAX);
        for (unsigned budget = 0; budget < 48; ++budget) compare(budget);
    }
    CHECK(oom_pairs >= 64);
    printf("PASS lua_fields functions=22 cases=%u oom_pairs=%u partial_tables=1 "
        "raw_stores=1 global_reentry=1 vm_heap_released=1\n", cases, oom_pairs);
    return 0;
}
