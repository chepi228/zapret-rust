/* MIT. Compare the guards under the protected Windows LuaJIT ABI. */
#include "windows_lua_guards_abi.h"
#include <lauxlib.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef main

enum operation { EXACT, RANGE, LENGTH, STRING, ABSOLUTE_INDEX };
enum input { ABSENT, BINARY, TEXT_NUMBER, NUMBER, BOOL_INPUT, NIL, TABLE, EMPTY };
static bool rust, fault, entered, returned;
static enum operation operation;
static int minimum, maximum, index;
static size_t output_slot;
static bool use_slot;
static unsigned denied, calls, faults;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL Lua guard case=%u op=%u line=%d: %s\n", calls, operation, __LINE__, #condition); \
    exit(1); } } while (0)

static void *allocate(void *context, void *pointer, size_t old_size, size_t size)
{
    (void)context;
    if (!size) { free(pointer); return NULL; }
    if (fault && size > old_size) { ++denied; return NULL; }
    return realloc(pointer, size);
}

static void old_arity(lua_State *lua, bool range)
{
    int actual = lua_gettop(lua);
    if (range) {
        if (actual < minimum || actual > maximum)
            luaL_error(lua, "%s expect from %d to %d arguments, got %d", "guard", minimum, maximum, actual);
    } else if (actual != minimum) {
        luaL_error(lua, "%s expect exactly %d arguments, got %d", "guard", minimum, actual);
    }
}

static const char *old_string(lua_State *lua, size_t *size)
{
    luaL_checktype(lua, index, LUA_TSTRING);
    return lua_tolstring(lua, index, size);
}

static int invoke(lua_State *lua)
{
    entered = true;
    switch (operation) {
    case EXACT:
        if (rust) lua_check_argc(lua, "guard", minimum);
        else old_arity(lua, false);
        break;
    case RANGE:
        if (rust) lua_check_argc_range(lua, "guard", minimum, maximum);
        else old_arity(lua, true);
        break;
    case LENGTH:
    case STRING: {
        size_t *out = operation == LENGTH && use_slot ? &output_slot : NULL;
        const char *text = rust ? (operation == LENGTH ? lua_reqlstring(lua, index, out) : lua_reqstring(lua, index))
                                : old_string(lua, out);
        CHECK(lua_type(lua, index) == LUA_TSTRING);
        lua_pushlstring(lua, text, lua_objlen(lua, index));
        returned = true;
        return 1;
    }
    case ABSOLUTE_INDEX: {
        int absolute = rust ? lua_absindex(lua, index) : index < 0 ? lua_gettop(lua) + index + 1 : index;
        lua_pushinteger(lua, absolute);
        returned = true;
        return 1;
    }
    }
    returned = true;
    return 0;
}

static int push_input(lua_State *lua, enum input input)
{
    switch (input) {
    case ABSENT: return 0;
    case BINARY: lua_pushlstring(lua, "ab\0cd", 5); break;
    case TEXT_NUMBER: lua_pushliteral(lua, "-1349.5"); break;
    case NUMBER: lua_pushnumber(lua, -1349.5); break;
    case BOOL_INPUT: lua_pushboolean(lua, true); break;
    case NIL: lua_pushnil(lua); break;
    case TABLE: lua_newtable(lua); break;
    case EMPTY: lua_pushliteral(lua, ""); break;
    }
    return 1;
}

struct result {
    int status, top, kind, absolute;
    size_t written, length;
    bool returned;
    char text[256];
};

static struct result run(bool selected, bool inject, int count, enum input input)
{
    lua_State *lua = lua_newstate(allocate, NULL);
    CHECK(lua);
    lua_gc(lua, LUA_GCSTOP, 0);
    CHECK(lua_checkstack(lua, count + 8));
    rust = selected;
    entered = returned = false;
    output_slot = SIZE_MAX;
    lua_pushcfunction(lua, invoke);
    if (operation == LENGTH || operation == STRING) count = push_input(lua, input);
    else for (int i = 0; i < count; ++i) lua_pushnil(lua);
    unsigned previous_denied = denied;
    fault = inject;
    struct result result;
    memset(&result, 0, sizeof(result));
    result.status = lua_pcall(lua, count, LUA_MULTRET, 0);
    fault = false;
    result.top = lua_gettop(lua);
    result.written = output_slot;
    result.returned = returned;
    if (result.top) {
        result.kind = lua_type(lua, -1);
        if (result.kind == LUA_TSTRING) {
            const char *text = lua_tolstring(lua, -1, &result.length);
            CHECK(result.length < sizeof(result.text));
            memcpy(result.text, text, result.length);
        } else result.absolute = (int)lua_tointeger(lua, -1);
    }
    if (inject) {
        CHECK(result.status == LUA_ERRMEM && denied > previous_denied && entered && !returned);
        lua_settop(lua, 0);
        lua_pushcfunction(lua, invoke);
        CHECK(lua_pcall(lua, 0, 0, 0) == LUA_ERRRUN);
        ++faults;
    }
    lua_close(lua);
    return result;
}

static void compare(int count, enum input input, bool inject)
{
    struct result old = run(false, inject, count, input), selected = run(true, inject, count, input);
    CHECK(old.status == selected.status && old.top == selected.top && old.kind == selected.kind);
    CHECK(old.absolute == selected.absolute && old.written == selected.written && old.length == selected.length);
    CHECK(old.returned == selected.returned && !memcmp(old.text, selected.text, sizeof(old.text)));
    if (operation == LENGTH || operation == STRING) {
        if (old.status || operation == STRING || !use_slot) CHECK(selected.written == SIZE_MAX);
        else CHECK(selected.written == selected.length);
        if (!inject && (index == 1 || index == -1)) {
            if (input == NUMBER) CHECK(selected.status == LUA_ERRRUN);
            if (input == TEXT_NUMBER) CHECK(!selected.status && selected.length == sizeof("-1349.5") - 1);
            if (input == BINARY) CHECK(!selected.status && selected.length == 5 && !memcmp(selected.text, "ab\0cd", 5));
        }
    }
    ++calls;
}

int main(void)
{
    for (operation = EXACT; operation <= RANGE; ++operation)
        for (minimum = -1; minimum < 5; ++minimum)
            for (maximum = -1; maximum < 5; ++maximum)
                for (int count = 0; count < 6; ++count) compare(count, ABSENT, false);
    for (operation = LENGTH; operation <= STRING; ++operation)
        for (int slot = 0; slot < 2; ++slot) {
            use_slot = slot != 0;
            for (index = -1; index <= 2; ++index) {
                if (!index) continue;
                for (enum input input = ABSENT; input <= EMPTY; ++input) {
                    // An absent negative index violates LuaJIT's public API precondition.
                    if (input != ABSENT || index > 0) compare(0, input, false);
                }
            }
        }
    const int indices[] = {INT_MIN, LUA_REGISTRYINDEX, -8, -1, 0, 1, 8, INT_MAX};
    operation = ABSOLUTE_INDEX;
    for (size_t i = 0; i < sizeof(indices) / sizeof(indices[0]); ++i) {
        index = indices[i];
        for (int count = 0; count < 6; ++count) compare(count, ABSENT, false);
    }
    minimum = maximum = index = 1;
    use_slot = true;
    for (operation = EXACT; operation <= STRING; ++operation)
        for (unsigned i = 0; i < 32; ++i) compare(0, NUMBER, true);
    printf("PASS windows_lua_guards comparisons=%u oom_recoveries=%u strict_strings=1 length_order=1\n", calls, faults);
    return 0;
}
