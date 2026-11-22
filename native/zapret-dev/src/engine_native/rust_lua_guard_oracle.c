/* MIT. Exercise the Rust VM's Windows C ABI and script buffer ownership. */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

typedef int (*load_fn)(lua_State *, const char *, size_t, const char *);
extern int zapret_lua_load_owned_buffer(lua_State *, char *, size_t, const char *,
                                       load_fn, void (*)(void *));

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "Rust Lua ABI check failed at line %d: %s\n", __LINE__, #test); \
    ExitProcess(1); \
} } while (0)

static unsigned releases;

static void release(void *bytes)
{
    ++releases;
    free(bytes);
}

static int load_ok(lua_State *lua, const char *bytes, size_t size, const char *name)
{
    return luaL_loadbuffer(lua, bytes, size, name);
}

static int load_escape(lua_State *lua, const char *bytes, size_t size, const char *name)
{
    (void)bytes;
    (void)size;
    (void)name;
    return luaL_error(lua, "%s %d %.2f %s %lld", "compiler escaped", 27, 4.25,
                      "after", -4000000000LL);
}

static int guarded_load(lua_State *lua)
{
    const char source[] = "return 17";
    char *bytes = malloc(sizeof(source));
    CHECK(bytes);
    memcpy(bytes, source, sizeof(source));
    load_fn load = lua_toboolean(lua, 1) ? load_escape : load_ok;
    CHECK(zapret_lua_load_owned_buffer(lua, bytes, sizeof(source) - 1, "=guard", load, release) == 0);
    lua_call(lua, 0, 1);
    return 1;
}

static int rooted_callback(lua_State *lua)
{
    const char binary[] = {'a', 0, 'b'};
    lua_pushlstring(lua, binary, sizeof(binary));
    lua_getglobal(lua, "collectgarbage");
    lua_pushstring(lua, "collect");
    lua_call(lua, 1, 0);
    size_t length;
    const char *bytes = lua_tolstring(lua, -1, &length);
    CHECK(bytes && length == sizeof(binary) && !memcmp(bytes, binary, length) && !bytes[length]);
    return 1;
}

static void hook(lua_State *lua, lua_Debug *debug)
{
    (void)lua;
    (void)debug;
}

static DWORD WINAPI signal_vm(void *lua)
{
    Sleep(20);
    lua_sethook(lua, hook, LUA_MASKCOUNT, 1);
    return 0;
}

int main(void)
{
    lua_State *lua = luaL_newstate();
    CHECK(lua);
    luaL_openlibs(lua);
    _Static_assert(sizeof(lua_Integer) == sizeof(ptrdiff_t), "signed C API integer");
    lua_pushnumber(lua, -731.875);
    CHECK(lua_tointeger(lua, -1) == -731 && luaL_checkinteger(lua, -1) == -731);
    lua_pushnumber(lua, (double)PTRDIFF_MAX + 1.0);
    CHECK(lua_tointeger(lua, -1) == PTRDIFF_MIN);
    lua_pushnumber(lua, NAN);
    CHECK(luaL_checkinteger(lua, -1) == PTRDIFF_MIN);
    lua_settop(lua, 0);
    const char *formatted = lua_pushfstring(lua, "%s %.2f %d %s %lld", "registers",
                                           1.25, -17, "stack", 4000000000LL);
    CHECK(formatted && !strcmp(formatted, "registers 1.25 -17 stack 4000000000"));
    lua_settop(lua, 0);
    lua_pushcfunction(lua, guarded_load);
    lua_pushboolean(lua, 0);
    CHECK(lua_pcall(lua, 1, 1, 0) == 0 && releases == 1 && lua_tointeger(lua, -1) == 17);
    lua_settop(lua, 0);
    lua_pushcfunction(lua, guarded_load);
    lua_pushboolean(lua, 1);
    CHECK(lua_pcall(lua, 1, 1, 0) == LUA_ERRRUN && releases == 2);
    CHECK(strcmp(lua_tostring(lua, -1), "compiler escaped 27 4.25 after -4000000000") == 0);
    lua_settop(lua, 0);
    const char invalid[] = "return )";
    char *bytes = malloc(sizeof(invalid));
    CHECK(bytes);
    memcpy(bytes, invalid, sizeof(invalid));
    CHECK(zapret_lua_load_owned_buffer(lua, bytes, sizeof(invalid) - 1, "=guard",
                                      load_ok, release) == LUA_ERRSYNTAX);
    CHECK(releases == 3 && lua_isstring(lua, -1));
    lua_settop(lua, 0);
    lua_pushcfunction(lua, rooted_callback);
    CHECK(lua_pcall(lua, 0, 1, 0) == 0 && lua_objlen(lua, -1) == 3);
    lua_settop(lua, 0);
    CHECK(luaL_dostring(lua, "local key='dynamic'; local t={[key..'1']=true,[key..'2']=nil}; return t.dynamic1 and t.dynamic2==nil") == 0);
    CHECK(lua_toboolean(lua, -1));
    lua_settop(lua, 0);
    CHECK(luaL_loadstring(lua, "while true do end") == 0);
    HANDLE thread = CreateThread(NULL, 0, signal_vm, lua, 0, NULL);
    CHECK(thread);
    CHECK(lua_pcall(lua, 0, 0, 0) == LUA_ERRRUN);
    CHECK(WaitForSingleObject(thread, 1000) == WAIT_OBJECT_0);
    CloseHandle(thread);
    CHECK(strcmp(lua_tostring(lua, -1), "INTERRUPT") == 0);
    lua_close(lua);
    puts("PASS Rust Lua ABI protected_unwind=1 released_buffers=3 varargs=2 signed_integer=1 binary_root=1 dynamic_keys=1 interrupt=1");
    return 0;
}
