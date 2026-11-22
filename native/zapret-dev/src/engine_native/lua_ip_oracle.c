/* MIT. Real Lua calls and private buffers use the same Winsock contract. */
#include "engine_lua.h"
#include <arpa/inet.h>
#undef main

static unsigned cases, boundaries;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL Lua IP case=%u line=%d: %s\n", cases, __LINE__, #condition); exit(1); } \
} while (0)
static void lua_check_argc(lua_State *vm, const char *name, int expected)
{
    int count = lua_gettop(vm);
    if (count != expected) luaL_error(vm, "%s expect exactly %d arguments, got %d", name, expected, count);
}
const char *lua_reqlstring(lua_State *vm, int index, size_t *length)
{
    luaL_checktype(vm, index, LUA_TSTRING);
    return lua_tolstring(vm, index, length);
}
const char *lua_reqstring(lua_State *vm, int index) { return lua_reqlstring(vm, index, NULL); }
#define luacall_ntop reference_luacall_ntop
#define luacall_pton reference_luacall_pton
#include "lua_ip_reference.inc"
#undef luacall_ntop
#undef luacall_pton
#include "lua_ip_windows.inc"

static lua_State *vm;
struct result { int status, kind; size_t length; char bytes[192]; };
static struct result invoke(lua_CFunction function, const char *data, size_t length, unsigned count)
{
    lua_settop(vm, 0);
    lua_pushcfunction(vm, function);
    for (unsigned index = 0; index < count; ++index) {
        if (data) lua_pushlstring(vm, data, length);
        else lua_pushinteger(vm, 123);
    }
    struct result value = {0};
    value.status = lua_pcall(vm, count, 1, 0);
    CHECK(lua_gettop(vm) == 1);
    value.kind = lua_type(vm, -1);
    if (value.kind == LUA_TSTRING) {
        const char *text = lua_tolstring(vm, -1, &value.length);
        CHECK(value.length < sizeof(value.bytes));
        memcpy(value.bytes, text, value.length);
    }
    return value;
}
static void compare(bool format, const char *data, size_t length, unsigned count)
{
    struct result left = invoke(format ? reference_luacall_ntop : reference_luacall_pton, data, length, count);
    struct result right = invoke(format ? luacall_ntop : luacall_pton, data, length, count);
    CHECK(left.status == right.status && left.kind == right.kind && left.length == right.length && !memcmp(left.bytes, right.bytes, left.length));
    ++cases;
}
static uint64_t random_state = 0x6c75615f69706164ULL;
static uint64_t next(void) { random_state ^= random_state << 13; random_state ^= random_state >> 7; random_state ^= random_state << 17; return random_state; }
int main(void)
{
    WSADATA winsock;
    CHECK(!WSAStartup(MAKEWORD(2, 2), &winsock));
    vm = luaL_newstate();
    CHECK(vm);
    char address[24], text[INET6_ADDRSTRLEN];
    for (unsigned round = 0; round < 8192; ++round) {
        for (unsigned index = 0; index < sizeof(address); ++index) address[index] = (char)next();
        unsigned size = round % 2 ? 4 : 16, offset = round % 8;
        compare(true, address + offset, size, 1);
        CHECK(inet_ntop(size == 4 ? AF_INET : AF_INET6, address + offset, text, sizeof(text)));
        compare(false, text, strlen(text), 1);
    }
    static const char *const input[] = {
        "", "0.0.0.0", "255.255.255.255", "127.0.0.1", "01.02.003.004", "1.2.3", "1.2.3.256", "0x7F.0.0.1",
        "+1.2.3.4", " 1.2.3.4", "1.2.3.4 ", "::", "::1", "1::", "1::1", "::ffff:1.2.3.4", "::1.2.3.4",
        "::ffff:0:1.2.3.4", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7", "1::2::3", "::gg", "fe80::1%2", "[::1]", "имя"
    };
    for (unsigned index = 0; index < sizeof(input) / sizeof(*input); ++index) {
        compare(false, input[index], strlen(input[index]), 1);
        uint8_t binary[16];
        size_t length = zapret_lua_pton(input[index], binary, sizeof(binary));
        if (length) compare(true, (const char *)binary, length, 1);
    }
    const char terminated[] = "127.0.0.1\0ignored";
    compare(false, terminated, sizeof(terminated) - 1, 1);
    for (unsigned length = 0; length < 24; ++length) compare(true, address, length, 1);
    for (unsigned count = 0; count <= 2; ++count) {
        compare(true, "one", 3, count);
        compare(false, "one", 3, count);
        compare(true, NULL, 0, count);
        compare(false, NULL, 0, count);
    }
    for (unsigned capacity = 0; capacity <= 20; ++capacity) {
        uint8_t output[32];
        memset(output, 0x3c, sizeof(output));
        size_t length = zapret_lua_pton("1.2.3.4", output + 3, capacity);
        CHECK(length == (capacity >= 4 ? 4 : 0));
        for (unsigned index = 0; index < sizeof(output); ++index)
            if (index < 3 || index >= 3 + length) CHECK(output[index] == 0x3c);
        memset(output, 0x3c, sizeof(output));
        CHECK(!zapret_lua_pton("invalid", output, capacity));
        for (unsigned index = 0; index < sizeof(output); ++index) CHECK(output[index] == 0x3c);
        boundaries += 2;
    }
    CHECK(!zapret_lua_ntop(NULL, 3, NULL, 0));
    lua_close(vm);
    WSACleanup();
    printf("PASS lua_ip cases=%u buffer_boundaries=%u\n", cases, boundaries);
    return 0;
}
