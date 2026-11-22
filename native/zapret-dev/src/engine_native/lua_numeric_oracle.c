/* MIT. Protected calls compare values, bytes, type errors and argument counts. */
#include "params.h"
#include "engine_lua.h"
#include "helpers.h"
#undef main

static unsigned cases, errors, scenario, function_index;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL lua numeric function=%u scenario=%u case=%u line=%d: %s\n", \
        function_index, scenario, cases, __LINE__, #condition); exit(1); } } while (0)
struct tm *zapret_localtime_r(const time_t *value, struct tm *output)
{
    CHECK(false); /* The numeric API must never observe the clock. */
    return NULL;
}
static void lua_check_argc(lua_State *L, const char *where, int argc)
{
    int count = lua_gettop(L);
    if (count != argc) luaL_error(L, "%s expect exactly %d arguments, got %d", where, argc, count);
}
static void lua_check_argc_range(lua_State *L, const char *where, int minimum, int maximum)
{
    int count = lua_gettop(L);
    if (count < minimum || count > maximum)
        luaL_error(L, "%s expect from %d to %d arguments, got %d", where, minimum, maximum, count);
}
const char *lua_reqlstring(lua_State *L, int index, size_t *length)
{
    luaL_checktype(L, index, LUA_TSTRING);
    return lua_tolstring(L, index, length);
}
struct numeric_function { const char *name; lua_CFunction legacy, rust; };
#include "lua_numeric_comparison.inc"

struct argument { int kind; int64_t number; const char *bytes; size_t length; };
struct snapshot { int status, kind; double number; size_t length; char bytes[512]; };
static lua_State *vm;
static struct argument number(int64_t v) { return (struct argument){.kind=LUA_TNUMBER, .number=v}; }
static struct argument binary(const char *v, size_t length) { return (struct argument){.kind=LUA_TSTRING, .bytes=v, .length=length}; }
static struct snapshot invoke(lua_CFunction fn, const struct argument *args, unsigned count)
{
    lua_settop(vm, 0);
    CHECK(lua_checkstack(vm, count + 4));
    lua_pushcfunction(vm, fn);
    for (unsigned i = 0; i < count; ++i) {
        switch (args[i].kind) {
            case LUA_TNUMBER: lua_pushlint(vm, args[i].number); break;
            case LUA_TSTRING: lua_pushlstring(vm, args[i].bytes, args[i].length); break;
            case LUA_TBOOLEAN: lua_pushboolean(vm, true); break;
            default: lua_pushnil(vm); break;
        }
    }
    struct snapshot out = {0};
    out.status = lua_pcall(vm, count, 1, 0);
    CHECK(lua_gettop(vm) == 1);
    out.kind = lua_type(vm, -1);
    if (out.kind == LUA_TNUMBER) out.number = lua_tonumber(vm, -1);
    else if (out.kind == LUA_TSTRING) {
        const char *text = lua_tolstring(vm, -1, &out.length);
        CHECK(out.length < sizeof(out.bytes));
        memcpy(out.bytes, text, out.length);
    }
    return out;
}
static void compare(const struct argument *args, unsigned count)
{
    const struct numeric_function *fn = &functions[function_index];
    struct snapshot c = invoke(fn->legacy, args, count), r = invoke(fn->rust, args, count);
    if (c.status != r.status || c.kind != r.kind || c.number != r.number || c.length != r.length || memcmp(c.bytes, r.bytes, c.length)) {
        fprintf(stderr, "%s C status=%d kind=%d value=%.17g bytes=%s Rust status=%d kind=%d value=%.17g bytes=%s\n",
            fn->name, c.status, c.kind, c.number, c.bytes, r.status, r.kind, r.number, r.bytes);
        CHECK(false);
    }
    ++cases;
    if (c.status) ++errors;
}
static uint64_t random_state = 0x123456789abcdef0ULL;
static uint64_t next_random(void)
{
    random_state ^= random_state << 13;
    random_state ^= random_state >> 7;
    random_state ^= random_state << 17;
    return random_state;
}
static unsigned width(const char *name)
{
    while (*name && (*name < '0' || *name > '9')) ++name;
    return *name ? (unsigned)atoi(name) : 48;
}
static volatile uint64_t benchmark_sink;
static double measure(lua_CFunction fn, const struct argument *args, unsigned count)
{
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency);
    lua_settop(vm, 0);
    QueryPerformanceCounter(&start);
    for (unsigned call = 0; call < 32768; ++call) {
        lua_pushcfunction(vm, fn);
        for (unsigned i = 0; i < count; ++i) {
            if (args[i].kind == LUA_TSTRING) lua_pushlstring(vm, args[i].bytes, args[i].length);
            else lua_pushlint(vm, args[i].number);
        }
        lua_call(vm, count, 1);
        benchmark_sink ^= lua_type(vm, -1) == LUA_TNUMBER ? (uint64_t)lua_tonumber(vm, -1) : lua_objlen(vm, -1);
        lua_pop(vm, 1);
    }
    QueryPerformanceCounter(&end);
    return (double)(end.QuadPart - start.QuadPart) * 1e9 / frequency.QuadPart / 32768;
}
static void benchmark(const char *name, const struct argument *args, unsigned count)
{
    const struct numeric_function *fn = NULL;
    for (unsigned i = 0; i < sizeof(functions) / sizeof(*functions); ++i)
        if (!strcmp(name, functions[i].name)) fn = &functions[i];
    CHECK(fn);
    double legacy[9], rust[9];
    for (unsigned round = 0; round < 9; ++round) {
        if (round & 1) { rust[round] = measure(fn->rust, args, count); legacy[round] = measure(fn->legacy, args, count); }
        else { legacy[round] = measure(fn->legacy, args, count); rust[round] = measure(fn->rust, args, count); }
    }
    for (unsigned i = 0; i < 9; ++i) for (unsigned j = i + 1; j < 9; ++j) {
        if (legacy[i] > legacy[j]) { double swap = legacy[i]; legacy[i] = legacy[j]; legacy[j] = swap; }
        if (rust[i] > rust[j]) { double swap = rust[i]; rust[i] = rust[j]; rust[j] = swap; }
    }
    printf("BENCH lua_numeric %s c_ns=%.2f rust_ns=%.2f rounds=9 calls_per_round=32768\n", name, legacy[4], rust[4]);
}
int main(void)
{
    vm = luaL_newstate();
    CHECK(vm);
    char data[64];
    for (unsigned i = 0; i < sizeof(data); ++i) data[i] = (char)(i * 71);
    for (function_index = 0; function_index < sizeof(functions) / sizeof(*functions); ++function_index) {
        const char *name = functions[function_index].name;
        unsigned bits = width(name);
        uint64_t mask = (1ULL << bits) - 1;
        bool read = name[0] == 'u' && !strstr(name, "add");
        bool variadic = strstr(name, "add") || !strcmp(name, "bitand") || !strcmp(name, "bitor") || !strcmp(name, "bitxor");
        bool shift = !strcmp(name, "bitlshift") || !strcmp(name, "bitrshift");
        bool get = !strcmp(name, "bitget"), set = !strcmp(name, "bitset"), divide = !strcmp(name, "divint");
        struct argument args[102];
        for (scenario = 0; scenario < 2048; ++scenario) {
            unsigned count = variadic ? 2 + next_random() % 99 : set ? 4 : get ? 3 : shift || divide ? 2 : 1;
            for (unsigned i = 0; i < count; ++i) {
                int64_t v = (int64_t)(next_random() & mask);
                args[i] = number(next_random() & 1 ? v : -v);
            }
            if (shift) args[1] = number(next_random() % 49);
            if (get || set) {
                unsigned from = next_random() % 48;
                args[1] = number(from);
                args[2] = number(from + next_random() % (48 - from));
            }
            if (divide && scenario % 7 == 0) args[1] = number(0);
            if (read) {
                args[0] = binary(data, sizeof(data));
                count = 1 + scenario % 2;
                args[1] = scenario % 3 == 0 ? (struct argument){.kind=LUA_TNIL} : number(1 + next_random() % (sizeof(data) - bits / 8 + 1));
            }
            compare(args, count);
        }
        static const int64_t positions[] = {-1, 0, 1, 2, 3, 7, 47, 48, 49, INT64_MAX};
        int64_t limits[] = {-(int64_t)mask - 1, -(int64_t)mask, -1, 0, 1, (int64_t)mask, (int64_t)mask + 1, INT64_MIN, INT64_MAX};
        unsigned count = set ? 4 : get ? 3 : shift || divide || !strcmp(name, "bitand") ? 2 : 1;
        for (scenario = 0; scenario < 9; ++scenario) {
            for (unsigned i = 0; i < 102; ++i) args[i] = number(1);
            args[0] = number(limits[scenario]);
            if (get || set) { args[1] = number(0); args[2] = number(47); }
            if (read) args[0] = binary(data, scenario);
            compare(args, count);
        }
        if (read || shift || get || set) {
            count = set ? 4 : get ? 3 : 2;
            for (scenario = 0; scenario < sizeof(positions) / sizeof(*positions); ++scenario) {
                args[0] = read ? binary(data, sizeof(data)) : number(0);
                args[1] = number(positions[scenario]);
                args[2] = number(47); args[3] = number(1);
                compare(args, count);
            }
        }
        for (unsigned i = 0; i < 102; ++i) args[i] = number(1);
        if (read) args[0] = binary(data, sizeof(data));
        for (scenario = 0; scenario < 5; ++scenario) {
            unsigned counts[] = {0, 1, 2, 100, 101};
            compare(args, counts[scenario]);
        }
        count = set ? 4 : get ? 3 : shift || divide || !strcmp(name, "bitand") ? 2 : 1;
        for (scenario = 0; scenario < 3; ++scenario) {
            args[0] = scenario == 0 ? binary("invalid", 7) : (struct argument){.kind=scenario == 1 ? LUA_TBOOLEAN : LUA_TNIL};
            if (get || set) { args[1] = number(0); args[2] = number(47); }
            compare(args, count);
        }
    }
    struct argument overflow[] = {number(INT64_MIN), number(-1)};
    struct snapshot nil = invoke(luacall_divint, overflow, 2);
    CHECK(!nil.status && nil.kind == LUA_TNIL);
    struct argument offset[] = {binary(data, sizeof(data)), number(INT64_MIN)};
    struct snapshot invalid = invoke(luacall_u48, offset, 2);
    CHECK(invalid.status && invalid.kind == LUA_TSTRING && !strcmp(invalid.bytes, "out of range"));
    printf("PASS lua_numeric functions=32 cases=%u errors=%u boundary_improvements=2\n", cases, errors);
    struct argument inputs[] = {number(123), number(3), number(17)};
    benchmark("bitlshift", inputs, 2);
    benchmark("bu48", inputs, 1);
    benchmark("u16add", inputs, 3);
    inputs[0] = binary(data, sizeof(data));
    benchmark("u16", inputs, 2);
    lua_close(vm);
    return 0;
}
