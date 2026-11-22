/* MIT. Real Lua calls, independent short vectors and pinned IETF C parity. */
#include "engine_lua.h"
#include "crypto/sha.h"
#undef main

static unsigned cases, boundaries;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL Lua hash case=%u line=%d: %s\n", cases, __LINE__, #condition); exit(1); } \
} while (0)
static void lua_check_argc(lua_State *vm, const char *name, int count)
{
    int actual = lua_gettop(vm);
    if (actual != count) luaL_error(vm, "%s expect exactly %d arguments, got %d", name, count, actual);
}
const char *lua_reqlstring(lua_State *vm, int index, size_t *length)
{
    luaL_checktype(vm, index, LUA_TSTRING);
    return lua_tolstring(vm, index, length);
}
#define luacall_hash reference_luacall_hash
#define luacall_hkdf reference_luacall_hkdf
#include "lua_hash_reference.inc"
#undef luacall_hash
#undef luacall_hkdf
#include "lua_hash_windows.inc"

struct argument { int kind; const char *bytes; size_t length; lua_Number number; };
static struct argument string(const void *bytes, size_t length)
{
    return (struct argument){.kind = LUA_TSTRING, .bytes = bytes, .length = length};
}
static struct argument number(lua_Number value) { return (struct argument){.kind = LUA_TNUMBER, .number = value}; }
static lua_State *vm;
struct result { int status, kind; size_t length; char bytes[8320]; };
static void push(lua_CFunction function, const struct argument *arguments, unsigned count)
{
    lua_pushcfunction(vm, function);
    for (unsigned index = 0; index < count; ++index) {
        const struct argument *argument = &arguments[index];
        switch (argument->kind) {
            case LUA_TSTRING: lua_pushlstring(vm, argument->bytes, argument->length); break;
            case LUA_TNUMBER: lua_pushnumber(vm, argument->number); break;
            case LUA_TBOOLEAN: lua_pushboolean(vm, 1); break;
            default: lua_pushnil(vm); break;
        }
    }
}
static struct result invoke(lua_CFunction function, const struct argument *arguments, unsigned count)
{
    lua_settop(vm, 0);
    push(function, arguments, count);
    struct result result = {0};
    result.status = lua_pcall(vm, count, 1, 0);
    CHECK(lua_gettop(vm) == 1);
    result.kind = lua_type(vm, -1);
    if (result.kind == LUA_TSTRING) {
        const char *text = lua_tolstring(vm, -1, &result.length);
        CHECK(result.length < sizeof(result.bytes));
        memcpy(result.bytes, text, result.length);
    }
    return result;
}
static void compare(bool derive, const struct argument *arguments, unsigned count)
{
    struct result left = invoke(derive ? reference_luacall_hkdf : reference_luacall_hash, arguments, count);
    struct result right = invoke(derive ? luacall_hkdf : luacall_hash, arguments, count);
    CHECK(left.status == right.status && left.kind == right.kind && left.length == right.length && !memcmp(left.bytes, right.bytes, left.length));
    ++cases;
}
static uint64_t random_state = 0x6c75615f68617368ULL;
static uint64_t next(void) { random_state ^= random_state << 13; random_state ^= random_state >> 7; random_state ^= random_state << 17; return random_state; }
static void check_hex(const uint8_t *bytes, size_t length, const char *hex)
{
    CHECK(strlen(hex) == 2 * length);
    static const char digits[] = "0123456789abcdef";
    for (size_t index = 0; index < length; ++index) {
        CHECK(digits[bytes[index] >> 4] == hex[2 * index]);
        CHECK(digits[bytes[index] & 15] == hex[2 * index + 1]);
    }
}
static volatile size_t sink;
static double measure(lua_CFunction function, const struct argument *arguments, unsigned count)
{
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency);
    lua_settop(vm, 0);
    QueryPerformanceCounter(&start);
    for (unsigned round = 0; round < 4096; ++round) {
        push(function, arguments, count);
        lua_call(vm, count, 1);
        sink ^= lua_objlen(vm, -1);
        lua_pop(vm, 1);
    }
    QueryPerformanceCounter(&end);
    return (double)(end.QuadPart - start.QuadPart) * 1e9 / frequency.QuadPart / 4096;
}
static void benchmark(const char *name, bool derive, const struct argument *arguments, unsigned count)
{
    double c[9], r[9];
    for (unsigned round = 0; round < 9; ++round) {
        if (round % 2) {
            r[round] = measure(derive ? luacall_hkdf : luacall_hash, arguments, count);
            c[round] = measure(derive ? reference_luacall_hkdf : reference_luacall_hash, arguments, count);
        } else {
            c[round] = measure(derive ? reference_luacall_hkdf : reference_luacall_hash, arguments, count);
            r[round] = measure(derive ? luacall_hkdf : luacall_hash, arguments, count);
        }
    }
    for (unsigned i = 0; i < 9; ++i) for (unsigned j = i + 1; j < 9; ++j) {
        if (c[i] > c[j]) { double swap = c[i]; c[i] = c[j]; c[j] = swap; }
        if (r[i] > r[j]) { double swap = r[i]; r[i] = r[j]; r[j] = swap; }
    }
    printf("BENCH lua_hash %s c_ns=%.2f rust_ns=%.2f rounds=9 calls_per_round=4096\n", name, c[4], r[4]);
}
int main(void)
{
    vm = luaL_newstate();
    CHECK(vm);
    uint8_t data[16384], salt[96], info[96], output[8320];
    for (unsigned index = 0; index < sizeof(data); ++index) data[index] = (uint8_t)next();
    for (unsigned index = 0; index < sizeof(salt); ++index) salt[index] = (uint8_t)next();
    for (unsigned index = 0; index < sizeof(info); ++index) info[index] = (uint8_t)next();
    for (unsigned bits = 224; bits <= 256; bits += 32) {
        const char *name = bits == 224 ? "sha224" : "sha256";
        for (unsigned round = 0; round < 8192; ++round) {
            struct argument arguments[] = {string(name, 6), string(data + round % 8, round % 1025)};
            compare(false, arguments, 2);
        }
        for (unsigned round = 0; round < 2048; ++round) {
            struct argument arguments[] = {string(name, 6), string(salt, round % 81), string(data, round % 257), string(info, round % 65), number(round % 97)};
            for (unsigned index = 1; index <= 3; ++index) if (!(round % (7 + index))) arguments[index].kind = LUA_TNIL;
            compare(true, arguments, 5);
        }
        const unsigned lengths[] = {0, 1, 27, 28, 29, 31, 32, 33, 55, 56, 63, 64, 65, 127, 128, 255, 256, 257, 7140, 7141, 8160, 8161};
        for (unsigned index = 0; index < sizeof(lengths) / sizeof(*lengths); ++index) {
            struct argument hash[] = {string(name, 6), string(data, lengths[index])};
            struct argument derive[] = {string(name, 6), string(salt, 96), string(data, 1024), string(info, 96), number(lengths[index])};
            compare(false, hash, 2);
            compare(true, derive, 5);
        }
        for (size_t capacity = 0; capacity <= 40; ++capacity) {
            uint8_t expected[sizeof(output)];
            memset(output, 0x69, sizeof(output));
            memcpy(expected, output, sizeof(output));
            size_t length = zapret_lua_hash(bits, data, 129, output + 8, capacity);
            CHECK(length == (capacity >= bits / 8 ? bits / 8 : 0));
            if (length) memcpy(expected + 8, output + 8, length);
            CHECK(!memcmp(expected, output, sizeof(output)));
            ++boundaries;
        }
        memset(output, 0x69, sizeof(output));
        CHECK(!zapret_lua_hkdf(bits, NULL, 0, NULL, 0, NULL, 0, output, 255 * (bits / 8) + 1));
        for (unsigned index = 0; index < sizeof(output); ++index) CHECK(output[index] == 0x69);
        ++boundaries;
        uint8_t in_place[129], digest[32];
        memcpy(in_place, data, sizeof(in_place));
        CHECK(zapret_lua_hash(bits, data, sizeof(in_place), digest, sizeof(digest)) == bits / 8);
        CHECK(zapret_lua_hash(bits, in_place, sizeof(in_place), in_place, sizeof(in_place)) == bits / 8);
        CHECK(!memcmp(digest, in_place, bits / 8));
        ++boundaries;
    }
    for (unsigned count = 0; count <= 6; ++count) {
        struct argument arguments[] = {string("sha256", 6), string(data, 20), string(data, 20), string(info, 10), number(42), number(9)};
        compare(false, arguments, count);
        compare(true, arguments, count);
    }
    for (unsigned index = 0; index < 5; ++index) for (int kind = LUA_TNIL; kind <= LUA_TSTRING; ++kind) {
        struct argument arguments[] = {string("sha256", 6), string(data, 20), string(data, 20), string(info, 10), number(42)};
        arguments[index].kind = kind;
        arguments[index].bytes = "unknown";
        arguments[index].length = 7;
        arguments[index].number = index == 4 ? -1 : 123;
        compare(true, arguments, 5);
        if (index < 2) compare(false, arguments, 2);
    }
    static const char *const vectors[] = {
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    };
    for (unsigned index = 0; index < 4; ++index) {
        size_t length = zapret_lua_hash(index < 2 ? 224 : 256, (const uint8_t *)"abc", index % 2 ? 3 : 0, output, sizeof(output));
        CHECK(length);
        check_hex(output, length, vectors[index]);
    }
    memset(data, 0x0b, 22);
    for (unsigned index = 0; index < 13; ++index) salt[index] = index;
    for (unsigned index = 0; index < 10; ++index) info[index] = 0xf0 + index;
    CHECK(zapret_lua_hkdf(256, salt, 13, data, 22, info, 10, output, 42));
    check_hex(output, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    CHECK(zapret_lua_hkdf(256, NULL, 0, data, 22, NULL, 0, output, 42));
    check_hex(output, 42, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
    /* A length outside HKDF's limit is rejected before allocating Lua userdata. */
    struct argument excessive[] = {string("sha256", 6), {0}, {0}, {0}, number(2147483647)};
    struct result rejected = invoke(luacall_hkdf, excessive, 5);
    CHECK(!rejected.status && rejected.kind == LUA_TNIL);
    ++boundaries;
    CHECK(!zapret_lua_hash(123, NULL, SIZE_MAX, NULL, 0));
    CHECK(!zapret_lua_hkdf(123, NULL, 0, NULL, 0, NULL, 0, NULL, 0));
    printf("PASS lua_hash cases=%u standard_vectors=6 buffer_boundaries=%u algorithms=2\n", cases, boundaries);
    struct argument small[] = {string("sha256", 6), string(data, 64)};
    struct argument large[] = {string("sha256", 6), string(data, sizeof(data))};
    struct argument derive[] = {string("sha256", 6), string(salt, 13), string(data, 22), string(info, 10), number(64)};
    benchmark("sha256_64", false, small, 2);
    benchmark("sha256_16384", false, large, 2);
    benchmark("hkdf256_64", true, derive, 5);
    lua_close(vm);
    return 0;
}
