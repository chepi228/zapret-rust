/* MIT. Compare real protected Lua calls and independent AES vectors. */
#include "engine_lua.h"
#include "crypto/aes.h"
#include "crypto/aes-ctr.h"
#undef main

static unsigned cases;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL Lua AES case=%u line=%d: %s\n", cases, __LINE__, #condition); exit(1); } \
} while (0)
static void lua_check_argc(lua_State *vm, const char *name, int count)
{
    if (lua_gettop(vm) != count) luaL_error(vm, "%s expect exactly %d arguments, got %d", name, count, lua_gettop(vm));
}
const char *lua_reqlstring(lua_State *vm, int index, size_t *length)
{
    luaL_checktype(vm, index, LUA_TSTRING);
    return lua_tolstring(vm, index, length);
}
#include "lua_aes_comparison.inc"

struct argument { const uint8_t *data; size_t length; int boolean; };
struct snapshot { int status, kind; size_t size; uint8_t bytes[2048]; };
static lua_State *vm;
static struct argument binary(const uint8_t *data, size_t size) { return (struct argument){.data = data, .length = size}; }
static void push(lua_CFunction fn, const struct argument *args, unsigned count)
{
    lua_pushcfunction(vm, fn);
    for (unsigned index = 0; index < count; ++index) {
        if (args[index].data) lua_pushlstring(vm, (const char *)args[index].data, args[index].length);
        else lua_pushboolean(vm, args[index].boolean);
    }
}
static struct snapshot invoke(lua_CFunction fn, const struct argument *args, unsigned count)
{
    lua_settop(vm, 0);
    push(fn, args, count);
    struct snapshot value = {0};
    value.status = lua_pcall(vm, count, 1, 0);
    CHECK(lua_gettop(vm) == 1);
    value.kind = lua_type(vm, -1);
    if (value.kind == LUA_TSTRING) {
        const char *text = lua_tolstring(vm, -1, &value.size);
        CHECK(value.size < sizeof(value.bytes));
        memcpy(value.bytes, text, value.size);
    }
    return value;
}
static void compare(lua_CFunction legacy, lua_CFunction rust, const struct argument *args, unsigned count)
{
    struct snapshot left = invoke(legacy, args, count), right = invoke(rust, args, count);
    CHECK(left.status == right.status && left.kind == right.kind && left.size == right.size && !memcmp(left.bytes, right.bytes, left.size));
    ++cases;
}
static uint64_t state = 0x6c75616165736374ULL;
static uint64_t next(void) { state ^= state << 13; state ^= state >> 7; state ^= state << 17; return state; }
static void fill(uint8_t *bytes, size_t size) { for (size_t i = 0; i < size; ++i) bytes[i] = (uint8_t)next(); }
static volatile uint64_t sink;
static double measure(lua_CFunction fn, const struct argument *args, unsigned count)
{
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency);
    lua_settop(vm, 0);
    QueryPerformanceCounter(&start);
    for (unsigned call = 0; call < 16384; ++call) {
        push(fn, args, count);
        lua_call(vm, count, 1);
        sink ^= lua_objlen(vm, -1);
        lua_pop(vm, 1);
    }
    QueryPerformanceCounter(&end);
    return (double)(end.QuadPart - start.QuadPart) * 1e9 / frequency.QuadPart / 16384;
}
static void benchmark(const char *name, lua_CFunction legacy, lua_CFunction rust, const struct argument *args, unsigned count)
{
    double c[9], r[9];
    for (unsigned round = 0; round < 9; ++round) {
        if (round % 2) { r[round] = measure(rust, args, count); c[round] = measure(legacy, args, count); }
        else { c[round] = measure(legacy, args, count); r[round] = measure(rust, args, count); }
    }
    for (unsigned i = 0; i < 9; ++i) for (unsigned j = i + 1; j < 9; ++j) {
        if (c[i] > c[j]) { double swap = c[i]; c[i] = c[j]; c[j] = swap; }
        if (r[i] > r[j]) { double swap = r[i]; r[i] = r[j]; r[j] = swap; }
    }
    printf("BENCH lua_aes %s c_ns=%.2f rust_ns=%.2f rounds=9 calls_per_round=16384\n", name, c[4], r[4]);
}

int main(void)
{
    vm = luaL_newstate();
    CHECK(vm);
    aes_init_keygen_tables();
    uint8_t key[40], input[1024], iv[16];
    const unsigned lengths[] = {0, 1, 15, 16, 17, 63, 127, 128, 129, 255, 256, 511, 1024};
    for (unsigned key_size = 16; key_size <= 32; key_size += 8) {
        for (unsigned round = 0; round < 512; ++round) {
            fill(key, sizeof(key)); fill(input, sizeof(input)); fill(iv, sizeof(iv));
            if (!(round % 8)) memset(iv, 0xff, sizeof(iv));
            struct argument block[] = {{.boolean = false}, binary(key, key_size), binary(input, 16)};
            compare(reference_luacall_aes, luacall_aes, block, 3);
            block[0].boolean = true;
            compare(reference_luacall_aes, luacall_aes, block, 3);
            struct argument ctr[] = {binary(key, key_size), binary(iv, 16), binary(input, lengths[round % 13])};
            compare(reference_luacall_aes_ctr, luacall_aes_ctr, ctr, 3);
            uint8_t in_place[1024], legacy[1024];
            memcpy(in_place, input, sizeof(input));
            CHECK(!aes_ctr_crypt(key, key_size, iv, input, lengths[round % 13], legacy));
            CHECK(zapret_lua_aes_ctr(key, key_size, iv, in_place, lengths[round % 13], in_place));
            CHECK(!memcmp(in_place, legacy, lengths[round % 13]));
            ++cases;
        }
    }
    for (unsigned length = 0; length < 35; ++length) {
        struct argument block[] = {{.boolean = true}, binary(key, length), binary(input, 16)};
        compare(reference_luacall_aes, luacall_aes, block, 3);
        struct argument ctr[] = {binary(key, length), binary(iv, 16), binary(input, 19)};
        compare(reference_luacall_aes_ctr, luacall_aes_ctr, ctr, 3);
    }
    for (unsigned length = 0; length < 25; ++length) {
        struct argument block[] = {{.boolean = true}, binary(key, 16), binary(input, length)};
        compare(reference_luacall_aes, luacall_aes, block, 3);
        struct argument ctr[] = {binary(key, 16), binary(iv, length % 17), binary(input, 32)};
        compare(reference_luacall_aes_ctr, luacall_aes_ctr, ctr, 3);
    }
    static const uint8_t plain[] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    static const uint8_t ciphertext[3][16] = {
        {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a},
        {0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91},
        {0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89}
    };
    for (unsigned i = 0; i < sizeof(key); ++i) key[i] = i;
    for (unsigned i = 0; i < 3; ++i) {
        uint8_t actual[16];
        CHECK(zapret_lua_aes_block(true, key, 16 + i * 8, plain, actual));
        CHECK(!memcmp(actual, ciphertext[i], 16));
        CHECK(zapret_lua_aes_block(false, key, 16 + i * 8, actual, actual));
        CHECK(!memcmp(actual, plain, 16));
    }
    static const uint8_t ctr_key[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    static const uint8_t ctr_plain[] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
    static const uint8_t ctr_cipher[] = {0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce};
    for (unsigned i = 0; i < 16; ++i) iv[i] = 0xf0 + i;
    CHECK(zapret_lua_aes_ctr(ctr_key, 16, iv, ctr_plain, 16, input) && !memcmp(input, ctr_cipher, 16));
    printf("PASS lua_aes cases=%u standard_vectors=4 key_sizes=3\n", cases);
    struct argument block[] = {{.boolean = true}, binary(key, 16), binary(input, 16)};
    struct argument ctr[] = {binary(key, 16), binary(iv, 16), binary(input, 1024)};
    benchmark("block128", reference_luacall_aes, luacall_aes, block, 3);
    benchmark("ctr1024", reference_luacall_aes_ctr, luacall_aes_ctr, ctr, 3);
    lua_close(vm);
    return 0;
}
