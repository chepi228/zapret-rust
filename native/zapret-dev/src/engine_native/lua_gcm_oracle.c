/* MIT. Pinned C parity, NIST vectors, buffer guards and real LuaJIT calls. */
#include "engine_lua.h"
#include "crypto/aes.h"
#include "crypto/aes-gcm.h"
#undef main

static unsigned cases;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL Lua GCM case=%u line=%d: %s\n", cases, __LINE__, #condition); exit(1); } \
} while (0)
static void lua_check_argc_range(lua_State *vm, const char *name, int minimum, int maximum)
{
    int count = lua_gettop(vm);
    if (count < minimum || count > maximum) luaL_error(vm, "%s expect from %d to %d arguments, got %d", name, minimum, maximum, count);
}
const char *lua_reqlstring(lua_State *vm, int index, size_t *length)
{
    luaL_checktype(vm, index, LUA_TSTRING);
    return lua_tolstring(vm, index, length);
}
#include "lua_gcm_comparison.inc"

struct argument { int kind; const char *bytes; size_t length; bool boolean; };
static struct argument binary(const void *bytes, size_t length) { return (struct argument){.kind = LUA_TSTRING, .bytes = bytes, .length = length}; }
static lua_State *vm;
struct result { int status, count, kinds[2]; size_t lengths[2]; char bytes[2][1280]; };
static void push(lua_CFunction function, const struct argument *arguments, unsigned count)
{
    lua_pushcfunction(vm, function);
    for (unsigned index = 0; index < count; ++index) {
        const struct argument *argument = &arguments[index];
        switch (argument->kind) {
            case LUA_TBOOLEAN: lua_pushboolean(vm, argument->boolean); break;
            case LUA_TSTRING: lua_pushlstring(vm, argument->bytes, argument->length); break;
            case LUA_TNUMBER: lua_pushinteger(vm, 123); break;
            default: lua_pushnil(vm); break;
        }
    }
}
static struct result invoke(lua_CFunction function, const struct argument *arguments, unsigned count)
{
    lua_settop(vm, 0);
    push(function, arguments, count);
    struct result result = {0};
    result.status = lua_pcall(vm, count, 2, 0);
    result.count = lua_gettop(vm);
    CHECK(result.count == (result.status ? 1 : 2));
    for (int index = 0; index < result.count; ++index) {
        result.kinds[index] = lua_type(vm, index + 1);
        if (result.kinds[index] == LUA_TSTRING) {
            const char *bytes = lua_tolstring(vm, index + 1, &result.lengths[index]);
            CHECK(result.lengths[index] < sizeof(result.bytes[index]));
            memcpy(result.bytes[index], bytes, result.lengths[index]);
        }
    }
    return result;
}
static void compare(const struct argument *arguments, unsigned count)
{
    struct result left = invoke(reference_luacall_aes_gcm, arguments, count);
    struct result right = invoke(luacall_aes_gcm, arguments, count);
    CHECK(left.status == right.status && left.count == right.count);
    for (int index = 0; index < left.count; ++index)
        CHECK(left.kinds[index] == right.kinds[index] && left.lengths[index] == right.lengths[index] && !memcmp(left.bytes[index], right.bytes[index], left.lengths[index]));
    ++cases;
}
static uint64_t random_state = 0x6c75615f67636d5fULL;
static uint64_t next(void) { random_state ^= random_state << 13; random_state ^= random_state >> 7; random_state ^= random_state << 17; return random_state; }
static void fill(uint8_t *bytes, size_t length) { for (size_t index = 0; index < length; ++index) bytes[index] = (uint8_t)next(); }
static size_t decode(const char *hex, uint8_t *output)
{
    size_t length = strlen(hex) / 2;
    CHECK(length * 2 == strlen(hex));
    for (size_t index = 0; index < length; ++index) {
        unsigned byte;
        CHECK(sscanf(hex + index * 2, "%2x", &byte) == 1);
        output[index] = (uint8_t)byte;
    }
    return length;
}
static void vector(const char *key_hex, const char *iv_hex, const char *aad_hex, const char *plain_hex, const char *cipher_hex, const char *tag_hex)
{
    uint8_t key[32], iv[64], aad[64], plain[128], expected[128], output[128], tag[16], expected_tag[16];
    size_t key_length = decode(key_hex, key), iv_length = decode(iv_hex, iv), aad_length = decode(aad_hex, aad), length = decode(plain_hex, plain);
    CHECK(decode(cipher_hex, expected) == length && decode(tag_hex, expected_tag) == 16);
    CHECK(zapret_lua_aes_gcm(true, key, key_length, iv, iv_length, plain, length, aad, aad_length, output, tag));
    if (memcmp(output, expected, length) || memcmp(tag, expected_tag, 16)) {
        fprintf(stderr, "GCM vector mismatch: key=%zu iv=%zu data=%zu tag=", key_length, iv_length, length);
        for (unsigned index = 0; index < 16; ++index) fprintf(stderr, "%02x", tag[index]);
        fprintf(stderr, "\n");
        CHECK(false);
    }
    CHECK(zapret_lua_aes_gcm(false, key, key_length, iv, iv_length, output, length, aad, aad_length, output, tag));
    CHECK(!memcmp(output, plain, length) && !memcmp(tag, expected_tag, 16));
}
static volatile size_t sink;
static double measure(lua_CFunction function, const struct argument *arguments)
{
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency);
    lua_settop(vm, 0);
    QueryPerformanceCounter(&start);
    for (unsigned round = 0; round < 4096; ++round) {
        push(function, arguments, 5);
        lua_call(vm, 5, 2);
        sink ^= lua_objlen(vm, -1);
        lua_pop(vm, 2);
    }
    QueryPerformanceCounter(&end);
    return (double)(end.QuadPart - start.QuadPart) * 1e9 / frequency.QuadPart / 4096;
}
static void benchmark(const char *name, const struct argument *arguments)
{
    double c[9], r[9];
    for (unsigned round = 0; round < 9; ++round) {
        if (round % 2) { r[round] = measure(luacall_aes_gcm, arguments); c[round] = measure(reference_luacall_aes_gcm, arguments); }
        else { c[round] = measure(reference_luacall_aes_gcm, arguments); r[round] = measure(luacall_aes_gcm, arguments); }
    }
    for (unsigned i = 0; i < 9; ++i) for (unsigned j = i + 1; j < 9; ++j) {
        if (c[i] > c[j]) { double swap = c[i]; c[i] = c[j]; c[j] = swap; }
        if (r[i] > r[j]) { double swap = r[i]; r[i] = r[j]; r[j] = swap; }
    }
    printf("BENCH lua_gcm %s c_ns=%.2f rust_ns=%.2f rounds=9 calls_per_round=4096\n", name, c[4], r[4]);
}
int main(void)
{
    vm = luaL_newstate();
    CHECK(vm);
    aes_init_keygen_tables();
    uint8_t key[40], iv[128], input[1040], aad[96];
    const unsigned iv_lengths[] = {1,2,7,8,11,12,13,15,16,17,31,32,60,128};
    const unsigned lengths[] = {0,1,15,16,17,63,127,128,129,255,256,511,1024};
    for (unsigned key_length = 16; key_length <= 32; key_length += 8) for (unsigned round = 0; round < 512; ++round) {
        fill(key, sizeof(key)); fill(iv, sizeof(iv)); fill(input, sizeof(input)); fill(aad, sizeof(aad));
        unsigned length = lengths[round % 13], iv_length = iv_lengths[round % 14], aad_length = round % sizeof(aad);
        struct argument arguments[] = {{.kind = LUA_TBOOLEAN}, binary(key, key_length), binary(iv, iv_length), binary(input + round % 8, length), binary(aad, aad_length)};
        compare(arguments, 5);
        arguments[0].boolean = true;
        compare(arguments, round % 3 ? 5 : 4);
        uint8_t actual[1040], expected[1040], actual_tag[24], expected_tag[24];
        memset(actual, 0x69, sizeof(actual));
        memcpy(actual + 8, input, length);
        memcpy(expected, actual, sizeof(actual));
        memset(actual_tag, 0x69, sizeof(actual_tag));
        memcpy(expected_tag, actual_tag, sizeof(actual_tag));
        bool encrypt = round % 2;
        CHECK(!aes_gcm_crypt(encrypt, expected + 8, input, length, key, key_length, iv, iv_length, aad, aad_length, expected_tag + 3, 16));
        CHECK(zapret_lua_aes_gcm(encrypt, key, key_length, iv, iv_length, actual + 8, length, aad, aad_length, actual + 8, actual_tag + 3));
        CHECK(!memcmp(expected, actual, sizeof(actual)) && !memcmp(expected_tag, actual_tag, sizeof(actual_tag)));
        ++cases;
    }
    for (unsigned length = 0; length <= 35; ++length) {
        struct argument arguments[] = {{.kind = LUA_TBOOLEAN, .boolean = true}, binary(key, length), binary(iv, 12), binary(input, 32), binary(aad, 20)};
        compare(arguments, 5);
    }
    for (unsigned length = 0; length <= 17; ++length) {
        struct argument arguments[] = {{.kind = LUA_TBOOLEAN}, binary(key, 16), binary(iv, length), binary(input, 32), binary(aad, 20)};
        compare(arguments, 5);
    }
    for (unsigned count = 0; count <= 6; ++count) {
        struct argument arguments[] = {{.kind = LUA_TBOOLEAN}, binary(key, 16), binary(iv, 12), binary(input, 32), binary(aad, 20), binary(aad, 20)};
        compare(arguments, count);
    }
    for (unsigned index = 0; index < 5; ++index) for (int kind = LUA_TNIL; kind <= LUA_TNUMBER; ++kind) {
        struct argument arguments[] = {{.kind = LUA_TBOOLEAN}, binary(key, 16), binary(iv, 12), binary(input, 32), binary(aad, 20)};
        arguments[index].kind = kind;
        compare(arguments, 5);
    }
    vector("00000000000000000000000000000000", "000000000000000000000000", "", "", "", "58e2fccefa7e3061367f1d57a4e7455a");
    vector("00000000000000000000000000000000", "000000000000000000000000", "", "00000000000000000000000000000000", "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf");
    const char *plain = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
    vector("feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "feedfacedeadbeeffeedfacedeadbeefabaddad2", plain,
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", "5bc94fbc3221a5db94fae95ae7121a47");
    vector("feffe9928665731c6d6a8f9467308308", "cafebabefacedbad", "feedfacedeadbeeffeedfacedeadbeefabaddad2", plain,
        "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598", "3612d2e79e3b0785561be14aaca2fccb");
    uint8_t output[64], tag[24];
    for (unsigned fault = 0; fault < 11; ++fault) {
        memset(output, 0x69, sizeof(output)); memset(tag, 0x69, sizeof(tag));
        CHECK(!zapret_lua_aes_gcm(true, fault == 8 ? NULL : key, fault == 0 ? 15 : 16,
            fault == 9 ? NULL : iv, fault == 1 ? 0 : fault == 4 ? UINT64_MAX / 8 + 1 : 12,
            fault == 5 ? NULL : input, fault == 2 ? (1ULL << 36) - 31 : 16,
            fault == 10 ? NULL : aad, fault == 3 ? UINT64_MAX / 8 + 1 : 20,
            fault == 7 ? NULL : output, fault == 6 ? NULL : tag));
        for (unsigned index = 0; index < sizeof(output); ++index) CHECK(output[index] == 0x69);
        for (unsigned index = 0; index < sizeof(tag); ++index) CHECK(tag[index] == 0x69);
    }
    printf("PASS lua_gcm cases=%u standard_vectors=4 in_place=1536 rejected_inputs=11 key_sizes=3\n", cases);
    struct argument arguments[] = {{.kind = LUA_TBOOLEAN, .boolean = true}, binary(key, 16), binary(iv, 12), binary(input, 1024), binary(aad, 20)};
    benchmark("encrypt1024_iv12", arguments);
    arguments[0].boolean = false;
    benchmark("decrypt1024_iv12", arguments);
    arguments[0].boolean = true; arguments[2].length = 8;
    benchmark("encrypt1024_iv8", arguments);
    lua_close(vm);
    return 0;
}
