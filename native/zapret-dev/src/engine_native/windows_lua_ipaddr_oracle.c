/* MIT. Compare address publication in a private pinned LuaJIT VM. */
#include "windows_lua_ipaddr_abi.h"
#include <lauxlib.h>
#include <stdlib.h>
#include <string.h>
#undef main

#define lua_push_ipaddr reference_value
#define lua_pushf_ipaddr reference_field
#define lua_pushi_ipaddr reference_index
#include "lua_packet_address_windows.inc"
#undef lua_pushi_ipaddr
#undef lua_pushf_ipaddr
#undef lua_push_ipaddr

enum entry { VALUE, FIELD, INDEX };
enum event { NONE, STRING_KEY, INTEGER_KEY, ADDRESS_VIEW, BYTES, NIL_VALUE, RAW_STORE };

struct test_case {
    enum entry entry;
    uint8_t *source;
    const char *field;
    lua_Integer index;
    bool populate, reject_view, change_family, change_bytes, reenter;
    enum event fail_at;
};

struct sample {
    unsigned trace_count, rejected;
    uint8_t trace[12], value[16];
    int status, arity, type;
    size_t length;
    char error[128];
};

struct allocator { bool armed; unsigned live, rejected; };
struct invocation {
    const struct test_case *test;
    struct sample *sample;
    struct allocator *memory;
    bool rust, nested;
};

static struct invocation *active;
static unsigned cases, guarded, reentry_pairs, faults, view_errors;

#define CHECK(value) do { if (!(value)) { \
    fprintf(stderr, "FAIL Lua address publication case=%u line=%d: %s\n", cases, __LINE__, #value); \
    exit(1); \
} } while (0)

static void observe(enum event stage)
{
    if (!active) return;
    struct sample *out = active->sample;
    CHECK(out->trace_count < sizeof(out->trace));
    out->trace[out->trace_count++] = (uint8_t)stage + (active->nested ? 16 : 0);
    if (!active->nested && active->test->fail_at == stage) {
        CHECK(active->memory);
        active->memory->armed = true;
    }
}

bool __real_zapret_lua_packet_address(const void *, zapret_lua_packet_address_view *);
void __real_lua_pushstring(lua_State *, const char *);
void __real_lua_pushinteger(lua_State *, lua_Integer);
void __real_lua_pushlstring(lua_State *, const char *, size_t);
void __real_lua_pushnil(lua_State *);
void __real_lua_rawset(lua_State *, int);

bool __wrap_zapret_lua_packet_address(const void *source, zapret_lua_packet_address_view *view)
{
    observe(ADDRESS_VIEW);
    if (active && !active->nested) {
        CHECK(source == active->test->source);
        if (active->test->reject_view) return false;
    }
    return __real_zapret_lua_packet_address(source, view);
}

static void change_family(void)
{
    if (active && !active->nested && active->test->change_family) {
        uint16_t family = AF_INET;
        memcpy(active->test->source, &family, sizeof(family));
    }
}

void __wrap_lua_pushstring(lua_State *lua, const char *value)
{
    observe(STRING_KEY);
    change_family();
    __real_lua_pushstring(lua, value);
}

void __wrap_lua_pushinteger(lua_State *lua, lua_Integer value)
{
    observe(INTEGER_KEY);
    change_family();
    __real_lua_pushinteger(lua, value);
}

void __wrap_lua_pushlstring(lua_State *lua, const char *value, size_t length)
{
    observe(BYTES);
    if (active && !active->nested) {
        uint8_t *source = active->test->source;
        uint16_t family;
        memcpy(&family, source, sizeof(family));
        CHECK(family == AF_INET || family == AF_INET6);
        size_t offset = family == AF_INET ? 4 : 8;
        CHECK(value == (const char *)source + offset && length == (family == AF_INET ? 4 : 16));
        if (active->test->change_bytes) source[offset] ^= 0xff;
        if (active->test->reenter) {
            int top = lua_gettop(lua);
            active->nested = true;
            (active->rust ? lua_push_ipaddr : reference_value)(lua, NULL);
            active->nested = false;
            CHECK(lua_gettop(lua) == top + 1 && lua_isnil(lua, -1));
            lua_pop(lua, 1);
        }
    }
    __real_lua_pushlstring(lua, value, length);
}

void __wrap_lua_pushnil(lua_State *lua)
{
    observe(NIL_VALUE);
    __real_lua_pushnil(lua);
}

void __wrap_lua_rawset(lua_State *lua, int index)
{
    observe(RAW_STORE);
    if (active) CHECK(index == -3);
    __real_lua_rawset(lua, index);
}

static void *allocate(void *context, void *pointer, size_t previous, size_t next)
{
    struct allocator *memory = context;
    if (!next) {
        if (pointer) { CHECK(memory->live); --memory->live; }
        free(pointer);
        return NULL;
    }
    if (memory->armed && next > previous) { ++memory->rejected; return NULL; }
    bool fresh = pointer == NULL;
    void *result = realloc(pointer, next);
    if (result && fresh) ++memory->live;
    return result;
}

static void push_key(lua_State *lua, const struct test_case *test)
{
    if (test->entry == FIELD) lua_pushstring(lua, test->field);
    else lua_pushinteger(lua, test->index);
}

static int publish(lua_State *lua)
{
    const struct test_case *test = active->test;
    const struct sockaddr *source = (const void *)test->source;
    if (test->entry == VALUE) (active->rust ? lua_push_ipaddr : reference_value)(lua, source);
    else if (test->entry == FIELD)
        (active->rust ? lua_pushf_ipaddr : reference_field)(lua, test->field, source);
    else (active->rust ? lua_pushi_ipaddr : reference_index)(lua, test->index, source);
    return 1;
}

static void run(lua_State *lua, const struct test_case *test, bool rust, struct sample *out)
{
    struct allocator memory = {0};
    if (test->fail_at) { lua = lua_newstate(allocate, &memory); CHECK(lua); }
    struct invocation invocation = {.test = test, .sample = out, .memory = &memory, .rust = rust};
    memset(out, 0, sizeof(*out));
    lua_settop(lua, 0);
    if (test->entry != VALUE) {
        lua_newtable(lua);
        if (test->populate) {
            push_key(lua, test);
            lua_pushliteral(lua, "previous");
            lua_rawset(lua, 1);
        }
    }
    lua_pushcfunction(lua, publish);
    if (test->entry != VALUE) lua_pushvalue(lua, 1);
    active = &invocation;
    out->status = lua_pcall(lua, test->entry != VALUE, LUA_MULTRET, 0);
    active = NULL;
    memory.armed = false;
    out->rejected = memory.rejected;
    out->arity = lua_gettop(lua);
    if (out->status) {
        const char *error = lua_tostring(lua, -1);
        CHECK(error && strlen(error) < sizeof(out->error));
        strcpy(out->error, error);
    }
    if (test->entry != VALUE && (test->entry == INDEX || test->field)) {
        push_key(lua, test);
        lua_rawget(lua, 1);
        out->type = lua_type(lua, -1);
    } else out->type = out->status ? LUA_TNONE : lua_type(lua, -1);
    if (out->type == LUA_TSTRING) {
        const char *value = lua_tolstring(lua, -1, &out->length);
        CHECK(out->length <= sizeof(out->value));
        memcpy(out->value, value, out->length);
    }
    if (test->fail_at) { lua_close(lua); CHECK(!memory.live); }
}

static void compare(lua_State *lua, const struct test_case *test)
{
    struct sample old, rust;
    uint8_t original[24];
    bool changes = test->change_family || test->change_bytes;
    if (changes) memcpy(original, test->source, sizeof(original));
    run(lua, test, false, &old);
    if (changes) memcpy(test->source, original, sizeof(original));
    run(lua, test, true, &rust);
    CHECK(!memcmp(&old, &rust, sizeof(old)));
    CHECK(rust.arity == (test->entry == VALUE ? 1 : 2));
    if (test->fail_at) {
        CHECK(rust.status == LUA_ERRMEM && rust.rejected && rust.type == LUA_TNIL);
        ++faults;
    } else if (test->reject_view) {
        CHECK(rust.status == LUA_ERRRUN && !strcmp(rust.error, "invalid packet address view"));
        if (test->entry != VALUE && test->populate)
            CHECK(rust.length == 8 && !memcmp(rust.value, "previous", 8));
        CHECK(rust.trace[rust.trace_count - 1] == ADDRESS_VIEW);
        ++view_errors;
    } else if (test->entry == FIELD && !test->field) {
        CHECK(rust.status == LUA_ERRRUN && strstr(rust.error, "table index is nil"));
        CHECK(rust.trace[0] == STRING_KEY && rust.trace[rust.trace_count - 1] == RAW_STORE);
    } else {
        CHECK(!rust.status);
        uint16_t family = 0;
        if (test->source) memcpy(&family, test->source, sizeof(family));
        size_t length = family == AF_INET ? 4 : family == AF_INET6 ? 16 : 0;
        CHECK(rust.length == length && rust.type == (length ? LUA_TSTRING : LUA_TNIL));
        if (length) CHECK(!memcmp(rust.value, test->source + (family == AF_INET ? 4 : 8), length));
    }
    if (test->reenter) {
        unsigned count = 0;
        for (unsigned i = 0; i < rust.trace_count; ++i) if (rust.trace[i] > 16) ++count;
        CHECK(count == 2);
        ++reentry_pairs;
    }
    lua_settop(lua, 0);
    ++cases;
}

int main(void)
{
    lua_State *lua = luaL_newstate();
    CHECK(lua);
    SYSTEM_INFO system;
    GetSystemInfo(&system);
    size_t page = system.dwPageSize;
    uint8_t *memory = VirtualAlloc(NULL, page * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    DWORD previous;
    CHECK(memory && VirtualProtect(memory + page, page, PAGE_NOACCESS, &previous));
    for (unsigned family = 0; family <= UINT16_MAX; ++family) {
        size_t bytes = family == AF_INET ? 8 : family == AF_INET6 ? 24 : 2;
        uint8_t *source = memory + page - bytes;
        for (size_t i = 0; i < bytes; ++i) source[i] = (uint8_t)(i * 31);
        if (bytes > 2) source[bytes - 2] = 0;
        uint16_t tag = (uint16_t)family;
        memcpy(source, &tag, sizeof(tag));
        for (unsigned entry = VALUE; entry <= INDEX; ++entry) {
            struct test_case test = {.entry = entry, .source = source,
                .field = "fixture", .index = -INT64_C(4294967311), .populate = true};
            compare(lua, &test);
            ++guarded;
        }
    }
    CHECK(VirtualFree(memory, 0, MEM_RELEASE));

    uint8_t bytes[25] = {0};
    uint8_t *source = bytes + 1;
    memset(source, 0xa5, 24);
    uint16_t family = AF_INET6;
    for (unsigned entry = VALUE; entry <= INDEX; ++entry) {
        memcpy(source, &family, sizeof(family));
        struct test_case test = {.entry = entry, .field = "fixture", .index = INT64_C(4294967311),
            .populate = true};
        compare(lua, &test);
        test.source = source;
        test.reject_view = true;
        compare(lua, &test);
        test.reject_view = false;
        test.change_family = entry != VALUE;
        test.change_bytes = test.reenter = true;
        compare(lua, &test);
    }
    struct test_case missing_key = {.entry = FIELD, .source = source};
    compare(lua, &missing_key);

    char field[1024];
    memset(field, 'k', sizeof(field) - 1);
    field[sizeof(field) - 1] = 0;
    memcpy(source, &family, sizeof(family));
    for (unsigned i = 0; i < 4; ++i) {
        const enum event checkpoints[] = {STRING_KEY, BYTES, RAW_STORE, RAW_STORE};
        struct test_case test = {.entry = i == 3 ? INDEX : FIELD, .source = source,
            .field = field, .index = INT64_C(4294967311), .fail_at = checkpoints[i]};
        compare(lua, &test);
    }
    lua_close(lua);
    printf("PASS windows_lua_ipaddr cases=%u guarded=%u reentry_pairs=%u faults=%u view_errors=%u "
        "exact_vm_trace=1 key_before_view=1 borrowed_bytes=1 vm_allocations_released=1\n",
        cases, guarded, reentry_pairs, faults, view_errors);
    return 0;
}
