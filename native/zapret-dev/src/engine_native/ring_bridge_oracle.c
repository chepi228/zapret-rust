/* Compare independent full entries using LuaJIT and a controlled v1 backend. */
#include <stdbool.h>
#include <stdlib.h>
#include "ring_bridge_types.inc"

static unsigned operation, variant, comparisons;
static uint64_t trace;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL ring bridge operation=%u variant=%u line=%d: %s\n", \
        operation, variant, __LINE__, #condition); exit(1); } } while (0)

static void record_bytes(const void *data, size_t length)
{
    const unsigned char *bytes = data;
    for (size_t i = 0; i < length; ++i)
        trace = (trace ^ bytes[i]) * UINT64_C(1099511628211);
}
static void record_number(uint64_t value) { record_bytes(&value, sizeof(value)); }
static void record_text(const char *text) { record_bytes(text, strlen(text) + 1); }
#ifdef ZAPRET_RUST_RING_VM
void __real_lua_setfield(lua_State *, int, const char *);
void __wrap_lua_setfield(lua_State *L, int index, const char *key)
{
    record_text(key);
    __real_lua_setfield(L, index, key);
}
const rr_api *zapret_ring_vm_backend(void) { return rr_backend; }
bool zapret_ring_vm_load(void) { return rr_backend != NULL; }
#else
static void observed_setfield(lua_State *L, int index, const char *key)
{
    record_text(key);
    lua_setfield(L, index, key);
}
#define lua_setfield observed_setfield
#endif

static int rr_load(void) { return 1; }
#define rr_gc old_ring_gc
#include "ring_bridge_gc.inc"
#define rr_call old_rr_call
#define rust_ring_register old_ring_register
#include "ring_bridge_reference.inc"
#undef rust_ring_register
#undef rr_call
#undef rr_gc
#ifndef ZAPRET_RUST_RING_VM
#include "ring_gc_windows.inc"
#include "ring_bridge_policy_windows.inc"
#undef lua_setfield
#endif
#include "ring_bridge_names.inc"

static unsigned invokes, drops;
static int invoke(uint32_t op, void *object, const rr_request *request,
    rr_response *response, unsigned char *bytes, size_t capacity)
{
    CHECK(op == operation);
    ++invokes;
    record_number(op);
    record_number((uintptr_t)object);
    record_number(capacity);
    record_number(request->present);
    record_number(request->text_present);
    if (request->text_present & RR_STORE_PRESENT)
        record_number((uintptr_t)request->strings[RR_STORE_SLOT]);
    record_bytes(request->numbers, sizeof(request->numbers));
    for (size_t i = 0; i < 16; ++i)
        if (request->text_present & (UINT64_C(1) << i)) {
            record_number(request->lengths[i]);
            record_bytes(request->strings[i], request->lengths[i]);
        }
    if (variant == 12) return -9;
    if (variant != 19) response->object = (void *)(uintptr_t)23;
    response->count = variant == 13 ? 9 : variant == 18 ? 0 : 4;
    response->values[0] = (rr_return){.kind = variant == 14 ? 7 : 0};
    response->values[1] = (rr_return){.kind = 1, .number = -19.5};
    response->values[2] = (rr_return){.kind = 2, .number = 1};
    response->values[3] = (rr_return){.kind = 3, .offset = 3, .length = 5};
    memcpy(bytes + 3, "\0A\xFF" "BC", 5);
    if (variant == 15) response->values[3].offset = capacity + 1;
    if (variant == 16 || variant == 17) {
        response->values[3].offset = capacity;
        response->values[3].length = variant == 16 ? 0 : 1;
    }
    return 0;
}
static void drop(void *object)
{
    ++drops;
    record_number((uintptr_t)object);
}
static const rr_api backend = {sizeof(rr_api), 1, invoke, drop};

struct allocator { bool armed; unsigned limit, attempts, rejected, live; };
static void *allocate(void *context, void *pointer, size_t previous, size_t next)
{
    struct allocator *state = context;
    if (!next) {
        if (pointer) {
            CHECK(state->live);
            --state->live;
        }
        free(pointer);
        return NULL;
    }
    if (next > previous && state->armed && state->attempts++ >= state->limit) {
        ++state->rejected;
        return NULL;
    }
    bool fresh = !pointer;
    void *result = realloc(pointer, next);
    if (result && fresh) ++state->live;
    return result;
}
static int register_old(lua_State *L) { CHECK(old_ring_register(L)); return 0; }
static int register_new(lua_State *L) { CHECK(rust_ring_register(L)); return 0; }

static int arguments(lua_State *L)
{
    if (variant == 2) return 0;
    const char *class = ((operation >= 2 && operation <= 8) || operation == RR_STORE_STAT) ? RR_STORE :
        ((operation >= 10 && operation <= 12) || operation == 24 || operation == 30 ||
        operation == RR_STORE_SCHEDULER) ?
        RR_CONTEXT : operation >= 26 && operation <= 28 ? RR_HOSTS : NULL;
    int count = variant == 8 ? 16 : variant == 9 ? 17 : 7;
    int index = 0;
    if (class) {
        rr_userdata *object = lua_newuserdata(L, sizeof(*object));
        object->object = variant == 3 ? NULL : (void *)(uintptr_t)17;
        luaL_getmetatable(L, variant == 4 ? "missing class" : class);
        lua_setmetatable(L, -2);
        ++index;
    }
    for (; index < count; ++index) {
        if (operation == RR_STORE_SCHEDULER && index == RR_STORE_SLOT &&
            (variant < 4 || variant == 10)) {
            rr_userdata *store = lua_newuserdata(L, sizeof(*store));
            store->object = variant == 1 ? NULL : (void *)(uintptr_t)31;
            luaL_getmetatable(L, variant == 10 ? RR_CONTEXT : RR_STORE);
            lua_setmetatable(L, -2);
            continue;
        }
        if (variant == 5 && index == count - 1) { lua_newtable(L); continue; }
        if (variant == 6 && index == count - 1) { lua_pushnumber(L, INFINITY); continue; }
        if (variant == 7 && index == count - 1) { lua_pushnumber(L, NAN); continue; }
        switch ((index + variant) % 5) {
        case 0: lua_pushlstring(L, "b\0\xFF", 3); break;
        case 1: lua_pushboolean(L, 0); break;
        case 2: lua_pushboolean(L, 1); break;
        case 3: lua_pushnumber(L, -12.75); break;
        case 4: lua_pushnil(L); break;
        }
    }
    return count;
}
static void result(lua_State *L)
{
    int count = lua_gettop(L);
    record_number(count);
    for (int i = 1; i <= count; ++i) {
        int type = lua_type(L, i);
        record_number(type);
        switch (type) {
        case LUA_TSTRING: {
            size_t length;
            const char *data = lua_tolstring(L, i, &length);
            record_number(length);
            record_bytes(data, length);
            break;
        }
        case LUA_TNUMBER: {
            lua_Number value = lua_tonumber(L, i);
            record_bytes(&value, sizeof(value));
            break;
        }
        case LUA_TBOOLEAN: record_number(lua_toboolean(L, i)); break;
        case LUA_TUSERDATA:
            record_number((uintptr_t)((rr_userdata *)lua_touserdata(L, i))->object);
            CHECK(lua_getmetatable(L, i));
            lua_getfield(L, -1, "__metatable");
            record_text(lua_tostring(L, -1));
            lua_pop(L, 2);
            break;
        }
    }
}

struct observation { uint64_t trace; int status; unsigned invokes, drops, rejected; };
static struct observation attempt(bool reference, int budget)
{
    struct allocator state = {0};
    lua_State *L = lua_newstate(allocate, &state);
    CHECK(L && lua_checkstack(L, 64));
    lua_gc(L, LUA_GCSTOP, 0);
    rr_backend = &backend;
    invokes = drops = 0;
    trace = UINT64_C(14695981039346656037);
    lua_pushcfunction(L, reference ? register_old : register_new);
    if (!operation && budget >= 0) {
        state.limit = budget;
        state.armed = true;
    }
    int status = lua_pcall(L, 0, 0, 0);
    state.armed = false;
    if (!status) {
        lua_getglobal(L, "zapret_ring_native");
        CHECK(lua_istable(L, -1));
        lua_getfield(L, -1, "api_version");
        CHECK(lua_tointeger(L, -1) == 1);
        lua_pop(L, 1);
        lua_getfield(L, -1, "backend");
        CHECK(!strcmp(lua_tostring(L, -1), "Rust"));
        lua_pop(L, 1);
        if (operation) {
            lua_getfield(L, -1, names[operation - 1]);
            CHECK(lua_isfunction(L, -1));
            lua_remove(L, -2);
            int count = arguments(L);
            if (budget >= 0) {
                state.limit = budget;
                state.armed = true;
            }
            status = lua_pcall(L, count, LUA_MULTRET, 0);
            state.armed = false;
        } else lua_pop(L, 1);
    }
    result(L);
    lua_close(L);
    CHECK(!state.live);
    return (struct observation){ trace, status, invokes, drops, state.rejected };
}
static unsigned faults, errors;
static void compare(int budget)
{
    struct observation a = attempt(true, budget), b = attempt(false, budget);
    CHECK(a.status == b.status && a.trace == b.trace && a.invokes == b.invokes &&
        a.drops == b.drops && a.rejected == b.rejected);
    faults += b.status == LUA_ERRMEM;
    errors += b.status == LUA_ERRRUN;
    ++comparisons;
}
int main(void)
{
    for (operation = 1; operation <= sizeof(names) / sizeof(*names); ++operation)
        for (variant = 0; variant < 20; ++variant)
            compare(-1);
    const unsigned fault_operations[] = {0, 1, 4, 9, 15, 25, 29};
    variant = 0;
    for (size_t i = 0; i < sizeof(fault_operations) / sizeof(*fault_operations); ++i) {
        operation = fault_operations[i];
        for (int budget = 0; budget < 64; ++budget)
            compare(budget);
    }
    CHECK(faults && errors);
#ifdef ZAPRET_RUST_RING_VM
    const char *label = "ring_rust_vm";
#else
    const char *label = "ring_bridge";
#endif
    printf("PASS %s operations=%zu cases=%u vm_errors=%u vm_allocation_faults=%u "
        "real_luajit=1 registration_order=1 exact_backend_inputs=1 finalizer_parity=1\n",
        label, sizeof(names) / sizeof(*names), comparisons, errors, faults);
    return 0;
}
