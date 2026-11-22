/* MIT. Compare only registry context creation and userdata validation. */
#include "params.h"
#include "engine_lua.h"
#include "lua_context_windows.h"
#include "windows_lua_context_abi.h"
#include "lauxlib.h"
#include "lj_state.h"
#include <string.h>
#undef main

#define lua_desync_ctx reference_context
#define lua_desync_ctx_create reference_create
#include "lua_context_entry_reference.inc"
#undef lua_desync_ctx_create
#undef lua_desync_ctx

struct params_s params;

enum creation {
    REGISTERED, ABSENT, NESTED, REDIRECTED, REFERENCE_CHANGED, LOOKUP_ERROR,
    INIT_ERROR, ALLOCATION_ERROR, REFERENCE_ERROR
};
enum observation { ALLOCATE = 1, INITIALIZE, LOOKUP, SET_META, REFERENCE, CHECK_META, LENGTH };

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL registry context line=%d: %s\n", __LINE__, #condition); exit(1); \
} } while (0)

struct sample {
    char error[256];
    unsigned char data[sizeof(t_lua_desync_context)];
    int trace[20], used, status, top, returned, reference, nested, target, remote_top, metatable;
};

struct allocator { bool deny; unsigned denied, live; };
static struct allocator allocator;
static struct sample *active;
static lua_State *primary, *alternate;
static enum creation mode;
static bool direct, validation_oom;
static unsigned depth;

static void record(enum observation operation)
{
    CHECK(active->used < (int)(sizeof(active->trace) / sizeof(*active->trace)));
    active->trace[active->used++] = operation;
}

static void *allocate(void *context, void *pointer, size_t old_size, size_t size)
{
    struct allocator *state = context;
    if (!size) {
        if (pointer) { CHECK(state->live); --state->live; }
        free(pointer);
        return NULL;
    }
    if (state->deny && size > old_size) { ++state->denied; return NULL; }
    bool fresh = pointer == NULL;
    void *result = realloc(pointer, size);
    if (result && fresh) ++state->live;
    return result;
}

void *__real_lua_newuserdata(lua_State *, size_t);
bool __real_zapret_lua_context_init(t_lua_desync_context *);
void __real_lua_getfield(lua_State *, int, const char *);
int __real_lua_setmetatable(lua_State *, int);
int __real_luaL_ref(lua_State *, int);
void *__real_luaL_checkudata(lua_State *, int, const char *);
size_t __real_lua_objlen(lua_State *, int);

void *__wrap_lua_newuserdata(lua_State *lua, size_t size)
{
    if (active) {
        CHECK(lua == primary && size == sizeof(t_lua_desync_context));
        record(ALLOCATE);
        if (mode == ALLOCATION_ERROR) allocator.deny = true;
    }
    return __real_lua_newuserdata(lua, size);
}

bool __wrap_zapret_lua_context_init(t_lua_desync_context *context)
{
    if (active) {
        record(INITIALIZE);
        if (mode == INIT_ERROR) return false;
    }
    return __real_zapret_lua_context_init(context);
}

void __wrap_lua_getfield(lua_State *lua, int table, const char *name)
{
    if (active && table == LUA_REGISTRYINDEX) {
        CHECK(lua == primary && !strcmp(name, "desync_ctx"));
        record(LOOKUP);
    }
    __real_lua_getfield(lua, table, name);
}

int __wrap_lua_setmetatable(lua_State *lua, int index)
{
    if (active) {
        CHECK(lua == primary && index == -2);
        record(SET_META);
    }
    return __real_lua_setmetatable(lua, index);
}

int __wrap_luaL_ref(lua_State *lua, int table)
{
    if (active) {
        CHECK((lua == primary || lua == alternate) && table == LUA_REGISTRYINDEX);
        active->target = lua == alternate ? 2 : 1;
        record(REFERENCE);
        if (mode == REFERENCE_ERROR) {
            // Leave the userdata on top with one slot left for luaL_ref.
            TValue value = *--lua->top;
            while (lua->top + 2 < tvref(lua->maxstack)) {
                setnilV(lua->top);
                ++lua->top;
            }
            *lua->top++ = value;
            allocator.deny = true;
        }
    }
    return __real_luaL_ref(lua, table);
}

void *__wrap_luaL_checkudata(lua_State *lua, int index, const char *name)
{
    if (active) {
        CHECK(lua == primary && index == 1 && !strcmp(name, "desync_ctx"));
        record(CHECK_META);
        if (validation_oom) allocator.deny = true;
    }
    return __real_luaL_checkudata(lua, index, name);
}

size_t __wrap_lua_objlen(lua_State *lua, int index)
{
    if (active && index == 1) {
        CHECK(lua == primary);
        record(LENGTH);
    }
    return __real_lua_objlen(lua, index);
}

static void create_context(lua_State *lua)
{
    (direct ? lua_desync_ctx_create : reference_create)(lua);
}

static int metatable_lookup(lua_State *lua)
{
    CHECK(lua == primary && lua_istable(lua, 1) &&
        !strcmp(lua_tostring(lua, 2), "desync_ctx"));
    if (mode == LOOKUP_ERROR) return luaL_error(lua, "registry metatable lookup declined");
    if (mode == REDIRECTED) params.L = alternate;
    if (mode == REFERENCE_CHANGED) params.ref_desync_ctx = -9;
    if (mode == NESTED && !depth) {
        ++depth;
        create_context(lua);
        --depth;
        CHECK(params.ref_desync_ctx > 0);
        active->nested = params.ref_desync_ctx;
    }
    lua_newtable(lua);
    lua_pushinteger(lua, 2 + depth);
    lua_rawseti(lua, -2, 1);
    return 1;
}

static void register_metatable(lua_State *lua)
{
    CHECK(luaL_newmetatable(lua, "desync_ctx"));
    lua_pushinteger(lua, 1);
    lua_rawseti(lua, -2, 1);
    lua_pop(lua, 1);
}

static void register_lookup(lua_State *lua)
{
    lua_pushvalue(lua, LUA_REGISTRYINDEX);
    lua_newtable(lua);
    lua_pushcfunction(lua, metatable_lookup);
    lua_setfield(lua, -2, "__index");
    CHECK(lua_setmetatable(lua, -2));
    lua_pop(lua, 1);
}

static int create_entry(lua_State *lua)
{
    int top = lua_gettop(lua);
    create_context(lua);
    CHECK(lua_gettop(lua) == top);
    active->returned = true;
    return top;
}

static void capture_error(lua_State *lua, struct sample *sample)
{
    const char *text = lua_tostring(lua, -1);
    CHECK(text && strlen(text) < sizeof(sample->error));
    strcpy(sample->error, text);
}

static int observe_context(lua_State *lua, int reference, unsigned char *data)
{
    unsigned char zero[sizeof(t_lua_desync_context)] = {0};
    lua_rawgeti(lua, LUA_REGISTRYINDEX, reference);
    const void *context = lua_touserdata(lua, -1);
    CHECK(context && lua_objlen(lua, -1) == sizeof(zero) && !memcmp(context, zero, sizeof(zero)));
    memcpy(data, context, sizeof(zero));
    int metatable = 0;
    if (lua_getmetatable(lua, -1)) {
        lua_rawgeti(lua, -1, 1);
        metatable = (int)lua_tointeger(lua, -1);
        lua_pop(lua, 2);
    }
    lua_pop(lua, 1);
    return metatable;
}

static struct sample observe_create(bool rust_side, int initial_ref, int argc)
{
    struct sample sample = {0};
    direct = rust_side;
    allocator = (struct allocator){0};
    primary = lua_newstate(allocate, &allocator);
    alternate = luaL_newstate();
    CHECK(primary && alternate);
    lua_pushliteral(alternate, "alternate registry reference");
    params.L = initial_ref ? NULL : primary;
    params.ref_desync_ctx = initial_ref;

    if (mode == REGISTERED || mode >= INIT_ERROR) register_metatable(primary);
    else if (mode != ABSENT) register_lookup(primary);
    lua_pushcfunction(primary, create_entry);
    for (int i = 0; i < argc; ++i) lua_pushinteger(primary, 20 + i);
    active = &sample;
    sample.status = lua_pcall(primary, argc, LUA_MULTRET, 0);
    active = NULL;
    allocator.deny = false;
    sample.reference = params.ref_desync_ctx;
    sample.top = lua_gettop(primary);
    sample.remote_top = lua_gettop(alternate);

    if (sample.status) {
        CHECK(sample.top == 1 && !sample.returned);
        capture_error(primary, &sample);
    } else {
        CHECK(sample.returned && sample.top == argc);
        for (int i = 0; i < argc; ++i) CHECK(lua_tointeger(primary, 1 + i) == 20 + i);
    }
    if (initial_ref) {
        CHECK(!sample.status && !sample.used && !params.L && sample.reference == initial_ref);
    } else if (mode == REDIRECTED) {
        CHECK(sample.status == LUA_ERRRUN && strstr(sample.error, "stack guard failure"));
        CHECK(params.L == alternate && sample.target == 2 && sample.reference > 0 && !sample.remote_top);
        lua_rawgeti(alternate, LUA_REGISTRYINDEX, sample.reference);
        CHECK(!strcmp(lua_tostring(alternate, -1), "alternate registry reference"));
    } else if (mode == LOOKUP_ERROR || mode == INIT_ERROR) {
        const char *message = mode == LOOKUP_ERROR ? "registry metatable lookup declined" :
            "invalid context storage";
        CHECK(sample.status == LUA_ERRRUN && strstr(sample.error, message) && !sample.reference);
    } else if (mode == ALLOCATION_ERROR || mode == REFERENCE_ERROR) {
        CHECK(sample.status == LUA_ERRMEM && allocator.denied && !sample.reference);
    } else {
        CHECK(!sample.status && sample.target == 1 && sample.reference > 0);
        sample.metatable = observe_context(primary, sample.reference, sample.data);
        CHECK(sample.metatable == (mode == REGISTERED ? 1 : mode == ABSENT ? 0 : 2));
        if (mode == NESTED) {
            unsigned char nested_data[sizeof(sample.data)];
            CHECK(sample.nested > 0 && sample.nested != sample.reference);
            CHECK(observe_context(primary, sample.nested, nested_data) == 3);
        }
    }
    lua_close(alternate);
    lua_close(primary);
    CHECK(!allocator.live);
    primary = alternate = params.L = NULL;
    return sample;
}

enum input {
    NO_ARGUMENT, NIL, BOOLEAN_VALUE, NUMBER, TABLE, LIGHTUSERDATA, NO_META, WRONG_META,
    INACTIVE, VALID, UNDERSIZED, OVERSIZED, EMPTY, VALIDATION_OOM
};

static int validate_entry(lua_State *lua)
{
    int top = lua_gettop(lua);
    t_lua_desync_context *context = (direct ? lua_desync_ctx : reference_context)(lua);
    CHECK(context == lua_touserdata(lua, 1) && lua_gettop(lua) == top);
    active->returned = true;
    return 0;
}

static void push_argument(lua_State *lua, enum input input)
{
    switch (input) {
    case NO_ARGUMENT: return;
    case NIL: lua_pushnil(lua); return;
    case BOOLEAN_VALUE: lua_pushboolean(lua, 1); return;
    case NUMBER: lua_pushinteger(lua, 9); return;
    case TABLE: lua_newtable(lua); return;
    case LIGHTUSERDATA: lua_pushlightuserdata(lua, &params); return;
    default: break;
    }
    size_t size = sizeof(t_lua_desync_context);
    if (input == UNDERSIZED) --size;
    if (input == OVERSIZED) ++size;
    if (input == EMPTY) size = 0;
    t_lua_desync_context *context = lua_newuserdata(lua, size);
    memset(context, 0, size);
    if (size == sizeof(*context)) context->valid = input != INACTIVE;
    if (input == NO_META || input == VALIDATION_OOM) return;
    if (input == WRONG_META) {
        CHECK(luaL_newmetatable(lua, "fixture metatable"));
        lua_pushliteral(lua, "desync_ctx");
        lua_setfield(lua, -2, "__name");
    } else luaL_getmetatable(lua, "desync_ctx");
    CHECK(lua_setmetatable(lua, -2));
}

static struct sample observe_validation(bool rust_side, enum input input)
{
    struct sample sample = {0};
    direct = rust_side;
    allocator = (struct allocator){0};
    primary = lua_newstate(allocate, &allocator);
    CHECK(primary);
    validation_oom = input == VALIDATION_OOM;
    if (!validation_oom) register_metatable(primary);
    lua_pushcfunction(primary, validate_entry);
    push_argument(primary, input);
    active = &sample;
    sample.status = lua_pcall(primary, input != NO_ARGUMENT, 0, 0);
    active = NULL;
    allocator.deny = false;
    sample.top = lua_gettop(primary);
    CHECK(sample.status == (input == VALID ? 0 : validation_oom ? LUA_ERRMEM : LUA_ERRRUN));
    if (sample.status) {
        CHECK(sample.top == 1 && !sample.returned);
        capture_error(primary, &sample);
    } else CHECK(sample.returned && sample.top == 0);
    if (input == NIL) CHECK(!sample.used && strstr(sample.error, "missing ctx"));
    if (input == WRONG_META) CHECK(sample.used == 1 && sample.trace[0] == CHECK_META);
    if (input == INACTIVE || input == UNDERSIZED || input == OVERSIZED || input == EMPTY)
        CHECK(sample.used == 2 && sample.trace[1] == LENGTH && strstr(sample.error, "ctx is invalid"));
    if (validation_oom) CHECK(allocator.denied && sample.used == 1 && sample.trace[0] == CHECK_META);
    lua_close(primary);
    primary = NULL;
    CHECK(!allocator.live);
    return sample;
}

int main(void)
{
    unsigned creations = 0, validations = 0, failures = 0, nested = 0;
    const int initial_refs[] = {0, -2, -1, 1};
    for (mode = REGISTERED; mode <= REFERENCE_ERROR; ++mode)
        for (unsigned i = 0; i < sizeof(initial_refs) / sizeof(*initial_refs); ++i)
            for (int argc = 0; argc <= 2; ++argc) {
                struct sample a = observe_create(false, initial_refs[i], argc);
                struct sample b = observe_create(true, initial_refs[i], argc);
                CHECK(!memcmp(&a, &b, sizeof(a)));
                ++creations;
                nested += b.nested > 0;
                failures += b.status == LUA_ERRMEM;
            }
    for (enum input input = NO_ARGUMENT; input <= VALIDATION_OOM; ++input) {
        for (unsigned repeat = 0; repeat < 8; ++repeat) {
            struct sample a = observe_validation(false, input);
            struct sample b = observe_validation(true, input);
            CHECK(!memcmp(&a, &b, sizeof(a)));
            ++validations;
            failures += b.status == LUA_ERRMEM;
        }
    }
    printf("PASS windows_lua_context creations=%u validations=%u nested=%u protected_oom_pairs=%u "
        "exact_metatable=1 deferred_vm_read=1 stack_guard_order=1 vm_allocations_released=1\n",
        creations, validations, nested, failures);
    return 0;
}
