/* MIT. Compare the direct Win64 Rust entries with the pinned LuaJIT helpers. */
#include "windows_lua_lifetime_abi.h"
#include "lua_lifetime_windows.h"
#include "lauxlib.h"
#include "lj_state.h"
#include <limits.h>
#include <process.h>
#include <stdarg.h>
#include <string.h>
#undef main

struct params_s params;

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL Lua lifetime line=%d: %s\n", __LINE__, #condition); exit(1); \
} } while (0)

#define lua_desync_ctx_destroy reference_destroy
#define lua_perror reference_perror
#define lua_panic reference_panic
#define lua_dlog_error reference_dlog_error
#include "lua_aux_reference.inc"
#undef lua_desync_ctx_destroy
#undef lua_perror
#undef lua_panic
#undef lua_dlog_error

enum operation { PREDICATE = 1, COERCE, POP, RELEASE, LOG };

struct sample {
    char log[512], error[256];
    unsigned trace[16], used, nested;
    int status, returned, primary_top, other_top, moved, slot, refs[2];
};

static struct sample *active;
static lua_State *primary, *other;
static unsigned mutation;
static int nested_reference;
static bool rust_side, reentering, panic_test, panic_verified;

static void record(lua_State *lua, enum operation operation)
{
    CHECK(active && active->used < sizeof(active->trace) / sizeof(*active->trace));
    CHECK(lua == primary || lua == other);
    active->trace[active->used++] = operation * 2 + (lua == other);
}

int __real_lua_isstring(lua_State *, int);
const char *__real_lua_tolstring(lua_State *, int, size_t *);
void __real_lua_settop(lua_State *, int);
void __real_luaL_unref(lua_State *, int, int);

int __wrap_lua_isstring(lua_State *lua, int index)
{
    if (active) { CHECK(index == -1); record(lua, PREDICATE); }
    int result = __real_lua_isstring(lua, index);
    if (active && (mutation & 1)) params.L = other;
    return result;
}

const char *__wrap_lua_tolstring(lua_State *lua, int index, size_t *length)
{
    if (active) { CHECK(index == -1 && !length); record(lua, COERCE); }
    const char *result = __real_lua_tolstring(lua, index, length);
    if (active && (mutation & 2)) params.L = primary;
    return result;
}

void __wrap_lua_settop(lua_State *lua, int index)
{
    if (active) { CHECK(index == -2); record(lua, POP); }
    __real_lua_settop(lua, index);
}

void __wrap_luaL_unref(lua_State *lua, int table, int reference)
{
    if (active) {
        CHECK(table == LUA_REGISTRYINDEX && params.ref_desync_ctx == reference);
        record(lua, RELEASE);
        active->refs[reentering] = reference;
        if (nested_reference && !reentering) {
            reentering = true;
            params.ref_desync_ctx = nested_reference;
            (rust_side ? lua_desync_ctx_destroy : reference_destroy)(lua);
            CHECK(params.ref_desync_ctx == 0);
            ++active->nested;
            reentering = false;
        }
    }
    __real_luaL_unref(lua, table, reference);
    if (active) params.ref_desync_ctx = -9;
}

int DLOG_ERR(const char *format, ...)
{
    record(primary, LOG);
    size_t used = strlen(active->log);
    va_list args;
    va_start(args, format);
    int count = vsnprintf(active->log + used, sizeof(active->log) - used, format, args);
    va_end(args);
    CHECK(count >= 0 && (size_t)count < sizeof(active->log) - used);
    if (mutation & 4) params.L = other;
    if ((mutation & 8) && !reentering) {
        reentering = true;
        lua_pushliteral(other, "nested report");
        (rust_side ? lua_perror : reference_perror)(other);
        ++active->nested;
        reentering = false;
    }
    if (panic_test && !strcmp(format, "LUA PANIC: THIS IS FATAL. DYING.\n")) {
        CHECK(!strcmp(active->log, "LUA ERROR: -1349.5\nLUA PANIC: THIS IS FATAL. DYING.\n"));
        const unsigned expected[] = {PREDICATE * 2, COERCE * 2, LOG * 2, POP * 2, LOG * 2};
        CHECK(active->used == 5 && !memcmp(active->trace, expected, sizeof(expected)));
        CHECK(lua_gettop(primary) == 0);
        panic_verified = true;
    }
    return count;
}

static void push_value(lua_State *lua, unsigned variant)
{
    switch (variant) {
    case 0: lua_pushnil(lua); break;
    case 1: lua_pushboolean(lua, 1); break;
    case 2: lua_pushnumber(lua, -1349.5); break;
    case 3: lua_pushliteral(lua, "primary\0hidden"); break;
    case 4: lua_newtable(lua); break;
    default: CHECK(false);
    }
}

static void report_error(lua_State *lua, bool global)
{
    if (global) (rust_side ? lua_dlog_error : reference_dlog_error)();
    else (rust_side ? lua_perror : reference_perror)(lua);
}

static struct sample observe_report(bool direct, bool global, unsigned variant, unsigned replacement)
{
    struct sample sample = {0};
    rust_side = direct;
    params.L = primary;
    lua_settop(primary, 0);
    lua_settop(other, 0);
    push_value(primary, variant);
    push_value(other, replacement);
    active = &sample;
    report_error(primary, global);
    active = NULL;
    sample.primary_top = lua_gettop(primary);
    sample.other_top = lua_gettop(other);
    sample.moved = params.L == other;
    return sample;
}

static int new_reference(lua_State *lua, const char *text)
{
    lua_pushstring(lua, text);
    return luaL_ref(lua, LUA_REGISTRYINDEX);
}

static struct sample observe_release(bool direct, int value, bool nested)
{
    struct sample sample = {0};
    rust_side = direct;
    primary = luaL_newstate();
    CHECK(primary);
    params.L = NULL;
    params.ref_desync_ctx = value > 0 ? new_reference(primary, "outer reference") : value;
    nested_reference = nested ? new_reference(primary, "nested reference") : 0;
    active = &sample;
    (direct ? lua_desync_ctx_destroy : reference_destroy)(primary);
    active = NULL;
    sample.slot = params.ref_desync_ctx;
    CHECK(sample.slot == 0 && lua_gettop(primary) == 0);
    CHECK(sample.used == (nested ? 2u : value != 0));
    if (value > 0) CHECK(new_reference(primary, "reused reference") == sample.refs[0]);
    if (nested) CHECK(new_reference(primary, "reused nested reference") == sample.refs[1]);
    nested_reference = 0;
    lua_close(primary);
    primary = NULL;
    return sample;
}

struct allocator { bool deny; unsigned denied, live; };
static struct allocator allocator;
static unsigned fault_kind;

static void *allocate(void *context, void *pointer, size_t previous, size_t size)
{
    struct allocator *state = context;
    if (!size) {
        if (pointer) { CHECK(state->live); --state->live; }
        free(pointer);
        return NULL;
    }
    if (state->deny && size > previous) { ++state->denied; return NULL; }
    bool fresh = pointer == NULL;
    void *result = realloc(pointer, size);
    if (result && fresh) ++state->live;
    return result;
}

static int fail_in_vm(lua_State *lua)
{
    if (fault_kind == 0) {
        // Leave one slot before luaL_unref requires a larger Lua stack.
        while (lua->top + 1 < tvref(lua->maxstack)) {
            setnilV(lua->top);
            ++lua->top;
        }
        allocator.deny = true;
        (rust_side ? lua_desync_ctx_destroy : reference_destroy)(lua);
    } else {
        lua_pushnumber(lua, 123456789.125);
        allocator.deny = true;
        report_error(lua, fault_kind == 2);
    }
    active->returned = true;
    return 0;
}

static struct sample observe_fault(bool direct)
{
    struct sample sample = {0};
    rust_side = direct;
    allocator = (struct allocator){0};
    primary = lua_newstate(allocate, &allocator);
    CHECK(primary);
    params.L = primary;
    int reference = fault_kind == 0 ? new_reference(primary, "retained reference") : 0;
    params.ref_desync_ctx = reference;
    lua_pushcfunction(primary, fail_in_vm);
    active = &sample;
    sample.status = lua_pcall(primary, 0, 0, 0);
    active = NULL;
    allocator.deny = false;
    CHECK(sample.status == LUA_ERRMEM && !sample.returned && allocator.denied);
    CHECK(lua_gettop(primary) == 1 && !sample.log[0]);
    CHECK(sample.used == (fault_kind == 0 ? 1u : 2u));
    const char *error = lua_tostring(primary, -1);
    CHECK(error && strlen(error) < sizeof(sample.error));
    strcpy(sample.error, error);
    lua_pop(primary, 1);
    sample.slot = params.ref_desync_ctx;
    CHECK(sample.slot == reference);
    if (reference) {
        lua_rawgeti(primary, LUA_REGISTRYINDEX, reference);
        CHECK(!strcmp(lua_tostring(primary, -1), "retained reference"));
        lua_pop(primary, 1);
        (direct ? lua_desync_ctx_destroy : reference_destroy)(primary);
        CHECK(params.ref_desync_ctx == 0);
    } else {
        lua_pushnumber(primary, 123456789.125);
        active = &sample;
        report_error(primary, fault_kind == 2);
        active = NULL;
        CHECK(!strcmp(sample.log, "LUA ERROR: 123456789.125\n"));
    }
    CHECK(lua_gettop(primary) == 0);
    lua_close(primary);
    primary = params.L = NULL;
    CHECK(!allocator.live);
    return sample;
}

static void reference_interrupt(lua_State *lua, lua_Debug *event)
{
    (void)event;
    lua_sethook(lua, NULL, 0, 0);
    luaL_error(lua, "INTERRUPT");
}

static void reference_install(void *lua)
{
    lua_sethook(lua, reference_interrupt,
        LUA_MASKCALL | LUA_MASKRET | LUA_MASKCOUNT | LUA_MASKLINE, 1);
}

static void load_chunk(lua_State *lua)
{
    const char code[] = "local total=0\nfor i=1,5 do total=total+i end\nreturn total";
    CHECK(!luaL_loadbuffer(lua, code, sizeof(code) - 1, "=interrupt fixture"));
}

static struct sample observe_interrupt(bool direct, bool first)
{
    struct sample sample = {0};
    lua_State *lua = luaL_newstate();
    CHECK(lua);
    load_chunk(lua);
    if (direct) zapret_lua_publish(lua);
    else zapret_lua_vm_publish(lua, reference_install);
    if (first) {
        CHECK(!lua_gethook(lua));
        lua_req_quit();
    }
    CHECK(lua_gethook(lua) && lua_gethookmask(lua) == 15 && lua_gethookcount(lua) == 1);
    sample.status = lua_pcall(lua, 0, 1, 0);
    CHECK(sample.status == LUA_ERRRUN && lua_gettop(lua) == 1);
    const char *error = lua_tostring(lua, -1);
    CHECK(error && strstr(error, "INTERRUPT") && strlen(error) < sizeof(sample.error));
    strcpy(sample.error, error);
    lua_pop(lua, 1);
    lua_req_quit();
    CHECK(!lua_gethook(lua) && !lua_gethookmask(lua) && !lua_gethookcount(lua));
    load_chunk(lua);
    CHECK(!lua_pcall(lua, 0, 1, 0) && lua_tointeger(lua, -1) == 15);
    CHECK(zapret_lua_vm_detach(lua));
    lua_close(lua);
    lua_req_quit();
    return sample;
}

static void check_panic_exit(void)
{
    if (!panic_verified) ExitProcess(1);
}

static void panic_child(bool direct)
{
    struct sample sample = {0};
    primary = luaL_newstate();
    CHECK(primary);
    panic_test = true;
    CHECK(!atexit(check_panic_exit));
    lua_CFunction selected = direct ? lua_panic : reference_panic;
    lua_atpanic(primary, selected);
    lua_CFunction installed = lua_atpanic(primary, NULL);
    CHECK(installed == selected);
    lua_pushnumber(primary, -1349.5);
    active = &sample;
    installed(primary);
    CHECK(false);
}

int main(int argc, char **argv)
{
    if (argc == 2) {
        CHECK(!strcmp(argv[1], "panic-rust") || !strcmp(argv[1], "panic-reference"));
        panic_child(!strcmp(argv[1], "panic-rust"));
    }
    CHECK(argc == 1);
    struct sample first = observe_interrupt(true, true);
    struct sample reference = observe_interrupt(false, false);
    struct sample pending = observe_interrupt(true, false);
    CHECK(!memcmp(&first, &reference, sizeof(first)) && !memcmp(&pending, &reference, sizeof(pending)));

    unsigned reports = 0, nested = 0, releases = 0, failures = 0;
    primary = luaL_newstate();
    other = luaL_newstate();
    CHECK(primary && other);
    for (unsigned global = 0; global < 2; ++global)
        for (unsigned variant = 0; variant < 5; ++variant)
            for (unsigned replacement = 0; replacement < 5; ++replacement)
                for (mutation = 0; mutation < 16; ++mutation) {
                    struct sample a = observe_report(false, global, variant, replacement);
                    struct sample b = observe_report(true, global, variant, replacement);
                    CHECK(!memcmp(&a, &b, sizeof(a)));
                    nested += b.nested;
                    ++reports;
                }
    lua_close(other);
    lua_close(primary);
    other = primary = NULL;
    mutation = 0;
    const int values[] = {INT_MIN, -2, -1, 0, 1, 1};
    for (unsigned i = 0; i < sizeof(values) / sizeof(*values); ++i) {
        bool has_nested = i == 5;
        struct sample a = observe_release(false, values[i], has_nested);
        struct sample b = observe_release(true, values[i], has_nested);
        CHECK(!memcmp(&a, &b, sizeof(a)));
        nested += b.nested;
        ++releases;
    }
    for (fault_kind = 0; fault_kind < 3; ++fault_kind)
        for (unsigned i = 0; i < 16; ++i) {
            struct sample a = observe_fault(false);
            struct sample b = observe_fault(true);
            CHECK(!memcmp(&a, &b, sizeof(a)));
            ++failures;
        }

    wchar_t exe[32768];
    DWORD path_length = GetModuleFileNameW(NULL, exe, sizeof(exe) / sizeof(*exe));
    CHECK(path_length && path_length < sizeof(exe) / sizeof(*exe));
    const wchar_t *reference_panic_args[] = {exe, L"panic-reference", NULL};
    const wchar_t *rust_panic_args[] = {exe, L"panic-rust", NULL};
    CHECK(_wspawnv(_P_WAIT, exe, reference_panic_args) == 100);
    CHECK(_wspawnv(_P_WAIT, exe, rust_panic_args) == 100);
    printf("PASS windows_lua_lifetime interrupts=3 reports=%u releases=%u nested=%u "
        "protected_oom_pairs=%u panic_exit_code=100 exact_errors=1 deferred_vm_reads=1\n",
        reports, releases, nested, failures);
    return 0;
}
