/* MIT. Exercise the timer adapter with the pinned LuaJIT and a private allocator. */
#include "windows_timer_vm_abi.h"
#include "lauxlib.h"
#include "lj_state.h"
#include <stdarg.h>
#undef main

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL timer VM line=%d: %s\n", __LINE__, #condition); exit(1); } \
} while (0)

struct params_s params;
static zapret_timer_info references;
static bool fail_alloc, fill_stack, returned, report_entered, numeric_error;
static unsigned denied, logged, calls;

#ifdef ZAPRET_TIMER_HOST_DIRECT
struct host_sample {
    uint64_t trace, next;
    uint64_t pending[4][3];
    unsigned events, invoked, denied, count;
    int status, top;
    bool dirty, returned, reported;
    char error[128];
};

static struct host_sample *host_observed;

static void observe(unsigned operation, uint64_t value)
{
    if (host_observed) {
        host_observed->trace = (host_observed->trace ^ operation) * 1099511628211ULL ^ value;
        ++host_observed->events;
    }
}

static uint64_t logged_bytes(const char *text)
{
    uint64_t hash = 0;
    for (const unsigned char *byte = (const unsigned char *)text; *byte; ++byte)
        hash = hash * 131 + *byte;
    return hash;
}

void __real_lua_rawgeti(lua_State *, int, int);
const char *__real_lua_tolstring(lua_State *, int, size_t *);
void __real_lua_settop(lua_State *, int);
int __real_lua_pcall(lua_State *, int, int, int);
void __real_luaL_unref(lua_State *, int, int);

void __wrap_lua_rawgeti(lua_State *lua, int table, int index)
{
    observe(4, (uint64_t)(uint32_t)table << 32 | (uint32_t)index);
    __real_lua_rawgeti(lua, table, index);
}

const char *__wrap_lua_tolstring(lua_State *lua, int index, size_t *size)
{
    observe(5, (uint32_t)index);
    return __real_lua_tolstring(lua, index, size);
}

void __wrap_lua_settop(lua_State *lua, int index)
{
    observe(6, (uint32_t)index);
    __real_lua_settop(lua, index);
}

int __wrap_lua_pcall(lua_State *lua, int arguments, int results, int handler)
{
    observe(7, (uint64_t)(uint32_t)arguments << 32 | (uint32_t)results);
    observe(8, (uint32_t)handler);
    return __real_lua_pcall(lua, arguments, results, handler);
}

void __wrap_luaL_unref(lua_State *lua, int table, int reference)
{
    observe(9, (uint64_t)(uint32_t)table << 32 | (uint32_t)reference);
    __real_luaL_unref(lua, table, reference);
}
#else
#define observe(...) ((void)0)
#endif

static void *allocate(void *context, void *pointer, size_t old_size, size_t size)
{
    (void)context;
    if (!size) { free(pointer); return NULL; }
    if (fail_alloc && size > old_size) { ++denied; return NULL; }
    return realloc(pointer, size);
}

uint64_t boottime_ms(void) { observe(1, 100); return 100; }

int DLOG(const char *format, ...)
{
    char text[256];
    va_list args;
    va_start(args, format);
    int count = vsnprintf(text, sizeof(text), format, args);
    va_end(args);
    CHECK(count > 0 && (size_t)count < sizeof(text));
    observe(2, logged_bytes(text));
    ++logged;
    return count;
}

void lua_dlog_error(void)
{
    observe(3, 0);
    report_entered = true;
    if (lua_isstring(params.L, -1)) CHECK(lua_tostring(params.L, -1));
    lua_pop(params.L, 1);
}

#ifdef ZAPRET_TIMER_HOST_DIRECT
#define TimerPoolRun reference_TimerPoolRun
#define TimerPoolDestroy reference_TimerPoolDestroy
#include "windows_timer_host_vm.inc"
#undef TimerPoolDestroy
#undef TimerPoolRun
#include "windows_timer_host_vm_abi.h"
#else
#include "windows_timer_host_vm.inc"
#endif

static int release_references(lua_State *lua)
{
    CHECK(lua == params.L);
    if (fill_stack) {
        // Leave one stack slot so the first registry lookup grows the stack.
        while (lua->top + 1 < tvref(lua->maxstack)) {
            setnilV(lua->top);
            ++lua->top;
        }
        fail_alloc = true;
    }
    zapret_timer_unref(&references);
    returned = true;
    return 0;
}

static int new_ref(lua_State *lua, const char *text)
{
    lua_pushstring(lua, text);
    return luaL_ref(lua, LUA_REGISTRYINDEX);
}

static int registry_integer(lua_State *lua, int key)
{
    lua_rawgeti(lua, LUA_REGISTRYINDEX, key);
    int result = (int)lua_tointeger(lua, -1);
    lua_pop(lua, 1);
    return result;
}

static void check_release(void)
{
    lua_State *lua = lua_newstate(allocate, NULL);
    CHECK(lua);
    params.L = lua;
    references.name_ref = new_ref(lua, "name");
    references.func_ref = new_ref(lua, "function");
    references.data_ref = new_ref(lua, "data");
    unsigned previous = denied;
    returned = false;
    fill_stack = true;
    lua_pushcfunction(lua, release_references);
    CHECK(lua_pcall(lua, 0, 0, 0) == LUA_ERRMEM);
    fail_alloc = fill_stack = false;
    CHECK(!returned && denied > previous && lua_gettop(lua) == 1);
    lua_pop(lua, 1);
    lua_rawgeti(lua, LUA_REGISTRYINDEX, references.name_ref);
    CHECK(lua_type(lua, -1) == LUA_TSTRING);
    lua_pop(lua, 1);

    lua_pushcfunction(lua, release_references);
    CHECK(!lua_pcall(lua, 0, 0, 0) && returned && lua_gettop(lua) == 0);
    CHECK(registry_integer(lua, 0) == references.data_ref);
    CHECK(registry_integer(lua, references.data_ref) == references.func_ref);
    CHECK(registry_integer(lua, references.func_ref) == references.name_ref);
    lua_close(lua);
    params.L = NULL;
}

static int timer_callback(lua_State *lua)
{
    CHECK(lua_gettop(lua) == 2);
    CHECK(!strcmp(lua_tostring(lua, 1), "timer") && !strcmp(lua_tostring(lua, 2), "data"));
    ++calls;
    if (numeric_error) {
        lua_pushnumber(lua, 123456789.125);
        fail_alloc = true;
        return lua_error(lua);
    }
    return 0;
}

static int run_timer(lua_State *lua)
{
    CHECK(lua == params.L);
    CHECK(!TimerPoolRun(&params.timers, &params.timers_dirty, 120));
    returned = true;
    return 0;
}

static void check_host(bool fail)
{
    lua_State *lua = lua_newstate(allocate, NULL);
    CHECK(lua);
    params.L = lua;
    zapret_timer_info timer = {.period = 10, .oneshot = 1};
    timer.name_ref = new_ref(lua, "timer");
    lua_pushcfunction(lua, timer_callback);
    timer.func_ref = luaL_ref(lua, LUA_REGISTRYINDEX);
    timer.data_ref = new_ref(lua, "data");
    CHECK(zapret_timer_set(&params.timers, "timer", &timer, 95, NULL) == 0);
    params.timers_dirty = true;
    unsigned prior_calls = calls, prior_logs = logged, prior_denied = denied;
    returned = report_entered = false;
    numeric_error = fail;
    lua_pushcfunction(lua, run_timer);
    int status = lua_pcall(lua, 0, 0, 0);
    fail_alloc = numeric_error = false;
    CHECK(calls == prior_calls + 1 && !params.timers_dirty);
    if (fail) {
        // The callback's protected call has returned. Number formatting in the
        // host error report can still unwind to the caller on allocation failure.
        CHECK(status == LUA_ERRMEM && report_entered && !returned && denied > prior_denied);
        CHECK(logged == prior_logs + 1 && params.timers && lua_gettop(lua) == 1);
        lua_pop(lua, 1);
        TimerPoolDestroy(&params.timers);
    } else {
        CHECK(!status && !report_entered && returned && logged == prior_logs + 2);
    }
    CHECK(!params.timers && lua_gettop(lua) == 0);
    lua_close(lua);
    params.L = NULL;
}

#ifdef ZAPRET_TIMER_HOST_DIRECT
static timer_pool *nested_pool;
static bool nested_dirty, reference_host, destroy_host, added;
static unsigned effect, fault, invoked;
static uint64_t instant, next;

static uint64_t dispatch_case(timer_pool **pool, bool *dirty, uint64_t now)
{
    return reference_host ? reference_TimerPoolRun(pool, dirty, now) : TimerPoolRun(pool, dirty, now);
}

static void destroy_case(timer_pool **pool)
{
    if (reference_host) reference_TimerPoolDestroy(pool);
    else TimerPoolDestroy(pool);
}

static int guest_timer(lua_State *lua);

static void seed_timer(timer_pool **pool, const char *name, uint64_t period, bool oneshot)
{
    zapret_timer_info timer = {.period = period, .oneshot = oneshot};
    timer.name_ref = new_ref(params.L, name);
    lua_pushcfunction(params.L, guest_timer);
    timer.func_ref = luaL_ref(params.L, LUA_REGISTRYINDEX);
    timer.data_ref = new_ref(params.L, "data");
    CHECK(zapret_timer_set(pool, name, &timer, 95, NULL) == 0);
}

static int guest_timer(lua_State *lua)
{
    CHECK(lua == params.L && lua_gettop(lua) == 2);
    const char *name = lua_tostring(lua, 1);
    const char *data = lua_tostring(lua, 2);
    CHECK(name && data && !strcmp(data, "data"));
    ++invoked;
    observe(10, logged_bytes(name));
    if (strcmp(name, "timer")) return 0;
    if (effect == 1) {
        observe(11, dispatch_case(&nested_pool, &nested_dirty, 120));
        CHECK(!nested_pool && !nested_dirty && lua_gettop(lua) == 2);
    } else if (effect == 2 && !added) {
        seed_timer(&params.timers, "added", 0, true);
        params.timers_dirty = added = true;
        CHECK(lua_gettop(lua) == 2);
    }
    if (fault == 1) {
        lua_pushliteral(lua, "test timer error");
        return lua_error(lua);
    }
    if (fault == 2) {
        lua_pushnumber(lua, 7654321.125);
        fail_alloc = true;
        return lua_error(lua);
    }
    return 0;
}

static int host_fixture_entry(lua_State *lua)
{
    CHECK(lua == params.L);
    if (destroy_host) destroy_case(&params.timers);
    else next = dispatch_case(&params.timers, &params.timers_dirty, instant);
    returned = true;
    return 0;
}

static struct host_sample observe_host(bool reference, unsigned seeded)
{
    struct host_sample sample;
    memset(&sample, 0, sizeof(sample));
    lua_State *lua = lua_newstate(allocate, NULL);
    CHECK(lua && !params.timers && !nested_pool);
    params.L = lua;
    params.timers_dirty = nested_dirty = true;
    reference_host = reference;
    added = returned = report_entered = false;
    invoked = next = 0;
    if (seeded) seed_timer(&params.timers, "timer", 5, true);
    if (seeded >= 2) seed_timer(&params.timers, "another", 10, false);
    if (effect == 1 && !destroy_host) seed_timer(&nested_pool, "nested", 1, true);
    unsigned prior = denied;
    host_observed = &sample;
    lua_pushcfunction(lua, host_fixture_entry);
    sample.status = lua_pcall(lua, 0, 0, 0);
    fail_alloc = false;
    host_observed = NULL;
    sample.top = lua_gettop(lua);
    sample.dirty = params.timers_dirty;
    sample.next = next;
    sample.invoked = invoked;
    sample.denied = denied - prior;
    sample.returned = returned;
    sample.reported = report_entered;
    if (sample.status) {
        const char *message = lua_tostring(lua, -1);
        CHECK(message && strlen(message) < sizeof(sample.error));
        strcpy(sample.error, message);
    }
    uint64_t after = 0;
    zapret_timer_info timer;
    while (zapret_timer_after(params.timers, after, &timer)) {
        CHECK(sample.count < sizeof(sample.pending) / sizeof(sample.pending[0]));
        uint64_t *fields = sample.pending[sample.count++];
        fields[0] = timer.period;
        fields[1] = timer.oneshot;
        fields[2] = timer.fires;
        after = timer.id;
    }
    destroy_case(&params.timers);
    destroy_case(&nested_pool);
    CHECK(!params.timers && !nested_pool);
    lua_close(lua);
    params.L = NULL;
    return sample;
}

static unsigned compare_host(void)
{
    const uint64_t times[] = {0, 99, 100, 120, UINT64_MAX};
    unsigned comparisons = 0, reentries = 0, failures = 0;
    for (effect = 0; effect < 3; ++effect)
        for (fault = 0; fault < 3; ++fault)
            for (unsigned i = 0; i < sizeof(times) / sizeof(times[0]); ++i) {
                instant = times[i];
                struct host_sample before = observe_host(true, 2), after = observe_host(false, 2);
                CHECK(!memcmp(&before, &after, sizeof(before)));
                if (effect == 1 && after.invoked > 1) ++reentries;
                if (after.status == LUA_ERRMEM) ++failures;
                ++comparisons;
            }
    CHECK(reentries && failures);
    destroy_host = true;
    for (unsigned seeded = 0; seeded < 3; ++seeded) {
        struct host_sample before = observe_host(true, seeded), after = observe_host(false, seeded);
        CHECK(!memcmp(&before, &after, sizeof(before)));
        CHECK(after.returned && !after.count && !after.status && !after.top);
        ++comparisons;
    }
    return comparisons;
}
#endif

int main(void)
{
    for (unsigned i = 0; i < 64; ++i) check_release();
    check_host(false);
    check_host(true);
#ifdef ZAPRET_TIMER_HOST_DIRECT
    const unsigned comparisons = compare_host();
    printf("PASS timer_vm protected_unref_oom=64 registry_order=1 host_run=1 host_report_oom=1 "
        "rust_host=1 host_comparisons=%u exact_vm_order=1 real_reentry=1\n", comparisons);
#else
    printf("PASS timer_vm protected_unref_oom=64 registry_order=1 host_run=1 host_report_oom=1\n");
#endif
    return 0;
}
