/* MIT. Real LuaJIT observations with deterministic native lifecycle boundaries. */
#include "params.h"
#include "engine_lua.h"
#include "nfqws.h"
#include <luajit.h>
#include <stdarg.h>
#undef main
struct params_s params;
#ifdef ZAPRET_RUST_LUA_VM
#include "windows_lua_vm_sources.inc"
#define gc_time native_lua_gc_time
lua_State *__real_luaL_newstate(void);
void __real_lua_close(lua_State *);
void __real_luaL_openlibs(lua_State *);
int __real_lua_gc(lua_State *, int, int);
#define real_newstate __real_luaL_newstate
#define real_close __real_lua_close
#define real_openlibs __real_luaL_openlibs
#define real_gc __real_lua_gc
#else
#define real_newstate luaL_newstate
#define real_close lua_close
#define real_openlibs luaL_openlibs
#define real_gc lua_gc
#endif
static unsigned cases,errors,nested_calls,finalizers,fault_cases,vm_faults,boundaries,real_closes;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL Lua VM cases=%u line=%d: %s\n",cases,__LINE__,#v);exit(1);}}while(0)
struct sample {
    int status, arity;
    bool normal, ok, null_vm, closed;
    unsigned clocks, collections, nested, finalized;
    uint64_t last;
    char trace[4096], log[4096], message[512];
#ifdef ZAPRET_RUST_LUA_VM
    unsigned target, alternate_top, resources, closed_parameter_releases;
#endif
};
static struct sample *active;static lua_State *owner;
static unsigned variant,operation,mutation,depth;static bool native_side,close_real;
static uint64_t next_time,reference_gc_time,gc_time;
#ifdef ZAPRET_RUST_LUA_VM
enum {
    VERSION_REDIRECT = 7, JIT_REDIRECT, SHUTDOWN_REDIRECT, COLLECT_REDIRECT,
    RELEASE_CONTEXT_ERROR, RELEASE_CONNTRACK_ERROR, RELEASE_TIMERS_ERROR, RELEASE_SUCCESS
};
static lua_State *alternate;
static bool actual_creation;
static struct params_s supplied;
static unsigned redirected_cases, ownership_cases, protected_cleanup_errors, parameter_cleanup_pairs;
#endif
static void reference_do_gc(void);
static void reference_cleanup(lua_State *);
void lua_cleanup(lua_State *);
static void record(const char *text){size_t have=strlen(active->trace),count=strlen(text);CHECK(have+count+2<sizeof(active->trace));memcpy(active->trace+have,text,count);active->trace[have+count]=';';active->trace[have+count+1]=0;}
static uint64_t *last_time(void){return native_side?&gc_time:&reference_gc_time;}
static void call_gc(void){if(native_side)lua_do_gc();else reference_do_gc();}
static void call_cleanup(lua_State *L){if(native_side)lua_cleanup(L);else reference_cleanup(L);}
static int append_log(const char *format,va_list args){size_t used=strlen(active->log);int count=vsnprintf(active->log+used,sizeof(active->log)-used,format,args);CHECK(count>=0 && (size_t)count<sizeof(active->log)-used);if(mutation==4 && strstr(format,"LUA GARBAGE"))*last_time()=UINT64_MAX;return count;}
int DLOG(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int out = append_log(format, args);
    va_end(args);
#ifdef ZAPRET_RUST_LUA_VM
    if (mutation == SHUTDOWN_REDIRECT && !strcmp(format, "LUA SHUTDOWN\n")) params.L = alternate;
#endif
    return out;
}
int DLOG_ERR(const char *format,...){va_list args;va_start(args,format);int out=append_log(format,args);va_end(args);return out;}
int DLOG_CONDUP(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int out = append_log(format, args);
    va_end(args);
#ifdef ZAPRET_RUST_LUA_VM
    if ((mutation == VERSION_REDIRECT && !strncmp(format, "LUA v", 5)) ||
        (mutation == JIT_REDIRECT && !strcmp(format, "JIT: ON"))) params.L = alternate;
#endif
    return out;
}

static void record_vm(const char *stage, const lua_State *lua)
{
    record(stage);
#ifdef ZAPRET_RUST_LUA_VM
    if (alternate && lua == alternate) {
        record("alternate");
        return;
    }
#endif
    CHECK(lua == owner);
}

static void fixture_context(lua_State *L)
{
    record_vm("context", L);
#ifdef ZAPRET_RUST_LUA_VM
    if (mutation == RELEASE_CONTEXT_ERROR) luaL_error(L, "context cleanup failed");
    if (params.ref_desync_ctx) {
        luaL_unref(L, LUA_REGISTRYINDEX, params.ref_desync_ctx);
        params.ref_desync_ctx = 0;
    }
    if (mutation == SHUTDOWN_REDIRECT) params.L = alternate;
#endif
    if (mutation == 1 && depth == 0) {
        ++depth;
        call_cleanup(L);
        --depth;
        ++active->nested;
    }
}

static void fixture_conntrack(t_conntrack *pool)
{
    CHECK(pool == &params.conntrack);
    record("conntrack");
#ifdef ZAPRET_RUST_LUA_VM
    if (mutation == RELEASE_CONNTRACK_ERROR) luaL_error(params.L, "connection pool cleanup failed");
    free(pool->pool);
    pool->pool = NULL;
#endif
}

static void fixture_timers(timer_pool **pool)
{
    CHECK(pool == &params.timers);
    record("timers");
#ifdef ZAPRET_RUST_LUA_VM
    if (mutation == RELEASE_TIMERS_ERROR) luaL_error(params.L, "timer pool cleanup failed");
    free(*pool);
    *pool = NULL;
#endif
}

static bool fixture_detach(void *L)
{
    record_vm("detach", L);
#ifdef ZAPRET_RUST_LUA_VM
    if (mutation == SHUTDOWN_REDIRECT) params.L = owner;
#endif
    return true;
}

static lua_State *fixture_newstate(void)
{
    record("new");
#ifdef ZAPRET_RUST_LUA_VM
    if (actual_creation) owner = real_newstate();
#endif
    return variant == 20 ? NULL : owner;
}

static void fixture_close(lua_State *L)
{
    record_vm("close", L);
    if (close_real) {
        real_close(L);
        active->closed = true;
        ++real_closes;
    }
}

static void fixture_openlibs(lua_State *L)
{
    record_vm("libraries", L);
#ifdef ZAPRET_RUST_LUA_VM
    if (actual_creation) real_openlibs(L);
#endif
}

static int fixture_ring(lua_State *L)
{
    record_vm("register", L);
    return variant == 19 ? 0 : variant == 24 ? 7 : variant == 25 ? -1 : 1;
}
static uint64_t fixture_clock(void){record("clock");uint64_t captured=next_time+active->clocks++;if(mutation==2)params.lua_gc=0;else if(mutation==3 && depth==0){++depth;call_gc();--depth;++active->nested;}else if(mutation==5)params.lua_gc=UINT64_MAX;return captured;}
static int fixture_gc(lua_State *L, int what, int value)
{
    CHECK(value == 0);
    if (what == LUA_GCCOUNT) {
        record_vm("count", L);
        return 300 - (int)active->collections * 7;
    }
    CHECK(what == LUA_GCCOLLECT);
    record_vm("collect", L);
    ++active->collections;
    return real_gc(L, what, value);
}
#ifdef ZAPRET_RUST_LUA_VM
void lua_desync_ctx_destroy(lua_State *L) { fixture_context(L); }
void ConntrackPoolDestroy(t_conntrack *pool) { fixture_conntrack(pool); }
void TimerPoolDestroy(timer_pool **pool) { fixture_timers(pool); }
bool __wrap_zapret_lua_vm_detach(void *L) { return fixture_detach(L); }
int rust_ring_register(lua_State *L) { return fixture_ring(L); }
uint64_t boottime_ms(void) { return fixture_clock(); }
lua_State *__wrap_luaL_newstate(void) { return fixture_newstate(); }
void __wrap_lua_close(lua_State *L) { fixture_close(L); }
void __wrap_luaL_openlibs(lua_State *L) { fixture_openlibs(L); }
int __wrap_lua_gc(lua_State *L, int what, int value) { return fixture_gc(L, what, value); }
#define lua_panic fixture_panic
#endif
#define lua_desync_ctx_destroy fixture_context
#define ConntrackPoolDestroy fixture_conntrack
#define TimerPoolDestroy fixture_timers
#define zapret_lua_vm_detach fixture_detach
#define luaL_newstate fixture_newstate
#define lua_close fixture_close
#define luaL_openlibs fixture_openlibs
#define rust_ring_register fixture_ring
#define boottime_ms fixture_clock
#define lua_gc(...) fixture_gc(__VA_ARGS__)
#include "lua_vm_common.inc"
#define lua_cleanup reference_cleanup
#define lua_shutdown reference_shutdown
#define lua_basic_init reference_init
#define lua_do_gc reference_do_gc
#define gc_time reference_gc_time
#include "lua_vm_reference.inc"
#undef lua_cleanup
#undef lua_shutdown
#undef lua_basic_init
#undef lua_do_gc
#undef gc_time
#ifdef ZAPRET_RUST_LUA_VM
#undef lua_panic
#define gc_time native_lua_gc_time
int lua_panic(lua_State *L) { return fixture_panic(L); }
#define lua_shutdown reference_shutdown
#define cleanup_params reference_cleanup_params
#include "engine_cleanup_native_windows.inc"
#undef cleanup_params
#undef lua_shutdown

void zapret_cleanup_closed_params(struct params_s *settings)
{
    CHECK(settings==&supplied && !params.L && supplied.debug);
    CHECK(!params.ref_desync_ctx && !params.conntrack.pool && !params.timers);
    supplied.debug=false;
    ++active->closed_parameter_releases;
    record("closed-parameters");
}
#else
#include "lua_vm_windows.inc"
#endif
#undef lua_desync_ctx_destroy
#undef luaL_newstate
#undef lua_close
#undef luaL_openlibs
#undef lua_gc
struct allocator {bool armed;unsigned attempts,limit,rejected,live;};
static struct allocator *fault_allocator;
static void *allocate(void *context,void *pointer,size_t previous,size_t next){struct allocator *a=context;if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}if(a->armed && next>previous && a->attempts++>=a->limit){++a->rejected;return NULL;}bool fresh=!pointer;void *result=realloc(pointer,next);if(result && fresh)++a->live;return result;}
static int finalized(lua_State *L)
{
    (void)L;
    record("finalized");
    ++active->finalized;
#ifdef ZAPRET_RUST_LUA_VM
    if (mutation == COLLECT_REDIRECT && L == owner) params.L = alternate;
#endif
    if (mutation == 6 && depth == 0) {
        ++depth;
        call_gc();
        --depth;
        ++active->nested;
    }
    return 0;
}
static const char *setup=
"local r=debug.getregistry() local v=... local j={status=function()return true,'SSE2',123 end} local t={jit=j} "
"if v==1 then t=nil elseif v==2 then t=false elseif v==3 then t=17 elseif v==4 then t={} "
"elseif v==5 then t.jit=false elseif v==6 then j.status=false elseif v==7 then j.status={} "
"elseif v==8 then j.status=function()return false,'soft',12 end "
"elseif v==9 then j.status=function()return {},true,'unread' end "
"elseif v==10 then j.status=function()return true,{},'unread' end "
"elseif v==11 then t=setmetatable({},{__index=function()error('jit table lookup failed')end}) "
"elseif v==12 then t.jit=setmetatable({},{__index=function()error('jit function lookup failed')end}) "
"elseif v==13 then j.status=function()error('jit status call failed')end "
"elseif v==14 then j.status=function()return true,1.25,123456789,'\195\169' end "
"elseif v==15 then j.status=function()return false,nil,'unread' end "
"elseif v==16 then j.status=function()end "
"elseif v==17 then j.status=function()return true,'',0,'last' end "
"elseif v==18 then j.status=function()collectgarbage('collect');return true,'gc' end "
"elseif v==21 then t=setmetatable({},{__index=function()return j end}) "
"elseif v==22 then j=setmetatable({},{__index=function()return function()return true,9 end end});t.jit=j "
"elseif v==23 then j.status=function()return true,function()end,'unread' end end "
"r._LOADED=t local p=newproxy(true) getmetatable(p).__gc=FINALIZED p=nil";
static lua_State *new_vm(struct allocator *a){lua_State *L=a?lua_newstate(allocate,a):real_newstate();CHECK(L);real_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);lua_register(L,"FINALIZED",finalized);CHECK(!luaL_loadstring(L,setup));lua_pushinteger(L,variant);CHECK(!lua_pcall(L,1,0,0));return L;}
static int run(lua_State *L)
{
    switch(operation){
    case 0:active->ok=native_side?lua_basic_init():reference_init();break;
    case 1:call_cleanup(L);active->ok=true;break;
    case 2:if(native_side)lua_shutdown();else reference_shutdown();active->ok=true;break;
#ifdef ZAPRET_RUST_LUA_VM
    case 4:
        if(native_side)cleanup_params(&supplied);else reference_cleanup_params(&supplied);
        active->ok=true;
        break;
#endif
    default:call_gc();active->ok=true;break;
    }
    active->normal=true;
    return lua_gettop(L);
}
#ifdef ZAPRET_RUST_LUA_VM
static void create_owned_values(lua_State *lua)
{
    lua_pushliteral(lua, "context resource");
    params.ref_desync_ctx = luaL_ref(lua, LUA_REGISTRYINDEX);
    params.conntrack.pool = malloc(1);
    params.timers = malloc(1);
    CHECK(params.ref_desync_ctx > 0 && params.conntrack.pool && params.timers);
}

static void prepare_mutation(void)
{
    if (mutation == VERSION_REDIRECT) {
        unsigned saved = variant;
        variant = 8;
        alternate = new_vm(NULL);
        variant = saved;
    } else if (mutation >= JIT_REDIRECT && mutation <= COLLECT_REDIRECT) {
        alternate = real_newstate();
        CHECK(alternate);
        if (mutation == JIT_REDIRECT) {
            for (int i = 0; i < 3; ++i) lua_pushnil(alternate);
            lua_pushliteral(alternate, "alternate flag");
        }
    } else if (mutation >= RELEASE_CONTEXT_ERROR && mutation <= RELEASE_SUCCESS) {
        create_owned_values(owner);
    }
}

static void capture_resources(struct sample *sample)
{
    if (params.ref_desync_ctx) {
        sample->resources |= 1;
        lua_rawgeti(owner, LUA_REGISTRYINDEX, params.ref_desync_ctx);
        CHECK(!strcmp(lua_tostring(owner, -1), "context resource"));
        lua_pop(owner, 1);
        luaL_unref(owner, LUA_REGISTRYINDEX, params.ref_desync_ctx);
        params.ref_desync_ctx = 0;
    }
    if (params.conntrack.pool) {
        sample->resources |= 2;
        free(params.conntrack.pool);
        params.conntrack.pool = NULL;
    }
    if (params.timers) {
        sample->resources |= 4;
        free(params.timers);
        params.timers = NULL;
    }
}
#endif

static void execute(bool rust, bool existing, uint64_t interval, uint64_t now, uint64_t last,
    struct allocator *allocator, struct sample *sample)
{
    native_side = rust;
    active = sample;
    depth = 0;
    memset(&params, 0, sizeof(params));
    owner = new_vm(allocator);
    params.L = existing ? owner : NULL;
    params.lua_gc = interval;
    next_time = now;
    *last_time() = last;
#ifdef ZAPRET_RUST_LUA_VM
    supplied.debug = true;
    prepare_mutation();
#endif
    lua_settop(owner, 0);
    lua_pushcfunction(owner, run);
    if (allocator) {
        allocator->armed = true;
        allocator->attempts = allocator->rejected = 0;
    }
    if (close_real) {
        lua_settop(owner, 0);
        if (rust) lua_shutdown();
        else reference_shutdown();
        sample->normal = sample->ok = true;
    } else sample->status = lua_pcall(owner, 0, LUA_MULTRET, 0);
    if (allocator) allocator->armed = false;
    sample->last = *last_time();
    sample->null_vm = params.L == NULL;
#ifdef ZAPRET_RUST_LUA_VM
    sample->target = params.L ? (params.L == alternate ? 2 : 1) : 0;
    if (alternate) sample->alternate_top = lua_gettop(alternate);
    capture_resources(sample);
#endif
    if (!sample->closed) {
        sample->arity = lua_gettop(owner);
        if (sample->status) {
            const char *message = lua_tostring(owner, -1);
            snprintf(sample->message, sizeof(sample->message), "%s", message ? message : "");
        }
        real_close(owner);
    }
#ifdef ZAPRET_RUST_LUA_VM
    if (alternate) real_close(alternate);
    alternate = NULL;
#endif
    active = NULL;
    owner = NULL;
}
static void compare(bool existing,uint64_t interval,uint64_t now,uint64_t last){struct sample a={0},b={0};execute(false,existing,interval,now,last,NULL,&a);execute(true,existing,interval,now,last,NULL,&b);if(memcmp(&a,&b,sizeof(a))){fprintf(stderr,"DETAIL op=%u variant=%u mutation=%u existing=%u interval=%llu now=%llu last=%llu oldstatus=%d newstatus=%d oldok=%u newok=%u oldarity=%d newarity=%d oldlast=%llu newlast=%llu\noldmsg=%s\nnewmsg=%s\noldtrace=%s\nnewtrace=%s\noldlog=%s\nnewlog=%s\n",operation,variant,mutation,existing,(unsigned long long)interval,(unsigned long long)now,(unsigned long long)last,a.status,b.status,a.ok,b.ok,a.arity,b.arity,(unsigned long long)a.last,(unsigned long long)b.last,a.message,b.message,a.trace,b.trace,a.log,b.log);CHECK(false);}++cases;if(a.status)++errors;nested_calls+=a.nested;finalizers+=a.finalized;}
static void faults(void){operation=0;mutation=0;close_real=false;const unsigned variants[]={0,8,11,12,13,14,16,17,18,22};for(unsigned i=0;i<10;++i){variant=variants[i];for(unsigned side=0;side<2;++side)for(unsigned limit=0;limit<64;++limit){struct allocator a={.limit=limit};struct sample sample={0};execute(side!=0,false,1,100,0,&a,&sample);if(sample.status==LUA_ERRMEM){CHECK(a.rejected);++vm_faults;}CHECK(!a.live);++fault_cases;}}CHECK(vm_faults>20);}
#ifdef ZAPRET_RUST_LUA_VM
static void check_moving_vm(void)
{
    variant = 0;
    for (mutation = VERSION_REDIRECT; mutation <= COLLECT_REDIRECT; ++mutation) {
        bool existing = mutation >= SHUTDOWN_REDIRECT;
        operation = mutation == SHUTDOWN_REDIRECT ? 2 : mutation == COLLECT_REDIRECT ? 3 : 0;
        struct sample reference = {0}, rust = {0};
        execute(false, existing, 1, 100, 0, NULL, &reference);
        execute(true, existing, 1, 100, 0, NULL, &rust);
        CHECK(!memcmp(&reference, &rust, sizeof(rust)) && !rust.status);
        if (mutation == VERSION_REDIRECT) {
            CHECK(strstr(rust.trace, "libraries;alternate;register;alternate;"));
            CHECK(strstr(rust.log, "JIT: OFF soft 12\n") && !rust.alternate_top && rust.target == 2);
        } else if (mutation == JIT_REDIRECT) {
            CHECK(strstr(rust.log, "JIT: ON alternate flag\n"));
            CHECK(rust.arity == 5 && !rust.alternate_top && rust.target == 2);
        } else if (mutation == SHUTDOWN_REDIRECT) {
            CHECK(strstr(rust.trace, "detach;alternate;context;conntrack;timers;close;alternate;"));
            CHECK(rust.null_vm);
        } else {
            CHECK(strstr(rust.trace, "clock;count;collect;finalized;count;alternate;"));
            CHECK(rust.last == 100 && rust.target == 2);
        }
        ++redirected_cases;
    }
}

static void check_cleanup_ownership(void)
{
    const unsigned remaining[] = {7, 6, 4, 0};
    const char *errors[] = {"context cleanup failed", "connection pool cleanup failed",
        "timer pool cleanup failed"};
    variant = 0;
    for (operation = 1; operation <= 2; ++operation)
        for (mutation = RELEASE_CONTEXT_ERROR; mutation <= RELEASE_SUCCESS; ++mutation) {
            struct sample reference = {0}, rust = {0};
            execute(false, true, 1, 100, 0, NULL, &reference);
            execute(true, true, 1, 100, 0, NULL, &rust);
            CHECK(!memcmp(&reference, &rust, sizeof(rust)));
            unsigned index = mutation - RELEASE_CONTEXT_ERROR;
            CHECK(rust.resources == remaining[index]);
            if (mutation != RELEASE_SUCCESS) {
                CHECK(rust.status == LUA_ERRRUN && strstr(rust.message, errors[index]));
                CHECK(!rust.null_vm && !strstr(rust.trace, "close;"));
                ++protected_cleanup_errors;
            } else CHECK(!rust.status && rust.null_vm == (operation == 2));
            ++ownership_cases;
        }
}

static void check_parameter_cleanup(void)
{
    operation=4;
    variant=0;
    for(mutation=RELEASE_CONTEXT_ERROR;mutation<=RELEASE_SUCCESS+1;++mutation){
        bool existing=mutation<=RELEASE_SUCCESS;
        bool success=mutation>=RELEASE_SUCCESS;
        struct sample reference={0},rust={0};
        execute(false,existing,1,100,0,NULL,&reference);
        execute(true,existing,1,100,0,NULL,&rust);
        CHECK(!memcmp(&reference,&rust,sizeof(rust)));
        CHECK(rust.closed_parameter_releases==(unsigned)success);
        CHECK(supplied.debug!=success && rust.null_vm==success);
        if(success)CHECK(!rust.status && strstr(rust.trace,"closed-parameters;"));
        else CHECK(rust.status==LUA_ERRRUN && !strstr(rust.trace,"closed-parameters"));
        ++parameter_cleanup_pairs;
    }
}

static void actual_session(bool rust, struct sample *sample)
{
    active = sample;
    native_side = rust;
    actual_creation = close_real = true;
    variant = mutation = 0;
    memset(&params, 0, sizeof(params));
    CHECK(rust ? lua_basic_init() : reference_init());
    CHECK(params.L == owner && lua_gettop(owner) == 0);
    CHECK(strstr(sample->log, LUAJIT_VERSION) && strstr(sample->log, "JIT: "));
    create_owned_values(owner);
    lua_newuserdata(owner, 1);
    lua_newtable(owner);
    lua_pushcfunction(owner, finalized);
    lua_setfield(owner, -2, "__gc");
    lua_setmetatable(owner, -2);
    lua_pop(owner, 1);
    supplied.debug=true;
    if (rust) cleanup_params(&supplied);
    else reference_cleanup_params(&supplied);
    CHECK(!params.L && !params.ref_desync_ctx && !params.conntrack.pool && !params.timers);
    CHECK(sample->closed && sample->finalized == 1 && sample->closed_parameter_releases == 1);
    actual_creation = close_real = false;
    active = NULL;
    owner = NULL;
}
#endif
#ifndef ZAPRET_RUST_LUA_VM
static void boundary_checks(void){zapret_lua_vm_init state={0};zapret_lua_vm_feedback feedback={.ok=2};CHECK(zapret_lua_vm_init_step(&state,&feedback)==19 && state.phase==0);++boundaries;CHECK(zapret_lua_vm_init_step(NULL,&feedback)==19);++boundaries;CHECK(!zapret_lua_vm_created(&state,1));++boundaries;CHECK(zapret_lua_vm_cleanup_step(NULL,0,1)==9);++boundaries;CHECK(zapret_lua_vm_cleanup_step(&state.phase,2,1)==9);++boundaries;CHECK(zapret_lua_gc_step(NULL,0,0,0)==7);++boundaries;state.phase=11;state.index=INT_MAX;feedback.ok=1;CHECK(zapret_lua_vm_init_step(&state,&feedback)==19);++boundaries;}
#endif

int main(void)
{
    for (operation = 0; operation < 3; ++operation)
        for (variant = 0; variant < 26; ++variant)
            for (mutation = 0; mutation < 2; ++mutation)
                for (unsigned existing = 0; existing < 2; ++existing)
                    compare(existing != 0, 1, 100, 0);
    operation = 3;
    variant = 0;
    const uint64_t values[] = {0, 1, 10, 100, UINT64_MAX - 1, UINT64_MAX};
    for (mutation = 0; mutation < 7; ++mutation)
        for (unsigned interval = 0; interval < 6; ++interval)
            for (unsigned now = 0; now < 6; ++now)
                for (unsigned last = 0; last < 6; ++last)
                    compare(true, values[interval], values[now], values[last]);
    operation = 2;
    mutation = 0;
    close_real = true;
    for (variant = 0; variant < 4; ++variant) compare(true, 1, 100, 0);
    close_real = false;
    faults();
#ifdef ZAPRET_RUST_LUA_VM
    check_moving_vm();
    check_cleanup_ownership();
    check_parameter_cleanup();
    struct sample reference = {0}, rust = {0};
    actual_session(false, &reference);
    actual_session(true, &rust);
    CHECK(!memcmp(&reference, &rust, sizeof(rust)));
    printf("PASS windows_lua_vm cases=%u vm_errors=%u nested_calls=%u finalizers=%u actual_closes=%u "
        "fault_cases=%u vm_allocation_faults=%u redirected_vm_pairs=%u native_ownership_pairs=%u "
        "protected_cleanup_errors=%u parameter_cleanup_pairs=%u actual_startup_pairs=1 real_luajit=1 exact_stage_order=1 exact_jit_logging=1 "
        "deferred_gc_reads=1 unsigned_gc_elapsed=1 rust_seh_unwind=1 vm_allocations_released=1\n",
        cases, errors, nested_calls, finalizers, real_closes, fault_cases, vm_faults,
        redirected_cases, ownership_cases, protected_cleanup_errors, parameter_cleanup_pairs);
#else
    boundary_checks();
    printf("PASS lua_vm cases=%u vm_errors=%u nested_calls=%u finalizers=%u actual_closes=%u "
        "boundaries=%u fault_cases=%u vm_allocation_faults=%u real_luajit=1 exact_stage_order=1 "
        "exact_jit_logging=1 deferred_gc_reads=1 unsigned_gc_elapsed=1 c_only_unwind=1 vm_allocations_released=1\n",
        cases, errors, nested_calls, finalizers, real_closes, boundaries, fault_cases, vm_faults);
#endif
    return 0;
}
