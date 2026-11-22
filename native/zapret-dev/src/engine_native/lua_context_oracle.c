/* MIT. Actual LuaJIT comparison for execution context and cutoff policy. */
#include <iphlpapi.h>
#include "params.h"
#include "engine_lua.h"
#include <luajit.h>
#include <stdarg.h>
#undef main
struct params_s params;
static char diagnostics[4096];
static int diagnostic(const char *format,va_list args)
{
    size_t used=strlen(diagnostics);return vsnprintf(diagnostics+used,sizeof(diagnostics)-used,format,args);
}
int DLOG(const char *format,...){va_list args;va_start(args,format);int result=diagnostic(format,args);va_end(args);return result;}
int DLOG_ERR(const char *format,...){va_list args;va_start(args,format);int result=diagnostic(format,args);va_end(args);return result;}
#ifdef ZAPRET_DIRECT_LUA_CUTOFF
#define lua_check_argc fixture_check_argc
#define lua_check_argc_range fixture_check_argc_range
#endif
#include "lua_context_common.inc"
#ifdef ZAPRET_DIRECT_LUA_CUTOFF
#undef lua_check_argc
#undef lua_check_argc_range
void lua_check_argc(lua_State *L, const char *location, int count)
{
    fixture_check_argc(L, location, count);
}
void lua_check_argc_range(lua_State *L, const char *location, int min, int max)
{
    fixture_check_argc_range(L, location, min, max);
}
#endif
#define lua_desync_ctx reference_context
#define lua_desync_ctx_create reference_create
#define luacall_instance_cutoff reference_instance
#define lua_instance_cutoff_check reference_check
#define luacall_lua_cutoff reference_cutoff
#define luacall_execution_plan_cancel reference_cancel
#define luacall_raw_packet reference_packet
#include "lua_context_reference.inc"
#undef lua_desync_ctx
#undef lua_desync_ctx_create
#undef luacall_instance_cutoff
#undef lua_instance_cutoff_check
#undef luacall_lua_cutoff
#undef luacall_execution_plan_cancel
#undef luacall_raw_packet
#ifdef ZAPRET_DIRECT_LUA_CUTOFF
#define lua_desync_ctx staged_context
#define luacall_instance_cutoff staged_instance_cutoff
#define lua_instance_cutoff_check staged_instance_check
#define luacall_lua_cutoff staged_lua_cutoff
#define luacall_execution_plan_cancel staged_cancel
#endif
#include "lua_context_windows.inc"
#ifdef ZAPRET_DIRECT_LUA_CUTOFF
#undef lua_desync_ctx
#undef luacall_instance_cutoff
#undef lua_instance_cutoff_check
#undef luacall_lua_cutoff
#undef luacall_execution_plan_cancel
#include "windows_lua_cutoff_abi.h"

t_lua_desync_context *lua_desync_ctx(lua_State *L)
{
    return staged_context(L);
}
#endif
static unsigned cases,sequences,transitions,boundaries,guarded,callback_cases,fault_cases,vm_faults,repairs;
#define CHECK(v) do { if(!(v)){fprintf(stderr,"FAIL Lua context cases=%u bounds=%u line=%d: %s\n",cases,boundaries,__LINE__,#v);exit(1);} } while(0)
static void phase(const char *name){if(getenv("ZAPRET_CONTEXT_TRACE")){fprintf(stderr,"PHASE %s cases=%u\n",name,cases);fflush(stderr);}}
static struct desync_profile profile;
static t_ctrack track;
static struct dissect packet;
static t_lua_desync_context *current;
static uint8_t packet_data[8192];
static char instance[400];
static bool rust,tracked,check_incoming;
static unsigned operation,input_kind,argument_kind,argc,table_kind;
static const char *factory=
    "COMMON=function() end function SAME(a,b) if type(a)~=type(b) then return false end if type(a)~='table' then return a==b end "
    "local n=0 for k,v in pairs(a) do n=n+1;if not SAME(v,b[k]) then return false end end for _ in pairs(b) do n=n-1 end return n==0 end "
    "function SETUP(kind,key,n) TRACE={} local p={[0]=false,[1]=true} local t={[n]=p} local r={} "
    "if kind==1 then r[key]=false elseif kind==2 then r[key]={[n]=false} elseif kind==3 then r[key]=t "
    "elseif kind==4 then setmetatable(r,{__index=function(_,k) TRACE[#TRACE+1]='get:'..k;return false end}) "
    "elseif kind==5 then setmetatable(r,{__index=function(_,k) TRACE[#TRACE+1]='get:'..k;return t end}) "
    "elseif kind==6 then setmetatable(r,{__index=function(_,k) error('lookup failure') end}) "
    "elseif kind==7 then setmetatable(t,{__index=function(_,k) error('integer lookup must be raw') end});r[key]=t "
    "elseif kind==8 then setmetatable(r,{__index={[key]=t}}) "
    "elseif kind==9 then r[key]={[n]={[0]=COMMON,[1]=''}} elseif kind==10 then r=false "
    "elseif kind==11 then setmetatable(r,{__index=function(_,k) TRACE[#TRACE+1]='reenter:'..k;CANCEL(CTX);return nil end}) end return r end "
    "function SEQUENCE(ctx) INSTANCE(ctx,true);INSTANCE(ctx,false);INSTANCE(ctx);CUTOFF(ctx,true);CUTOFF(ctx,false);CANCEL(ctx);return RAW(ctx) end "
    "function CALLBACK(ctx) INSTANCE(ctx,true);CANCEL(ctx);error('callback failure') end";

static int cancel_binding(lua_State *L){return (rust?luacall_execution_plan_cancel:reference_cancel)(L);}
static int instance_binding(lua_State *L){return (rust?luacall_instance_cutoff:reference_instance)(L);}
static int cutoff_binding(lua_State *L){return (rust?luacall_lua_cutoff:reference_cutoff)(L);}
static int packet_binding(lua_State *L){return (rust?luacall_raw_packet:reference_packet)(L);}
static int dispatch(lua_State *L)
{
    switch(operation){
    case 0:return instance_binding(L);
    case 1:return cutoff_binding(L);
    case 2:return cancel_binding(L);
    case 3:return packet_binding(L);
    case 4:lua_pushboolean(L,(rust?lua_instance_cutoff_check:reference_check)(L,current,check_incoming));return 1;
    case 5:(rust?lua_desync_ctx_create:reference_create)(L);return 0;
    default:CHECK(false);return 0;
    }
}
static void register_bindings(lua_State *L)
{
    lua_pushcfunction(L,cancel_binding);lua_setglobal(L,"CANCEL");
    lua_pushcfunction(L,instance_binding);lua_setglobal(L,"INSTANCE");
    lua_pushcfunction(L,cutoff_binding);lua_setglobal(L,"CUTOFF");
    lua_pushcfunction(L,packet_binding);lua_setglobal(L,"RAW");
}
static void prepare(lua_State *L,unsigned seed)
{
    // LuaJIT lua_rawgeti takes a signed int. The pinned setter creates a
    // different key above INT_MAX and then raw-writes through nil (C API UB).
    // Exercise the full uint32 range in the VM-free transition/ABI matrix.
    static const uint32_t numbers[]={0,1,2,0x7fffffff,0x7ffffffe,65535};
    memset(&profile,0,sizeof(profile));memset(&track,0,sizeof(track));memset(&packet,0,sizeof(packet));
    profile.n=numbers[seed%6];track.lua_instance_cutoff=4096;
    track.b_lua_in_cutoff=(seed&1)!=0;track.b_lua_out_cutoff=(seed&2)!=0;
    memset(instance,'a'+seed%26,seed%3==0?399:7);instance[seed%3==0?399:7]=0;
    packet.data_pkt=packet_data;packet.len_pkt=seed%4==0?0:seed%4==1?1:seed%4==2?64:4096;
    lua_settop(L,0);diagnostics[0]=0;
    current=lua_newuserdata(L,sizeof(*current));memset(current,0,sizeof(*current));
    current->valid=input_kind!=4;current->func_n=seed;current->func="rule";current->instance=instance;
    current->dp=&profile;current->dis=&packet;current->ctrack=tracked?&track:NULL;current->incoming=(seed&4)!=0;current->cancel=(seed&8)!=0;
    luaL_getmetatable(L,"desync_ctx");lua_setmetatable(L,-2);lua_pushvalue(L,-1);lua_setglobal(L,"CTX");lua_pop(L,1);
    lua_getglobal(L,"SETUP");lua_pushinteger(L,table_kind);lua_pushstring(L,instance);lua_pushinteger(L,(int)profile.n);
    CHECK(!lua_pcall(L,3,1,0));lua_rawseti(L,LUA_REGISTRYINDEX,4096);
}
static void push_context(lua_State *L)
{
    switch(input_kind){
    case 1:lua_pushnil(L);break;
    case 2:lua_pushboolean(L,false);break;
    case 3:lua_newuserdata(L,sizeof(*current));break;
    case 5:lua_newtable(L);break;
    default:lua_getglobal(L,"CTX");break;
    }
}
static void push_arguments(lua_State *L)
{
    if(argc)push_context(L);
    if(argc>=2){
        switch(argument_kind){
        case 0:lua_pushnil(L);break;case 1:lua_pushboolean(L,true);break;case 2:lua_pushboolean(L,false);break;
        case 3:lua_pushinteger(L,1);break;case 4:lua_pushliteral(L,"true");break;
        case 5:lua_newtable(L);break;default:lua_pushcfunction(L,dispatch);break;
        }
    }
    for(unsigned i=2;i<argc;++i)lua_pushnil(L);
}
struct sample {int status,reference;char error[1024],log[4096];t_lua_desync_context context;bool in_cutoff,out_cutoff;};
static struct sample execute(lua_State *L,unsigned seed,bool native,bool sequence,bool callback)
{
    if(getenv("ZAPRET_CONTEXT_TRACE") && cases>=1700 && cases<2048){fprintf(stderr,"EXEC cases=%u seed=%u native=%u op=%u tracked=%u argc=%u arg=%u table=%u\n",cases,seed,native,operation,tracked,argc,argument_kind,table_kind);fflush(stderr);}
    struct sample sample={0};rust=native;prepare(L,seed);
    if(sequence || callback){lua_getglobal(L,callback?"CALLBACK":"SEQUENCE");push_context(L);}
    else{lua_pushcfunction(L,dispatch);push_arguments(L);}
    if(callback){if(rust)CHECK(zapret_lua_context_active(current,true));else current->valid=true;}
    sample.status=lua_pcall(L,sequence||callback?1:argc,LUA_MULTRET,0);
    if(callback){if(rust)CHECK(zapret_lua_context_active(current,false));else current->valid=false;CHECK(!current->valid);++callback_cases;}
    if(sample.status){snprintf(sample.error,sizeof(sample.error),"%s",lua_tostring(L,-1));lua_settop(L,0);}
    int results=lua_gettop(L);lua_newtable(L);
    for(int n=1;n<=results;++n){lua_pushvalue(L,n);lua_rawseti(L,-2,n);}
    lua_newtable(L);lua_pushvalue(L,-2);lua_setfield(L,-2,"results");
    lua_rawgeti(L,LUA_REGISTRYINDEX,4096);lua_setfield(L,-2,"cutoff");lua_getglobal(L,"TRACE");lua_setfield(L,-2,"trace");
    sample.reference=luaL_ref(L,LUA_REGISTRYINDEX);lua_settop(L,0);
    memcpy(&sample.context,current,sizeof(sample.context));sample.in_cutoff=track.b_lua_in_cutoff;sample.out_cutoff=track.b_lua_out_cutoff;
    strcpy(sample.log,diagnostics);return sample;
}
static void compare(lua_State *L,unsigned seed,bool sequence,bool callback)
{
    if(cases%1024==0)phase("compare");
    struct sample old=execute(L,seed,false,sequence,callback),native=execute(L,seed,true,sequence,callback);
    CHECK(old.status==native.status);
    if(strcmp(old.error,native.error)||strcmp(old.log,native.log)){
        fprintf(stderr,"DETAIL seed=%u op=%u argc=%u input=%u arg=%u table=%u old=%s new=%s oldlog=%s newlog=%s\n",seed,operation,argc,input_kind,argument_kind,table_kind,old.error,native.error,old.log,native.log);CHECK(false);
    }
    CHECK(!memcmp(&old.context,&native.context,sizeof(old.context)));
    CHECK(old.in_cutoff==native.in_cutoff && old.out_cutoff==native.out_cutoff);
    lua_getglobal(L,"SAME");lua_rawgeti(L,LUA_REGISTRYINDEX,old.reference);lua_rawgeti(L,LUA_REGISTRYINDEX,native.reference);
    CHECK(!lua_pcall(L,2,1,0));CHECK(lua_toboolean(L,-1));lua_settop(L,0);
    luaL_unref(L,LUA_REGISTRYINDEX,old.reference);luaL_unref(L,LUA_REGISTRYINDEX,native.reference);
    ++cases;if(sequence)++sequences;
}
static void transition_checks(void)
{
    const char *names[]={"","rule","raw\xff\xfe",instance};
    const size_t capacities[]={0,1,2,8,32,256,512};
    for(unsigned seed=0;seed<2048;++seed){
        t_lua_desync_context old,native;
        memset(&old,0xa5,sizeof(old));memset(&native,0xa5,sizeof(native));
        memset(&old,0,sizeof(old));CHECK(zapret_lua_context_init(&native));CHECK(!memcmp(&old,&native,sizeof(old)));++transitions;
        old.func_n=native.func_n=seed;old.func=native.func="old";old.instance=native.instance="old_instance";
        old.valid=native.valid=(seed&1)!=0;old.cancel=native.cancel=true;
        old.dp=&profile;old.ctrack=seed&2?&track:NULL;old.dis=&packet;old.incoming=(seed&4)!=0;old.cancel=false;
        CHECK(zapret_lua_context_prepare(&native,&profile,old.ctrack,&packet,old.incoming));CHECK(!memcmp(&old,&native,sizeof(old)));++transitions;
        profile.n=seed%3==0?0:seed%3==1?1:UINT32_MAX;
        for(unsigned cap=0;cap<7;++cap){
            char left[512],right[512];memset(left,0xa5,sizeof(left));memset(right,0xa5,sizeof(right));
            const char *name=names[seed%4];uint32_t number=seed&1?seed:UINT32_MAX;
            old.func=name;old.func_n=number;snprintf(left,capacities[cap],"%s_%u_%u",name,profile.n,number);old.instance=left;
            CHECK(zapret_lua_context_rule(&native,name,number,right,capacities[cap]));CHECK(native.instance==right);
            CHECK(!memcmp(left,right,sizeof(left)));old.instance=native.instance=NULL;
            CHECK(!memcmp(&old,&native,sizeof(old)));++transitions;
        }
        old.valid=true;CHECK(zapret_lua_context_active(&native,true));CHECK(zapret_lua_context_valid(&native,sizeof(native)));
        old.cancel=true;CHECK(zapret_lua_context_cancel(&native));CHECK(zapret_lua_context_cancelled(&native));
        old.valid=false;CHECK(zapret_lua_context_active(&native,false));CHECK(!zapret_lua_context_valid(&native,sizeof(native)));
        CHECK(!memcmp(&old,&native,sizeof(old)));++transitions;
    }
}
static void boundaries_check(void)
{
    _Alignas(8) uint8_t bytes[512]={0};t_lua_desync_context ctx={0};zapret_lua_context_scope_values scope;zapret_lua_context_span span;
    memset(&scope,0xa5,sizeof(scope));memset(&span,0xa5,sizeof(span));
#define BOUND(v) do{CHECK(v);++boundaries;}while(0)
    BOUND(!zapret_lua_context_init(NULL));BOUND(!zapret_lua_context_init((void *)(bytes+1)));
    BOUND(!zapret_lua_context_valid(NULL,sizeof(ctx)));BOUND(!zapret_lua_context_valid((void *)8,0));
    BOUND(!zapret_lua_context_prepare(NULL,NULL,NULL,NULL,false));BOUND(!zapret_lua_context_active(NULL,true));
    BOUND(!zapret_lua_context_rule(NULL,"f",1,(char *)bytes,sizeof(bytes)));
    BOUND(!zapret_lua_context_rule(&ctx,"f",1,(char *)bytes,sizeof(bytes)));
    BOUND(!zapret_lua_context_scope(NULL,0,true,&scope));BOUND(!zapret_lua_context_scope(&ctx,3,true,&scope));
    BOUND(!zapret_lua_context_scope(&ctx,0,true,NULL));BOUND(!zapret_lua_context_scope(&ctx,0,true,(void *)(bytes+1)));
    ctx.ctrack=(void *)(bytes+1);BOUND(!zapret_lua_context_scope(&ctx,0,true,&scope));
    BOUND(!zapret_lua_context_cutoff(&ctx,0));ctx.ctrack=NULL;
    BOUND(!zapret_lua_context_cutoff(&ctx,UINT32_MAX));BOUND(!zapret_lua_context_cancel(NULL));BOUND(!zapret_lua_context_cancelled(NULL));
    BOUND(!zapret_lua_context_packet(NULL,&span));BOUND(!zapret_lua_context_packet(&ctx,&span));
    ctx.dis=&packet;packet.data_pkt=NULL;packet.len_pkt=1;BOUND(!zapret_lua_context_packet(&ctx,&span));
    packet.data_pkt=packet_data;packet.len_pkt=SIZE_MAX;BOUND(!zapret_lua_context_packet(&ctx,&span));
    packet.len_pkt=0;BOUND(!zapret_lua_context_packet(&ctx,NULL));BOUND(!zapret_lua_context_packet(&ctx,(void *)(bytes+1)));
    for(unsigned i=0;i<sizeof(scope);++i)CHECK(((uint8_t *)&scope)[i]==0xa5);
    for(unsigned i=0;i<sizeof(span);++i)CHECK(((uint8_t *)&span)[i]==0xa5);
#undef BOUND
}
struct allocator {bool armed;unsigned calls,fail_after,rejected,live;};
static void *allocate(void *context,void *pointer,size_t previous,size_t next)
{
    struct allocator *a=context;if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}
    if(a->armed && next>previous && a->calls++>=a->fail_after){++a->rejected;return NULL;}
    bool fresh=!pointer;void *result=realloc(pointer,next);if(result && fresh)++a->live;return result;
}
static void fault_checks(void)
{
    unsigned observed[5][2]={{0}};
    for(unsigned op=0;op<5;++op)for(unsigned limit=0;limit<24;++limit)for(unsigned side=0;side<2;++side){
        struct allocator a={.fail_after=limit};lua_State *L=lua_newstate(allocate,&a);CHECK(L);params.L=L;
        luaL_openlibs(L);CHECK(!luaL_dostring(L,factory));luaL_newmetatable(L,"desync_ctx");lua_pop(L,1);register_bindings(L);
        rust=side!=0;operation=op==4?0:op==3?5:op==2?3:op;table_kind=op==4?11:0;tracked=true;input_kind=0;argc=operation==5?0:1;
        prepare(L,3);params.ref_desync_ctx=0;lua_pushcfunction(L,dispatch);push_arguments(L);
        if(rust)CHECK(zapret_lua_context_active(current,true));else current->valid=true;
        a.armed=true;int status=lua_pcall(L,argc,LUA_MULTRET,0);a.armed=false;
        if(rust)CHECK(zapret_lua_context_active(current,false));else current->valid=false;
        CHECK(!current->valid);
        if(status){CHECK(status==LUA_ERRMEM && a.rejected);++vm_faults;++observed[op][side];}else CHECK(!a.rejected);
        params.ref_desync_ctx=0;lua_close(L);CHECK(!a.live);++fault_cases;
    }
    params.L=NULL;
    for(unsigned op=0;op<5;++op)for(unsigned side=0;side<2;++side){
        if(op==1)CHECK(observed[op][side]==0);
        else CHECK(observed[op][side]>0);
    }
}
static void guarded_checks(void)
{
    uint8_t *memory=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(memory);
    uint8_t *end=memory+4096;DWORD old;CHECK(VirtualProtect(end,4096,PAGE_NOACCESS,&old));
    t_lua_desync_context *ctx=(void *)(end-sizeof(*ctx));memset(ctx,0,sizeof(*ctx));ctx->valid=true;
    CHECK(VirtualProtect(memory,4096,PAGE_READONLY,&old));
    for(unsigned n=0;n<1024;++n){CHECK(zapret_lua_context_valid(ctx,sizeof(*ctx)));zapret_lua_context_scope_values scope;CHECK(zapret_lua_context_scope(ctx,n%3,true,&scope));++guarded;}
    CHECK(VirtualProtect(memory,4096,PAGE_READWRITE,&old));memset(ctx,0,sizeof(*ctx));
    struct dissect *dis=(void *)(end-sizeof(*dis));memset(dis,0,sizeof(*dis));
    t_lua_desync_context separate={.dis=dis};zapret_lua_context_span span;
    dis->data_pkt=packet_data;dis->len_pkt=sizeof(packet_data);CHECK(VirtualProtect(memory,4096,PAGE_READONLY,&old));
    CHECK(zapret_lua_context_packet(&separate,&span));CHECK(span.data==packet_data && span.length==sizeof(packet_data));++guarded;
    CHECK(VirtualFree(memory,0,MEM_RELEASE));
}
static void constructor_checks(lua_State *L)
{
    for(unsigned side=0;side<2;++side){rust=side!=0;params.ref_desync_ctx=0;operation=5;argc=0;
        lua_settop(L,0);lua_pushcfunction(L,dispatch);CHECK(!lua_pcall(L,0,0,0));int reference=params.ref_desync_ctx;CHECK(reference>0);
        lua_rawgeti(L,LUA_REGISTRYINDEX,reference);t_lua_desync_context *ctx=lua_touserdata(L,-1);CHECK(ctx);
        t_lua_desync_context zero={0};CHECK(!memcmp(ctx,&zero,sizeof(zero)));lua_pop(L,1);
        (rust?lua_desync_ctx_create:reference_create)(L);CHECK(params.ref_desync_ctx==reference);
        lua_desync_ctx_destroy(L);CHECK(!params.ref_desync_ctx);lua_desync_ctx_destroy(L);++transitions;
    }
    rust=true;operation=2;argc=1;lua_settop(L,0);lua_pushcfunction(L,dispatch);
    lua_newuserdata(L,0);luaL_getmetatable(L,"desync_ctx");lua_setmetatable(L,-2);
    CHECK(lua_pcall(L,1,0,0)==LUA_ERRRUN);CHECK(strstr(lua_tostring(L,-1),"ctx is invalid"));lua_settop(L,0);++repairs;
}
#ifdef ZAPRET_DIRECT_LUA_CUTOFF
static struct desync_profile alternate_profile;
static unsigned cutoff_reentries;
static bool direct_instance_check;

static int mutate_cutoff_context(lua_State *L)
{
    (void)L;
    current->instance = "reentered";
    current->dp = &alternate_profile;
    ++cutoff_reentries;
    return 0;
}

static int check_during_lookup(lua_State *L)
{
    bool (*check)(lua_State *, const t_lua_desync_context *, bool) =
        direct_instance_check ? lua_instance_cutoff_check : staged_instance_check;
    lua_pushboolean(L, check(L, current, true));
    return 1;
}

static unsigned cutoff_reentry_checks(lua_State *L)
{
    const char *setup =
        "local p, name, read, fail = ... "
        "local prior = { [p] = { [1] = true }, [p+1] = { [1] = false } } "
        "return setmetatable({}, { __index = function(_,key) "
        "assert(key == name); MUTATE_CUTOFF_CONTEXT(); CANCEL_CUTOFF_CONTEXT(CTX); "
        "if fail then error('cutoff lookup failed') end; "
        "if read then return prior end end })";
    lua_pushcfunction(L, mutate_cutoff_context);
    lua_setglobal(L, "MUTATE_CUTOFF_CONTEXT");
    for (unsigned read = 0; read < 2; ++read) {
        for (unsigned fail = 0; fail < 2; ++fail) {
            char expected[sizeof(diagnostics)];
            for (unsigned direct = 0; direct < 2; ++direct) {
                tracked = true;
                input_kind = table_kind = 0;
                prepare(L, 1);
                alternate_profile.n = profile.n + 1;
                lua_pushcfunction(L, direct ? luacall_execution_plan_cancel : staged_cancel);
                lua_setglobal(L, "CANCEL_CUTOFF_CONTEXT");
                CHECK(!luaL_loadstring(L, setup));
                lua_pushinteger(L, profile.n);
                lua_pushstring(L, instance);
                lua_pushboolean(L, read);
                lua_pushboolean(L, fail);
                CHECK(!lua_pcall(L, 4, 1, 0));
                lua_rawseti(L, LUA_REGISTRYINDEX, 4096);

                direct_instance_check = direct != 0;
                lua_pushcfunction(L, read ? check_during_lookup :
                    direct ? luacall_instance_cutoff : staged_instance_cutoff);
                if (!read) lua_getglobal(L, "CTX");
                int status = lua_pcall(L, read ? 0 : 1, LUA_MULTRET, 0);
                CHECK(current->cancel && current->dp == &alternate_profile &&
                    !strcmp(current->instance, "reentered"));
                if (fail) {
                    CHECK(status == LUA_ERRRUN && lua_gettop(L) == 1);
                    CHECK(strstr(lua_tostring(L, -1), "cutoff lookup failed"));
                } else {
                    CHECK(!status && lua_gettop(L) == (int)read);
                    if (read) CHECK(lua_toboolean(L, -1));
                }
                if (!direct) strcpy(expected, diagnostics);
                else CHECK(!strcmp(expected, diagnostics));
                lua_settop(L, 0);

                // Inspect the registry by raw key so the check cannot reenter.
                lua_rawgeti(L, LUA_REGISTRYINDEX, 4096);
                lua_pushliteral(L, "reentered");
                lua_rawget(L, -2);
                CHECK(lua_isnil(L, -1));
                lua_pop(L, 1);
                lua_pushstring(L, instance);
                lua_rawget(L, -2);
                if (read || fail) CHECK(lua_isnil(L, -1));
                else {
                    CHECK(lua_istable(L, -1));
                    lua_rawgeti(L, -1, alternate_profile.n);
                    CHECK(lua_isnil(L, -1));
                    lua_pop(L, 1);
                    lua_rawgeti(L, -1, profile.n);
                    CHECK(lua_istable(L, -1));
                    lua_rawgeti(L, -1, 1);
                    CHECK(lua_toboolean(L, -1));
                }
                lua_settop(L, 0);
            }
        }
    }
    CHECK(cutoff_reentries == 8);
    return cutoff_reentries / 2;
}
#endif

int main(void)
{
    phase("start");
    for(unsigned n=0;n<sizeof(packet_data);++n)packet_data[n]=(uint8_t)(n*17);
    lua_State *L=luaL_newstate();CHECK(L);params.L=L;luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);
    CHECK(!luaL_dostring(L,factory));luaL_newmetatable(L,"desync_ctx");lua_pop(L,1);register_bindings(L);
    for(unsigned seed=0;seed<48;++seed)for(table_kind=0;table_kind<12;++table_kind)for(unsigned tracking=0;tracking<2;++tracking){
        tracked=tracking!=0;input_kind=0;
        for(operation=0;operation<2;++operation)for(argument_kind=0;argument_kind<7;++argument_kind){argc=2;compare(L,seed,false,false);}
        operation=4;argc=0;for(unsigned direction=0;direction<2;++direction){check_incoming=direction!=0;compare(L,seed,false,false);}
        operation=2;argc=1;compare(L,seed,false,false);operation=3;compare(L,seed,false,false);
    }
    phase("argument-errors");table_kind=0;tracked=true;
    for(operation=0;operation<4;++operation)for(input_kind=0;input_kind<6;++input_kind)for(argc=0;argc<4;++argc)for(argument_kind=0;argument_kind<7;++argument_kind)compare(L,1,false,false);
    phase("sequences");input_kind=0;argc=1;
    for(unsigned seed=0;seed<96;++seed){table_kind=seed%12;tracked=seed&1;compare(L,seed,true,false);compare(L,seed,false,true);}
#ifdef ZAPRET_DIRECT_LUA_CUTOFF
    unsigned reentries = cutoff_reentry_checks(L);
#endif
    phase("constructors");constructor_checks(L);lua_close(L);params.L=NULL;
    phase("transitions");transition_checks();phase("boundaries");boundaries_check();
    phase("guarded");guarded_checks();phase("allocation-faults");fault_checks();
#ifdef ZAPRET_DIRECT_LUA_CUTOFF
    printf("PASS windows_lua_cutoff direct_cutoff=1 reentry_pairs=%u retained_scope=1 ", reentries);
#else
    printf("PASS lua_context ");
#endif
    printf("functions=7 cases=%u sequences=%u transitions=%u callbacks=%u guarded=%u boundaries=%u vm_allocation_faults=%u fault_cases=%u userdata_size_repairs=%u real_luajit=1 lazy_lookup_order=1 vm_allocations_released=1\n",cases,sequences,transitions,callback_cases,guarded,boundaries,vm_faults,fault_cases,repairs);
    return 0;
}
