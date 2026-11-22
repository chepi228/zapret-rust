/* MIT. Compare argument substitution and execution plans inside real LuaJIT. */
#include <iphlpapi.h>
#include "params.h"
#include "engine_lua.h"
#include <luajit.h>
#include <stdarg.h>
#undef main
struct params_s params;
static char diagnostic[512];
int DLOG(const char *format,...){(void)format;return 0;}
int DLOG_ERR(const char *format,...){va_list args;va_start(args,format);vsnprintf(diagnostic,sizeof(diagnostic),format,args);va_end(args);return 0;}
#ifdef ZAPRET_RUST_LUA_EXECUTION_VIEW
#define lua_check_argc reference_check_argc
#define lua_desync_ctx reference_context
#define lua_pushf_range reference_range
#endif
#include "lua_execution_common.inc"
#ifdef ZAPRET_RUST_LUA_EXECUTION_VIEW
#undef lua_check_argc
#undef lua_desync_ctx
#undef lua_pushf_range
static void (*observe_range)(lua_State *, const struct packet_range *);
void lua_check_argc(lua_State *L, const char *where, int count)
{
    reference_check_argc(L, where, count);
}
t_lua_desync_context *lua_desync_ctx(lua_State *L)
{
    return reference_context(L);
}
void lua_pushf_range(lua_State *L, const char *name, const struct packet_range *range)
{
    if (observe_range) observe_range(L, range);
    reference_range(L, name, range);
}
#endif
#include "lua_instance_windows.inc"
#define lua_pushf_args reference_args
#define luacall_execution_plan reference_plan
#include "lua_execution_reference.inc"
#undef lua_pushf_args
#undef luacall_execution_plan
#ifdef ZAPRET_RUST_LUA_EXECUTION_VIEW
#define lua_pushf_args staged_args
#define luacall_execution_plan staged_plan
#endif
#include "lua_execution_view_windows.inc"
#ifdef ZAPRET_RUST_LUA_EXECUTION_VIEW
#undef lua_pushf_args
#undef luacall_execution_plan
#include "windows_lua_execution_view_abi.h"
#endif
static unsigned cases,argument_cases,plan_cases,boundaries,vm_faults,fault_cases;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL Lua execution cases=%u bounds=%u line=%d: %s\n",cases,boundaries,__LINE__,#v);exit(1);}}while(0)
static struct str2_list arguments[16],rule_arguments[8][4];
static struct str2_list_head args;
static struct func_list rules[8];
static struct desync_profile profile;
static bool substitute,negative_index;
static unsigned input_kind;
static uint32_t completed;
static bool incoming;
static const char *values[]={NULL,"","plain","%blob","#blob","\\%blob","\\#blob","\\\\%blob","%","#","\\","#missing","%missing","raw\xff\xfe","a%b#c","#blob"};
static const char *factory=
"COMMON_FUNCTION=function() end function DESYNC(id) TRACE={} _G.blob='global' _G.missing=nil _G['']='empty global' "
"local t={} if id==1 then t.blob='local'..string.char(0)..'bytes' elseif id==2 then t.blob=false elseif id==3 then t.blob=123.5 "
"elseif id==4 then t.blob={1,2,3} elseif id==5 then t.blob=COMMON_FUNCTION elseif id==6 then t.blob='' elseif id==7 then _G.blob=nil end "
"local log=TRACE; return setmetatable(t,{__index=function(_,key) log[#log+1]=key;if id==8 and key=='blob' then error('blob lookup failed') end;return nil end}) end "
"function SAME(a,b) if type(a)~=type(b) then return false end if type(a)~='table' then return a==b end local n=0 "
"for k,v in pairs(a) do n=n+1;if not SAME(v,b[k]) then return false end end for _ in pairs(b) do n=n-1 end return n==0 end";
static void prepare_args(unsigned count,unsigned offset,bool duplicate)
{
    static char names[16][16];memset(arguments,0,sizeof(arguments));LIST_INIT(&args);
    for(unsigned i=0;i<count;++i){snprintf(names[i],sizeof(names[i]),"arg%u",duplicate?i%3:i);arguments[i].str1=names[i];arguments[i].str2=(char *)values[(i+offset)%16];
        arguments[i].next.le_next=i+1<count?&arguments[i+1]:NULL;arguments[i].next.le_prev=i?&arguments[i-1].next.le_next:&args.lh_first;
    }if(count)args.lh_first=arguments;
}
static int invoke_args(lua_State *L,bool rust)
{
    int idx=negative_index?-1:1;bool ok=(rust?lua_pushf_args:reference_args)(L,&args,idx,substitute);
    CHECK(lua_gettop(L)==1);lua_pushboolean(L,ok);lua_pushvalue(L,1);return 2;
}
static int old_args(lua_State *L){return invoke_args(L,false);}static int new_args(lua_State *L){return invoke_args(L,true);}
static int old_plan(lua_State *L){return reference_plan(L);}static int new_plan(lua_State *L){return luacall_execution_plan(L);}
struct sample {int status,reference;char error[512],log[512],trace[1024];};
static void trace(lua_State *L,char *output,size_t capacity)
{
    size_t used=0;output[0]=0;lua_getglobal(L,"TRACE");
    for(unsigned i=1;;++i){lua_rawgeti(L,-1,i);if(lua_isnil(L,-1)){lua_pop(L,1);break;}const char *text=lua_tostring(L,-1);CHECK(text);size_t length=strlen(text);CHECK(used+length+2<capacity);memcpy(output+used,text,length);used+=length;output[used++]=';';output[used]=0;lua_pop(L,1);}lua_pop(L,1);
}
static void push_context(lua_State *L)
{
    if(input_kind==1){lua_pushnil(L);return;}if(input_kind==2){lua_pushinteger(L,1);return;}
    t_lua_desync_context *ctx=lua_newuserdata(L,sizeof(*ctx));memset(ctx,0,sizeof(*ctx));ctx->valid=input_kind!=3;ctx->dp=&profile;ctx->func_n=completed;ctx->incoming=incoming;
    luaL_getmetatable(L,"desync_ctx");lua_setmetatable(L,-2);
}
static struct sample execute(lua_State *L,unsigned id,bool plan,bool rust)
{
    struct sample result={0};lua_settop(L,0);diagnostic[0]=0;
    if(plan){lua_newtable(L);lua_setglobal(L,"TRACE");lua_pushcfunction(L,rust?new_plan:old_plan);push_context(L);}
    else{lua_pushcfunction(L,rust?new_args:old_args);lua_getglobal(L,"DESYNC");lua_pushinteger(L,id);CHECK(!lua_pcall(L,1,1,0));}
    result.status=lua_pcall(L,1,plan?1:2,0);
    if(result.status){const char *text=lua_tostring(L,-1);snprintf(result.error,sizeof(result.error),"%s",text?text:"");result.reference=LUA_NOREF;}
    else {lua_newtable(L);if(plan){lua_pushvalue(L,1);lua_rawseti(L,-2,1);}else{lua_pushvalue(L,1);lua_rawseti(L,-2,1);lua_pushvalue(L,2);lua_rawseti(L,-2,2);}result.reference=luaL_ref(L,LUA_REGISTRYINDEX);}
    strcpy(result.log,diagnostic);trace(L,result.trace,sizeof(result.trace));lua_settop(L,0);return result;
}
static void compare(lua_State *L,unsigned id,bool plan)
{
    struct sample old=execute(L,id,plan,false),rust=execute(L,id,plan,true);
    if(old.status!=rust.status || strcmp(old.error,rust.error) || strcmp(old.log,rust.log) || strcmp(old.trace,rust.trace)) {fprintf(stderr,"DETAIL plan=%u id=%u old=%d/%s rust=%d/%s traces=%s/%s\n",plan,id,old.status,old.error,rust.status,rust.error,old.trace,rust.trace);CHECK(false);}
    if(!old.status){lua_getglobal(L,"SAME");lua_rawgeti(L,LUA_REGISTRYINDEX,old.reference);lua_rawgeti(L,LUA_REGISTRYINDEX,rust.reference);CHECK(!lua_pcall(L,2,1,0));if(!lua_toboolean(L,-1)){fprintf(stderr,"DETAIL tables differ plan=%u id=%u\n",plan,id);CHECK(false);}luaL_unref(L,LUA_REGISTRYINDEX,old.reference);luaL_unref(L,LUA_REGISTRYINDEX,rust.reference);}
    lua_settop(L,0);++cases;if(plan)++plan_cases;else ++argument_cases;
}
static void prepare_plan(unsigned count,unsigned seed)
{
    static char names[8][400];const uint64_t masks[]={0,1,2,8,0x7fffffffULL,1ULL<<63,1ULL<<31,UINT64_MAX};
    memset(&profile,0,sizeof(profile));memset(rules,0,sizeof(rules));memset(rule_arguments,0,sizeof(rule_arguments));
    profile.n=seed%3==0?0:seed%3==1?1:UINT32_MAX;
    for(unsigned i=0;i<count;++i){size_t width=(seed%4==0)?399:3+i;memset(names[i],'a'+i,width);names[i][width]=0;rules[i].func=names[i];rules[i].payload_type=masks[(seed+i)%8];
        rules[i].range_in.from=(struct packet_pos){.mode='n',.pos=seed+i};rules[i].range_in.to=(struct packet_pos){.mode='b',.pos=UINT32_MAX-i};rules[i].range_in.upper_cutoff=(i&1)!=0;
        rules[i].range_out.from=(struct packet_pos){.mode='s',.pos=seed*17+i};rules[i].range_out.to=(struct packet_pos){.mode='x',.pos=i};rules[i].range_out.upper_cutoff=(i&1)==0;
        rules[i].args.lh_first=rule_arguments[i];for(unsigned k=0;k<4;++k){rule_arguments[i][k].str1=k&1?"duplicate":"other";rule_arguments[i][k].str2=(char *)values[(seed+i+k)%16];rule_arguments[i][k].next.le_next=k<3?&rule_arguments[i][k+1]:NULL;}
        rules[i].next.le_next=i+1<count?&rules[i+1]:NULL;
    }profile.lua_desync.lh_first=count?rules:NULL;
}
struct allocator {bool armed;unsigned calls,rejected,fail_after,live;};
static void *allocate(void *context,void *pointer,size_t previous,size_t next)
{
    struct allocator *a=context;if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}
    if(a->armed && next>previous && a->calls++>=a->fail_after){++a->rejected;return NULL;}
    bool fresh=!pointer;void *out=realloc(pointer,next);if(out && fresh)++a->live;return out;
}
static void fault_checks(void)
{
    for(unsigned mode=0;mode<3;++mode)for(unsigned limit=0;limit<32;++limit)for(unsigned side=0;side<2;++side){
        bool plan=mode==2;
        struct allocator a={0};a.fail_after=limit;lua_State *L=lua_newstate(allocate,&a);CHECK(L);params.L=L;luaL_openlibs(L);CHECK(!luaL_dostring(L,factory));luaL_newmetatable(L,"desync_ctx");lua_pop(L,1);
        input_kind=0;completed=0;incoming=true;prepare_plan(8,1);prepare_args(8,0,false);substitute=mode==1;negative_index=false;
        if(plan){lua_pushcfunction(L,side?new_plan:old_plan);push_context(L);}else{lua_pushcfunction(L,side?new_args:old_args);lua_getglobal(L,"DESYNC");lua_pushinteger(L,1);CHECK(!lua_pcall(L,1,1,0));}
        a.armed=true;int status=lua_pcall(L,1,plan?1:2,0);a.armed=false;if(status){CHECK(status==LUA_ERRMEM && a.rejected);++vm_faults;}else CHECK(!a.rejected);
        lua_close(L);CHECK(!a.live);++fault_cases;
    }params.L=NULL;CHECK(vm_faults>=64);
}
static void boundary_checks(void)
{
    zapret_lua_argument_view arg;const struct str2_list *a=NULL;zapret_lua_plan_cursor cursor;zapret_lua_plan_entry entry;_Alignas(8) uint8_t storage[400]={0};
    CHECK(zapret_lua_argument_view_next(NULL,false,&arg)==2);++boundaries;CHECK(zapret_lua_argument_view_next(&a,false,NULL)==2);++boundaries;
    CHECK(zapret_lua_argument_view_next(&a,false,&arg)==0);++boundaries;a=(void *)(storage+1);CHECK(zapret_lua_argument_view_next(&a,false,&arg)==2);++boundaries;
    CHECK(!zapret_lua_plan_begin(NULL,0,0,false,NULL));++boundaries;CHECK(!zapret_lua_plan_begin((void *)(storage+1),0,0,false,&cursor));++boundaries;
    CHECK(zapret_lua_plan_begin(NULL,0,0,false,&cursor) && zapret_lua_plan_next(&cursor,&entry)==0);++boundaries;
    CHECK(zapret_lua_plan_next(NULL,&entry)==2);++boundaries;CHECK(zapret_lua_plan_next(&cursor,NULL)==2);++boundaries;
    CHECK(zapret_lua_plan_begin(rules,0,0,false,&cursor));cursor.number=UINT32_MAX;CHECK(zapret_lua_plan_next(&cursor,&entry)==2);++boundaries;
    CHECK(!zapret_lua_plan_payload_next(0,NULL));++boundaries;uint32_t payload=UINT32_MAX;CHECK(!zapret_lua_plan_payload_next(UINT64_MAX,&payload));++boundaries;
    CHECK(zapret_lua_argument_view_next((void *)(storage+1),false,&arg)==2);++boundaries;
    CHECK(zapret_lua_argument_view_next(&a,false,(void *)(storage+1))==2);++boundaries;
    CHECK(!zapret_lua_plan_begin(NULL,0,0,false,(void *)(storage+1)));++boundaries;
    CHECK(zapret_lua_plan_next((void *)(storage+1),&entry)==2);++boundaries;
    CHECK(zapret_lua_plan_next(&cursor,(void *)(storage+1))==2);++boundaries;
    CHECK(!zapret_lua_plan_payload_next(0,(void *)(storage+1)));++boundaries;
}
#ifdef ZAPRET_RUST_LUA_EXECUTION_VIEW
static bool (*selected_args)(lua_State *, const struct str2_list_head *, int, bool);
static lua_CFunction selected_plan;
static bool missing_blob;
static unsigned argument_reentries, plan_reentries, retained_tables, guarded_plans;

static int reenter_arguments(lua_State *L)
{
    const char *key = lua_tostring(L, 2);
    CHECK(key);
    if (strcmp(key, "blob")) { lua_pushnil(L); return 1; }

    arguments[0].next.le_next = NULL;
    arguments[1].str2 = missing_blob ? "#fixture_missing_blob" : "updated";
    struct str2_list nested = {.str1 = "inner", .str2 = "nested"};
    const struct str2_list_head list = {.lh_first = &nested};
    lua_newtable(L);
    CHECK(selected_args(L, &list, -1, false));
    lua_getfield(L, -1, "arg");
    lua_getfield(L, -1, "inner");
    CHECK(!strcmp(lua_tostring(L, -1), "nested"));
    lua_pop(L, 3);
    ++argument_reentries;
    lua_pushliteral(L, "b\0lob");
    return 1;
}

static int invoke_alias_args(lua_State *L)
{
    bool ok = selected_args(L, &args, -1, true);
    CHECK(lua_gettop(L) == 1);
    lua_pushboolean(L, ok);
    lua_pushvalue(L, 1);
    return 2;
}

static void check_argument_aliases(lua_State *L)
{
    for (unsigned side = 0; side < 2; ++side) {
        selected_args = side ? lua_pushf_args : staged_args;
        for (unsigned failure = 0; failure < 2; ++failure) {
            missing_blob = failure != 0;
            prepare_args(3, 0, false);
            arguments[0].str2 = "%blob";
            arguments[2].str2 = "successor";
            lua_settop(L, 0);
            lua_pushnil(L);
            lua_setglobal(L, "fixture_missing_blob");
            diagnostic[0] = 0;
            lua_pushcfunction(L, invoke_alias_args);
            lua_newtable(L);
            lua_pushliteral(L, "existing");
            lua_setfield(L, -2, "arg");
            lua_newtable(L);
            lua_pushcfunction(L, reenter_arguments);
            lua_setfield(L, -2, "__index");
            CHECK(lua_setmetatable(L, -2));
            CHECK(!lua_pcall(L, 1, 2, 0));
            CHECK(lua_toboolean(L, 1) == !missing_blob);
            lua_getfield(L, 2, "arg");
            if (missing_blob) {
                CHECK(!strcmp(lua_tostring(L, -1), "existing"));
                CHECK(!strcmp(diagnostic, "blob 'fixture_missing_blob' unavailable\n"));
                ++retained_tables;
            } else {
                size_t length;
                lua_getfield(L, -1, "arg0");
                const char *bytes = lua_tolstring(L, -1, &length);
                CHECK(bytes && length == 5 && !memcmp(bytes, "b\0lob", length));
                lua_pop(L, 1);
                lua_getfield(L, -1, "arg1");
                CHECK(!strcmp(lua_tostring(L, -1), "updated"));
                lua_pop(L, 1);
                lua_getfield(L, -1, "arg2");
                CHECK(!strcmp(lua_tostring(L, -1), "successor"));
            }
        }
    }
    lua_settop(L, 0);
}

static void reenter_plan(lua_State *L, const struct packet_range *range)
{
    CHECK(range == &rules[0].range_in);
    observe_range = NULL;
    rules[0].range_in.from.pos = 9001;
    rules[0].payload_type = 0;
    rules[0].next.le_next = NULL;
    rule_arguments[1][0].str2 = "updated";
    lua_pushcfunction(L, selected_plan);
    lua_pushvalue(L, 1);
    CHECK(!lua_pcall(L, 1, 1, 0) && lua_objlen(L, -1) == 1);
    lua_pop(L, 1);
    ++plan_reentries;
}

static void check_plan_aliases(lua_State *L)
{
    for (unsigned side = 0; side < 2; ++side) {
        selected_plan = side ? luacall_execution_plan : staged_plan;
        input_kind = completed = 0;
        incoming = true;
        prepare_plan(2, 1);
        rules[0].payload_type = L7P_ALL;
        rule_arguments[1][0].str1 = "late";
        lua_settop(L, 0);
        lua_pushcfunction(L, selected_plan);
        push_context(L);
        observe_range = reenter_plan;
        CHECK(!lua_pcall(L, 1, 1, 0) && !observe_range && lua_objlen(L, 1) == 2);
        lua_rawgeti(L, 1, 1);
        lua_getfield(L, -1, "payload");
        lua_getfield(L, -1, "all");
        CHECK(lua_toboolean(L, -1));
        lua_pop(L, 2);
        lua_getfield(L, -1, "range");
        lua_getfield(L, -1, "from");
        lua_getfield(L, -1, "pos");
        CHECK(lua_tointeger(L, -1) == 9001);
        lua_settop(L, 1);
        lua_rawgeti(L, 1, 2);
        lua_getfield(L, -1, "arg");
        lua_getfield(L, -1, "late");
        CHECK(!strcmp(lua_tostring(L, -1), "updated"));

        _Alignas(8) unsigned char misaligned[16] = {0};
        prepare_plan(1, 1);
        rules[0].args.lh_first = (void *)(misaligned + 1);
        lua_settop(L, 0);
        lua_pushcfunction(L, selected_plan);
        push_context(L);
        CHECK(!lua_pcall(L, 1, 1, 0) && lua_objlen(L, 1) == 1);
        lua_rawgeti(L, 1, 1);
        lua_getfield(L, -1, "arg");
        CHECK(lua_isnil(L, -1));
        lua_pop(L, 1);
        lua_getfield(L, -1, "func");
        CHECK(!strcmp(lua_tostring(L, -1), rules[0].func));
        ++guarded_plans;

        lua_settop(L, 0);
        lua_pushcfunction(L, selected_plan);
        push_context(L);
        ((t_lua_desync_context *)lua_touserdata(L, -1))->dp = NULL;
        CHECK(lua_pcall(L, 1, 1, 0) == LUA_ERRRUN);
        CHECK(strstr(lua_tostring(L, -1), "invalid execution plan state"));
        ++guarded_plans;
    }
    lua_settop(L, 0);
}
#endif
static double measure(lua_State *L,unsigned mode,bool rust)
{
    LARGE_INTEGER start,end,frequency;CHECK(QueryPerformanceFrequency(&frequency));CHECK(QueryPerformanceCounter(&start));
    for(unsigned i=0;i<4096;++i){lua_settop(L,1);if(mode==2)(rust?luacall_execution_plan:reference_plan)(L);else CHECK((rust?lua_pushf_args:reference_args)(L,&args,1,mode==1));}
    lua_settop(L,1);CHECK(QueryPerformanceCounter(&end));return (double)(end.QuadPart-start.QuadPart)*1e9/(double)frequency.QuadPart/4096;
}
static void benchmark(void)
{
    for(unsigned mode=0;mode<3;++mode){lua_State *L=luaL_newstate();CHECK(L);params.L=L;luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);luaL_newmetatable(L,"desync_ctx");lua_pop(L,1);
        input_kind=0;completed=2;incoming=true;prepare_plan(8,1);prepare_args(8,0,false);
        if(mode==2)push_context(L);else{lua_newtable(L);lua_pushliteral(L,"binary blob");lua_setfield(L,-2,"blob");}
        measure(L,mode,false);measure(L,mode,true);
        for(unsigned round=0;round<9;++round){double old,rust;if(round&1){rust=measure(L,mode,true);old=measure(L,mode,false);}else{old=measure(L,mode,false);rust=measure(L,mode,true);}printf("BENCH lua_execution_view mode=%u round=%u old_ns=%.3f rust_ns=%.3f ratio=%.5f\n",mode,round,old,rust,rust/old);}
        params.L=NULL;lua_close(L);
    }
}
int main(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"--benchmark")){benchmark();return 0;}
    lua_State *L=luaL_newstate();CHECK(L);params.L=L;luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);CHECK(!luaL_dostring(L,factory));luaL_newmetatable(L,"desync_ctx");lua_pop(L,1);
    for(unsigned count=0;count<=16;++count)for(unsigned offset=0;offset<16;++offset)for(unsigned duplicate=0;duplicate<2;++duplicate){prepare_args(count,offset,duplicate!=0);
        for(unsigned flags=0;flags<4;++flags){substitute=flags&1;negative_index=flags&2;for(unsigned id=0;id<9;++id)compare(L,id,false);}
    }
    for(unsigned offset=0;offset<16;++offset)for(unsigned flag=0;flag<2;++flag){prepare_args(1,offset,false);arguments[0].str1=NULL;substitute=flag!=0;for(unsigned id=0;id<9;++id)compare(L,id,false);}
    uint8_t *guard=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(guard);uint8_t *end=guard+4096;DWORD protection;CHECK(VirtualProtect(end,4096,PAGE_NOACCESS,&protection));
    const char *tiny[]={"","%","#","\\","\\%","\\#","%blob","\xff"};
    for(unsigned n=0;n<8;++n){size_t length=strlen(tiny[n])+1;char *text=(char *)end-length;memcpy(text,tiny[n],length);for(unsigned flag=0;flag<2;++flag){prepare_args(1,0,false);arguments[0].str2=text;substitute=flag!=0;for(unsigned id=0;id<9;++id)compare(L,id,false);}}CHECK(VirtualFree(guard,0,MEM_RELEASE));
    const uint32_t positions[]={0,1,2,7,8,9,UINT32_MAX};
    input_kind=0;for(unsigned count=0;count<=8;++count)for(unsigned seed=0;seed<24;++seed){prepare_plan(count,seed);for(unsigned p=0;p<7;++p)for(unsigned direction=0;direction<2;++direction){completed=positions[p];incoming=direction!=0;compare(L,seed,true);}}
    for(input_kind=1;input_kind<=3;++input_kind)compare(L,0,true);input_kind=0;
#ifdef ZAPRET_RUST_LUA_EXECUTION_VIEW
    check_argument_aliases(L);
    check_plan_aliases(L);
#endif
    boundary_checks();params.L=NULL;lua_close(L);fault_checks();
#ifdef ZAPRET_RUST_LUA_EXECUTION_VIEW
    printf("PASS windows_lua_execution_view rust_seh_unwind=1 argument_reentries=%u plan_reentries=%u "
        "retained_tables=%u guarded_plans=%u ", argument_reentries, plan_reentries, retained_tables, guarded_plans);
#else
    printf("PASS lua_execution_view ");
#endif
    printf("argument_cases=%u plan_cases=%u boundaries=%u vm_allocation_faults=%u fault_cases=%u real_luajit=1 lazy_blob_lookup=1 vm_allocations_released=1\n",
        argument_cases,plan_cases,boundaries,vm_faults,fault_cases);
    return 0;
}
