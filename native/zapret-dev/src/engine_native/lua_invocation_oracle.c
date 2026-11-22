/* MIT. Full desync dispatch through the real LuaJIT VM and Rust rule/context ABI. */
#include <iphlpapi.h>
#include "params.h"
#include "engine_lua.h"
#include "nfqws.h"
#include <luajit.h>
#include <limits.h>
#include <stdarg.h>
#undef main
struct params_s params;
#include "packet_range_windows.inc"
#include "packet_verdict_windows.inc"
#include "lua_rules_abi.h"
#include "lua_context_windows.h"
#include "lua_packet_arguments_windows.h"
static unsigned cases,result_cases,fault_cases,vm_faults,handled_faults,boundaries,guarded,reentry_cases,reconstruct_cases;
static unsigned seed,variant,operation,nesting,calls,lookups,reconstructed,collected;
static bool native_side,benchmarking;
static char diagnostic[65536],trace[8192];
static struct desync_profile profile;
static struct func_list rules[4];
static struct str2_list arguments[4];
static t_ctrack track;
static struct dissect packet;
static struct tcphdr tcp;
static t_lua_desync_context *context;
static uint8_t wire[64],modified[64];
static size_t modified_length;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL Lua invocation op=%u variant=%u seed=%u line=%d: %s\n",operation,variant,seed,__LINE__,#v);exit(1);}}while(0)
static int log_message(const char *format,va_list args)
{size_t used=strlen(diagnostic);CHECK(used<sizeof(diagnostic));int out=vsnprintf(diagnostic+used,sizeof(diagnostic)-used,format,args);CHECK(out>=0 && (size_t)out<sizeof(diagnostic)-used);return out;}
int DLOG(const char *format,...){if(benchmarking)return 0;va_list args;va_start(args,format);int out=log_message(format,args);va_end(args);return out;}
int DLOG_ERR(const char *format,...){if(benchmarking)return 0;va_list args;va_start(args,format);int out=log_message(format,args);va_end(args);return out;}
static void event(const char *name,unsigned number)
{if(benchmarking)return;size_t used=strlen(trace);int out=snprintf(trace+used,sizeof(trace)-used,"%u:%s:%u;",nesting,name,number);CHECK(out>=0 && (size_t)out<sizeof(trace)-used);}
#include "lua_invocation_common.inc"
#include "lua_rules_windows.inc"
static void native_lua_packet_arguments(const zapret_lua_packet_argument_input *input,const t_ctrack *current,const t_ctrack_positions *positions)
{
    (void)current;(void)positions;
    CHECK(input->profile==&profile && input->packet==&packet);
    lua_newtable(params.L);lua_pushf_table(params.L,"dis");lua_pushf_str(params.L,"blob","\0binary\xff");
    lua_pushf_int(params.L,"profile_n",input->profile->n);lua_pushf_bool(params.L,"outgoing",!input->incoming);
}
bool lua_reconstruct_dissect(lua_State *L,int index,uint8_t *output,size_t *length,bool keepsum,bool badsum,uint8_t next,bool preserve)
{
    CHECK(!keepsum && !badsum && next==IPPROTO_NONE);++reconstructed;event("reconstruct",preserve);
    lua_getfield(L,index,"fail");bool failed=lua_toboolean(L,-1);lua_pop(L,1);if(failed || *length<8)return false;
    memset(output,0x3c,8);output[0]=(uint8_t)calls;output[1]=(uint8_t)preserve;*length=8;return true;
}
#define desync_get_result reference_result
#define desync reference_desync
#include "lua_invocation_reference.inc"
#undef desync_get_result
#undef desync
#include "lua_invocation_result_windows.inc"
#include "lua_invocation_windows.inc"
#define desync candidate_desync
#include "lua_invocation_candidate.inc"
#undef desync
static int dispatch(lua_State *L);
static int inspect(lua_State *L)
{
    unsigned id=(unsigned)lua_tointeger(L,1);t_lua_desync_context *ctx=lua_touserdata(L,2);CHECK(ctx==context && ctx->valid);++calls;event("call",id);
    lua_getfield(L,3,"func_n");CHECK((unsigned)lua_tointeger(L,-1)==ctx->func_n);lua_pop(L,1);
    lua_getfield(L,3,"func");CHECK(!strcmp(lua_tostring(L,-1),ctx->func));lua_pop(L,1);
    lua_getfield(L,3,"func_instance");CHECK(!strcmp(lua_tostring(L,-1),ctx->instance));lua_pop(L,1);
    if(variant==1 && id==1+seed%3)CHECK(zapret_lua_context_cancel(ctx));
    if(variant==2 && id==1){rules[1].range_in.from.mode=rules[1].range_out.from.mode='x';rules[2].func="missing_function";params.debug=!params.debug;}
    if(variant==3){
        if(seed%3==0){lua_pushboolean(L,false);lua_setfield(L,3,"dis");}
        else if(seed%3==1){lua_getfield(L,3,"dis");lua_pushboolean(L,true);lua_setfield(L,-2,"fail");lua_pop(L,1);}
    }
    if(variant==4)return luaL_error(L,"handler inspect failure");
    if(variant==5 && !nesting){
        int before=lua_gettop(L);nesting=1;lua_pushcfunction(L,dispatch);lua_call(L,0,1);lua_pop(L,1);nesting=0;CHECK(lua_gettop(L)==before);++reentry_cases;
    }
    if(variant==10)lua_gc(L,LUA_GCCOLLECT,0);
    return 0;
}
static int lookup(lua_State *L)
{
    ++lookups;event("lookup",(unsigned)lua_objlen(L,1));
    if(variant==9){if(seed&1)return luaL_error(L,"cutoff lookup failure");CHECK(zapret_lua_context_cancel(context));}
    if(variant==6 && seed%4==0)return luaL_error(L,"function lookup failure");
    return 0;
}
static int finalizer(lua_State *L){(void)L;++collected;event("gc",0);rules[2].payload_type=UINT64_C(1)<<L7P_LAST;return 0;}
static const char *factory=
    "function RESULT(k) "
    "if k==0 then return elseif k==1 then return nil elseif k<10 then return k-2 elseif k==10 then return 8 elseif k==11 then return -1 "
    "elseif k==12 then return 1.75 elseif k==13 then return '2.7' elseif k==14 then return '7' elseif k==15 then return 'bad' "
    "elseif k==16 then return false elseif k==17 then return {} elseif k==18 then return function()end elseif k==19 then return nil,1 "
    "elseif k==20 then return 0/0 elseif k==21 then return 1/0 elseif k==22 then return 2^63 elseif k==23 then return '0x2' "
    "elseif k==24 then return ' 4 ' elseif k==25 then return 7.9 elseif k==26 then return VALUE_CTX elseif k==27 then return true "
    "elseif k==28 then return -0.5 elseif k==29 then return '1e0' elseif k==30 then error('handler failure') else error({}) end end "
    "function BODY(id,ctx,a) INSPECT(id,ctx,a);if MODE==3 then return 5 elseif MODE==8 then return id==1 and 5 or id==2 and 2 or 0 end return RESULT((SEED+id)%32)end "
    "function F1(ctx,a)return BODY(1,ctx,a)end function F2(ctx,a)return BODY(2,ctx,a)end function F3(ctx,a)return BODY(3,ctx,a)end "
    "function SET_LOOKUP() F1=nil;setmetatable(_G,{__index=function(_,name)LOOKUP(name);if SEED%4==1 then return false elseif SEED%4==2 then return function(ctx,a)return BODY(1,ctx,a)end end end})end "
    "function CUTOFF_ROOT()return setmetatable({},{__index=function(_,name)LOOKUP(name);return nil end})end";
static void prepare(lua_State *L)
{
    memset(&params,0,sizeof(params));memset(&profile,0,sizeof(profile));memset(&track,0,sizeof(track));memset(&packet,0,sizeof(packet));memset(rules,0,sizeof(rules));memset(arguments,0,sizeof(arguments));
    params.L=L;params.debug=!!(seed&1);params.server=!!(seed&2);calls=lookups=reconstructed=collected=nesting=0;diagnostic[0]=trace[0]=0;
    lua_pushcfunction(L,luaopen_base);lua_call(L,0,0);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);lua_gc(L,LUA_GCSTOP,0);
    lua_pushcfunction(L,inspect);lua_setglobal(L,"INSPECT");lua_pushcfunction(L,lookup);lua_setglobal(L,"LOOKUP");
    CHECK(!luaL_dostring(L,factory));lua_pushinteger(L,seed);lua_setglobal(L,"SEED");lua_pushinteger(L,variant);lua_setglobal(L,"MODE");
    luaL_newmetatable(L,"desync_ctx");lua_pop(L,1);context=lua_newuserdata(L,sizeof(*context));CHECK(zapret_lua_context_init(context));luaL_getmetatable(L,"desync_ctx");lua_setmetatable(L,-2);
    lua_pushvalue(L,-1);lua_setglobal(L,"VALUE_CTX");params.ref_desync_ctx=luaL_ref(L,LUA_REGISTRYINDEX);
    if(variant==9){lua_getglobal(L,"CUTOFF_ROOT");CHECK(!lua_pcall(L,0,1,0));}else lua_newtable(L);
    track.lua_instance_cutoff=luaL_ref(L,LUA_REGISTRYINDEX);
    profile.n=seed%17;profile.name="invocation";
    track.pos.client.pcounter=seed%8;track.pos.server.pcounter=(seed/8)%8;
    if(seed%29==0)track.b_lua_in_cutoff=track.b_lua_out_cutoff=true;
    unsigned count=seed%4;profile.lua_desync.lh_first=count?rules:NULL;
    const char *texts[]={"plain","%blob","#blob","%missing_blob","#missing_blob","literal"};
    for(unsigned n=0;n<count;++n){
        struct func_list *rule=&rules[n];rule->func=n==0?"F1":n==1?"F2":"F3";rule->next.le_next=n+1<count?&rules[n+1]:NULL;
        rule->range_in.from.mode=rule->range_in.to.mode=rule->range_out.from.mode=rule->range_out.to.mode='a';
        if(seed%11==0 && n==0)rule->range_in.from.mode=rule->range_out.from.mode='x';
        if(seed%7==0 && n==1){rule->range_in.to.mode=rule->range_out.to.mode='n';rule->range_in.to.pos=rule->range_out.to.pos=1;}
        rule->payload_type=seed%5==0 && n==0?UINT64_C(1)<<L7P_HTTP_REQ:0;
        arguments[n].str1="value";arguments[n].str2=(char *)texts[(seed+n)%6];rule->args.lh_first=&arguments[n];
        if(variant==7)arguments[n].str2="%missing_blob";
        if(seed%13==0){
            char name[256];zapret_lua_context_prepare(context,&profile,&track,&packet,false);CHECK(zapret_lua_context_rule(context,rule->func,n+1,name,sizeof(name)));
            lua_rawgeti(L,LUA_REGISTRYINDEX,track.lua_instance_cutoff);lua_pushf_table(L,name);lua_getfield(L,-1,name);lua_pushi_table(L,profile.n);lua_rawgeti(L,-1,profile.n);
            lua_pushboolean(L,true);lua_rawseti(L,-2,seed&4?1:0);lua_pop(L,3);
        }
    }
    if(variant==6){lua_getglobal(L,"SET_LOOKUP");CHECK(!lua_pcall(L,0,0,0));}
    if(variant==10){lua_newuserdata(L,1);lua_newtable(L);lua_pushcfunction(L,finalizer);lua_setfield(L,-2,"__gc");lua_setmetatable(L,-2);lua_pop(L,1);}
    packet.data_pkt=wire;packet.len_pkt=40;packet.tcp=&tcp;modified_length=sizeof(modified);memset(modified,0xa5,sizeof(modified));
    CHECK(zapret_lua_context_prepare(context,&profile,seed&8?&track:NULL,&packet,!!(seed&4)));CHECK(zapret_lua_context_active(context,false));
    diagnostic[0]=trace[0]=0;
}
static int dispatch(lua_State *L)
{
    if(operation==1){
        lua_getglobal(L,"RESULT");lua_pushinteger(L,seed%30);lua_call(L,1,LUA_MULTRET);
        uint8_t verdict=99;bool ok=(native_side?desync_get_result:reference_result)(&verdict);CHECK(!lua_gettop(L));
        lua_pushboolean(L,ok);lua_pushinteger(L,verdict);return 2;
    }
    uint8_t verdict=(native_side?candidate_desync:reference_desync)(&profile,seed,"Wi-Fi",NULL,!!(seed&4),seed&8?&track:NULL,seed&16?&track.pos:NULL,
        seed%L7P_LAST,seed%L7_LAST,&packet,NULL,NULL,443,modified,&modified_length,0,0,0,NULL,0,NULL,0);
    CHECK(!lua_gettop(L));lua_pushinteger(L,verdict);return 1;
}
struct allocator {bool armed;unsigned limit,calls,rejected,live;};
static void *allocate(void *context,void *pointer,size_t previous,size_t next)
{
    struct allocator *a=context;if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}
    if(a->armed && next>previous && a->calls++>=a->limit){++a->rejected;return NULL;}
    bool fresh=!pointer;void *out=realloc(pointer,next);if(out && fresh)++a->live;return out;
}
struct sample {int status,stack,verdict,ok;char error[512],log[65536],trace[8192];unsigned calls,lookups,reconstructed,collected,rejected,number,registry;bool valid,cancelled,in_cutoff,out_cutoff;size_t length;uint8_t bytes[64];};
static struct sample left,right,fault_reference;
static void execute(bool native,unsigned limit,struct sample *out)
{
    if(getenv("ZAPRET_INVOCATION_TRACE") && limit!=UINT_MAX){fprintf(stderr,"START side=%u seed=%u limit=%u\n",native,seed,limit);fflush(stderr);}
    struct allocator a={.limit=limit};lua_State *L=lua_newstate(allocate,&a);CHECK(L);native_side=native;prepare(L);
    lua_pushcfunction(L,dispatch);a.armed=limit!=UINT_MAX;out->status=lua_pcall(L,0,LUA_MULTRET,0);a.armed=false;
    if(getenv("ZAPRET_INVOCATION_TRACE") && limit!=UINT_MAX){fprintf(stderr,"CAPTURE side=%u seed=%u limit=%u status=%d\n",native,seed,limit,out->status);fflush(stderr);}
    out->stack=lua_gettop(L);out->error[0]=0;out->verdict=-1;out->ok=-1;
    if(out->status){const char *text=lua_tostring(L,-1);snprintf(out->error,sizeof(out->error),"%s",text?text:"nonstring error");}
    else {CHECK(out->stack==(operation==1?2:1));out->verdict=(int)lua_tointeger(L,-1);if(operation==1)out->ok=lua_toboolean(L,1);}
    if(getenv("ZAPRET_INVOCATION_TRACE") && limit!=UINT_MAX){fprintf(stderr,"REGISTRY side=%u seed=%u limit=%u\n",native,seed,limit);fflush(stderr);}
    // Failed LuaJIT table growth can leave lua_next cycling even in the pinned
    // C reference. Inspect registry ownership in the no-fault matrix; fault
    // runs instead verify the live context and allocator balance at VM close.
    out->registry=0;
    if(limit==UINT_MAX){unsigned entries=0;lua_pushnil(L);while(lua_next(L,LUA_REGISTRYINDEX)){CHECK(++entries<512);if(lua_type(L,-2)==LUA_TNUMBER && lua_tointeger(L,-2)>0 && lua_type(L,-1)!=LUA_TNUMBER)++out->registry;lua_pop(L,1);}}
    if(getenv("ZAPRET_INVOCATION_TRACE") && limit!=UINT_MAX){fprintf(stderr,"READ_CONTEXT side=%u seed=%u limit=%u\n",native,seed,limit);fflush(stderr);}
    out->number=context->func_n;out->valid=context->valid;out->cancelled=context->cancel;out->in_cutoff=track.b_lua_in_cutoff;out->out_cutoff=track.b_lua_out_cutoff;
    CHECK(!out->valid);out->calls=calls;out->lookups=lookups;out->reconstructed=reconstructed;out->rejected=a.rejected;out->length=modified_length;memcpy(out->bytes,modified,sizeof(modified));
    strcpy(out->log,diagnostic);strcpy(out->trace,trace);
    if(getenv("ZAPRET_INVOCATION_TRACE") && limit!=UINT_MAX){fprintf(stderr,"CLOSE side=%u seed=%u limit=%u\n",native,seed,limit);fflush(stderr);}
    lua_close(L);CHECK(!a.live);out->collected=collected;
}
static void compare(unsigned limit)
{
    if(getenv("ZAPRET_INVOCATION_TRACE") && (seed%32==0 || limit==0)){fprintf(stderr,"CASE op=%u variant=%u seed=%u limit=%u\n",operation,variant,seed,limit);fflush(stderr);}
    execute(false,limit,&left);execute(true,limit,&right);
    if(limit!=UINT_MAX){
        const struct sample *samples[]={&left,&right};
        for(unsigned i=0;i<2;++i){const struct sample *s=samples[i];CHECK(s->stack==1 && !s->valid);CHECK(!strncmp(fault_reference.trace,s->trace,strlen(s->trace)));
            if(s->status){CHECK(s->status==LUA_ERRMEM && s->rejected);++vm_faults;}
            else if(s->rejected){CHECK(s->verdict==VERDICT_PASS || s->verdict==fault_reference.verdict);++handled_faults;}
            else {CHECK(s->verdict==fault_reference.verdict && !strcmp(s->log,fault_reference.log) && !strcmp(s->trace,fault_reference.trace));}
        }++fault_cases;return;
    }
    if(left.status!=right.status || left.stack!=right.stack || left.verdict!=right.verdict || left.ok!=right.ok || strcmp(left.error,right.error) || strcmp(left.log,right.log) || strcmp(left.trace,right.trace)){
        fprintf(stderr,"DETAIL status=%d/%d result=%d/%d ok=%d/%d error=%s/%s\noldlog=%s\nnewlog=%s\noldtrace=%s\nnewtrace=%s\n",left.status,right.status,left.verdict,right.verdict,left.ok,right.ok,left.error,right.error,left.log,right.log,left.trace,right.trace);CHECK(false);
    }
    CHECK(left.calls==right.calls && left.lookups==right.lookups && left.reconstructed==right.reconstructed && left.registry==right.registry && left.collected==right.collected);
    CHECK(left.number==right.number && left.cancelled==right.cancelled && left.in_cutoff==right.in_cutoff && left.out_cutoff==right.out_cutoff);
    CHECK(left.length==right.length && !memcmp(left.bytes,right.bytes,sizeof(left.bytes)));if(left.reconstructed)++reconstruct_cases;
    if(operation==1)++result_cases;else ++cases;
}
static void boundary_checks(void)
{
    _Alignas(8) uint8_t bytes[64]={0};zapret_lua_invocation_flow flow={0};zapret_lua_invocation_feedback feedback={0};uint8_t verdict=99;
#define BOUND(v) do{CHECK(v);++boundaries;}while(0)
    BOUND(zapret_lua_invocation_step(NULL,&feedback)==LUA_INVOKE_INVALID);
    BOUND(zapret_lua_invocation_step(&flow,NULL)==LUA_INVOKE_INVALID);
    BOUND(zapret_lua_invocation_step((void *)(bytes+1),&feedback)==LUA_INVOKE_INVALID);
    flow.phase=UINT_MAX;BOUND(zapret_lua_invocation_step(&flow,&feedback)==LUA_INVOKE_INVALID && flow.phase==UINT_MAX);
    flow.phase=LUA_INVOKE_RESULT;feedback.result=true;feedback.verdict=8;BOUND(zapret_lua_invocation_step(&flow,&feedback)==LUA_INVOKE_INVALID && flow.phase==LUA_INVOKE_RESULT);
    BOUND(zapret_lua_invocation_result(0,0,0,NULL)==4);
    BOUND(zapret_lua_invocation_result(-1,0,0,&verdict)==4 && verdict==99);
    BOUND(zapret_lua_invocation_result(1,3,0,&verdict)==4 && verdict==99);
    BOUND(zapret_lua_invocation_result(2,3,0,&verdict)==1 && verdict==99);
    BOUND(zapret_lua_invocation_result(1,1,INT64_MIN,&verdict)==3 && verdict==99);
    uint8_t *memory=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(memory);DWORD previous;
    CHECK(VirtualProtect(memory+4096,4096,PAGE_NOACCESS,&previous));
    zapret_lua_invocation_feedback *at=(void *)(memory+4096-sizeof(*at));
    *at=(zapret_lua_invocation_feedback){.available=true,.in_range=true,.payload=true,.function=true,.args=true,.call=true,.result=true,.verdict=7};
    CHECK(VirtualProtect(memory,4096,PAGE_READONLY,&previous));
    for(unsigned phase=0;phase<=14;++phase){flow=(zapret_lua_invocation_flow){.phase=phase};BOUND(zapret_lua_invocation_step(&flow,at)!=LUA_INVOKE_INVALID);++guarded;}
    CHECK(VirtualFree(memory,0,MEM_RELEASE));
#undef BOUND
}
static int compare_ticks(const void *a,const void *b){uint64_t x=*(const uint64_t *)a,y=*(const uint64_t *)b;return (x>y)-(x<y);}
static void benchmark(void)
{
    enum{ROUNDS=9,CALLS=4096};uint64_t ticks[2][ROUNDS];LARGE_INTEGER frequency,start,end;CHECK(QueryPerformanceFrequency(&frequency));
    benchmarking=true;operation=0;variant=0;seed=37;
    for(unsigned round=0;round<ROUNDS;++round)for(unsigned order=0;order<2;++order){
        unsigned side=(round+order)&1;lua_State *L=luaL_newstate();CHECK(L);native_side=side!=0;prepare(L);lua_gc(L,LUA_GCRESTART,0);
        for(unsigned i=0;i<128;++i){lua_pushcfunction(L,dispatch);lua_call(L,0,1);lua_pop(L,1);}
        CHECK(calls==128 && context->valid==false);
        CHECK(QueryPerformanceCounter(&start));
        for(unsigned i=0;i<CALLS;++i){lua_pushcfunction(L,dispatch);lua_call(L,0,1);lua_pop(L,1);}
        CHECK(QueryPerformanceCounter(&end));ticks[side][round]=(uint64_t)(end.QuadPart-start.QuadPart);lua_close(L);
    }
    benchmarking=false;qsort(ticks[0],ROUNDS,sizeof(uint64_t),compare_ticks);qsort(ticks[1],ROUNDS,sizeof(uint64_t),compare_ticks);
    printf("BENCH lua_invocation c_ns=%.2f rust_ns=%.2f rounds=%u calls_per_round=%u\n",(double)ticks[0][ROUNDS/2]*1e9/frequency.QuadPart/CALLS,(double)ticks[1][ROUNDS/2]*1e9/frequency.QuadPart/CALLS,ROUNDS,CALLS);
}
int main(void)
{
    operation=0;for(variant=0;variant<11;++variant)for(seed=0;seed<256;++seed)compare(UINT_MAX);
    operation=1;variant=0;for(seed=0;seed<120;++seed)compare(UINT_MAX);
    operation=0;for(variant=0;variant<=5;variant+=5)for(seed=15;seed<=47;seed+=16){execute(false,UINT_MAX,&fault_reference);for(unsigned limit=0;limit<96;++limit)compare(limit);}
    CHECK(vm_faults+handled_faults>=16 && reentry_cases && reconstruct_cases);boundary_checks();
    printf("PASS lua_invocation cases=%u result_cases=%u fault_cases=%u fault_runs=%u vm_allocation_faults=%u handled_vm_faults=%u boundaries=%u guarded=%u reentries=%u reconstruction_cases=%u real_luajit=1 rule_cursor=1 numeric_coercion=1 error_fallback=1 context_inactive=1 registry_cleanup=1 vm_allocations_released=1\n",cases,result_cases,fault_cases,fault_cases*2,vm_faults,handled_faults,boundaries,guarded,reentry_cases,reconstruct_cases);
    benchmark();
    return 0;
}
