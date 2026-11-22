/* MIT. Compare the exact pinned packet argument block through real LuaJIT. */
#include <iphlpapi.h>
#include "params.h"
#include "engine_lua.h"
#include "nfqws.h"
#include <luajit.h>
#include <limits.h>
#undef main
struct params_s params;
#include "lua_packet_arguments_windows.h"
static unsigned cases,fault_cases,vm_faults,handled_faults,fault_timing_differences,boundaries,guarded,guarded_vm_cases,reentries,gc_cases,lookup_cases;
static unsigned seed,variant,observed,mutations,lookups,nesting,collected;
static bool native_side,benchmarking;
static char trace[8192];
static struct desync_profile profile;
static struct dissect packet;
static t_ctrack track;
static t_ctrack_positions positions;
static zapret_lua_packet_argument_input input;
static uint8_t bytes[4096],target4[4]={127,0,0,1},target6[16]={0x20,1};
static struct tcphdr tcp;
static const uint8_t *guard_data;
static size_t guard_span;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL Lua packet arguments seed=%u variant=%u line=%d: %s\n",seed,variant,__LINE__,#v);exit(1);}}while(0)
static void observe(lua_State *,const char *);
#include "lua_packet_arguments_common.inc"
void lua_pushf_dissect(lua_State *L,const struct dissect *dis)
{
    CHECK(dis==&packet);lua_pushf_table(L,"dis");lua_getfield(L,-1,"dis");
    lua_pushf_int(L,"length",dis->len_pkt);lua_pushf_bool(L,"tcp",dis->tcp!=NULL);lua_pop(L,1);observe(L,"dissect");
}
void lua_pushf_ctrack(lua_State *L,const t_ctrack *current,const t_ctrack_positions *snapshot,bool incoming)
{
    CHECK(current==(seed&1?&track:NULL) && snapshot==(seed&2?&positions:NULL) && incoming==input.incoming);
    if(current){lua_pushf_table(L,"track");lua_getfield(L,-1,"track");lua_pushf_bool(L,"incoming",incoming);lua_pop(L,1);}
    observe(L,"ctrack");
}
#include "lua_packet_arguments_reference.inc"
#include "lua_packet_arguments_windows.inc"
#include "lua_packet_arguments_candidate.inc"
static int invoke(lua_State *L)
{
    (native_side?candidate_packet_arguments:reference_packet_arguments)(&input,seed&1?&track:NULL,seed&2?&positions:NULL);
    return 1;
}
static void event(const char *name)
{
    size_t used=strlen(trace),length=strlen(name);CHECK(used+length+3<sizeof(trace));
    trace[used++]=nesting?'1':'0';memcpy(trace+used,name,length);trace[used+length]=';';trace[used+length+1]=0;
}
static void mutate(void)
{
    ++mutations;profile.n+=7;profile.name=mutations&1?"changed profile":NULL;profile.cookie=mutations&2?"changed cookie":"";
    positions.client.mss=(uint16_t)(400+mutations);positions.server.mss=(uint16_t)(800-mutations);
    if(mutations%5==0)positions.client.mss=0;
    if(mutations%7==0)packet.tcp=packet.tcp?NULL:&tcp;
}
static void observe(lua_State *L,const char *name)
{
    if(benchmarking)return;
    ++observed;event(name);
    if(nesting)return;
    if(variant==4)mutate();
    if(variant==3 && observed==1+seed%27)luaL_error(L,"packet argument publication failed at %s",name);
    if(variant==5 && !strcmp(name,"fwmark")){
        int before=lua_gettop(L);nesting=1;lua_pushcfunction(L,invoke);lua_call(L,0,1);lua_pop(L,1);nesting=0;
        CHECK(lua_gettop(L)==before);++reentries;
    }
    if(variant==6 && !strcmp(name,"reasm_data"))lua_gc(L,LUA_GCCOLLECT,0);
}
static int gc_callback(lua_State *L){(void)L;++collected;event("gc");mutate();return 0;}
static int default_mss(lua_State *L)
{
    const char *key=lua_tostring(L,2);if(!key || strcmp(key,"DEFAULT_MSS"))return 0;
    ++lookups;event("DEFAULT_MSS");mutate();
    switch(seed%7){
        case 0:lua_pushinteger(L,1220);return 1;
        case 1:lua_pushboolean(L,false);return 1;
        case 2:lua_pushliteral(L,"");return 1;
        case 3:lua_newtable(L);lua_pushinteger(L,73);lua_setfield(L,-2,"fallback");return 1;
        case 4:return 0;
        case 5:return luaL_error(L,"default MSS lookup failed");
        default:lua_pushcfunction(L,gc_callback);return 1;
    }
}
static void prepare(lua_State *L)
{
    static const uint32_t numbers[]={0,1,UINT32_MAX,UINT32_MAX-1,0x80000000,65535};
    static const uint16_t sizes[]={0,1,1220,1460,65535};
    memset(&params,0,sizeof(params));memset(&profile,0,sizeof(profile));memset(&packet,0,sizeof(packet));memset(&track,0,sizeof(track));memset(&positions,0,sizeof(positions));memset(&input,0,sizeof(input));
    params.L=L;observed=mutations=lookups=nesting=collected=0;trace[0]=0;
    profile.n=numbers[seed%6];profile.name=seed%3==0?NULL:seed%3==1?"":"profile-данные";
    profile.cookie=seed%4==0?NULL:seed%4==1?"":"cookie\xff";
    packet.data_pkt=bytes;packet.len_pkt=seed%4097;packet.tcp=seed%3==0?NULL:&tcp;
    positions.client.mss=sizes[seed%5];positions.server.mss=sizes[(seed/5)%5];
    input=(zapret_lua_packet_argument_input){
        .profile=&profile,.packet=&packet,.current=seed%4==0?NULL:&positions.client,.opposite=seed%4==1?NULL:&positions.server,
        .interface_in=seed%3==0?NULL:seed%3==1?"":"Wi-Fi\xff",.interface_out=seed%5==0?NULL:seed%5==1?"":"интерфейс",
        .target4=seed&1?target4:NULL,.target6=seed&2?target6:NULL,.port=seed%3?65535:0,.incoming=!!(seed&4),
        .mark=numbers[(seed/6)%6],.piece=numbers[seed%6],.pieces=numbers[(seed/6)%6],
        .payload=seed%(L7P_LAST+2),.protocol=seed%(L7_LAST+2),
        .reassembly=seed&8?bytes:NULL,.decryption=seed&16?bytes+17:NULL,
        .reassembly_length=seed%4==0?0:seed%4==1?1:seed%4==2?17:4096,
        .decryption_length=seed%4==0?0:seed%4==1?17:seed%4==2?31:4000,
        .reassembly_offset=seed%3==0?SIZE_MAX:seed%3==1?(SIZE_MAX/2+1):seed,
    };
    if(!input.reassembly && seed%11==0)input.reassembly_length=SIZE_MAX;
    if(!input.decryption && seed%13==0)input.decryption_length=SIZE_MAX;
    if(guard_data){
        input.target4=guard_data-4;input.target6=guard_data-16;
        input.reassembly=input.decryption=guard_data-guard_span;input.reassembly_length=input.decryption_length=guard_span;
        input.interface_in=(const char *)guard_data-1;input.interface_out=(const char *)guard_data-2;
        profile.name=profile.cookie=(char *)guard_data-2;
    }
    lua_pushinteger(L,1220);lua_setglobal(L,"DEFAULT_MSS");
    if(variant==1 || variant==7){
        lua_pushnil(L);lua_setglobal(L,"DEFAULT_MSS");lua_pushvalue(L,LUA_GLOBALSINDEX);lua_newtable(L);
        lua_pushcfunction(L,default_mss);lua_setfield(L,-2,"__index");lua_setmetatable(L,-2);lua_pop(L,1);
    }
    if(variant==2){lua_pushliteral(L,"custom MSS");lua_setglobal(L,"DEFAULT_MSS");}
    if(variant==6){
        lua_newuserdata(L,1);lua_newtable(L);lua_pushcfunction(L,gc_callback);lua_setfield(L,-2,"__gc");lua_setmetatable(L,-2);lua_pop(L,1);
    }
}
static uint64_t hash_bytes(const void *bytes,size_t size)
{uint64_t hash=UINT64_C(14695981039346656037);const uint8_t *data=bytes;for(size_t i=0;i<size;++i)hash=(hash^data[i])*UINT64_C(1099511628211);return hash;}
static uint64_t hash_value(lua_State *L,int index,unsigned depth)
{
    CHECK(depth<16);index=lua_absindex(L,index);int type=lua_type(L,index);uint64_t hash=(uint64_t)(type+2)*UINT64_C(0x9e3779b185ebca87);
    switch(type){
        case LUA_TNUMBER:{lua_Number value=lua_tonumber(L,index);return hash^hash_bytes(&value,sizeof(value));}
        case LUA_TBOOLEAN:return hash^(uint64_t)lua_toboolean(L,index);
        case LUA_TSTRING:{size_t length;const char *text=lua_tolstring(L,index,&length);return hash^hash_bytes(text,length);}
        case LUA_TTABLE:{unsigned count=0;lua_pushnil(L);while(lua_next(L,index)){hash^=hash_value(L,-2,depth+1)*UINT64_C(0x9e3779b185ebca87)+hash_value(L,-1,depth+1);++count;lua_pop(L,1);}return hash+count;}
        default:return hash;
    }
}
struct allocator{bool armed;unsigned limit,calls,rejected,live;};
static void *allocate(void *context,void *pointer,size_t previous,size_t next)
{
    struct allocator *a=context;if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}
    if(a->armed && next>previous && a->calls++>=a->limit){++a->rejected;return NULL;}
    bool fresh=!pointer;void *result=realloc(pointer,next);if(result && fresh)++a->live;return result;
}
struct sample{int status,stack;uint64_t value;char error[512],trace[8192];unsigned observed,mutations,lookups,collected,rejected;};
static struct sample left,right,fault_reference;
static void execute(bool native,unsigned limit,struct sample *out)
{
    struct allocator a={.limit=limit};lua_State *L=lua_newstate(allocate,&a);CHECK(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);native_side=native;
    prepare(L);lua_pushcfunction(L,invoke);a.armed=limit!=UINT_MAX;out->status=lua_pcall(L,0,LUA_MULTRET,0);a.armed=false;
    out->stack=lua_gettop(L);out->error[0]=0;out->value=0;
    if(out->status){const char *error=lua_tostring(L,-1);snprintf(out->error,sizeof(out->error),"%s",error?error:"nonstring error");}
    else {CHECK(out->stack==1 && lua_istable(L,1));out->value=hash_value(L,1,0);}
    strcpy(out->trace,trace);out->observed=observed;out->mutations=mutations;out->lookups=lookups;out->rejected=a.rejected;
    lua_close(L);CHECK(!a.live);out->collected=collected;
}
static void compare(unsigned limit)
{
    execute(false,limit,&left);execute(true,limit,&right);
    if(limit!=UINT_MAX){
        // LuaJIT allocation timing can differ even between two copies of the
        // same C implementation. Each failed trace must remain a prefix of the
        // exact no-fault C trace; successful retries must keep its full result.
        const struct sample *samples[]={&left,&right};
        for(unsigned side=0;side<2;++side){const struct sample *sample=samples[side];
            CHECK(sample->stack==1);
            CHECK(!strncmp(fault_reference.trace,sample->trace,strlen(sample->trace)));
            if(sample->status){CHECK(sample->status==LUA_ERRMEM && sample->rejected);++vm_faults;}
            else {CHECK(sample->value==fault_reference.value && !strcmp(sample->trace,fault_reference.trace));if(sample->rejected)++handled_faults;}
        }
        if(left.status!=right.status || strcmp(left.trace,right.trace))++fault_timing_differences;
        ++fault_cases;return;
    }
    if(left.status!=right.status || left.stack!=right.stack || left.value!=right.value || strcmp(left.error,right.error) || strcmp(left.trace,right.trace)){
        fprintf(stderr,"DETAIL limit=%u status=%d/%d stack=%d/%d value=%llx/%llx error=%s/%s\noldtrace=%s\nnewtrace=%s\n",limit,left.status,right.status,left.stack,right.stack,(unsigned long long)left.value,(unsigned long long)right.value,left.error,right.error,left.trace,right.trace);CHECK(false);
    }
    CHECK(left.observed==right.observed && left.mutations==right.mutations && left.lookups==right.lookups && left.collected==right.collected);
    ++cases;if(left.lookups)++lookup_cases;if(left.collected)++gc_cases;
}
static int compare_ticks(const void *a,const void *b){uint64_t x=*(const uint64_t *)a,y=*(const uint64_t *)b;return (x>y)-(x<y);}
static void benchmark(void)
{
    enum{ROUNDS=9,CALLS=4096};uint64_t ticks[2][ROUNDS];LARGE_INTEGER frequency,start,end;
    CHECK(QueryPerformanceFrequency(&frequency));benchmarking=true;variant=0;seed=37;
    lua_State *states[]={luaL_newstate(),luaL_newstate()};CHECK(states[0] && states[1]);
    for(unsigned round=0;round<ROUNDS;++round)for(unsigned order=0;order<2;++order){unsigned side=(round+order)&1;lua_State *L=states[side];prepare(L);
        for(unsigned i=0;i<128;++i){lua_settop(L,0);(side?candidate_packet_arguments:reference_packet_arguments)(&input,&track,NULL);}
        CHECK(QueryPerformanceCounter(&start));
        for(unsigned i=0;i<CALLS;++i){lua_settop(L,0);(side?candidate_packet_arguments:reference_packet_arguments)(&input,&track,NULL);}
        CHECK(QueryPerformanceCounter(&end));ticks[side][round]=(uint64_t)(end.QuadPart-start.QuadPart);
    }
    lua_close(states[0]);lua_close(states[1]);benchmarking=false;
    qsort(ticks[0],ROUNDS,sizeof(uint64_t),compare_ticks);qsort(ticks[1],ROUNDS,sizeof(uint64_t),compare_ticks);
    printf("BENCH lua_packet_arguments c_ns=%.2f rust_ns=%.2f rounds=%u calls_per_round=%u\n",(double)ticks[0][ROUNDS/2]*1e9/frequency.QuadPart/CALLS,(double)ticks[1][ROUNDS/2]*1e9/frequency.QuadPart/CALLS,ROUNDS,CALLS);
}
static void boundary_checks(void)
{
    _Alignas(8) uint8_t storage[256]={0};zapret_lua_packet_argument_input data={0};zapret_lua_packet_argument output={.kind=37};uint32_t index=0;
#define BOUND(v) do{CHECK(v);++boundaries;}while(0)
    BOUND(zapret_lua_packet_argument_next(NULL,&data,&output)==2);
    BOUND(zapret_lua_packet_argument_next(&index,NULL,&output)==2);
    BOUND(zapret_lua_packet_argument_next(&index,&data,NULL)==2);
    BOUND(zapret_lua_packet_argument_next((void *)(storage+1),&data,&output)==2);
    BOUND(zapret_lua_packet_argument_next(&index,(void *)(storage+1),&output)==2);
    BOUND(zapret_lua_packet_argument_next(&index,&data,(void *)(storage+1))==2);
    BOUND(zapret_lua_packet_argument_next(&index,&data,&output)==2);
    index=23;BOUND(zapret_lua_packet_argument_next(&index,&data,&output)==0 && output.kind==37);
    index=UINT_MAX;BOUND(zapret_lua_packet_argument_next(&index,&data,&output)==2);
    data.profile=(void *)(storage+1);index=1;BOUND(zapret_lua_packet_argument_next(&index,&data,&output)==2);
    data.packet=(void *)(storage+1);index=22;BOUND(zapret_lua_packet_argument_next(&index,&data,&output)==2);
    uint8_t *memory=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(memory);DWORD previous;
    CHECK(VirtualProtect(memory+4096,4096,PAGE_NOACCESS,&previous));
    zapret_lua_packet_argument_input *at=(void *)(memory+4096-sizeof(*at));memset(at,0,sizeof(*at));
    struct desync_profile dp={0};struct dissect dis={0};at->profile=&dp;at->packet=&dis;
    CHECK(VirtualProtect(memory,4096,PAGE_READONLY,&previous));index=0;
    while(zapret_lua_packet_argument_next(&index,at,&output)==1)++guarded;
    CHECK(index==23 && guarded>=14);
    data.packet=&packet;packet.tcp=&tcp;data.current=NULL;data.opposite=(void *)(memory+4096);index=22;
    BOUND(zapret_lua_packet_argument_next(&index,&data,&output)==1 && output.kind==11);
    positions.client.mss=0;data.current=&positions.client;index=22;
    BOUND(zapret_lua_packet_argument_next(&index,&data,&output)==1 && output.kind==11);
    packet.tcp=NULL;data.current=(void *)(memory+4096);index=22;
    BOUND(zapret_lua_packet_argument_next(&index,&data,&output)==0);
    CHECK(VirtualProtect(memory,4096,PAGE_READWRITE,&previous));
    for(unsigned i=0;i<32;++i)memory[4096-32+i]=(uint8_t)(255-i);
    memory[4095]=0;memory[4094]='X';CHECK(VirtualProtect(memory,4096,PAGE_READONLY,&previous));
    guard_data=memory+4096;variant=0;seed=31;
    for(guard_span=0;guard_span<=32;++guard_span){compare(UINT_MAX);++guarded_vm_cases;}
    guard_data=NULL;CHECK(VirtualFree(memory,0,MEM_RELEASE));
#undef BOUND
}
int main(void)
{
    for(unsigned i=0;i<sizeof(bytes);++i)bytes[i]=(uint8_t)i;
    for(variant=0;variant<8;++variant)for(seed=0;seed<512;++seed)compare(UINT_MAX);
    for(variant=0;variant<=5;variant+=5)for(seed=31;seed<=63;seed+=32){execute(false,UINT_MAX,&fault_reference);for(unsigned limit=0;limit<192;++limit)compare(limit);}
    CHECK(vm_faults>=16 && lookup_cases && gc_cases && reentries);boundary_checks();
    printf("PASS lua_packet_arguments fields=23 cases=%u fault_cases=%u fault_runs=%u vm_allocation_faults=%u handled_vm_faults=%u fault_timing_differences=%u boundaries=%u guarded=%u guarded_vm_cases=%u reentries=%u gc_cases=%u lazy_mss_cases=%u real_luajit=1 deferred_profile_reads=1 replay_wrap=1 nullable_spans=1 vm_allocations_released=1\n",cases,fault_cases,fault_cases*2,vm_faults,handled_faults,fault_timing_differences,boundaries,guarded,guarded_vm_cases,reentries,gc_cases,lookup_cases);
    benchmark();
    return 0;
}
