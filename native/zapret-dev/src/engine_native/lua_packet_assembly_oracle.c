/* MIT. Real LuaJIT packets and lazy table lookups, compared with the pinned C assembler. */
#include <iphlpapi.h>
#include "params.h"
#include "engine_lua.h"
#include <stdarg.h>
#include <lualib.h>
#include <luajit.h>
#undef main
struct params_s params;
static char diagnostic[512];
int DLOG(const char *format,...){(void)format;return 0;}
int DLOG_CONDUP(const char *format,...){(void)format;return 0;}
int DLOG_ERR(const char *format,...){va_list args;va_start(args,format);vsnprintf(diagnostic,sizeof(diagnostic),format,args);va_end(args);return 0;}
int DLOG_PERROR(const char *text){(void)text;return 0;}
#include "lua_packet_common.inc"
#include "lua_numeric_windows.inc"
#include "packet_lua_windows.c"
#define lua_reconstruct_dissect reference_lua_reconstruct_dissect
#define lua_ip6_l4proto_from_dissect reference_lua_ip6_l4proto_from_dissect
#include "lua_packet_reference.inc"
#undef lua_reconstruct_dissect
#undef lua_ip6_l4proto_from_dissect
#include "lua_packet_assembly_windows.inc"
static unsigned cases,successes,vm_errors,guarded,boundaries,vm_faults,fault_cases;
#define CHECK(value) do{if(!(value)){fprintf(stderr,"FAIL Lua assembly cases=%u boundaries=%u line=%d: %s\n",cases,boundaries,__LINE__,#value);exit(1);}}while(0)
struct vm_allocator {bool armed;unsigned calls,rejected,fail_after,live;};
static struct vm_allocator *fault_allocator;
static void *vm_allocate(void *context,void *pointer,size_t previous,size_t next)
{
    struct vm_allocator *state=context;
    if(!next){if(pointer){CHECK(state->live);--state->live;}free(pointer);return NULL;}
    if(state->armed && next>previous && state->calls++>=state->fail_after){++state->rejected;return NULL;}
    bool fresh=!pointer;void *result=realloc(pointer,next);if(result && fresh)++state->live;return result;
}
static const char *factory=
"function PACKET_CASE(id) LOOKUPS={} local z=string.rep(string.char(0),16) "
"local ip={ip_ttl=64,ip_p=6,ip_src=string.char(192,0,2,1),ip_dst=string.char(198,51,100,2)} "
"local ip6={ip6_hlim=64,ip6_nxt=6,ip6_src=z,ip6_dst=z} "
"local tcp={th_sport=1234,th_dport=443,th_seq=12345,th_ack=54321,th_flags=2,th_win=4096} "
"local udp={uh_sport=1234,uh_dport=443} local icmp={icmp_type=8,icmp_code=0,icmp_data=17} "
"local t={ip=ip,tcp=tcp,payload=string.char(0,255,1,2)} "
"if id==1 then t.ip=nil;t.ip6=ip6 "
"elseif id==2 then t.tcp=nil;t.udp=udp;ip.ip_p=17 "
"elseif id==3 then t.ip=nil;t.ip6=ip6;t.tcp=nil;t.udp=udp "
"elseif id==4 then t.tcp=nil;t.icmp=icmp;ip.ip_p=1 "
"elseif id==5 then t.ip=nil;t.ip6=ip6;t.tcp=nil;t.icmp=icmp "
"elseif id==6 then t.tcp=nil "
"elseif id==7 then t.frag_off=0;t.tcp={invalid=true} "
"elseif id==8 then t.ip=nil;t.ip6=ip6;t.frag_off=8;t.tcp={invalid=true} "
"elseif id==9 then ip.options=string.rep(string.char(1),40) "
"elseif id==10 then tcp.options={{kind=1},{kind=2,data=string.char(5,180)},{kind=8,data=string.rep(string.char(0),8)}} "
"elseif id==11 then t.ip=nil;t.ip6=ip6;ip6.exthdr={{type=0,next=0,data=string.rep(string.char(0),6)}} "
"elseif id==12 then t.ip={} "
"elseif id==13 then t={} "
"elseif id==14 then tcp.th_seq='bad' "
"elseif id==15 then t.tcp=nil;t.udp={uh_sport=1} "
"elseif id==16 then t.tcp=nil;icmp.icmp_data='bad';t.icmp=icmp "
"elseif id==17 then t.payload=123.5 "
"elseif id==18 then t.payload=nil "
"elseif id==19 then t.payload=string.rep('x',65536) "
"elseif id==20 then t.frag_off=0;t.payload=string.rep('x',65535) "
"elseif id==21 then t.frag_off={} "
"elseif id==31 or id==32 then t.tcp=nil;t.udp=udp;ip.ip_p=17;t.payload=string.rep('x',65535);if id==32 then t.ip=nil;t.ip6=ip6 end "
"elseif id>=33 and id<=36 then ip.ip_off=id==33 and 8192 or id==36 and 3 or 1;ip.ip_len=id==33 and 24 or id==34 and 28 or id==35 and 65535 or 44 "
"elseif id>=37 and id<=40 then t.ip=nil;t.ip6=ip6;ip6.ip6_plen=id==38 and 1 or id==39 and 65535 or 24;ip6.exthdr={{type=44,next=6,data=string.char(id==40 and 255 or 0,248)..string.rep(string.char(0),4)}};if id==37 then ip6.exthdr[1].data=string.char(0,8)..string.rep(string.char(0),4) end "
"elseif id==41 then t.ip=nil;t.ip6=ip6;ip6.exthdr={{type=60,next=51,data=string.rep(string.char(0),6)},{type=51,next=6,data=string.rep(string.char(0),10)}} "
"elseif id==42 then t.ip=nil;t.ip6=ip6;t.tcp=nil "
"elseif id==43 then t.ip6=ip6;t.tcp=nil;t.icmp=icmp "
"elseif id==44 then t.udp={};t.icmp={} "
"elseif id==45 then t.frag_off=false "
"elseif id==46 then t.ip='ignored';t.ip6='ignored' "
"elseif id==47 then t.payload={} "
"elseif id>=28 and id<=30 then "
" VM_RETAINS={} local function touch(k) local s=string.rep(k..#VM_RETAINS,4096);VM_RETAINS[#VM_RETAINS+1]=s end "
" if id==29 then local a,b=ip,tcp;t.ip=setmetatable({},{__index=function(_,k) touch(k);return a[k] end});t.tcp=setmetatable({},{__index=function(_,k) touch(k);return b[k] end}) "
" else local fields=t;if id==30 then fields.payload=nil end;t=setmetatable({},{__index=function(_,k) if id==28 or k=='payload' then touch(k) end;if id==30 and k=='payload' then return 12345.6789012345 end;return fields[k] end}) end "
"elseif id>=22 then "
" if id==23 then t.ip=nil;t.ip6=ip6;t.tcp=nil;t.icmp=icmp end "
" local fields=t;t=setmetatable({},{__index=function(_,k) LOOKUPS[#LOOKUPS+1]=k "
" if id==24 and (k=='ip6' or k=='udp' or k=='icmp') then error('eager packet lookup') end "
" if id==25 and k=='payload' then error('payload lookup failed') end "
" return fields[k] end}) "
" if id==26 then setmetatable(tcp,{__index=function(_,k) LOOKUPS[#LOOKUPS+1]='tcp.'..k;return nil end}) end "
" if id==27 then fields.frag_off=1;fields.tcp=nil;fields.udp=nil;fields.icmp=nil end "
"end return t end";
struct sample{uint8_t *buffer;size_t capacity,written;unsigned flags;uint8_t protocol;bool normal,ok;int error;int32_t random_after;unsigned allocations,rejected;char message[512],log[512],lookups[1024];};
static struct sample *active;
static int run_packet(lua_State *L,bool rust){size_t written=active->capacity;bool ok=rust?lua_reconstruct_dissect(L,1,active->buffer,&written,active->flags&1,active->flags&2,active->protocol,active->flags&4):reference_lua_reconstruct_dissect(L,1,active->buffer,&written,active->flags&1,active->flags&2,active->protocol,active->flags&4);active->written=written;active->normal=true;active->ok=ok;lua_pushboolean(L,ok);return 1;}
static int old_packet(lua_State *L){return run_packet(L,false);}static int new_packet(lua_State *L){return run_packet(L,true);}
static void lookups(lua_State *L,char *output,size_t cap){size_t used=0;output[0]=0;lua_getglobal(L,"LOOKUPS");for(unsigned i=1;;++i){lua_rawgeti(L,-1,i);if(lua_isnil(L,-1)){lua_pop(L,1);break;}const char *value=lua_tostring(L,-1);CHECK(value);size_t size=strlen(value);CHECK(used+size+2<cap);memcpy(output+used,value,size);used+=size;output[used++]=';';output[used]=0;lua_pop(L,1);}lua_pop(L,1);}
static void execute(lua_State *L,unsigned id,bool rust,struct sample *sample)
{
    lua_settop(L,0);lua_pushcfunction(L,rust?new_packet:old_packet);lua_getglobal(L,"PACKET_CASE");lua_pushinteger(L,id);CHECK(lua_pcall(L,1,1,0)==0);
    active=sample;sample->written=sample->capacity;diagnostic[0]=0;srandom(1234+id+sample->flags);
    if(fault_allocator){fault_allocator->armed=true;fault_allocator->calls=fault_allocator->rejected=0;}
    sample->error=lua_pcall(L,1,1,0);
    if(fault_allocator){fault_allocator->armed=false;sample->allocations=fault_allocator->calls;sample->rejected=fault_allocator->rejected;}
    sample->random_after=random();if(sample->error){const char *message=lua_tostring(L,-1);snprintf(sample->message,sizeof(sample->message),"%s",message?message:"");}
    strcpy(sample->log,diagnostic);lookups(L,sample->lookups,sizeof(sample->lookups));lua_settop(L,0);
}
struct guard{uint8_t *allocation,*end;};
static struct guard guard_new(void){struct guard value;value.allocation=VirtualAlloc(NULL,81920,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(value.allocation);value.end=value.allocation+77824;DWORD old;CHECK(VirtualProtect(value.end,4096,PAGE_NOACCESS,&old));return value;}
static void compare(lua_State *L,unsigned id,size_t capacity,unsigned flags,uint8_t protocol,unsigned offset,struct guard *a,struct guard *b){struct sample old={0},rust={0};old.buffer=a->end-capacity-offset;rust.buffer=b->end-capacity-offset;old.capacity=rust.capacity=capacity;old.flags=rust.flags=flags;old.protocol=rust.protocol=protocol;memset(old.buffer-16,0xa5,capacity+offset+16);memset(rust.buffer-16,0xa5,capacity+offset+16);execute(L,id,false,&old);execute(L,id,true,&rust);
    if(old.error!=rust.error || old.normal!=rust.normal || old.ok!=rust.ok || old.written!=rust.written || old.random_after!=rust.random_after || strcmp(old.message,rust.message) || strcmp(old.log,rust.log) || strcmp(old.lookups,rust.lookups)){fprintf(stderr,"DETAIL id=%u cap=%zu flags=%u proto=%u offset=%u olderr=%d newerr=%d oldok=%d newok=%d oldlen=%zu newlen=%zu\noldlog=%s\nnewlog=%s\noldtrace=%s\nnewtrace=%s\n",id,capacity,flags,protocol,offset,old.error,rust.error,old.ok,rust.ok,old.written,rust.written,old.log,rust.log,old.lookups,rust.lookups);CHECK(false);}
    if(old.normal && old.ok){CHECK(old.written<=capacity && !memcmp(old.buffer,rust.buffer,old.written));++successes;}if(old.error)++vm_errors;
    for(unsigned i=1;i<=16;++i)CHECK(old.buffer[-(int)i]==0xa5 && rust.buffer[-(int)i]==0xa5);for(unsigned i=0;i<offset;++i)CHECK(old.buffer[capacity+i]==0xa5 && rust.buffer[capacity+i]==0xa5);++guarded;++cases;
}
static void boundary_checks(void)
{
    uint8_t data[32]={0};zapret_lua_packet_state state={0};zapret_lua_packet_observation value={0};_Alignas(8)uint8_t storage[96]={0};
    CHECK(!zapret_lua_packet_begin(NULL,32,0,59,&state));++boundaries;
    CHECK(!zapret_lua_packet_begin(data,SIZE_MAX,0,59,&state));++boundaries;
    CHECK(!zapret_lua_packet_begin(data,32,0,59,(void *)(storage+1)));++boundaries;
    CHECK(!zapret_lua_packet_begin(data,32,16,59,&state));++boundaries;
    CHECK(!zapret_lua_packet_observe(NULL,&value));++boundaries;
    CHECK(zapret_lua_packet_begin(data,8,0,59,&state));value.present=value.success=true;value.length=20;
    CHECK(zapret_lua_packet_observe(&state,&value) && state.phase==13 && state.error==11 && state.used==0);++boundaries;
    CHECK(!zapret_lua_packet_observe(&state,NULL));++boundaries;
    CHECK(!zapret_lua_packet_observe((void *)(storage+1),&value));++boundaries;
    CHECK(zapret_lua_packet_begin(data,32,0,59,&state));state.used=33;CHECK(!zapret_lua_packet_observe(&state,&value));++boundaries;
    CHECK(zapret_lua_packet_begin(data,32,0,59,&state));state.available=31;CHECK(!zapret_lua_packet_observe(&state,&value));++boundaries;
    CHECK(zapret_lua_packet_begin(data,32,0,59,&state));state.output++;CHECK(!zapret_lua_packet_observe(&state,&value));++boundaries;
    CHECK(zapret_lua_packet_begin(data,32,0,59,&state));state.phase=3;CHECK(!zapret_lua_packet_observe(&state,&value));++boundaries;
}
static void vm_fault_checks(struct guard *a,struct guard *b)
{
    for(unsigned id=28;id<=30;++id)for(unsigned limit=0;limit<16;++limit){
        struct sample left={0},right={0};left.buffer=a->end-8192;right.buffer=b->end-8192;left.capacity=right.capacity=8192;left.protocol=right.protocol=59;
        for(unsigned side=0;side<2;++side){
            struct vm_allocator allocator={0};allocator.fail_after=limit;lua_State *L=lua_newstate(vm_allocate,&allocator);CHECK(L);params.L=L;
            luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);CHECK(!luaL_dostring(L,factory));
            struct sample *value=side?&right:&left;memset(value->buffer-16,0xa5,8192+16);fault_allocator=&allocator;execute(L,id,side!=0,value);fault_allocator=NULL;
            if(value->error){CHECK(value->error==LUA_ERRMEM && value->rejected && !value->normal && value->written==value->capacity);++vm_faults;}else CHECK(!value->rejected && value->ok);
            for(unsigned i=1;i<=16;++i)CHECK(value->buffer[-(int)i]==0xa5);
            lua_close(L);CHECK(!allocator.live);
        }
        CHECK(left.error==right.error && left.normal==right.normal && left.ok==right.ok && left.written==right.written && left.allocations==right.allocations && left.rejected==right.rejected && left.random_after==right.random_after && !strcmp(left.message,right.message) && !strcmp(left.log,right.log));
        if(left.ok)CHECK(!memcmp(left.buffer,right.buffer,left.written));++fault_cases;
    }
    CHECK(vm_faults>=32);params.L=NULL;
}
static double measure(lua_State *L,bool rust,unsigned iterations)
{
    uint8_t data[2048];LARGE_INTEGER start,end,frequency;CHECK(QueryPerformanceFrequency(&frequency));CHECK(QueryPerformanceCounter(&start));
    for(unsigned i=0;i<iterations;++i){size_t length=sizeof(data);bool ok=rust?lua_reconstruct_dissect(L,1,data,&length,false,false,59,false):reference_lua_reconstruct_dissect(L,1,data,&length,false,false,59,false);CHECK(ok && length>=20);}
    CHECK(QueryPerformanceCounter(&end));return (double)(end.QuadPart-start.QuadPart)*1e9/(double)frequency.QuadPart/iterations;
}
static void benchmark(void)
{
    for(unsigned id=0;id<=6;++id){lua_State *L=luaL_newstate();CHECK(L);params.L=L;luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);CHECK(!luaL_dostring(L,factory));lua_getglobal(L,"PACKET_CASE");lua_pushinteger(L,id);CHECK(!lua_pcall(L,1,1,0));measure(L,false,1000);measure(L,true,1000);
        for(unsigned round=0;round<9;++round){double old,rust;if(round&1){rust=measure(L,true,20000);old=measure(L,false,20000);}else{old=measure(L,false,20000);rust=measure(L,true,20000);}printf("BENCH lua_packet_assembly id=%u round=%u old_ns=%.3f rust_ns=%.3f ratio=%.5f\n",id,round,old,rust,rust/old);}
        params.L=NULL;lua_close(L);
    }
}
int main(int argc,char **argv){if(argc==2 && !strcmp(argv[1],"--benchmark")){benchmark();return 0;}lua_State *L=luaL_newstate();CHECK(L);params.L=L;luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);CHECK(luaL_dostring(L,factory)==0);struct guard a=guard_new(),b=guard_new();const size_t capacities[]={0,1,7,8,19,20,27,28,39,40,47,48,59,60,61,80,128,512,65535,65536,65596};const uint8_t protocols[]={59,6,17};
    for(unsigned id=0;id<48;++id){if(id>=28 && id<=30)continue;for(unsigned c=0;c<21;++c)for(unsigned flags=0;flags<8;++flags)for(unsigned p=0;p<3;++p)for(unsigned offset=0;offset<2;++offset)compare(L,id,capacities[c],flags,protocols[p],offset?7:0,&a,&b);}
    boundary_checks();params.L=NULL;lua_close(L);vm_fault_checks(&a,&b);CHECK(VirtualFree(a.allocation,0,MEM_RELEASE) && VirtualFree(b.allocation,0,MEM_RELEASE));printf("PASS lua_packet_assembly cases=%u successes=%u vm_errors=%u guarded=%u boundaries=%u vm_allocation_faults=%u fault_cases=%u real_luajit=1 lazy_lookup_order=1 vm_allocations_released=1\n",cases,successes,vm_errors,guarded,boundaries,vm_faults,fault_cases);return 0;
}
