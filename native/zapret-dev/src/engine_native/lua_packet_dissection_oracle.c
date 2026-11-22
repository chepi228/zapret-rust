/* MIT. Real Lua tables from the pinned C decoder and borrowed Rust wire views. */
#include <iphlpapi.h>
#include "params.h"
#include "engine_lua.h"
#include <luajit.h>
#undef main
struct params_s params;
#include "lua_dissection_common.inc"
#define lua_pushf_tcphdr_options reference_tcp_options
#define lua_pushf_ip6exthdr reference_ip6_extensions
#define lua_push_tcphdr reference_tcp
#define lua_push_udphdr reference_udp
#define lua_push_icmphdr reference_icmp
#define lua_push_iphdr reference_ip
#define lua_push_ip6hdr reference_ip6
#include "lua_dissection_reference.inc"
#undef lua_pushf_tcphdr_options
#undef lua_pushf_ip6exthdr
#undef lua_push_tcphdr
#undef lua_push_udphdr
#undef lua_push_icmphdr
#undef lua_push_iphdr
#undef lua_push_ip6hdr
#include "lua_packet_dissection_windows.inc"
static unsigned cases,boundaries,guarded,fault_cases,vm_faults,items;
#define CHECK(v) do {if(!(v)){fprintf(stderr,"FAIL Lua dissection cases=%u bounds=%u line=%d: %s\n",cases,boundaries,__LINE__,#v);exit(1);}}while(0)
typedef void (*header_function)(lua_State *,const void *,size_t);
static header_function old_headers[]={(header_function)reference_tcp,(header_function)reference_udp,(header_function)reference_icmp,(header_function)reference_ip,(header_function)reference_ip6,(header_function)reference_tcp_options,(header_function)reference_ip6_extensions};
static header_function new_headers[]={(header_function)lua_push_tcphdr,(header_function)lua_push_udphdr,(header_function)lua_push_icmphdr,(header_function)lua_push_iphdr,(header_function)lua_push_ip6hdr,(header_function)lua_pushf_tcphdr_options,(header_function)lua_pushf_ip6exthdr};
static unsigned active_kind;
static const uint8_t *active_data;
static size_t active_length;
static int invoke(lua_State *L,bool rust){if(active_kind>=5)lua_newtable(L);(rust?new_headers:old_headers)[active_kind](L,active_data,active_length);CHECK(lua_gettop(L)==1);return 1;}
static int old_decode(lua_State *L){return invoke(L,false);}
static int new_decode(lua_State *L){return invoke(L,true);}
static const char *same=
"function SAME(a,b) if type(a)~=type(b) then return false end if type(a)~='table' then return a==b end "
"local n=0 for k,v in pairs(a) do n=n+1;if not SAME(v,b[k]) then return false end end for _ in pairs(b) do n=n-1 end return n==0 end";
static void compare(lua_State *L,unsigned kind,const uint8_t *data,size_t length)
{
    lua_settop(L,0);active_kind=kind;active_data=data;active_length=length;
    lua_pushcfunction(L,old_decode);CHECK(!lua_pcall(L,0,1,0));
    lua_pushcfunction(L,new_decode);CHECK(!lua_pcall(L,0,1,0));
    lua_getglobal(L,"SAME");lua_pushvalue(L,1);lua_pushvalue(L,2);CHECK(!lua_pcall(L,2,1,0));
    if(!lua_toboolean(L,-1)){fprintf(stderr,"DETAIL kind=%u length=%zu\n",kind,length);CHECK(false);}
    if(lua_istable(L,2)){lua_getfield(L,2,kind==4||kind==6?"exthdr":"options");if(lua_istable(L,-1))items+=(unsigned)lua_objlen(L,-1);}
    lua_settop(L,0);++cases;
}
struct guard {uint8_t *allocation,*end;};
static struct guard guard_new(void){struct guard g;g.allocation=VirtualAlloc(NULL,16384,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(g.allocation);g.end=g.allocation+12288;DWORD old;CHECK(VirtualProtect(g.end,4096,PAGE_NOACCESS,&old));return g;}
static uint64_t random_state=0x6469737365637465ULL;
static uint8_t next_byte(void){random_state^=random_state<<13;random_state^=random_state>>7;random_state^=random_state<<17;return (uint8_t)random_state;}
static void put16(uint8_t *data,unsigned value){data[0]=(uint8_t)(value>>8);data[1]=(uint8_t)value;}
static void packet(uint8_t *data,unsigned kind,unsigned pattern,unsigned forced_protocol)
{
    for(unsigned i=0;i<4096;++i)data[i]=next_byte();
    if(kind==0||kind==5){
        static const uint8_t patterns[][16]={
            {0},{1,1,0},{0,0,1,0},{2,4,0,0,0,0,0,0},{2,2,0,0},{2,1,0,0},{2,255,0,0},
            {0,0,2,1},{0,2,2,0},{1,2,3,0,0,0},{8,10,0,0,0,0,0,0,0,0,0,1},{3,3,7,1,0,0}};
        data[12]=(uint8_t)(((pattern%16)<<4)|(pattern%16));
        if(pattern>=16)data[12]=(uint8_t)(0xf0|(pattern%16));
        for(unsigned i=20;i<80;++i)data[i]=patterns[pattern%12][(i-20)%16];
    }else if(kind==3){data[0]=(uint8_t)(((pattern%16)<<4)|((pattern*7)%16));}
    else if(kind==4||kind==6){
        const unsigned plen[]={0,1,2,7,8,9,15,16,24,40,128,65535};
        const uint8_t protocols[]={0,43,44,51,60,135,139,140,59,6,17,255};
        data[0]=(uint8_t)(0x60|(pattern%16));put16(data+4,plen[pattern%12]);data[6]=forced_protocol<256?(uint8_t)forced_protocol:protocols[pattern%12];
        for(unsigned i=40;i+8<=4096;i+=8){data[i]=protocols[((i-40)/8+pattern+1)%12];data[i+1]=(uint8_t)(pattern>=24?pattern-24:0);put16(data+i+2,(pattern%4==0)?0:(pattern%4==1)?1:(pattern%4==2)?8:65535);}
    }
}
struct allocator {bool armed;unsigned calls,fail_after,rejected,live;};
static void *vm_allocate(void *context,void *pointer,size_t previous,size_t next)
{
    struct allocator *a=context;
    if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}
    if(a->armed && next>previous && a->calls++>=a->fail_after){++a->rejected;return NULL;}
    bool fresh=!pointer;void *out=realloc(pointer,next);if(out && fresh)++a->live;return out;
}
static void fault_checks(void)
{
    uint8_t data[4096];
    for(unsigned kind=0;kind<7;++kind)for(unsigned limit=0;limit<24;++limit)for(unsigned side=0;side<2;++side){
        struct allocator a={0};a.fail_after=limit;lua_State *L=lua_newstate(vm_allocate,&a);CHECK(L);params.L=L;
        packet(data,kind,20,256);if(kind==4||kind==6){put16(data+4,32);data[6]=0;for(unsigned n=40;n<72;n+=8){data[n]=n==64?6:0;data[n+1]=0;}}
        active_kind=kind;active_data=data;active_length=128;lua_pushcfunction(L,side?new_decode:old_decode);
        a.armed=true;int status=lua_pcall(L,0,1,0);a.armed=false;
        if(status){CHECK(status==LUA_ERRMEM && a.rejected);++vm_faults;}else CHECK(!a.rejected && lua_istable(L,-1));
        lua_close(L);CHECK(!a.live);++fault_cases;
    }
    params.L=NULL;CHECK(vm_faults>=64);
}
static void boundary_checks(void)
{
    uint8_t data[64]={0};zapret_lua_packet_header_values header;zapret_lua_packet_cursor c={0};zapret_lua_packet_item item;
    _Alignas(8) uint8_t storage[128];memset(&header,0xa5,sizeof(header));
    CHECK(!zapret_lua_packet_header(0,NULL,64,&header));++boundaries;
    CHECK(!zapret_lua_packet_header(0,data,SIZE_MAX,&header));++boundaries;
    CHECK(!zapret_lua_packet_header(5,data,64,&header));++boundaries;
    CHECK(!zapret_lua_packet_header(0,data,19,&header));++boundaries;
    CHECK(!zapret_lua_packet_header(0,data,64,NULL));++boundaries;
    CHECK(!zapret_lua_packet_header(0,data,64,(void *)(storage+1)));++boundaries;
    for(unsigned i=0;i<sizeof(header);++i)CHECK(((uint8_t *)&header)[i]==0xa5);
    CHECK(zapret_lua_packet_item_next(NULL,&item)==2);++boundaries;
    CHECK(zapret_lua_packet_item_next(&c,NULL)==2);++boundaries;
    CHECK(zapret_lua_packet_item_next((void *)(storage+1),&item)==2);++boundaries;
    CHECK(zapret_lua_packet_item_next(&c,(void *)(storage+1))==2);++boundaries;
    c.length=1;CHECK(zapret_lua_packet_item_next(&c,&item)==2);++boundaries;
    c.data=data;c.length=SIZE_MAX;CHECK(zapret_lua_packet_item_next(&c,&item)==2);++boundaries;
    c.length=2;c.offset=3;CHECK(zapret_lua_packet_item_next(&c,&item)==2);++boundaries;
    c.offset=0;c.kind=2;CHECK(zapret_lua_packet_item_next(&c,&item)==2);++boundaries;
    c.kind=0;c.length=0;c.data=NULL;CHECK(zapret_lua_packet_item_next(&c,&item)==0);++boundaries;
}
static double measure(lua_State *L,unsigned kind,bool rust)
{
    LARGE_INTEGER start,end,frequency;CHECK(QueryPerformanceFrequency(&frequency));CHECK(QueryPerformanceCounter(&start));
    for(unsigned i=0;i<8192;++i){lua_settop(L,0);if(kind>=5)lua_newtable(L);(rust?new_headers:old_headers)[kind](L,active_data,active_length);}
    lua_settop(L,0);CHECK(QueryPerformanceCounter(&end));return (double)(end.QuadPart-start.QuadPart)*1e9/(double)frequency.QuadPart/8192;
}
static void benchmark(void)
{
    uint8_t data[4096];
    for(unsigned kind=0;kind<7;++kind){packet(data,kind,20,256);if(kind==4||kind==6){put16(data+4,32);data[6]=0;for(unsigned n=40;n<72;n+=8){data[n]=n==64?6:0;data[n+1]=0;}}
        active_data=data;active_length=128;lua_State *L=luaL_newstate();CHECK(L);params.L=L;luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);
        measure(L,kind,false);measure(L,kind,true);
        for(unsigned round=0;round<9;++round){double old,rust;if(round&1){rust=measure(L,kind,true);old=measure(L,kind,false);}else{old=measure(L,kind,false);rust=measure(L,kind,true);}printf("BENCH lua_packet_dissection kind=%u round=%u old_ns=%.3f rust_ns=%.3f ratio=%.5f\n",kind,round,old,rust,rust/old);}
        params.L=NULL;lua_close(L);
    }
}
int main(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"--benchmark")){benchmark();return 0;}
    lua_State *L=luaL_newstate();CHECK(L);params.L=L;luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);CHECK(!luaL_dostring(L,same));
    struct guard g=guard_new();uint8_t data[4096];
    for(unsigned kind=0;kind<7;++kind)for(unsigned pattern=0;pattern<32;++pattern){packet(data,kind,pattern,256);
        for(size_t length=0;length<=128;++length){if(kind==5 && length<20)continue;
            for(unsigned offset=0;offset<2;++offset){uint8_t *target=g.end-length-offset;memset(target-16,0xa5,length+offset+16);memcpy(target,data,length);compare(L,kind,target,length);CHECK(!memcmp(target,data,length));for(unsigned i=1;i<=16;++i)CHECK(target[-(int)i]==0xa5);if(offset)CHECK(target[length]==0xa5);++guarded;}
        }
    }
    const size_t lengths[]={0,1,39,40,41,42,47,48,49,55,56,63,64,72,80,128,256,512,4096};
    for(unsigned proto=0;proto<256;++proto)for(unsigned pattern=0;pattern<4;++pattern){packet(data,4,pattern+8,proto);
        for(unsigned i=0;i<sizeof(lengths)/sizeof(*lengths);++i){size_t length=lengths[i];uint8_t *target=g.end-length;memcpy(target,data,length);compare(L,4,target,length);++guarded;}
    }
    for(unsigned kind=0;kind<5;++kind)compare(L,kind,NULL,0);
    boundary_checks();CHECK(VirtualFree(g.allocation,0,MEM_RELEASE));params.L=NULL;lua_close(L);fault_checks();
    printf("PASS lua_packet_dissection functions=7 cases=%u items=%u guarded=%u boundaries=%u vm_allocation_faults=%u fault_cases=%u real_luajit=1 input_preserved=1 vm_allocations_released=1\n",cases,items,guarded,boundaries,vm_faults,fault_cases);return 0;
}
