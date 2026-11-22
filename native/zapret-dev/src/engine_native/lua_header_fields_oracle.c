/* MIT. Compare complete old/new builders through real, protected LuaJIT calls. */
#include "params.h"
#include "engine_lua.h"
#include <lualib.h>
#include <luajit.h>
#undef main
#include "lua_header_fields_common.inc"
#define ZAPRET_LUA_PACKET_ASSEMBLY_RUST
#define read_packet_integer reference_read_packet_integer
#define read_packet_u32 reference_read_packet_u32
#define read_packet_address reference_read_packet_address
#define lua_reconstruct_iphdr reference_lua_reconstruct_iphdr
#define lua_reconstruct_ip6hdr reference_lua_reconstruct_ip6hdr
#define lua_reconstruct_tcphdr reference_lua_reconstruct_tcphdr
#define lua_reconstruct_udphdr reference_lua_reconstruct_udphdr
#define lua_reconstruct_icmphdr reference_lua_reconstruct_icmphdr
#include "lua_header_fields_reference.inc"
#undef read_packet_integer
#undef read_packet_u32
#undef read_packet_address
#undef lua_reconstruct_iphdr
#undef lua_reconstruct_ip6hdr
#undef lua_reconstruct_tcphdr
#undef lua_reconstruct_udphdr
#undef lua_reconstruct_icmphdr
#include "lua_header_fields_candidate.inc"

static unsigned cases,successes,errors,boundaries,guarded,fault_cases,vm_faults,reentries;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL Lua header cases=%u boundaries=%u line=%d: %s\n",cases,boundaries,__LINE__,#v);exit(1);}}while(0)
struct allocator{bool armed;unsigned attempts,rejected,limit,live;};
static struct allocator *fault_allocator;
static void *allocate(void *context,void *pointer,size_t previous,size_t next)
{
    struct allocator *state=context;
    if(!next){if(pointer){CHECK(state->live);--state->live;}free(pointer);return NULL;}
    if(state->armed && next>previous && state->attempts++>=state->limit){++state->rejected;return NULL;}
    bool fresh=!pointer;void *result=realloc(pointer,next);if(result && fresh)++state->live;return result;
}
static const char *factory=
"NAMES={{'ip_tos','ip_len','ip_id','ip_off','ip_ttl','ip_p','ip_src','ip_dst'},"
"{'ip6_flow','ip6_nxt','ip6_hlim','ip6_src','ip6_dst','ip6_plen'},"
"{'th_sport','th_dport','th_seq','th_ack','th_x2','th_flags','th_win','th_sum','th_urp'},"
"{'uh_sport','uh_dport','uh_ulen','uh_sum'},{'icmp_type','icmp_code','icmp_data','icmp_cksum'}} "
"function HEADER_CASE(kind,field,variant,mode,tail) "
"local z=string.rep(string.char(0),16) local all={"
"{ip_tos=16,ip_len=40,ip_id=257,ip_off=0,ip_ttl=64,ip_p=6,ip_src=string.char(192,0,2,1),ip_dst=string.char(198,51,100,2)},"
"{ip6_flow=1610612736,ip6_nxt=6,ip6_hlim=64,ip6_src=z,ip6_dst=z},"
"{th_sport=1234,th_dport=443,th_seq=4294967295,th_ack=2147483649,th_x2=0,th_flags=2,th_win=4096,th_sum=257,th_urp=0},"
"{uh_sport=1234,uh_dport=443,uh_ulen=9,uh_sum=256},{icmp_type=8,icmp_code=0,icmp_data=65537,icmp_cksum=257}} "
"local t=all[kind+1] local names=NAMES[kind+1] "
"local values={false,true,0,-1,255,256,65535,65536,4294967295,4294967296,-4294967297,3.75,'65537','bad','',"
"string.char(0,255,1,2),z,string.rep('x',3),string.rep('x',17),{},function()end,math.huge,0/0} "
"if field==0 then return variant==0 and nil or values[variant] end "
"if field>0 then t[names[field]]=variant==0 and nil or values[variant] end "
"if tail==1 then if kind==0 then t.options=string.rep(string.char(1),40) "
"elseif kind==1 then t.exthdr={{type=60,next=51,data=string.rep(string.char(0),6)},{type=51,next=6,data=string.rep(string.char(0),10)}} "
"elseif kind==2 then t.options={{kind=1},{kind=2,data=string.char(5,180)},{kind=8,data=string.rep(string.char(0),8)}} end "
"elseif tail==2 then if kind==0 then t.options=string.rep('x',41) elseif kind==1 then t.exthdr={{type=44,data='bad'}} "
"elseif kind==2 then t.options={{kind=2,data='x'},{kind='bad'}} end "
"elseif tail==3 then if kind==1 then t.exthdr={{type=0,data=string.rep('x',6)},false} elseif kind==2 then t.options={{kind=1},false} end end "
"if mode==0 then return t end local held={} "
"return setmetatable({},{__index=function(_,k) TRACE(k) "
"if mode==2 and k==names[1] then t[names[2]]=-257 end "
"if mode==3 and k==names[field>0 and field or #names] then error('header lookup failed: '..k) end "
"if mode==4 and k==names[1] then REENTER(t) end "
"if mode==5 then held[#held+1]=string.rep(k..#held,4096);collectgarbage('step',1) end "
"return t[k] end}) end";
struct sample{uint8_t *buffer;size_t capacity,written;unsigned kind,flags;bool rust,negative,normal,ok;int error,stack;unsigned nested;uint32_t nested_hash;char message[512],trace[1024];size_t trace_length;};
static struct sample *active;
static bool build(lua_State *L,int index,uint8_t *buffer,size_t *length,bool rust,unsigned kind,unsigned flags)
{
    switch(kind){
    case 0:return rust?lua_reconstruct_iphdr(L,index,(struct ip *)buffer,length):reference_lua_reconstruct_iphdr(L,index,(struct ip *)buffer,length);
    case 1:return rust?lua_reconstruct_ip6hdr(L,index,(struct ip6_hdr *)buffer,length,flags&1?17:59,flags&2):reference_lua_reconstruct_ip6hdr(L,index,(struct ip6_hdr *)buffer,length,flags&1?17:59,flags&2);
    case 2:return rust?lua_reconstruct_tcphdr(L,index,(struct tcphdr *)buffer,length):reference_lua_reconstruct_tcphdr(L,index,(struct tcphdr *)buffer,length);
    case 3:return rust?lua_reconstruct_udphdr(L,index,(struct udphdr *)buffer):reference_lua_reconstruct_udphdr(L,index,(struct udphdr *)buffer);
    default:return rust?lua_reconstruct_icmphdr(L,index,(struct icmp46 *)buffer):reference_lua_reconstruct_icmphdr(L,index,(struct icmp46 *)buffer);
    }
}
static int trace(lua_State *L){const char *key=lua_tostring(L,1);size_t length=strlen(key);CHECK(active->trace_length+length+2<sizeof(active->trace));memcpy(active->trace+active->trace_length,key,length);active->trace_length+=length;active->trace[active->trace_length++]=';';active->trace[active->trace_length]=0;return 0;}
static int reenter(lua_State *L){uint8_t data[128];memset(data,0x5a,sizeof(data));size_t length=sizeof(data);bool ok=build(L,1,data,&length,active->rust,active->kind,active->flags);active->nested++;active->nested_hash=ok;for(unsigned i=0;i<128;++i)active->nested_hash=active->nested_hash*16777619u^data[i];return 0;}
static int run(lua_State *L){size_t length=active->capacity;int top=lua_gettop(L);bool ok=build(L,active->negative?-1:1,active->buffer,&length,active->rust,active->kind,active->flags);active->written=length;active->ok=ok;active->normal=true;active->stack=lua_gettop(L)-top;lua_pushboolean(L,ok);return 1;}
static lua_State *new_vm(struct allocator *allocator)
{
    lua_State *L=allocator?lua_newstate(allocate,allocator):luaL_newstate();CHECK(L);luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);
    lua_register(L,"TRACE",trace);lua_register(L,"REENTER",reenter);CHECK(!luaL_dostring(L,factory));return L;
}
static void execute(lua_State *L,int field,unsigned variant,unsigned mode,unsigned tail,struct sample *sample)
{
    lua_settop(L,0);lua_pushcfunction(L,run);lua_getglobal(L,"HEADER_CASE");lua_pushinteger(L,sample->kind);lua_pushinteger(L,field);lua_pushinteger(L,variant);lua_pushinteger(L,mode);lua_pushinteger(L,tail);CHECK(!lua_pcall(L,5,1,0));active=sample;sample->written=sample->capacity;
    if(fault_allocator){fault_allocator->armed=true;fault_allocator->attempts=fault_allocator->rejected=0;}
    sample->error=lua_pcall(L,1,1,0);
    if(fault_allocator)fault_allocator->armed=false;
    CHECK(lua_gettop(L)==1);if(sample->error){const char *message=lua_tostring(L,-1);snprintf(sample->message,sizeof(sample->message),"%s",message?message:"");}lua_settop(L,0);
}
struct guard{uint8_t *base,*end;};
static struct guard guard_new(void){struct guard value;value.base=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(value.base);value.end=value.base+4096;DWORD old;CHECK(VirtualProtect(value.end,4096,PAGE_NOACCESS,&old));return value;}
static void compare(lua_State *L,unsigned kind,int field,unsigned variant,unsigned mode,unsigned tail,size_t capacity,unsigned flags,bool negative,unsigned offset,struct guard *a,struct guard *b)
{
    struct sample left={.buffer=a->end-256-offset,.capacity=capacity,.kind=kind,.flags=flags,.negative=negative},right=left;right.buffer=b->end-256-offset;right.rust=true;
    memset(left.buffer-16,0xa5,272+offset);memset(right.buffer-16,0xa5,272+offset);execute(L,field,variant,mode,tail,&left);execute(L,field,variant,mode,tail,&right);
    if(left.error!=right.error || left.normal!=right.normal || left.ok!=right.ok || left.written!=right.written || left.stack!=right.stack || left.nested!=right.nested || left.nested_hash!=right.nested_hash || strcmp(left.message,right.message) || strcmp(left.trace,right.trace) || memcmp(left.buffer-16,right.buffer-16,272+offset)){
        fprintf(stderr,"DETAIL kind=%u field=%d variant=%u mode=%u tail=%u cap=%zu flags=%u negative=%u offset=%u olderr=%d newerr=%d oldok=%u newok=%u oldlen=%zu newlen=%zu\noldmsg=%s\nnewmsg=%s\noldtrace=%s\nnewtrace=%s\n",kind,field,variant,mode,tail,capacity,flags,negative,offset,left.error,right.error,left.ok,right.ok,left.written,right.written,left.message,right.message,left.trace,right.trace);CHECK(false);
    }
    for(unsigned i=1;i<=16;++i)CHECK(left.buffer[-(int)i]==0xa5);
    size_t limit=kind>=3?8:capacity;for(size_t i=limit;i<256+offset;++i)CHECK(left.buffer[i]==0xa5);
    if(left.normal)CHECK(left.stack==0);if(left.ok)++successes;if(left.error)++errors;reentries+=left.nested;++cases;++guarded;
}
static void boundary_checks(void)
{
    _Alignas(8)uint8_t memory[128];memset(memory,0xa5,sizeof(memory));zapret_lua_header_cursor cursor={0};zapret_lua_header_field field;zapret_lua_header_value value={0};
    CHECK(!zapret_lua_header_begin(5,memory,18,&cursor));++boundaries;
    CHECK(!zapret_lua_header_begin(0,NULL,18,&cursor));++boundaries;
    CHECK(!zapret_lua_header_begin(0,memory,17,&cursor));CHECK(memory[0]==0xa5);++boundaries;
    CHECK(!zapret_lua_header_begin(0,memory+1,18,&cursor));++boundaries;
    CHECK(!zapret_lua_header_begin(0,memory,18,NULL));++boundaries;
    CHECK(!zapret_lua_header_begin(0,memory,18,(void *)(memory+33)));++boundaries;
    CHECK(zapret_lua_header_next(NULL,&field)==2);++boundaries;
    CHECK(zapret_lua_header_observe(NULL,&value)==2);++boundaries;
    CHECK(zapret_lua_header_begin(0,memory,18,&cursor));CHECK(zapret_lua_header_next(&cursor,NULL)==2);++boundaries;
    CHECK(zapret_lua_header_next((void *)(memory+33),&field)==2);++boundaries;
    CHECK(zapret_lua_header_observe(&cursor,NULL)==2);++boundaries;
    CHECK(zapret_lua_header_observe(&cursor,(void *)(memory+33))==2);++boundaries;
    cursor.kind=5;CHECK(zapret_lua_header_next(&cursor,&field)==2 && zapret_lua_header_observe(&cursor,&value)==2);++boundaries;
    cursor.kind=0;cursor.index=9;CHECK(zapret_lua_header_next(&cursor,&field)==2 && zapret_lua_header_observe(&cursor,&value)==2);++boundaries;
    cursor.index=8;CHECK(zapret_lua_header_next(&cursor,&field)==0 && zapret_lua_header_observe(&cursor,&value)==2);++boundaries;
    cursor.index=0;cursor.target=NULL;CHECK(zapret_lua_header_next(&cursor,&field)==2 && zapret_lua_header_observe(&cursor,&value)==2);++boundaries;
    struct guard target=guard_new(),input=guard_new(),metadata=guard_new();const size_t sizes[]={18,44,20,8,8};
    for(unsigned kind=0;kind<5;++kind){
        CHECK(zapret_lua_header_begin(kind,target.end-sizes[kind],sizes[kind],&cursor));++boundaries;
        while(zapret_lua_header_next(&cursor,&field)==1){
            value=(zapret_lua_header_value){.tag=LUA_TNUMBER,.number=-1};
            if(field.conversion==4){value.tag=LUA_TSTRING;value.length=kind==0?4:16;value.data=input.end-value.length;memset((void *)value.data,0x7f,value.length);}
            zapret_lua_header_value *readonly=(void *)(metadata.end-sizeof(value));memcpy(readonly,&value,sizeof(value));DWORD old;CHECK(VirtualProtect(metadata.base,4096,PAGE_READONLY,&old));CHECK(zapret_lua_header_observe(&cursor,readonly)==0);CHECK(VirtualProtect(metadata.base,4096,PAGE_READWRITE,&old));++boundaries;
        }
        CHECK(zapret_lua_header_next(&cursor,&field)==0);
    }
    CHECK(VirtualFree(target.base,0,MEM_RELEASE) && VirtualFree(input.base,0,MEM_RELEASE) && VirtualFree(metadata.base,0,MEM_RELEASE));
}
static void allocation_checks(struct guard *a,struct guard *b)
{
    for(unsigned kind=0;kind<5;++kind)for(unsigned limit=0;limit<20;++limit){
        struct sample left={.buffer=a->end-256,.capacity=128,.kind=kind},right=left;right.buffer=b->end-256;right.rust=true;
        for(unsigned side=0;side<2;++side){struct allocator allocator={.limit=limit};lua_State *L=new_vm(&allocator);struct sample *sample=side?&right:&left;memset(sample->buffer-16,0xa5,272);fault_allocator=&allocator;execute(L,-1,0,5,1,sample);fault_allocator=NULL;
            if(sample->error){CHECK(sample->error==LUA_ERRMEM && allocator.rejected && !sample->normal && sample->written==sample->capacity);++vm_faults;}else CHECK(sample->ok && !allocator.rejected && sample->stack==0);
            for(unsigned i=1;i<=16;++i)CHECK(sample->buffer[-(int)i]==0xa5);for(unsigned i=128;i<256;++i)CHECK(sample->buffer[i]==0xa5);
            lua_close(L);CHECK(!allocator.live);
        }
        /* Trace and partial bytes stay identical with the same allocation budget. */
        CHECK(left.error==right.error && left.normal==right.normal && left.ok==right.ok && left.written==right.written && !strcmp(left.message,right.message) && !strcmp(left.trace,right.trace) && !memcmp(left.buffer-16,right.buffer-16,272));++fault_cases;
    }
    CHECK(vm_faults>20);
}
static double measure(lua_State *L,bool rust,unsigned kind,unsigned count)
{
    uint8_t data[128];LARGE_INTEGER begin,end,frequency;CHECK(QueryPerformanceFrequency(&frequency) && QueryPerformanceCounter(&begin));
    for(unsigned i=0;i<count;++i){size_t length=128;CHECK(build(L,1,data,&length,rust,kind,0));}
    CHECK(QueryPerformanceCounter(&end));return (double)(end.QuadPart-begin.QuadPart)*1e9/frequency.QuadPart/count;
}
static void benchmark(void)
{
    for(unsigned kind=0;kind<5;++kind){lua_State *L=new_vm(NULL);lua_getglobal(L,"HEADER_CASE");lua_pushinteger(L,kind);lua_pushinteger(L,-1);lua_pushinteger(L,0);lua_pushinteger(L,0);lua_pushinteger(L,1);CHECK(!lua_pcall(L,5,1,0));measure(L,false,kind,1000);measure(L,true,kind,1000);
        for(unsigned round=0;round<7;++round){double old,rust;if(round&1){rust=measure(L,true,kind,30000);old=measure(L,false,kind,30000);}else{old=measure(L,false,kind,30000);rust=measure(L,true,kind,30000);}printf("BENCH lua_header_fields kind=%u round=%u old_ns=%.3f rust_ns=%.3f ratio=%.5f\n",kind,round,old,rust,rust/old);}lua_close(L);
    }
}
int main(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"--benchmark")){benchmark();return 0;}
    lua_State *L=new_vm(NULL);struct guard a=guard_new(),b=guard_new();const unsigned lengths[]={8,6,9,4,4};const size_t capacities[]={0,7,19,20,39,40,59,60,80,128};
    for(unsigned kind=0;kind<5;++kind)for(int field=-1;field<=(int)lengths[kind];++field)for(unsigned variant=0;variant<24;++variant){if(field<0 && variant)continue;
        for(unsigned mode=0;mode<5;++mode)for(unsigned c=0;c<10;++c)compare(L,kind,field,variant,mode,variant%4,capacities[c],variant%4,c&1,(c&1)?1:0,&a,&b);
    }
    boundary_checks();lua_close(L);allocation_checks(&a,&b);CHECK(VirtualFree(a.base,0,MEM_RELEASE) && VirtualFree(b.base,0,MEM_RELEASE));
    printf("PASS lua_header_fields headers=5 fields=31 cases=%u successes=%u vm_errors=%u guarded=%u boundaries=%u reentries=%u fault_cases=%u vm_allocation_faults=%u real_luajit=1 exact_lookup_order=1 exact_partial_output=1 c_only_unwind=1 vm_allocations_released=1\n",cases,successes,errors,guarded,boundaries,reentries,fault_cases,vm_faults);return 0;
}
