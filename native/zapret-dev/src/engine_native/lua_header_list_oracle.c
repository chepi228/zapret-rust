/* MIT. Complete previous/new builders, including their observable Lua boundary. */
#include "params.h"
#include "engine_lua.h"
#include <lualib.h>
#include <luajit.h>
#undef main
#include "packet_write_windows.h"
#include "lua_header_list_common.inc"
#include "lua_header_fields_windows.inc"
#define lua_reconstruct_ip6hdr reference_lua_reconstruct_ip6hdr
#define lua_reconstruct_tcphdr reference_lua_reconstruct_tcphdr
#include "lua_header_list_reference.inc"
#undef lua_reconstruct_ip6hdr
#undef lua_reconstruct_tcphdr
#include "lua_header_list_windows.inc"
#include "lua_header_list_candidate.inc"

static unsigned cases,successes,errors,guarded,boundaries,reentries,fault_cases,vm_faults;
static bool reference_control;
static unsigned control_differences;
static unsigned fault_checkpoints,fault_tail_writes[2],fault_successes[2],fault_vm_differences;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL Lua header list cases=%u boundaries=%u line=%d: %s\n",cases,boundaries,__LINE__,#v);exit(1);}}while(0)
struct allocator{bool armed;unsigned calls,rejected,limit,live;};
static struct allocator *fault_allocator;
static void *allocate(void *context,void *pointer,size_t previous,size_t next){struct allocator *a=context;if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}if(a->armed && next>previous && a->calls++>=a->limit){++a->rejected;return NULL;}bool fresh=!pointer;void *result=realloc(pointer,next);if(result && fresh)++a->live;return result;}
static const char *factory=
"function LIST_CASE(mode,k,d,length,shape,behavior) "
"local kinds={false,true,-257,-1,0,1,2,44,51,60,256,257,258,3.75,'1','2','60',{},function()end,math.huge,0/0,2147483648,4294967297,65535} "
"local nexts={false,true,'17',257,-1} local z=string.rep(string.char(0),16) "
"local root=mode==0 and {th_sport=1234,th_dport=443,th_seq=4294967295,th_ack=2147483649,th_flags=18,th_win=4096} "
"or {ip6_flow=1610612736,ip6_nxt=6,ip6_hlim=64,ip6_src=z,ip6_dst=z} "
"local name=mode==0 and 'options' or 'exthdr' local key=mode==0 and 'kind' or 'type' "
"local raw={} raw[key]=kinds[k] raw.next=nexts[k%6] "
"local data=string.rep(string.char(0,255),math.floor(length/2))..(length%2==1 and 'q' or '') "
"local values={data,false,true,123,{},function()end,'123'} raw.data=values[d] "
"if shape==12 and mode==0 then raw[key]=k%2;raw.data=nil end "
"local list={} local held={} local element=raw "
"if behavior>0 or shape==12 and mode==0 then element=setmetatable({},{__index=function(_,field) TRACE(field) "
"if shape==12 and mode==0 and field=='data' then error('END/NOP data was queried') end "
"if behavior==2 and field==key then raw.next='17';raw.data=string.rep('M',mode==0 and 2 or 6);list[2]=raw;root[name]={};root.th_seq=99;root.ip6_plen=99 end "
"if behavior==3 and field==({key,'next','data'})[k%3+1] then error('list field failed: '..field) end "
"if behavior==4 and field==key then REENTER(root) end "
"if behavior==5 then held[#held+1]=string.rep(field..#held,4096);collectgarbage('step',1) end "
"return raw[field] end}) end "
"list[1]=element "
"if shape==0 then list=nil elseif shape==1 then list=false elseif shape==2 then list=123 elseif shape==3 then list='ignored' "
"elseif shape==4 then list={} elseif shape==6 then list[2]=element "
"elseif shape==7 then list[3]=setmetatable({},{__index=function()error('sparse tail was queried')end}) "
"elseif shape==8 then setmetatable(list,{__index=function()error('array __index was queried')end}) "
"elseif shape==9 then list[1]=false "
"elseif shape==10 then for i=1,64 do list[i]=element end "
"elseif shape==11 then list[key]=raw[key];list.next=raw.next;list.data=raw.data;for i=1,513 do list[i]=list end "
"elseif shape==13 then list[2]=false elseif shape==15 then return false end "
"root[name]=list if behavior>0 or shape==14 then local backing=root;root=setmetatable({},{__index=function(_,field) TRACE(field) "
"if shape==14 and field==name then error('list lookup failed') end "
"if behavior==5 then held[#held+1]=string.rep(field..#held,4096) end return backing[field] end}) end "
"return root end";
struct sample{uint8_t *buffer;size_t capacity,written;unsigned mode,flags,nested,trace_count,stop;bool rust,negative,normal,ok;int error,stack;uint32_t nested_hash;size_t trace_length;char message[512],trace[32768];};
static struct sample *active;
static bool build(lua_State *L,int index,uint8_t *buffer,size_t *length,bool rust,unsigned mode,unsigned flags){if(mode==0)return rust?lua_reconstruct_tcphdr(L,index,(struct tcphdr *)buffer,length):reference_lua_reconstruct_tcphdr(L,index,(struct tcphdr *)buffer,length);return rust?lua_reconstruct_ip6hdr(L,index,(struct ip6_hdr *)buffer,length,flags&1?17:59,flags&2):reference_lua_reconstruct_ip6hdr(L,index,(struct ip6_hdr *)buffer,length,flags&1?17:59,flags&2);}
static int trace(lua_State *L){const char *key=lua_tostring(L,1);size_t n=strlen(key);CHECK(active->trace_length+n+2<sizeof(active->trace));memcpy(active->trace+active->trace_length,key,n);active->trace_length+=n;active->trace[active->trace_length++]=';';active->trace[active->trace_length]=0;++active->trace_count;if(active->stop && active->trace_count==active->stop)return luaL_error(L,"forced list checkpoint");return 0;}
static int reenter(lua_State *L){if(active->nested)return 0;active->nested=1;uint8_t buffer[512];memset(buffer,0x5a,sizeof(buffer));size_t length=sizeof(buffer);bool ok=build(L,1,buffer,&length,active->rust,active->mode,active->flags);active->nested_hash=ok;for(unsigned i=0;i<512;++i)active->nested_hash=active->nested_hash*16777619u^buffer[i];return 0;}
static int run(lua_State *L){size_t length=active->capacity;int top=lua_gettop(L);bool ok=build(L,active->negative?-1:1,active->buffer,&length,active->rust,active->mode,active->flags);active->written=length;active->normal=true;active->ok=ok;active->stack=lua_gettop(L)-top;lua_pushboolean(L,ok);return 1;}
static lua_State *new_vm(struct allocator *a){lua_State *L=a?lua_newstate(allocate,a):luaL_newstate();CHECK(L);luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);lua_register(L,"TRACE",trace);lua_register(L,"REENTER",reenter);CHECK(!luaL_dostring(L,factory));return L;}
static void execute(lua_State *L,unsigned k,unsigned d,unsigned length,unsigned shape,unsigned behavior,struct sample *s){lua_settop(L,0);lua_pushcfunction(L,run);lua_getglobal(L,"LIST_CASE");lua_pushinteger(L,s->mode);lua_pushinteger(L,k);lua_pushinteger(L,d);lua_pushinteger(L,length);lua_pushinteger(L,shape);lua_pushinteger(L,behavior);CHECK(!lua_pcall(L,6,1,0));active=s;s->written=s->capacity;if(fault_allocator){fault_allocator->armed=true;fault_allocator->calls=fault_allocator->rejected=0;}s->error=lua_pcall(L,1,1,0);if(fault_allocator)fault_allocator->armed=false;CHECK(lua_gettop(L)==1);if(s->error){const char *message=lua_tostring(L,-1);snprintf(s->message,sizeof(s->message),"%s",message?message:"");}lua_settop(L,0);}
struct guard{uint8_t *base,*end;};
static struct guard guard_new(void){struct guard g;g.base=VirtualAlloc(NULL,32768,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(g.base);g.end=g.base+28672;DWORD old;CHECK(VirtualProtect(g.end,4096,PAGE_NOACCESS,&old));return g;}
static void compare(lua_State *L,unsigned mode,unsigned k,unsigned d,unsigned length,unsigned shape,unsigned behavior,size_t capacity,unsigned flags,unsigned offset,struct guard *a,struct guard *b){struct sample left={.buffer=a->end-capacity-offset,.capacity=capacity,.mode=mode,.flags=flags,.negative=offset!=0},right=left;right.buffer=b->end-capacity-offset;right.rust=true;memset(left.buffer-16,0xa5,capacity+offset+16);memset(right.buffer-16,0xa5,capacity+offset+16);execute(L,k,d,length,shape,behavior,&left);execute(L,k,d,length,shape,behavior,&right);
    if(left.error!=right.error || left.normal!=right.normal || left.ok!=right.ok || left.written!=right.written || left.stack!=right.stack || left.nested!=right.nested || left.nested_hash!=right.nested_hash || strcmp(left.message,right.message) || strcmp(left.trace,right.trace) || memcmp(left.buffer-16,right.buffer-16,capacity+offset+16)){
        fprintf(stderr,"DETAIL mode=%u k=%u d=%u length=%u shape=%u behavior=%u cap=%zu flags=%u offset=%u olderr=%d newerr=%d oldok=%u newok=%u oldlen=%zu newlen=%zu\noldmsg=%s\nnewmsg=%s\noldtrace=%s\nnewtrace=%s\n",mode,k,d,length,shape,behavior,capacity,flags,offset,left.error,right.error,left.ok,right.ok,left.written,right.written,left.message,right.message,left.trace,right.trace);CHECK(false);
    }
    for(unsigned i=1;i<=16;++i)CHECK(left.buffer[-(int)i]==0xa5);for(unsigned i=0;i<offset;++i)CHECK(left.buffer[capacity+i]==0xa5);if(left.normal)CHECK(left.stack==0);if(left.ok)++successes;if(left.error)++errors;reentries+=left.nested;++cases;++guarded;
}
static void step(zapret_lua_header_list_state *s,zapret_lua_header_list_action *a,int tag,int64_t number,const uint8_t *data,size_t length){zapret_lua_header_list_value v={data,length,number,tag};CHECK(zapret_lua_header_list_step(s,&v,a));}
static void boundary_checks(void){
    _Alignas(8)uint8_t storage[256];memset(storage,0xa5,sizeof(storage));zapret_tcp_fields tcp={0};zapret_ipv6_fields ip6={0};zapret_lua_header_list_state state;zapret_lua_header_list_action action;zapret_lua_header_list_value value={0};
#define BAD_BEGIN(mode,out,cap,fields,keep,s,a) do{CHECK(!zapret_lua_header_list_begin(mode,out,cap,fields,17,keep,s,a));++boundaries;}while(0)
    BAD_BEGIN(2,storage,64,&tcp,0,&state,&action);BAD_BEGIN(0,NULL,64,&tcp,0,&state,&action);BAD_BEGIN(0,storage,19,&tcp,0,&state,&action);BAD_BEGIN(1,storage,39,&ip6,0,&state,&action);BAD_BEGIN(0,storage,SIZE_MAX,&tcp,0,&state,&action);BAD_BEGIN(0,storage,64,NULL,0,&state,&action);BAD_BEGIN(0,storage,64,storage+1,0,&state,&action);BAD_BEGIN(0,storage,64,&tcp,2,&state,&action);BAD_BEGIN(0,storage,64,&tcp,0,NULL,&action);BAD_BEGIN(0,storage,64,&tcp,0,(void *)(storage+129),&action);BAD_BEGIN(0,storage,64,&tcp,0,&state,NULL);BAD_BEGIN(0,storage,64,&tcp,0,&state,(void *)(storage+129));CHECK(storage[0]==0xa5);
    CHECK(zapret_lua_header_list_begin(0,storage,64,&tcp,17,0,&state,&action));
    CHECK(!zapret_lua_header_list_step(NULL,&value,&action));++boundaries;CHECK(!zapret_lua_header_list_step(&state,NULL,&action));++boundaries;CHECK(!zapret_lua_header_list_step(&state,&value,NULL));++boundaries;
    CHECK(!zapret_lua_header_list_step((void *)(storage+129),&value,&action));++boundaries;CHECK(!zapret_lua_header_list_step(&state,(void *)(storage+129),&action));++boundaries;CHECK(!zapret_lua_header_list_step(&state,&value,(void *)(storage+129)));++boundaries;
    for(unsigned bad=0;bad<9;++bad){CHECK(zapret_lua_header_list_begin(0,storage,64,&tcp,17,0,&state,&action));switch(bad){case 0:state.mode=2;break;case 1:state.phase=0;break;case 2:state.phase=4;break;case 3:state.used=65;break;case 4:state.used=19;break;case 5:state.item=0;break;case 6:state.next_offset=6;break;case 7:state.preserve=2;break;case 8:state.output=NULL;break;}CHECK(!zapret_lua_header_list_step(&state,&value,&action));CHECK(storage[0]==0xa5);++boundaries;}
    struct guard out=guard_new(),input=guard_new(),metadata=guard_new();
    for(unsigned mode=0;mode<2;++mode){CHECK(zapret_lua_header_list_begin(mode,out.end-64,64,mode?(void *)&ip6:(void *)&tcp,17,0,&state,&action));step(&state,&action,5,0,NULL,0);step(&state,&action,5,0,NULL,0);step(&state,&action,3,mode?60:2,NULL,0);if(mode)step(&state,&action,3,17,NULL,0);memset(input.end-6,7,6);zapret_lua_header_list_value *readonly=(void *)(metadata.end-sizeof(value));*readonly=(zapret_lua_header_list_value){input.end-6,6,0,4};DWORD old;CHECK(VirtualProtect(metadata.base,28672,PAGE_READONLY,&old));CHECK(zapret_lua_header_list_step(&state,readonly,&action));CHECK(VirtualProtect(metadata.base,28672,PAGE_READWRITE,&old));CHECK(action.operation==2);step(&state,&action,0,0,NULL,0);CHECK(action.operation==0 && action.length==(mode?48:28));CHECK(!zapret_lua_header_list_step(&state,&value,&action));boundaries+=3;}
    CHECK(VirtualFree(out.base,0,MEM_RELEASE) && VirtualFree(input.base,0,MEM_RELEASE) && VirtualFree(metadata.base,0,MEM_RELEASE));
}
struct catalogue{unsigned count;size_t length;uint8_t bytes[64][144];char trace[32768];};
static void catalogue(struct guard *g,unsigned mode,struct catalogue *c){
    struct sample complete={.buffer=g->end-128,.capacity=128,.mode=mode};lua_State *L=new_vm(NULL);memset(complete.buffer-16,0xa5,144);execute(L,mode?10:7,1,6,6,5,&complete);CHECK(complete.ok && !complete.error && complete.normal && complete.trace_count<64);c->count=complete.trace_count+1;c->length=complete.written;strcpy(c->trace,complete.trace);memcpy(c->bytes[0],complete.buffer-16,144);lua_close(L);
    for(unsigned stop=1;stop<c->count;++stop){L=new_vm(NULL);struct sample s={.buffer=g->end-128,.capacity=128,.mode=mode,.stop=stop};memset(s.buffer-16,0xa5,144);execute(L,mode?10:7,1,6,6,5,&s);CHECK(s.error==LUA_ERRRUN && !s.normal && strstr(s.message,"forced list checkpoint"));memcpy(c->bytes[stop],s.buffer-16,144);lua_close(L);}fault_checkpoints+=c->count;
}
static void allocation_checks(struct guard *a,struct guard *b){for(unsigned mode=0;mode<2;++mode){struct catalogue c;catalogue(a,mode,&c);for(unsigned limit=0;limit<96;++limit){struct sample left={.buffer=a->end-128,.capacity=128,.mode=mode},right=left;right.buffer=b->end-128;right.rust=!reference_control;unsigned calls[2],rejected[2];
    for(unsigned side=0;side<2;++side){struct allocator allocator={.limit=limit};lua_State *L=new_vm(&allocator);struct sample *s=side?&right:&left;memset(s->buffer-16,0xa5,144);fault_allocator=&allocator;execute(L,mode?10:7,1,6,6,5,s);fault_allocator=NULL;calls[side]=allocator.calls;rejected[side]=allocator.rejected;
        CHECK(s->trace_length<=strlen(c.trace) && !strncmp(c.trace,s->trace,s->trace_length));bool known=false;for(unsigned i=0;i<c.count;++i)if(!memcmp(c.bytes[i],s->buffer-16,144))known=true;CHECK(known);
        if(s->error){CHECK(s->error==LUA_ERRMEM && allocator.rejected && !s->normal && s->written==s->capacity && !strcmp(s->message,"not enough memory"));++vm_faults;if(s->buffer[mode?40:20]!=0xa5)++fault_tail_writes[mode];}else{CHECK(s->ok && !allocator.rejected && s->stack==0 && s->written==c.length && !strcmp(c.trace,s->trace) && !memcmp(c.bytes[0],s->buffer-16,144));++fault_successes[mode];}
        for(unsigned i=1;i<=16;++i)CHECK(s->buffer[-(int)i]==0xa5);lua_close(L);CHECK(!allocator.live);
    }
    /* LuaJIT's fresh VMs can reach different GC checkpoints at the same growth
       budget, including old-vs-old runs. Check every result against all exact
       C checkpoint outputs and a prefix of the complete C trace instead. */
    if(left.error!=right.error || left.written!=right.written || calls[0]!=calls[1] || rejected[0]!=rejected[1] || strcmp(left.trace,right.trace) || memcmp(left.buffer-16,right.buffer-16,144)){++fault_vm_differences;if(reference_control)++control_differences;}++fault_cases;
}}CHECK(vm_faults>20 && fault_tail_writes[0] && fault_tail_writes[1] && fault_successes[0] && fault_successes[1]);}
static double measure(lua_State *L,bool rust,unsigned mode,unsigned flags,unsigned count){uint8_t output[8192];LARGE_INTEGER begin,end,frequency;CHECK(QueryPerformanceFrequency(&frequency) && QueryPerformanceCounter(&begin));for(unsigned i=0;i<count;++i){size_t length=8192;CHECK(build(L,1,output,&length,rust,mode,flags));}CHECK(QueryPerformanceCounter(&end));return (double)(end.QuadPart-begin.QuadPart)*1e9/frequency.QuadPart/count;}
static void benchmark(void){for(unsigned mode=0;mode<2;++mode)for(unsigned scenario=0;scenario<4;++scenario){lua_State *L=new_vm(NULL);lua_getglobal(L,"LIST_CASE");lua_pushinteger(L,mode);lua_pushinteger(L,mode?10:7);lua_pushinteger(L,1);lua_pushinteger(L,mode?6:2);lua_pushinteger(L,scenario==0?0:scenario==1?5:scenario==2?6:10);lua_pushinteger(L,0);CHECK(!lua_pcall(L,6,1,0));if(mode==0 && scenario==3){lua_getfield(L,1,"options");for(unsigned i=11;i<=64;++i){lua_pushnil(L);lua_rawseti(L,-2,i);}lua_pop(L,1);}measure(L,false,mode,0,500);measure(L,true,mode,0,500);for(unsigned round=0;round<7;++round){double old,rust;if(round&1){rust=measure(L,true,mode,0,10000);old=measure(L,false,mode,0,10000);}else{old=measure(L,false,mode,0,10000);rust=measure(L,true,mode,0,10000);}printf("BENCH lua_header_list mode=%u scenario=%u round=%u old_ns=%.3f rust_ns=%.3f ratio=%.5f\n",mode,scenario,round,old,rust,rust/old);}lua_close(L);}}
int main(int argc,char **argv){if(argc==2 && !strcmp(argv[1],"--benchmark")){benchmark();return 0;}if(argc==2 && !strcmp(argv[1],"--oom-control")){reference_control=true;struct guard a=guard_new(),b=guard_new();allocation_checks(&a,&b);CHECK(VirtualFree(a.base,0,MEM_RELEASE) && VirtualFree(b.base,0,MEM_RELEASE));printf("PASS lua_header_list_reference_control pairs=%u independent_vm_differences=%u\n",fault_cases,control_differences);return 0;}lua_State *L=new_vm(NULL);struct guard a=guard_new(),b=guard_new();const size_t capacities[]={0,19,20,21,23,24,39,40,41,48,51,52,59,60,61,64,80,128,512,4096,8192};const unsigned lengths[]={0,1,2,5,6,7,10,38,40,41};
    for(unsigned mode=0;mode<2;++mode)for(unsigned k=0;k<25;++k)for(unsigned d=0;d<8;++d)for(unsigned n=0;n<10;++n)for(unsigned c=0;c<10;++c)compare(L,mode,k,d,lengths[n],5,1,capacities[c],k%4,c&1?7:0,&a,&b);
    for(unsigned mode=0;mode<2;++mode)for(unsigned shape=0;shape<16;++shape)for(unsigned behavior=0;behavior<5;++behavior)for(unsigned c=0;c<21;++c)for(unsigned flags=0;flags<4;++flags)compare(L,mode,mode?10:7,1,6,shape,behavior,capacities[c],flags,c&1?7:0,&a,&b);
    for(unsigned length=0;length<=42;++length)for(size_t capacity=20;capacity<=64;++capacity)compare(L,0,7,1,length,6,1,capacity,0,0,&a,&b);
    const unsigned extension_lengths[]={6,7,8,9,10,14,30,1021,1022,1023,1024,2045,2046,2047,2048};
    for(unsigned k=8;k<=10;++k)for(unsigned n=0;n<15;++n)for(unsigned c=0;c<21;++c)compare(L,1,k,1,extension_lengths[n],6,1,capacities[c],c%4,c&1?7:0,&a,&b);
    boundary_checks();lua_close(L);allocation_checks(&a,&b);CHECK(VirtualFree(a.base,0,MEM_RELEASE) && VirtualFree(b.base,0,MEM_RELEASE));printf("PASS lua_header_list headers=2 cases=%u successes=%u vm_errors=%u guarded=%u boundaries=%u reentries=%u fault_cases=%u vm_allocation_faults=%u fault_checkpoints=%u tcp_partial_faults=%u ipv6_partial_faults=%u independent_vm_differences=%u real_luajit=1 exact_lookup_order=1 exact_partial_output=1 raw_array_access=1 c_only_unwind=1 vm_allocations_released=1\n",cases,successes,errors,guarded,boundaries,reentries,fault_cases,vm_faults,fault_checkpoints,fault_tail_writes[0],fault_tail_writes[1],fault_vm_differences);return 0;}
