/* MIT. Complete outer Lua APIs; packet algorithms are real, I/O boundaries fake. */
#include <iphlpapi.h>
#include "params.h"
#include "engine_lua.h"
#include <lualib.h>
#include <luajit.h>
#include <stdarg.h>
#undef main
struct params_s params;
static unsigned cases,errors,reentries,boundaries,fault_cases,vm_faults,sends,feeds;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL packet dispatch cases=%u boundaries=%u line=%d: %s\n",cases,boundaries,__LINE__,#v);exit(1);}}while(0)
struct sample{unsigned mode,variant,option,flags,depth,nested,trace_count;bool rust;int status,count,types[2];size_t lengths[2];uint64_t hashes[2],send_hash,parse_hash,ifout_hash;int repeats;uint32_t mark,reverse;long random_after;size_t used;char trace[8192],diagnostic[2048],message[512];};static struct sample *active;static lua_State *active_vm;
static uint64_t hash(const void *data,size_t length){const uint8_t *p=data;uint64_t h=1469598103934665603ull;for(size_t i=0;i<length;++i)h=(h^p[i])*1099511628211ull;return h;}
static void event(const char *name){size_t n=strlen(name);CHECK(active->used+n+2<sizeof(active->trace));memcpy(active->trace+active->used,name,n);active->used+=n;active->trace[active->used++]=';';active->trace[active->used]=0;++active->trace_count;}
static int log_message(const char *format,va_list args){size_t n=strlen(active->diagnostic);CHECK(n<sizeof(active->diagnostic));return vsnprintf(active->diagnostic+n,sizeof(active->diagnostic)-n,format,args);}
int DLOG(const char *format,...){va_list args;va_start(args,format);int n=log_message(format,args);va_end(args);return n;}
int DLOG_ERR(const char *format,...){va_list args;va_start(args,format);int n=log_message(format,args);va_end(args);return n;}
#include "lua_packet_dispatch_common.inc"
#include "lua_packet_options_windows.inc"
#define ZAPRET_LUA_PACKET_ASSEMBLY_RUST
#include "lua_packet_dispatch_headers.inc"
#include "lua_packet_assembly_windows.inc"
bool zapret_packet_extract_dst(const uint8_t *,size_t,void *);
static bool fake_destination(const uint8_t *data,size_t length,struct sockaddr *destination){event("destination");if(active->flags&4)return false;return zapret_packet_extract_dst(data,length,destination);}
static void fake_parse(const uint8_t *data,size_t length,struct dissect *out,bool partial){event(partial?"parse-partial":"parse");active->parse_hash=hash(data,length);proto_dissect_l3l4(data,length,out,partial);}
static uintptr_t pools[2];static t_ctrack track;
static void fake_purge(t_conntrack *pool){event("purge");CHECK(pool==&params.conntrack);if(active->flags&128)luaL_error(active_vm,"purge callback failed");params.conntrack.pool=(void *)&pools[1];if(active->flags&64)params.ctrack_disable=true;}
static bool fake_feed(t_conntrack *pool,const struct dissect *packet,t_ctrack **out,bool *reverse){event("feed");CHECK(pool==&params.conntrack && pool->pool==(void *)&pools[1]);++feeds;if(active->flags&256)luaL_error(active_vm,"feed callback failed");if(active->flags&8 || (!packet->tcp && !packet->udp))return false;*out=active->flags&32?NULL:&track;*reverse=(active->flags&2)!=0;active->reverse=*reverse;return true;}
static void fake_push_track(lua_State *L,const t_ctrack *value,const t_ctrack_positions *position,bool reverse){event("track");CHECK(!position && value==(active->flags&32?NULL:&track));if(active->flags&512)luaL_error(L,"track constructor failed");lua_newtable(L);lua_pushboolean(L,reverse);lua_setfield(L,-2,"reverse");lua_pushinteger(L,active->parse_hash%2147483647);lua_setfield(L,-2,"packet");}
static void fake_push_dissect(lua_State *L,const struct dissect *packet){event("dissect");lua_newtable(L);lua_pushinteger(L,packet->len_pkt);lua_setfield(L,-2,"length");lua_pushinteger(L,packet->proto);lua_setfield(L,-2,"proto");lua_pushinteger(L,packet->len_payload);lua_setfield(L,-2,"payload_length");}
static bool fake_send(int repeats,const struct sockaddr *destination,uint32_t mark,const char *ifout,const void *data,size_t length){event("send");CHECK(destination->sa_family==AF_INET || destination->sa_family==AF_INET6);++sends;active->repeats=repeats;active->mark=mark;active->ifout_hash=ifout?hash(ifout,strlen(ifout)):0;active->send_hash=hash(data,length);if(active->flags&1024)luaL_error(active_vm,"send callback failed");return (active->flags&16)==0;}
#define extract_dst fake_destination
#define proto_dissect_l3l4 fake_parse
#define ConntrackPoolPurge fake_purge
#define ConntrackPoolFeed fake_feed
#define lua_push_ctrack fake_push_track
#define lua_push_dissect fake_push_dissect
#define rawsend_rep fake_send
#define luacall_rawsend reference_rawsend
#define luacall_rawsend_dissect reference_rawsend_dissect
#define luacall_conntrack_feed reference_conntrack_feed
#define luacall_reconstruct_dissect reference_reconstruct_dissect
#define luacall_dissect reference_dissect
#include "lua_packet_dispatch_reference.inc"
#undef luacall_rawsend
#undef luacall_rawsend_dissect
#undef luacall_conntrack_feed
#undef luacall_reconstruct_dissect
#undef luacall_dissect
#include "lua_packet_dispatch_windows.inc"
static lua_CFunction entry(bool rust,unsigned mode){switch(mode){case 0:return rust?luacall_rawsend:reference_rawsend;case 1:return rust?luacall_rawsend_dissect:reference_rawsend_dissect;case 2:return rust?luacall_conntrack_feed:reference_conntrack_feed;case 3:return rust?luacall_reconstruct_dissect:reference_reconstruct_dissect;default:return rust?luacall_dissect:reference_dissect;}}
static int trace(lua_State *L){event(lua_tostring(L,1));return 0;}
static int mutate(lua_State *L){params.desync_fwmark=(uint32_t)lua_tointeger(L,1);if(active->flags&64)params.ctrack_disable=!params.ctrack_disable;return 0;}
static int nested(lua_State *L){if(active->depth)return 0;event("nested-begin");++active->depth;++active->nested;++reentries;lua_pushcfunction(L,entry(active->rust,2));lua_getglobal(L,"WIRE");int code=lua_pcall(L,1,2,0);CHECK(!code);lua_pop(L,2);--active->depth;event("nested-end");return 0;}
static const char *factory=
"function BASE() return {ip={ip_ttl=64,ip_p=6,ip_src=string.char(192,0,2,1),ip_dst=string.char(198,51,100,2)},tcp={th_sport=12345,th_dport=443,th_seq=100,th_ack=0,th_flags=2,th_win=4096},payload='a'..string.char(0)..'bc'} end "
"function CASE(id,opt) local t=BASE() local z=string.rep(string.char(0),16) "
"if id==1 then t.ip=nil;t.ip6={ip6_src=z,ip6_dst=z,ip6_hlim=64};t.tcp=nil;t.udp={uh_sport=12345,uh_dport=443} "
"elseif id==2 then t.ip.ip_p=17;t.tcp=nil;t.udp={uh_sport=12345,uh_dport=443} "
"elseif id==3 then t.ip.ip_p=1;t.tcp=nil;t.icmp={icmp_type=8,icmp_code=0,icmp_data=42} "
"elseif id==4 then t={} elseif id==5 then t=false elseif id==6 then t=42 elseif id==7 then t=nil elseif id==8 then t='short' elseif id==9 then t=WIRE elseif id==10 then t=WIRE6 "
"elseif id==11 then t.payload=123 elseif id==12 then t.payload={} elseif id==13 then t.payload=string.rep('x',70000) elseif id==14 then t.tcp.th_seq='bad' "
"elseif id==15 then t.ip.ip_src='bad' elseif id==16 then t.frag_off=0;t.tcp={} elseif id==17 then t.ip.options=string.rep('x',41) "
"elseif id==18 then t.tcp.options={{kind=1},{kind=2,data=string.char(5,180)}} "
"elseif id==19 then t.ip=nil;t.ip6={ip6_src=z,ip6_dst=z,ip6_hlim=64,exthdr={{type=0,data=string.rep('x',6)}}} "
"elseif id==20 then local backing=t;t=setmetatable({},{__index=function(_,k)TRACE('packet.'..k);return backing[k]end}) "
"elseif id==21 then t.ip=nil;t.ip6={ip6_src=z,ip6_dst=z,ip6_plen=false} elseif id==22 then t.payload=string.rep('x',65535) "
"elseif id==23 then t.tcp=nil elseif id==24 then t.ip='skip' end "
"local o,r={},{} local held={} local function wrap(backing,group) return setmetatable({},{__index=function(_,k) TRACE(group..k) "
"if opt==5 then MARK(2048);if k=='fwmark' then backing.fwmark=7 end;if k=='badsum' then error('option callback failed') end "
"elseif opt==6 then held[#held+1]=string.rep(group..k..#held,4096);collectgarbage('step',1) "
"elseif opt==7 then NESTED() end return backing[k] end}) end "
"if opt==1 then o={repeats=2,fwmark=3,ifout='7.2'};r={badsum=true} elseif opt==2 then o={repeats=-1} elseif opt==3 then o=false;r=false elseif opt==4 then o=nil;r=nil "
"elseif opt>=5 then o=wrap({repeats=2,fwmark=3,ifout='7.2'},'send.');r=wrap({keepsum=false,badsum=true,ip6_preserve_next=false},'reconstruct.') end return t,o,r end "
"function SERIAL(v) if type(v)~='table' then return tostring(v) end local keys={}for k in pairs(v)do keys[#keys+1]=k end table.sort(keys) local s='' for _,k in ipairs(keys)do s=s..k..'='..SERIAL(v[k])..';' end return s end";
struct allocator{bool armed;unsigned limit,calls,rejected,live;};static struct allocator *fault_allocator;
static void *allocate(void *context,void *pointer,size_t previous,size_t next){struct allocator *a=context;if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}if(a->armed && next>previous && a->calls++>=a->limit){++a->rejected;return NULL;}bool fresh=!pointer;void *result=realloc(pointer,next);if(result && fresh)++a->live;return result;}
static lua_State *new_vm(struct allocator *a){lua_State *L=a?lua_newstate(allocate,a):luaL_newstate();CHECK(L);luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);lua_register(L,"TRACE",trace);lua_register(L,"MARK",mutate);lua_register(L,"NESTED",nested);uint8_t wire[]={0x45,0,0,40,0,1,0,0,64,6,0,0,192,0,2,1,198,51,100,2,0x30,0x39,1,0xbb,0,0,0,100,0,0,0,0,0x50,2,0x20,0,0,0,0,0};lua_pushlstring(L,(char *)wire,sizeof(wire));lua_setglobal(L,"WIRE");uint8_t wire6[48]={0x60};wire6[5]=8;wire6[6]=17;wire6[7]=64;wire6[41]=1;wire6[43]=2;wire6[45]=8;lua_pushlstring(L,(char *)wire6,sizeof(wire6));lua_setglobal(L,"WIRE6");CHECK(!luaL_dostring(L,factory));return L;}
static void prepare(lua_State *L,struct sample *s,unsigned argc){lua_settop(L,0);lua_pushcfunction(L,entry(s->rust,s->mode));lua_getglobal(L,"CASE");lua_pushinteger(L,s->variant);lua_pushinteger(L,s->option);CHECK(!lua_pcall(L,2,3,0));if(s->mode==2 || s->mode==3){lua_remove(L,3);}if(s->mode==4){lua_settop(L,2);lua_pushboolean(L,s->option!=3 && s->option!=4);}while(lua_gettop(L)>(int)argc+1)lua_pop(L,1);while(lua_gettop(L)<(int)argc+1)lua_pushnil(L);}
static void capture(lua_State *L,struct sample *s){s->count=lua_gettop(L);CHECK(s->count<=2);for(int i=0;i<s->count;++i){int index=i+1;s->types[i]=lua_type(L,index);if(s->types[i]==LUA_TSTRING){const char *data=lua_tolstring(L,index,&s->lengths[i]);s->hashes[i]=hash(data,s->lengths[i]);}else if(s->types[i]==LUA_TBOOLEAN)s->hashes[i]=lua_toboolean(L,index);else if(s->types[i]==LUA_TTABLE){lua_getglobal(L,"SERIAL");lua_pushvalue(L,index);CHECK(!lua_pcall(L,1,1,0));size_t length;const char *data=lua_tolstring(L,-1,&length);s->hashes[i]=hash(data,length);s->lengths[i]=length;lua_pop(L,1);}else CHECK(s->types[i]==LUA_TNIL);}}
static void execute(lua_State *L,struct sample *s,unsigned argc){prepare(L,s,argc);active=s;active_vm=L;params.ctrack_disable=(s->flags&1)!=0;params.desync_fwmark=0x100;params.conntrack.pool=(void *)&pools[0];srandom(1234+s->variant);if(fault_allocator){fault_allocator->armed=true;fault_allocator->calls=fault_allocator->rejected=0;}s->status=lua_pcall(L,argc,LUA_MULTRET,0);if(fault_allocator)fault_allocator->armed=false;s->random_after=random();if(s->status){CHECK(lua_gettop(L)==1);const char *msg=lua_tostring(L,-1);snprintf(s->message,sizeof(s->message),"%s",msg?msg:"");}else capture(L,s);lua_settop(L,0);}
static void compare(lua_State *L,unsigned mode,unsigned variant,unsigned option,unsigned flags,unsigned argc){struct sample a={.mode=mode,.variant=variant,.option=option,.flags=flags},b=a;b.rust=true;execute(L,&a,argc);execute(L,&b,argc);b.rust=false;if(memcmp(&a,&b,sizeof(a))){fprintf(stderr,"DETAIL mode=%u variant=%u option=%u flags=%u argc=%u olderr=%d newerr=%d oldcount=%d newcount=%d\noldmsg=%s\nnewmsg=%s\noldtrace=%s\nnewtrace=%s\noldlog=%s\nnewlog=%s\n",mode,variant,option,flags,argc,a.status,b.status,a.count,b.count,a.message,b.message,a.trace,b.trace,a.diagnostic,b.diagnostic);CHECK(false);}++cases;if(a.status)++errors;}
static void boundaries_check(void){_Alignas(8)uint8_t memory[256];memset(memory,0xa5,sizeof(memory));zapret_lua_packet_dispatch_state state;zapret_lua_packet_dispatch_action action;zapret_lua_packet_dispatch_value value={0};CHECK(!zapret_lua_packet_dispatch_begin(5,memory,64,&state,&action));++boundaries;CHECK(!zapret_lua_packet_dispatch_begin(1,NULL,64,&state,&action));++boundaries;CHECK(!zapret_lua_packet_dispatch_begin(1,memory,SIZE_MAX,&state,&action));++boundaries;CHECK(!zapret_lua_packet_dispatch_begin(0,NULL,0,NULL,&action));++boundaries;CHECK(!zapret_lua_packet_dispatch_begin(0,NULL,0,&state,NULL));++boundaries;CHECK(!zapret_lua_packet_dispatch_begin(0,NULL,0,(void *)(memory+1),&action));++boundaries;CHECK(!zapret_lua_packet_dispatch_step(NULL,&value,&action));++boundaries;CHECK(!zapret_lua_packet_dispatch_step(&state,NULL,&action));++boundaries;CHECK(!zapret_lua_packet_dispatch_step(&state,&value,NULL));++boundaries;
    for(unsigned bad=0;bad<8;++bad){CHECK(zapret_lua_packet_dispatch_begin(0,NULL,0,&state,&action));switch(bad){case 0:state.mode=5;break;case 1:state.phase=0;break;case 2:state.phase=23;break;case 3:state.phase=12;break;case 4:state.reverse=2;break;case 5:state.success=2;break;case 6:state.length=1;break;case 7:state.capacity=SIZE_MAX;break;}CHECK(!zapret_lua_packet_dispatch_step(&state,&value,&action));++boundaries;}
    uint8_t *pages=VirtualAlloc(NULL,16384,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(pages);DWORD old;CHECK(VirtualProtect(pages+4096,4096,PAGE_NOACCESS,&old) && VirtualProtect(pages+12288,4096,PAGE_NOACCESS,&old));zapret_lua_packet_dispatch_state *end=(void *)(pages+4096-sizeof(state));zapret_lua_packet_dispatch_action *out=(void *)(pages+12288-sizeof(action));CHECK(zapret_lua_packet_dispatch_begin(0,NULL,0,end,out));CHECK(zapret_lua_packet_dispatch_step(end,&value,out));CHECK(out->kind==5);zapret_lua_packet_dispatch_value *readonly=(void *)(pages+4096-sizeof(state)-sizeof(value));*readonly=(zapret_lua_packet_dispatch_value){.data=pages,.length=4};CHECK(VirtualProtect(pages,4096,PAGE_READONLY,&old));CHECK(!zapret_lua_packet_dispatch_step((void *)(pages+1),readonly,out));CHECK(VirtualProtect(pages,4096,PAGE_READWRITE,&old));CHECK(zapret_lua_packet_dispatch_step(end,readonly,out) && out->kind==7);boundaries+=3;CHECK(VirtualFree(pages,0,MEM_RELEASE));}
static void faults(void){for(unsigned mode=0;mode<5;++mode){unsigned variant=(mode==0 || mode==4)?9:0;struct sample baseline={.mode=mode,.variant=variant,.option=6};lua_State *initial=new_vm(NULL);execute(initial,&baseline,mode==1?3:2);CHECK(!baseline.status);lua_close(initial);for(unsigned side=0;side<2;++side)for(unsigned limit=0;limit<64;++limit){struct allocator a={.limit=limit};lua_State *L=new_vm(&a);struct sample s={.mode=mode,.variant=variant,.option=6,.rust=side!=0};fault_allocator=&a;execute(L,&s,mode==1?3:2);fault_allocator=NULL;CHECK(s.used<=baseline.used && !strncmp(s.trace,baseline.trace,s.used));if(s.status){CHECK(s.status==LUA_ERRMEM && a.rejected);++vm_faults;}else{CHECK(!a.rejected && s.count==baseline.count && !memcmp(s.hashes,baseline.hashes,sizeof(s.hashes)) && !strcmp(s.diagnostic,baseline.diagnostic));}lua_close(L);CHECK(!a.live);++fault_cases;}}CHECK(vm_faults>20);}
int main(void){lua_State *L=new_vm(NULL);const unsigned flags[]={0,1,2,4,8,16,32,64};for(unsigned mode=0;mode<5;++mode)for(unsigned variant=0;variant<25;++variant)for(unsigned option=0;option<8;++option)for(unsigned f=0;f<8;++f)for(unsigned argc=0;argc<5;++argc)compare(L,mode,variant,option,flags[f],argc);for(unsigned flag=128;flag<=1024;flag*=2)for(unsigned mode=0;mode<5;++mode)for(unsigned option=0;option<2;++option)compare(L,mode,mode==0 || mode==4?9:0,option,flag,mode==1?3:2);lua_close(L);boundaries_check();faults();printf("PASS lua_packet_dispatch apis=5 cases=%u vm_errors=%u reentries=%u boundaries=%u fault_cases=%u vm_allocation_faults=%u send_calls=%u feed_calls=%u real_luajit=1 exact_stage_order=1 exact_arity=1 mutable_pool_reads=1 disabled_shortcut=1 no_live_sends=1 c_only_unwind=1 vm_allocations_released=1\n",cases,errors,reentries,boundaries,fault_cases,vm_faults,sends,feeds);return 0;}
