/* MIT. Fake socket boundary, real LuaJIT errors and allocations; no network. */
#include "params.h"
#include "engine_lua.h"
#include <lualib.h>
#include <luajit.h>
#undef main
#include "route_source_windows.h"
static unsigned cases,lua_cases,boundaries,closed,fault_cases,vm_faults;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL route source cases=%u lua_cases=%u line=%d: %s\n",cases,lua_cases,__LINE__,#v);exit(1);}}while(0)
struct sample{unsigned version,seed,failure,count,live;uintptr_t handle;bool mutate;uint8_t target[32],output[32],destination[28],*watched;int status,result_type;size_t result_length;char trace[32],message[256];};static struct sample *active;
static void event(char c){CHECK(active->count+1<sizeof(active->trace));active->trace[active->count++]=c;active->trace[active->count]=0;}
static SOCKET WSAAPI simulated_socket(int family,int type,int protocol){event('s');CHECK(family==(active->version==4?AF_INET:AF_INET6) && type==SOCK_DGRAM && !protocol);if(active->failure==1)return INVALID_SOCKET;++active->live;if(active->mutate)for(unsigned i=0;i<(active->version==4?4:16);++i)active->target[i]^=0x5a;return active->handle;}
static int WSAAPI simulated_connect(SOCKET socket,const struct sockaddr *address,int length){event('c');CHECK(active->live==1 && socket==active->handle && length==(active->version==4?16:28));memcpy(active->destination,address,length);CHECK(active->destination[2]==255 && active->destination[3]==255);return active->failure==2?SOCKET_ERROR:0;}
static int WSAAPI simulated_name(SOCKET socket,struct sockaddr *address,int *length){event('n');CHECK(active->live==1 && socket==active->handle && *length==(active->version==4?16:28));uint8_t *data=(void *)address;for(unsigned i=0;i<(unsigned)*length;++i)data[i]=(uint8_t)(active->seed+i*7);*length=active->seed%3?0:*length;return active->failure==3?SOCKET_ERROR:0;}
static int WSAAPI simulated_close(SOCKET socket){event('x');CHECK(active->live==1 && socket==active->handle);--active->live;++closed;if(active->watched)for(unsigned i=0;i<16;++i)CHECK(active->watched[i]==0xa5);return active->seed&1?SOCKET_ERROR:0;}
#define socket simulated_socket
#define connect simulated_connect
#define getsockname simulated_name
#define closesocket simulated_close
#define get_source_ip4 reference_source4
#define get_source_ip6 reference_source6
#include "route_source_reference.inc"
#include "lua_source_ip_common.inc"
#define luacall_get_source_ip reference_lua_source
#include "lua_source_ip_reference.inc"
#undef luacall_get_source_ip
#undef get_source_ip4
#undef get_source_ip6
#undef socket
#undef connect
#undef getsockname
#undef closesocket
static uintptr_t op_open(int family,int type,int protocol){return simulated_socket(family,type,protocol);}static int op_connect(uintptr_t socket,const void *data,int length){return simulated_connect(socket,data,length);}static int op_name(uintptr_t socket,void *data,int *length){return simulated_name(socket,data,length);}static int op_close(uintptr_t socket){return simulated_close(socket);}static const zapret_route_source_ops ops={op_open,op_connect,op_name,op_close};
static uint32_t simulated_lua_source(const uint8_t *target,size_t length,uint8_t *out,const zapret_route_source_ops *input){CHECK(!input);return zapret_lua_source_ip(target,length,out,&ops);}
#define zapret_lua_source_ip simulated_lua_source
#include "lua_source_ip_windows.inc"
#undef zapret_lua_source_ip
static void initialize(struct sample *s,unsigned version,unsigned seed,unsigned failure,bool mutate){memset(s,0,sizeof(*s));s->version=version;s->seed=seed;s->failure=failure;s->handle=seed&1?(uintptr_t)0xabcdef1234567890ull:0;s->mutate=mutate;for(unsigned i=0;i<32;++i)s->target[i]=seed+i;memset(s->output,0xa5,32);}
static void compare(unsigned version,unsigned seed,unsigned failure,bool mutate,unsigned offset){struct sample a,b;initialize(&a,version,seed,failure,mutate);initialize(&b,version,seed,failure,mutate);bool old,rust;active=&a;a.watched=a.output+offset;old=version==4?reference_source4((void *)a.target,(void *)(a.output+offset)):reference_source6((void *)a.target,(void *)(a.output+offset));active=&b;b.watched=b.output+offset;rust=zapret_route_source(version,b.target,b.output+offset,&ops);CHECK(old==rust && !a.live && !b.live && !strcmp(a.trace,b.trace) && !memcmp(a.destination,b.destination,28) && !memcmp(a.output,b.output,32));for(unsigned i=0;i<offset;++i)CHECK(a.output[i]==0xa5);if(old){unsigned length=version==4?4:16,base=version==4?4:8;for(unsigned i=0;i<length;++i)CHECK(a.output[offset+i]==(uint8_t)(seed+(base+i)*7));}++cases;}
struct allocator{bool armed;unsigned limit,calls,rejected,live;};static struct allocator *fault_allocator;
static void *allocate(void *context,void *pointer,size_t previous,size_t next){struct allocator *a=context;if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}if(a->armed && next>previous && a->calls++>=a->limit){++a->rejected;return NULL;}bool fresh=!pointer;void *result=realloc(pointer,next);if(result && fresh)++a->live;return result;}
static lua_State *new_vm(struct allocator *a){lua_State *L=a?lua_newstate(allocate,a):luaL_newstate();CHECK(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);return L;}
static void execute(lua_State *L,bool rust,unsigned length,unsigned argc,unsigned bad,struct sample *s){active=s;lua_settop(L,0);lua_pushcfunction(L,rust?luacall_get_source_ip:reference_lua_source);for(unsigned i=0;i<argc;++i){if(bad)lua_pushinteger(L,1);else lua_pushlstring(L,(const char *)s->target,length);}if(fault_allocator){fault_allocator->armed=true;fault_allocator->calls=fault_allocator->rejected=0;}s->status=lua_pcall(L,argc,1,0);if(fault_allocator)fault_allocator->armed=false;CHECK(lua_gettop(L)==1 && !s->live);if(s->status){const char *message=lua_tostring(L,-1);snprintf(s->message,sizeof(s->message),"%s",message?message:"");}else{s->result_type=lua_type(L,-1);if(s->result_type==LUA_TSTRING){const char *result=lua_tolstring(L,-1,&s->result_length);CHECK(s->result_length<=16);memcpy(s->output,result,s->result_length);}else CHECK(s->result_type==LUA_TNIL);}lua_settop(L,0);}
static void compare_lua(lua_State *L,unsigned length,unsigned argc,unsigned bad,unsigned failure,unsigned seed){struct sample a,b;initialize(&a,length==4?4:6,seed,failure,false);initialize(&b,length==4?4:6,seed,failure,false);execute(L,false,length,argc,bad,&a);execute(L,true,length,argc,bad,&b);CHECK(a.status==b.status && a.result_type==b.result_type && a.result_length==b.result_length && !strcmp(a.message,b.message) && !strcmp(a.trace,b.trace) && !memcmp(a.output,b.output,32));++lua_cases;}
static void boundaries_check(void){uint8_t data[32]={0};CHECK(!zapret_route_source(0,data,data,&ops));++boundaries;CHECK(!zapret_route_source(4,NULL,data,&ops));++boundaries;CHECK(!zapret_route_source(4,data,NULL,&ops));++boundaries;CHECK(!zapret_route_source(4,data,data,(void *)(data+1)));++boundaries;CHECK(zapret_lua_source_ip(data,SIZE_MAX,data,&ops)==2);++boundaries;
    uint8_t *buffer=VirtualAlloc(NULL,16384,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(buffer);DWORD old;CHECK(VirtualProtect(buffer+4096,4096,PAGE_NOACCESS,&old) && VirtualProtect(buffer+12288,4096,PAGE_NOACCESS,&old));for(unsigned version=4;version<=6;version+=2){unsigned width=version==4?4:16;uint8_t *target=buffer+4096-width,*output=buffer+12288-width;memset(target,7,width);struct sample s;initialize(&s,version,7,0,false);active=&s;CHECK(zapret_route_source(version,target,output,&ops));CHECK(!s.live);++boundaries;}CHECK(VirtualFree(buffer,0,MEM_RELEASE));}
static void faults(void){for(unsigned version=4;version<=6;version+=2)for(unsigned side=0;side<2;++side)for(unsigned failure=0;failure<4;++failure)for(unsigned limit=0;limit<16;++limit){struct allocator a={.limit=limit};lua_State *L=new_vm(&a);struct sample s;initialize(&s,version,77,failure,false);fault_allocator=&a;execute(L,side!=0,version==4?4:16,1,0,&s);fault_allocator=NULL;if(s.status){CHECK(s.status==LUA_ERRMEM && a.rejected);++vm_faults;}else CHECK(!a.rejected && s.result_type==(failure?LUA_TNIL:LUA_TSTRING));CHECK(!s.live);lua_close(L);CHECK(!a.live);++fault_cases;}CHECK(vm_faults>0);}
int main(void){for(unsigned version=4;version<=6;version+=2)for(unsigned seed=0;seed<256;++seed)for(unsigned failure=0;failure<4;++failure)for(unsigned mutate=0;mutate<2;++mutate)for(unsigned offset=0;offset<2;++offset)compare(version,seed,failure,mutate,offset);lua_State *L=new_vm(NULL);for(unsigned length=0;length<=24;++length)for(unsigned argc=0;argc<3;++argc)for(unsigned bad=0;bad<2;++bad)for(unsigned failure=0;failure<4;++failure)compare_lua(L,length,argc,bad,failure,length+argc);lua_close(L);boundaries_check();faults();printf("PASS route_source cases=%u lua_cases=%u boundaries=%u socket_closes=%u fault_cases=%u vm_allocation_faults=%u real_luajit=1 unaligned_spans=1 exact_socket_order=1 close_before_publish=1 output_on_success_only=1 no_live_network=1 vm_allocations_released=1\n",cases,lua_cases,boundaries,closed,fault_cases,vm_faults);return 0;}
