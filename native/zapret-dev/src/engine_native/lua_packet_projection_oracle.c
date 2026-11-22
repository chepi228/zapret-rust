/* MIT. Old/new metadata through real LuaJIT, borrowed bytes and live cursors. */
#include "params.h"
#include "engine_lua.h"
#include <lualib.h>
#include <luajit.h>
#undef main
#ifdef ZAPRET_RUST_LUA_PACKET_PROJECTION
#define PROJECTION_OBSERVER
#define PROJECTION_LABEL "windows_lua_packet_projection"
#define PROJECTION_UNWIND "rust_seh_unwind=1"
#else
#define PROJECTION_OBSERVER static
#define PROJECTION_LABEL "lua_packet_projection"
#define PROJECTION_UNWIND "c_only_unwind=1"
#endif
struct params_s params;
static unsigned cases,errors,header_cases,item_cases,guarded,mutations,nested_total,eager_controls,fault_cases,vm_faults,boundaries;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL packet metadata cases=%u line=%d: %s\n",cases,__LINE__,#v);exit(1);}}while(0)
struct sample {int status,arity;size_t length;char bytes[32768],message[512];uint64_t trace;size_t cursor_offset;uint8_t cursor_kind,cursor_next,cursor_stopped;unsigned nested,mutated;};
static struct sample *active;static bool native_side,nested_entered,mutated;static unsigned nested_boundary,nested_kind,depth,wire_mutation,cursor_mutation,selected_operation;
static uint8_t wire[1024];static const uint8_t *selected_wire;static size_t selected_length;
static void nested_call(lua_State *L);
static void cursor_change(unsigned point);
static uint64_t hash(const void *p,size_t n){uint64_t h=1469598103934665603ULL;const uint8_t *bytes=p;for(size_t i=0;i<n;++i)h=(h^bytes[i])*1099511628211ULL;return h;}
static void event(unsigned kind,uint64_t value){if(active)active->trace=(active->trace*1099511628211ULL^kind)*1099511628211ULL^value;}
static void change_wire(unsigned point){if(!active || depth || mutated || wire_mutation!=point)return;mutated=true;++active->mutated;++mutations;if(point==1){wire[0]^=0x11;wire[12]=203;wire[16]=198;wire[8]=17;wire[24]=29;}else{wire[22]=11;wire[23]=12;wire[42]=13;wire[43]=14;}}
PROJECTION_OBSERVER void metadata_vm_table(lua_State *L,int array,int records){if(active && !depth && nested_boundary==1 && !nested_entered)nested_call(L);event(1,(uint64_t)(uint32_t)array<<32|(uint32_t)records);if(selected_operation==7 && records)cursor_change(2);else change_wire(1);lua_createtable(L,array,records);}
PROJECTION_OBSERVER void metadata_vm_string(lua_State *L,const char *p){if(active && !depth && nested_boundary==2 && !nested_entered)nested_call(L);event(2,p?hash(p,strlen(p)):0);if(p && !strcmp(p,"data"))change_wire(2);if(p && (!strcmp(p,"kind") || !strcmp(p,"type")))cursor_change(3);lua_pushstring(L,p);}
static void metadata_vm_bytes(lua_State *L,const char *p,size_t n){if(active && !depth && nested_boundary==3 && !nested_entered)nested_call(L);event(3,n);event(4,hash(p,n));lua_pushlstring(L,p,n);}
PROJECTION_OBSERVER void metadata_vm_integer(lua_State *L,lua_Integer n){event(5,(uint64_t)n);if(selected_operation==7)cursor_change(1);lua_pushinteger(L,n);}
PROJECTION_OBSERVER void metadata_vm_nil(lua_State *L){event(6,0);lua_pushnil(L);}
PROJECTION_OBSERVER void metadata_vm_rawset(lua_State *L,int index){event(7,(uint32_t)index);lua_rawset(L,index);}
#define lua_createtable metadata_vm_table
#define lua_pushstring metadata_vm_string
#define lua_pushlstring metadata_vm_bytes
#define lua_pushinteger metadata_vm_integer
#define lua_pushnil metadata_vm_nil
#define lua_rawset metadata_vm_rawset
#include "lua_table_common.inc"
#include "lua_numeric_windows.inc"
#define native_lua_push_packet_items reference_items
#define native_lua_push_packet_header reference_header
#define lua_pushf_tcphdr_options reference_tcp_options
#define lua_pushf_ip6exthdr reference_extensions
#define lua_push_tcphdr reference_tcp
#define lua_push_udphdr reference_udp
#define lua_push_icmphdr reference_icmp
#define lua_push_iphdr reference_ip
#define lua_push_ip6hdr reference_ip6
#include "lua_packet_projection_reference.inc"
#undef native_lua_push_packet_items
#undef native_lua_push_packet_header
#undef lua_pushf_tcphdr_options
#undef lua_pushf_ip6exthdr
#undef lua_push_tcphdr
#undef lua_push_udphdr
#undef lua_push_icmphdr
#undef lua_push_iphdr
#undef lua_push_ip6hdr
#define ZAPRET_LUA_PACKET_TYPES_DEFINED
#ifdef ZAPRET_RUST_LUA_PACKET_PROJECTION
#include "windows_lua_packet_projection_abi.h"
#else
#include "lua_packet_projection_windows.inc"
#endif
static zapret_lua_packet_cursor cursor;
static void cursor_change(unsigned point){if(!active || depth || mutated || selected_operation!=7 || cursor_mutation!=point)return;mutated=true;cursor.kind=1;++active->mutated;++mutations;}
static const char *snapshot="function SNAP(v) local t=type(v);if t=='table' then local keys,out={},{};for k in pairs(v) do keys[#keys+1]=k end;table.sort(keys,function(a,b)if type(a)~=type(b) then return type(a)<type(b) end return a<b end);for _,k in ipairs(keys) do out[#out+1]=SNAP(k)..'='..SNAP(v[k]) end;return '{'..table.concat(out,';')..'}' elseif t=='string' then return t..#v..':'..v elseif t=='number' then return t..string.format('%.17g',v) else return t..tostring(v) end end";
typedef void (*header_fn)(lua_State *,const void *,size_t);
static header_fn old_headers[]={(header_fn)reference_tcp,(header_fn)reference_udp,(header_fn)reference_icmp,(header_fn)reference_ip,(header_fn)reference_ip6,(header_fn)reference_tcp_options,(header_fn)reference_extensions};
static header_fn new_headers[]={(header_fn)lua_push_tcphdr,(header_fn)lua_push_udphdr,(header_fn)lua_push_icmphdr,(header_fn)lua_push_iphdr,(header_fn)lua_push_ip6hdr,(header_fn)lua_pushf_tcphdr_options,(header_fn)lua_pushf_ip6exthdr};
static int publish(lua_State *L){if(selected_operation>=5)lua_newtable(L);if(selected_operation==7){if(native_side)native_lua_push_packet_items(L,"items",&cursor);else reference_items(L,"items",&cursor);}else (native_side?new_headers:old_headers)[selected_operation](L,selected_wire,selected_length);return 1;}
static int nested_error(lua_State *L){return luaL_error(L,"nested metadata fixture");}
static void nested_call(lua_State *L){nested_entered=true;++depth;int top=lua_gettop(L);if(nested_kind==2){lua_pushcfunction(L,nested_error);int status=lua_pcall(L,0,1,0);event(20,status);}else{uint8_t zero[8]={0};(native_side?new_headers:old_headers)[1](L,zero,8);event(20,lua_type(L,-1));}lua_settop(L,top);--depth;++active->nested;++nested_total;if(nested_kind==3){luaL_error(L,"nested metadata publication failure");return;}lua_gc(L,LUA_GCCOLLECT,0);}
struct allocator {bool armed;unsigned calls,rejected,limit,live;};static struct allocator *fault_allocator;
static void *allocate(void *context,void *p,size_t before,size_t after){struct allocator *a=context;if(!after){if(p){CHECK(a->live);--a->live;}free(p);return NULL;}if(a->armed && after>before && a->calls++>=a->limit){++a->rejected;return NULL;}bool fresh=!p;void *out=realloc(p,after);if(out && fresh)++a->live;return out;}
static lua_State *new_vm(struct allocator *a){lua_State *L=a?lua_newstate(allocate,a):luaL_newstate();CHECK(L);params.L=L;luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);CHECK(!luaL_dostring(L,snapshot));return L;}
static struct sample invoke(lua_State *L,bool rust){struct sample out={0};lua_settop(L,0);lua_pushcfunction(L,publish);native_side=rust;nested_entered=false;depth=0;mutated=false;active=&out;if(fault_allocator){fault_allocator->armed=true;fault_allocator->calls=fault_allocator->rejected=0;}out.status=lua_pcall(L,0,1,0);if(fault_allocator)fault_allocator->armed=false;active=NULL;out.arity=lua_gettop(L);CHECK(out.arity==1);if(out.status){const char *p=lua_tostring(L,-1);snprintf(out.message,sizeof(out.message),"%s",p?p:"");}else{lua_getglobal(L,"SNAP");lua_pushvalue(L,1);CHECK(!lua_pcall(L,1,1,0));const char *p=lua_tolstring(L,-1,&out.length);CHECK(p && out.length<sizeof(out.bytes));memcpy(out.bytes,p,out.length);}
    if(selected_operation==7){out.cursor_offset=cursor.offset;out.cursor_kind=cursor.kind;out.cursor_next=cursor.next;out.cursor_stopped=cursor.stopped;}lua_settop(L,0);return out;}
static void pattern(unsigned kind,unsigned value){for(unsigned i=0;i<sizeof(wire);++i)wire[i]=(uint8_t)(i*11+value*7);if(kind==0||kind==5){wire[12]=(uint8_t)((value%16)<<4);static const uint8_t opts[][8]={{0},{1,0,1,0},{2,2,0},{2,4,5,180},{2,1,0},{8,10,0,0},{0,2,255,0},{1,1,1,1}};for(unsigned i=20;i<128;++i)wire[i]=opts[value%8][(i-20)%8];}if(kind==3)wire[0]=(uint8_t)(0x40|(value%16));if(kind==4||kind==6){const uint8_t protocols[]={0,43,44,51,60,59,6,255};wire[0]=0x60;wire[4]=0;wire[5]=(uint8_t)(value%5==0?8:120);wire[6]=protocols[value%8];for(unsigned i=40;i+8<sizeof(wire);i+=8){wire[i]=protocols[(i/8+value)%8];wire[i+1]=(uint8_t)(value%4);wire[i+2]=0;wire[i+3]=(uint8_t)(value%4==0?8:0);}}selected_wire=wire;}
static void set_cursor(unsigned kind,size_t length,unsigned malformed){cursor=(zapret_lua_packet_cursor){.data=wire,.length=length,.kind=(uint8_t)kind,.next=(uint8_t)(kind?0:0)};if(malformed==1)cursor.offset=length+1;else if(malformed==2)cursor.kind=2;else if(malformed==3)cursor.data=NULL;else if(malformed==4)cursor.length=SIZE_MAX;else if(malformed==5)cursor.stopped=true;}
static void equal(struct sample *a,struct sample *b,unsigned variant){if(memcmp(a,b,sizeof(*a))){fprintf(stderr,"DETAIL op=%u length=%zu variant=%u old=%d/%zu new=%d/%zu old_trace=%llx new_trace=%llx old_cursor=%zu:%u:%u new_cursor=%zu:%u:%u oldmsg=%s newmsg=%s\n",selected_operation,selected_length,variant,a->status,a->length,b->status,b->length,(unsigned long long)a->trace,(unsigned long long)b->trace,a->cursor_offset,a->cursor_kind,a->cursor_next,b->cursor_offset,b->cursor_kind,b->cursor_next,a->message,b->message);CHECK(false);}++cases;if(a->status)++errors;}
static void compare_header(lua_State *L,unsigned kind,unsigned variant,size_t length){selected_operation=kind;selected_length=length;pattern(kind,variant);struct sample a=invoke(L,false);pattern(kind,variant);struct sample b=invoke(L,true);equal(&a,&b,variant);++header_cases;}
static void compare_cursor(lua_State *L,unsigned kind,size_t length,unsigned malformed){selected_operation=7;memset(wire,1,sizeof(wire));if(kind){memset(wire,0,sizeof(wire));for(unsigned i=0;i<length && i+1<sizeof(wire);i+=8){wire[i]=0;wire[i+1]=0;}}set_cursor(kind,length,malformed);struct sample a=invoke(L,false);set_cursor(kind,length,malformed);struct sample b=invoke(L,true);equal(&a,&b,malformed);++item_cases;}
static void controls(lua_State *L){uint8_t frozen[1024];wire_mutation=1;for(unsigned kind=3;kind<=4;++kind){pattern(kind,5);selected_operation=kind;selected_length=64;struct sample live=invoke(L,false);pattern(kind,5);memcpy(frozen,wire,sizeof(frozen));selected_wire=frozen;struct sample eager=invoke(L,false);CHECK(!live.status && !eager.status && (live.length!=eager.length || memcmp(live.bytes,eager.bytes,live.length)));++eager_controls;}wire_mutation=0;}
static void faults(void){for(unsigned operation=0;operation<8;++operation)for(unsigned side=0;side<2;++side)for(unsigned budget=0;budget<64;++budget){struct allocator a={.limit=budget};lua_State *L=new_vm(&a);selected_operation=operation;selected_length=96;pattern(operation,3);if(operation==7)set_cursor(0,64,0);fault_allocator=&a;struct sample result=invoke(L,side);fault_allocator=NULL;if(result.status){CHECK(result.status==LUA_ERRMEM && a.rejected);++vm_faults;}lua_close(L);CHECK(!a.live);++fault_cases;}CHECK(vm_faults>0);}
static void guards(lua_State *L){uint8_t *memory=VirtualAlloc(NULL,16384,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(memory);DWORD old;CHECK(VirtualProtect(memory+12288,4096,PAGE_NOACCESS,&old));for(unsigned kind=0;kind<7;++kind)for(unsigned variant=0;variant<8;++variant)for(unsigned length=0;length<=160;++length){pattern(kind,variant);uint8_t *p=memory+12288-length;memcpy(p,wire,length);selected_operation=kind;selected_length=length;selected_wire=p;struct sample a=invoke(L,false),b=invoke(L,true);equal(&a,&b,variant);++header_cases;++guarded;}
    zapret_lua_packet_metadata_action action={.kind=91};zapret_lua_packet_header_projection_state state;zapret_lua_packet_items_state items;CHECK(!zapret_lua_packet_header_projection_begin(0,NULL,0,NULL,&action));++boundaries;CHECK(!zapret_lua_packet_header_projection_begin(0,NULL,0,&state,NULL));++boundaries;CHECK(!zapret_lua_packet_header_projection_begin(0,NULL,0,(void *)(memory+1),&action));++boundaries;CHECK(!zapret_lua_packet_header_projection_step(NULL,&action));++boundaries;CHECK(!zapret_lua_packet_items_step(NULL,&action));++boundaries;CHECK(!zapret_lua_packet_items_begin("items",NULL,NULL,&action));++boundaries;CHECK(!zapret_lua_packet_items_prepare(1,NULL,0,&cursor,NULL));++boundaries;CHECK(!zapret_lua_packet_items_prepare(0,NULL,0,NULL,(void *)&memory));++boundaries;CHECK(action.kind==91);++boundaries;zapret_lua_packet_header_projection_state *edge=(void *)(memory+12288-sizeof(state));CHECK(zapret_lua_packet_header_projection_begin(255,NULL,SIZE_MAX,edge,&action) && action.kind==1);CHECK(zapret_lua_packet_header_projection_step(edge,&action) && action.kind==0);++boundaries;CHECK(zapret_lua_packet_items_begin("items",NULL,&items,&action));CHECK(zapret_lua_packet_items_step(&items,&action));CHECK(zapret_lua_packet_items_step(&items,&action) && action.kind==9);++boundaries;CHECK(VirtualFree(memory,0,MEM_RELEASE));}
int main(void){lua_State *L=new_vm(NULL);for(unsigned kind=0;kind<7;++kind)for(unsigned variant=0;variant<32;++variant)for(unsigned length=0;length<=160;++length)compare_header(L,kind,variant,length);for(unsigned kind=0;kind<2;++kind)for(unsigned malformed=0;malformed<6;++malformed)for(unsigned length=0;length<=128;++length)compare_cursor(L,kind,length,malformed);
    for(wire_mutation=1;wire_mutation<=2;++wire_mutation)for(unsigned kind=0;kind<7;++kind)for(unsigned variant=0;variant<8;++variant)compare_header(L,kind,variant,96);wire_mutation=0;for(cursor_mutation=1;cursor_mutation<=3;++cursor_mutation)for(unsigned kind=0;kind<2;++kind)compare_cursor(L,kind,32,0);cursor_mutation=0;
    for(nested_boundary=1;nested_boundary<=3;++nested_boundary)for(nested_kind=1;nested_kind<=3;++nested_kind)for(unsigned kind=0;kind<7;++kind)compare_header(L,kind,3,96);nested_boundary=0;controls(L);guards(L);lua_close(L);faults();printf("PASS " PROJECTION_LABEL " cases=%u header_cases=%u item_cases=%u vm_errors=%u guarded=%u nested_calls=%u mutable_updates=%u eager_snapshot_controls=%u boundaries=%u fault_cases=%u vm_allocation_faults=%u real_luajit=1 actual_wire_decoders=1 exact_vm_order=1 exact_metadata=1 cursor_progress=1 deferred_cursor_kind=1 captured_scalars=1 borrowed_wire_bytes=1 vm_allocations_released=1 " PROJECTION_UNWIND "\n",cases,header_cases,item_cases,errors,guarded,nested_total,mutations,eager_controls,boundaries,fault_cases,vm_faults);return 0;}
