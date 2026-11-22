/* MIT. Complete old/new connection publication with real LuaJIT VM boundaries. */
#include <iphlpapi.h>
#include "params.h"
#include "engine_lua.h"
#include <lualib.h>
#include <luajit.h>
#include "lua_connection_view_types.h"
#undef main
#ifdef ZAPRET_RUST_LUA_CONNECTION_VIEW
#define PUBLICATION_OBSERVER
#define PUBLICATION_LABEL "windows_lua_connection_view"
#define PUBLICATION_UNWIND "rust_seh_unwind=1"
#else
#define PUBLICATION_OBSERVER static
#define PUBLICATION_LABEL "lua_connection_publication"
#define PUBLICATION_UNWIND "c_only_unwind=1"
#endif
struct publication_trace {uint64_t hash;unsigned calls,mutations,nested;};
static struct publication_trace traces[2],*recording;
static zapret_lua_track_values *observed_track;
static zapret_lua_track_position_values *observed_position;
static int child_index=-1,alias_key;
static bool publication_native,publication_mutated,nested_entered,eager_hostname,eager_alias;
static bool query_direction;
static unsigned mutation_kind,nested_boundary,nested_kind,publication_depth,special_cases,publication_errors,mutation_count,nested_count,identity_count,eager_controls,publication_boundaries;
static char live_hostname[64],frozen_hostname[64];
static zapret_lua_track_position_values manual_position,frozen_position;
static const zapret_lua_track_position_values *manual_source=&manual_position;
static void publication_change(unsigned point);
static void publication_nested(lua_State *L);
static uint64_t publication_hash(const void *data,size_t length){uint64_t value=1469598103934665603ULL;const uint8_t *p=data;for(size_t i=0;i<length;++i)value=(value^p[i])*1099511628211ULL;return value;}
static void publication_event(unsigned tag,uint64_t value){if(recording)recording->hash=(recording->hash*1099511628211ULL^tag)*1099511628211ULL^value;}
PUBLICATION_OBSERVER void publication_bytes(lua_State *L,const char *data,size_t length){if(recording && !publication_depth && nested_boundary==1 && !nested_entered)publication_nested(L);publication_event(1,length);publication_event(2,publication_hash(data,length));if(length==5 && !memcmp(data,"track",5))publication_change(1);if(!publication_depth){if(length==6 && !memcmp(data,"client",6))child_index=0;if(length==6 && !memcmp(data,"server",6))child_index=1;if(length==6 && !memcmp(data,"direct",6)){alias_key=1;publication_change(6);}if(length==7 && !memcmp(data,"reverse",7))alias_key=2;}lua_pushlstring(L,data,length);}
static void publication_string(lua_State *L,const char *data){if(recording && !publication_depth && nested_boundary==2 && !nested_entered)publication_nested(L);publication_event(3,data?publication_hash(data,strlen(data)):0);if(data){if(!strcmp(data,"hostname")){publication_change(3);publication_change(7);}if(!strcmp(data,"pbcounter"))publication_change(4);if(!strcmp(data,"rseq"))publication_change(5);}lua_pushstring(L,data);}
PUBLICATION_OBSERVER void publication_table(lua_State *L,int array,int records){if(recording && !publication_depth && nested_boundary==3 && !nested_entered)publication_nested(L);publication_event(4,(uint64_t)(uint32_t)array<<32|(uint32_t)records);if(records==9)publication_change(2);lua_createtable(L,array,records);}
PUBLICATION_OBSERVER void publication_rawset(lua_State *L,int index){publication_event(5,(uint32_t)index);lua_rawset(L,index);}
PUBLICATION_OBSERVER void publication_getfield(lua_State *L,int index,const char *name){if(recording && !publication_depth && eager_alias && alias_key && index==-2){bool server=alias_key==1?query_direction:!query_direction;name=server?"server":"client";}publication_event(6,(uint32_t)index);publication_event(7,publication_hash(name,strlen(name)));lua_getfield(L,index,name);alias_key=0;}
static void publication_registry(lua_State *L,int index,int reference){publication_event(8,(uint64_t)(uint32_t)index<<32|(uint32_t)reference);lua_rawgeti(L,index,reference);}
PUBLICATION_OBSERVER bool publication_query_position(const t_ctrack *track,const t_ctrack_position *position,zapret_lua_track_position_values *out){bool ok=zapret_lua_track_position(track,position,out);if(recording && !publication_depth){++recording->calls;observed_position=ok?out:NULL;observed_track=NULL;child_index=-1;publication_event(9,ok);}return ok;}
PUBLICATION_OBSERVER uint32_t publication_query_track(const t_ctrack *track,const t_ctrack_positions *positions,bool incoming,bool server,zapret_lua_track_values *out){uint32_t status=zapret_lua_track_view(track,positions,incoming,server,out);if(recording && !publication_depth){++recording->calls;observed_track=status==1?out:NULL;observed_position=NULL;child_index=-1;publication_event(10,status);publication_event(11,server);if(status==1){query_direction=out->direct_is_server;if(eager_hostname && out->hostname){snprintf(frozen_hostname,sizeof(frozen_hostname),"%s",out->hostname);out->hostname=frozen_hostname;}}}return status;}
static void publication_start(bool native){memset(&traces[native],0,sizeof(traces[native]));recording=&traces[native];publication_native=native;publication_mutated=false;nested_entered=false;publication_depth=0;observed_track=NULL;observed_position=NULL;child_index=-1;alias_key=0;}
static void publication_end(void){recording=NULL;observed_track=NULL;observed_position=NULL;child_index=-1;alias_key=0;}
#define lua_pushlstring publication_bytes
#define lua_pushstring publication_string
#define lua_createtable publication_table
#define lua_rawset publication_rawset
#define lua_getfield publication_getfield
#define lua_rawgeti publication_registry
#define zapret_lua_track_position publication_query_position
#define zapret_lua_track_view publication_query_track
#include "lua_connection_fixture.inc"

static zapret_lua_track_position_values *current_position(void){if(observed_position)return observed_position;if(observed_track && child_index>=0)return &observed_track->positions[child_index];return NULL;}
static void publication_change(unsigned point){if(!recording || publication_depth || publication_mutated || mutation_kind!=point)return;
    zapret_lua_track_position_values *position=current_position();
    if((point==2 || point==3 || point==6 || point==7) && !observed_track)return;
    if((point==4 || point==5) && !position)return;
    publication_mutated=true;++recording->mutations;++mutation_count;
    if(point==1){params.server=!params.server;track_storage.pos.client.pcounter=1234567;track_storage.incoming_ttl=197;}
    if(point==2){track_storage.pos.client.pcounter=7654321;track_storage.incoming_ttl=198;track_storage.hostname=NULL;}
    if(point==3){live_hostname[0]='z';live_hostname[1]='Z';}
    if(point==4){position->ipv6_flow=0x12345678u;position->is_tcp=!position->is_tcp;position->tcp[2]=12345;position->over_2g=true;}
    if(point==5){position->over_2g=!position->over_2g;position->tcp[3]=54321;}
    if(point==6)observed_track->direct_is_server=!observed_track->direct_is_server;
    if(point==7){observed_track->hostname=NULL;observed_track->hostname_is_ip=false;}
}
static int publication_nested_value(lua_State *L){if(nested_kind==2)return luaL_error(L,"nested connection fixture");t_ctrack track={0};track.pos.ipproto=IPPROTO_TCP;lua_newtable(L);if(publication_native)lua_pushf_ctrack_pos(L,&track,&track.pos.client);else reference_position(L,&track,&track.pos.client);return 1;}
static void publication_nested(lua_State *L){nested_entered=true;++publication_depth;int top=lua_gettop(L);lua_pushcfunction(L,publication_nested_value);int status=lua_pcall(L,0,1,0);publication_event(20,status);lua_settop(L,top);--publication_depth;++recording->nested;++nested_count;if(nested_kind==3){luaL_error(L,"nested connection publication failure");return;}lua_gc(L,LUA_GCCOLLECT,0);}
struct publication_result {int status,arity;uint64_t trace;unsigned calls,mutated,nested;size_t length;char bytes[16384],error[512];};
static const char *snapshot="function SNAP(v) local t=type(v);if t=='table' then local keys,out={},{};for k in pairs(v) do keys[#keys+1]=k end;table.sort(keys,function(a,b)if type(a)~=type(b) then return type(a)<type(b) end return a<b end);for _,k in ipairs(keys) do out[#out+1]=SNAP(k)..'='..SNAP(v[k]) end;return '{'..table.concat(out,';')..'}' elseif t=='string' then return t..#v..':'..v elseif t=='number' then return t..string.format('%.17g',v) elseif t=='function' then return 'function' else return t..tostring(v) end end";
static void publication_identity(lua_State *L){if(mode==0 || mode==3)return;if(mode==2)lua_getfield(L,1,"track");else lua_pushvalue(L,1);if(lua_isnil(L,-1)){lua_pop(L,1);return;}lua_getfield(L,-1,"pos");lua_getfield(L,-1,"client");lua_getfield(L,-2,"server");CHECK(!lua_rawequal(L,-1,-2));lua_pop(L,2);lua_getfield(L,-1,"direct");lua_getfield(L,-2,"client");bool client=lua_rawequal(L,-1,-2);lua_pop(L,1);lua_getfield(L,-2,"server");CHECK(client || lua_rawequal(L,-1,-2));lua_pop(L,2);lua_getfield(L,-1,"reverse");lua_getfield(L,-2,"client");client=lua_rawequal(L,-1,-2);lua_pop(L,1);lua_getfield(L,-2,"server");CHECK(client || lua_rawequal(L,-1,-2));lua_pop(L,4);++identity_count;}
static struct publication_result publication_execute(lua_State *L,bool native){struct publication_result result={0};lua_settop(L,0);lua_pushcfunction(L,native?new_view:old_view);result.status=lua_pcall(L,0,1,0);publication_end();result.arity=lua_gettop(L);CHECK(result.arity==1);result.trace=traces[native].hash;result.calls=traces[native].calls;result.mutated=traces[native].mutations;result.nested=traces[native].nested;
    if(result.status){const char *p=lua_tostring(L,-1);snprintf(result.error,sizeof(result.error),"%s",p?p:"");}else{publication_identity(L);lua_getglobal(L,"SNAP");lua_pushvalue(L,1);CHECK(!lua_pcall(L,1,1,0));const char *p=lua_tolstring(L,-1,&result.length);CHECK(p && result.length<sizeof(result.bytes));memcpy(result.bytes,p,result.length);}lua_settop(L,0);return result;}
static void publication_reset(const t_ctrack *track,const t_ctrack_positions *delayed,const zapret_lua_track_position_values *manual,bool server){memcpy(&track_storage,track,sizeof(*track));memcpy(&delayed_storage,delayed,sizeof(*delayed));manual_position=*manual;strcpy(live_hostname,"before.hostname");params.server=server;manual_source=&manual_position;}
static void publication_compare_special(lua_State *L,unsigned seed){prepare(seed);track_storage.hostname=live_hostname;strcpy(live_hostname,"before.hostname");manual_position=(zapret_lua_track_position_values){.counters={-1,INT64_MIN,17},.tcp={1,2,3,4,5,6,7,8,9,10},.ipv6_flow=0,.is_tcp=true,.over_2g=false};t_ctrack base=track_storage;t_ctrack_positions delayed=delayed_storage;zapret_lua_track_position_values manual=manual_position;bool server=params.server;
    publication_reset(&base,&delayed,&manual,server);struct publication_result a=publication_execute(L,false);publication_reset(&base,&delayed,&manual,server);struct publication_result b=publication_execute(L,true);if(memcmp(&a,&b,sizeof(a))){fprintf(stderr,"DETAIL mode=%u mutation=%u seed=%u old=%d/%zu new=%d/%zu old_trace=%llx new_trace=%llx old_error=%s new_error=%s\n",mode,mutation_kind,seed,a.status,a.length,b.status,b.length,(unsigned long long)a.trace,(unsigned long long)b.trace,a.error,b.error);CHECK(false);}++special_cases;if(a.status)++publication_errors;}
static void publication_controls(lua_State *L){prepare(10);mode=1;incoming=false;params.server=false;track_storage.hostname=live_hostname;strcpy(live_hostname,"before.hostname");t_ctrack base=track_storage;t_ctrack_positions delayed=delayed_storage;zapret_lua_track_position_values manual={0};
    mutation_kind=3;publication_reset(&base,&delayed,&manual,false);struct publication_result live=publication_execute(L,false);publication_reset(&base,&delayed,&manual,false);eager_hostname=true;struct publication_result eager=publication_execute(L,false);eager_hostname=false;CHECK(!live.status && !eager.status && (live.length!=eager.length || memcmp(live.bytes,eager.bytes,live.length)));++eager_controls;
    mutation_kind=6;publication_reset(&base,&delayed,&manual,false);live=publication_execute(L,false);publication_reset(&base,&delayed,&manual,false);eager_alias=true;eager=publication_execute(L,false);eager_alias=false;CHECK(!live.status && !eager.status && (live.length!=eager.length || memcmp(live.bytes,eager.bytes,live.length)));++eager_controls;
    mode=3;mutation_kind=4;manual=(zapret_lua_track_position_values){.counters={1,2,3},.is_tcp=false};publication_reset(&base,&delayed,&manual,false);live=publication_execute(L,false);publication_reset(&base,&delayed,&manual,false);frozen_position=manual_position;manual_source=&frozen_position;eager=publication_execute(L,false);CHECK(!live.status && !eager.status && (live.length!=eager.length || memcmp(live.bytes,eager.bytes,live.length)));++eager_controls;mutation_kind=0;manual_source=&manual_position;
}
static void publication_abi(void){_Alignas(8)uint8_t memory[512];memset(memory,0xa5,sizeof(memory));zapret_lua_connection_action out={.kind=91};zapret_lua_track_publication_state state;zapret_lua_position_publication_state position;
    CHECK(!zapret_lua_track_publication_begin(2,&state,&out) && out.kind==91);++publication_boundaries;CHECK(!zapret_lua_track_publication_begin(0,NULL,&out));++publication_boundaries;CHECK(!zapret_lua_track_publication_begin(0,(void *)(memory+1),&out));++publication_boundaries;CHECK(!zapret_lua_track_publication_begin(0,&state,NULL));++publication_boundaries;CHECK(!zapret_lua_track_publication_step(NULL,0,&out));++publication_boundaries;CHECK(!zapret_lua_position_publication_begin(NULL,&position,&out));++publication_boundaries;CHECK(!zapret_lua_position_publication_begin((void *)memory,NULL,&out));++publication_boundaries;CHECK(!zapret_lua_position_publication_step(NULL,&out));++publication_boundaries;
    uint8_t *pages=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(pages);DWORD old;CHECK(VirtualProtect(pages+4096,4096,PAGE_NOACCESS,&old));zapret_lua_track_publication_state *edge=(void *)(pages+4096-sizeof(state));CHECK(zapret_lua_track_publication_begin(1,edge,&out) && out.kind==9);CHECK(zapret_lua_track_publication_step(edge,0,&out) && out.kind==1);++publication_boundaries;CHECK(VirtualFree(pages,0,MEM_RELEASE));}
int main(void){connection_baseline_main();lua_State *L=luaL_newstate();CHECK(L);params.L=L;luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);CHECK(!luaL_dostring(L,snapshot));create_references(L);
    for(mode=0;mode<4;++mode)for(mutation_kind=1;mutation_kind<=7;++mutation_kind)for(unsigned seed=0;seed<64;++seed)for(unsigned flags=0;flags<4;++flags){incoming=flags&1;params.server=(flags&2)!=0;publication_compare_special(L,seed);}mutation_kind=0;
    for(nested_boundary=1;nested_boundary<=3;++nested_boundary)for(nested_kind=1;nested_kind<=3;++nested_kind)for(mode=0;mode<4;++mode){incoming=true;params.server=false;publication_compare_special(L,10);}nested_boundary=0;publication_controls(L);publication_abi();publication_end();params.L=NULL;lua_close(L);
    printf("PASS " PUBLICATION_LABEL " baseline_cases=%u special_cases=%u vm_errors=%u identity_checks=%u mutable_updates=%u nested_calls=%u eager_snapshot_controls=%u guarded=%u boundaries=%u fault_cases=%u vm_allocation_faults=%u real_luajit=1 exact_vm_order=1 exact_field_catalog=1 registry_identity=1 table_alias_identity=1 deferred_native_query=1 deferred_view_reads=1 borrowed_hostname=1 vm_allocations_released=1 " PUBLICATION_UNWIND "\n",cases,special_cases,publication_errors,identity_count,mutation_count,nested_count,eager_controls,guarded,boundaries+publication_boundaries,fault_cases,vm_faults);return 0;}
