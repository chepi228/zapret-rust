/* MIT. Compare the pinned C connection view and Rust using actual LuaJIT. */
#include <iphlpapi.h>
#include "params.h"
#include "engine_lua.h"
#include <luajit.h>
#undef main
struct params_s params;
#include "lua_conntrack_common.inc"
#define lua_pushf_ctrack_pos reference_position
#define lua_push_ctrack reference_track
#define lua_pushf_ctrack reference_field
#include "lua_conntrack_reference.inc"
#undef lua_pushf_ctrack_pos
#undef lua_push_ctrack
#undef lua_pushf_ctrack
#ifdef ZAPRET_RUST_LUA_CONNECTION_VIEW
#include "windows_lua_connection_view_abi.h"
#else
#include "lua_conntrack_view_windows.inc"
#endif
#include "lua_conntrack_wrapper.inc"

static unsigned cases,position_cases,track_cases,alias_checks,boundaries,guarded,fault_cases,vm_faults;
#define CHECK(v) do { if(!(v)) { fprintf(stderr,"FAIL Lua connection cases=%u bounds=%u line=%d: %s\n",cases,boundaries,__LINE__,#v); exit(1); } } while(0)
static t_ctrack track_storage;
static t_ctrack_positions delayed_storage;
static const t_ctrack *active_track;
static const t_ctrack_positions *active_positions;
static const t_ctrack_position *active_position;
static bool incoming;
static unsigned mode;
static int references[8];
static const char *same=
    "function SAME(a,b) if type(a)~=type(b) then return false end "
    "if type(a)~='table' then return a==b end local n=0 "
    "for k,v in pairs(a) do n=n+1;if not SAME(v,b[k]) then return false end end "
    "for _ in pairs(b) do n=n-1 end return n==0 end";

static int invoke(lua_State *L,bool rust)
{
    if(mode!=1)lua_newtable(L);
    if(mode==0)(rust?lua_pushf_ctrack_pos:reference_position)(L,active_track,active_position);
    else if(mode==1)(rust?lua_push_ctrack:reference_track)(L,active_track,active_positions,incoming);
    else (rust?lua_pushf_ctrack:reference_field)(L,active_track,active_positions,incoming);
    CHECK(lua_gettop(L)==1);
    return 1;
}
static int old_view(lua_State *L){return invoke(L,false);}
static int new_view(lua_State *L){return invoke(L,true);}

static void check_identity(lua_State *L)
{
    if(mode==0)return;
    lua_pushvalue(L,2);
    if(mode==2){lua_getfield(L,-1,"track");lua_remove(L,-2);}
    if(!active_track){CHECK(lua_isnil(L,-1));lua_pop(L,1);return;}
    CHECK(lua_istable(L,-1));
    lua_getfield(L,-1,"lua_state");lua_rawgeti(L,LUA_REGISTRYINDEX,active_track->lua_state);
    CHECK(lua_rawequal(L,-1,-2));lua_pop(L,2);
    lua_getfield(L,-1,"hostname_is_ip");
    if(active_track->hostname)CHECK(lua_isboolean(L,-1) && !!lua_toboolean(L,-1)==active_track->hostname_is_ip);
    else CHECK(lua_isnil(L,-1));
    lua_pop(L,1);
    lua_getfield(L,-1,"pos");
    lua_getfield(L,-1,"client");lua_getfield(L,-2,"server");CHECK(!lua_rawequal(L,-1,-2));lua_pop(L,2);
    lua_getfield(L,-1,"direct");lua_getfield(L,-2,(params.server^incoming)?"server":"client");
    CHECK(lua_rawequal(L,-1,-2));lua_pop(L,2);
    lua_getfield(L,-1,"reverse");lua_getfield(L,-2,(params.server^incoming)?"client":"server");
    CHECK(lua_rawequal(L,-1,-2));lua_pop(L,4);++alias_checks;
}
static void compare(lua_State *L)
{
    t_ctrack before;memcpy(&before,&track_storage,sizeof(before));
    t_ctrack_positions delayed_before;memcpy(&delayed_before,&delayed_storage,sizeof(delayed_before));
    lua_settop(L,0);
    lua_pushcfunction(L,old_view);int old=lua_pcall(L,0,1,0);
    if(old){fprintf(stderr,"DETAIL old=%d %s\n",old,lua_tostring(L,-1));CHECK(false);}
    lua_pushcfunction(L,new_view);int updated=lua_pcall(L,0,1,0);
    if(updated){fprintf(stderr,"DETAIL new=%d %s\n",updated,lua_tostring(L,-1));CHECK(false);}
    lua_getglobal(L,"SAME");lua_pushvalue(L,1);lua_pushvalue(L,2);CHECK(!lua_pcall(L,2,1,0));
    if(!lua_toboolean(L,-1)){fprintf(stderr,"DETAIL mode=%u incoming=%u server=%u proto=%u l7=%u delayed=%u\n",mode,incoming,params.server,track_storage.pos.ipproto,track_storage.l7proto,active_positions!=NULL);CHECK(false);}
    lua_pop(L,1);check_identity(L);CHECK(lua_gettop(L)==2);
    CHECK(!memcmp(&before,&track_storage,sizeof(before)));
    CHECK(!memcmp(&delayed_before,&delayed_storage,sizeof(delayed_before)));
    lua_settop(L,0);++cases;if(mode==0)++position_cases;else ++track_cases;
}

static uint64_t random_state=0x636f6e6e74726163ULL;
static uint64_t random_value(void){random_state^=random_state<<13;random_state^=random_state>>7;random_state^=random_state<<17;return random_state;}
static uint32_t scalar(unsigned seed)
{
    static const uint32_t edges[]={0,1,2,0x7fffffff,0x80000000,0xfffffffe,UINT32_MAX};
    return seed%8<7?edges[seed%8]:(uint32_t)random_value();
}
static void fill_position(t_ctrack_position *p,unsigned seed)
{
    p->pcounter=seed%5==0?UINT64_MAX:seed%5==1?1ULL<<63:random_value();
    p->pdcounter=seed%3==0?0:seed%3==1?1ULL<<53:random_value();p->pbcounter=random_value();
    p->ip6flow=seed%3==0?0:scalar(seed+1);
    p->seq0=scalar(seed);p->seq_last=scalar(seed+2);p->pos=scalar(seed+3);
    p->uppos=scalar(seed+4);p->uppos_prev=scalar(seed+5);
    p->winsize=(uint16_t)scalar(seed);p->mss=(uint16_t)scalar(seed+1);p->winsize_calc=scalar(seed+2);
    p->scale=(uint8_t)scalar(seed+3);p->rseq_over_2G=(seed&1)!=0;
}
static void prepare(unsigned seed)
{
    static const char *hosts[]={NULL,"","example.com","192.0.2.1","2001:db8::1","raw\xff\xfe.example"};
    static const int64_t seconds[]={0,1,-1,INT32_MAX,INT32_MIN,9007199254740991LL,9007199254740993LL,INT64_MAX,INT64_MIN};
    memset(&track_storage,0,sizeof(track_storage));memset(&delayed_storage,0,sizeof(delayed_storage));
    track_storage.t_start.tv_sec=seconds[seed%9];track_storage.t_start.tv_nsec=(long)(scalar(seed)%1000000000);
    track_storage.pos.t_last.tv_sec=seconds[(seed+2)%9];track_storage.pos.t_last.tv_nsec=(long)(scalar(seed+1)%1000000000);
    delayed_storage.t_last.tv_sec=seconds[(seed+4)%9];delayed_storage.t_last.tv_nsec=seed%3==0?-999999999:(long)(random_value()%1000000000);
    track_storage.pos.ipproto=seed%5==0?IPPROTO_TCP:seed%5==1?IPPROTO_UDP:seed%5==2?0:seed%5==3?IPPROTO_ICMPV6:255;
    delayed_storage.ipproto=(uint8_t)~track_storage.pos.ipproto;
    fill_position(&track_storage.pos.client,seed);fill_position(&track_storage.pos.server,seed+1);
    fill_position(&delayed_storage.client,seed+2);fill_position(&delayed_storage.server,seed+3);
    track_storage.incoming_ttl=(uint8_t)scalar(seed+2);track_storage.l7proto=seed%18==17?UINT32_MAX:seed%18;
    track_storage.hostname=(char *)hosts[seed%6];track_storage.hostname_is_ip=(seed&1)!=0;
    track_storage.b_lua_in_cutoff=(seed&2)!=0;track_storage.b_lua_out_cutoff=(seed&4)!=0;
    track_storage.lua_state=references[seed%8];
    active_track=&track_storage;active_positions=(seed&8)?&delayed_storage:NULL;
    active_position=(seed&16)?&delayed_storage.server:&track_storage.pos.client;
}
static void create_references(lua_State *L)
{
    references[0]=LUA_REFNIL;references[1]=LUA_NOREF;
    lua_newtable(L);lua_pushliteral(L,"identity");lua_setfield(L,-2,"value");references[2]=luaL_ref(L,LUA_REGISTRYINDEX);
    lua_pushboolean(L,false);references[3]=luaL_ref(L,LUA_REGISTRYINDEX);
    lua_pushboolean(L,true);references[4]=luaL_ref(L,LUA_REGISTRYINDEX);
    lua_pushnumber(L,123.25);references[5]=luaL_ref(L,LUA_REGISTRYINDEX);
    lua_pushliteral(L,"saved state");references[6]=luaL_ref(L,LUA_REGISTRYINDEX);
    lua_pushcfunction(L,new_view);references[7]=luaL_ref(L,LUA_REGISTRYINDEX);
}

struct guard {uint8_t *allocation,*end;};
static struct guard guard_new(void)
{
    struct guard g;g.allocation=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(g.allocation);
    g.end=g.allocation+4096;DWORD old;CHECK(VirtualProtect(g.end,4096,PAGE_NOACCESS,&old));return g;
}
static void guarded_checks(lua_State *L)
{
    struct guard track=guard_new(),positions=guard_new(),position=guard_new();
    for(unsigned seed=0;seed<256;++seed){
        prepare(seed);memcpy(track.end-sizeof(t_ctrack),&track_storage,sizeof(t_ctrack));
        memcpy(positions.end-sizeof(t_ctrack_positions),&delayed_storage,sizeof(t_ctrack_positions));
        memcpy(position.end-sizeof(t_ctrack_position),active_position,sizeof(t_ctrack_position));
        active_track=(const void *)(track.end-sizeof(t_ctrack));
        active_positions=seed&1?(const void *)(positions.end-sizeof(t_ctrack_positions)):NULL;
        active_position=(const void *)(position.end-sizeof(t_ctrack_position));
        DWORD old;CHECK(VirtualProtect(track.allocation,4096,PAGE_READONLY,&old));
        CHECK(VirtualProtect(positions.allocation,4096,PAGE_READONLY,&old));
        CHECK(VirtualProtect(position.allocation,4096,PAGE_READONLY,&old));
        for(unsigned flags=0;flags<4;++flags){incoming=flags&1;params.server=(flags&2)!=0;
            for(mode=0;mode<3;++mode){compare(L);++guarded;}}
        CHECK(VirtualProtect(track.allocation,4096,PAGE_READWRITE,&old));
        CHECK(VirtualProtect(positions.allocation,4096,PAGE_READWRITE,&old));
        CHECK(VirtualProtect(position.allocation,4096,PAGE_READWRITE,&old));
    }
    CHECK(VirtualFree(track.allocation,0,MEM_RELEASE));CHECK(VirtualFree(positions.allocation,0,MEM_RELEASE));CHECK(VirtualFree(position.allocation,0,MEM_RELEASE));
}
static void boundary_checks(void)
{
    _Alignas(8) uint8_t storage[512]={0};zapret_lua_track_values view;
    zapret_lua_track_position_values pos;
    memset(&view,0xa5,sizeof(view));memset(&pos,0xa5,sizeof(pos));
#define BOUND(v) do { CHECK(v); ++boundaries; } while(0)
    BOUND(!zapret_lua_track_position(NULL,&track_storage.pos.client,&pos));
    BOUND(!zapret_lua_track_position(&track_storage,NULL,&pos));
    BOUND(!zapret_lua_track_position(&track_storage,&track_storage.pos.client,NULL));
    BOUND(!zapret_lua_track_position((void *)(storage+1),&track_storage.pos.client,&pos));
    BOUND(!zapret_lua_track_position(&track_storage,(void *)(storage+1),&pos));
    BOUND(!zapret_lua_track_position(&track_storage,&track_storage.pos.client,(void *)(storage+1)));
    BOUND(zapret_lua_track_view(NULL,(void *)1,true,true,&view)==0);
    BOUND(zapret_lua_track_view(&track_storage,NULL,false,false,NULL)==2);
    BOUND(zapret_lua_track_view(&track_storage,NULL,false,false,(void *)(storage+1))==2);
    BOUND(zapret_lua_track_view((void *)(storage+1),NULL,false,false,&view)==2);
    BOUND(zapret_lua_track_view(&track_storage,(void *)(storage+1),false,false,&view)==2);
    for(unsigned i=0;i<sizeof(view);++i)CHECK(((uint8_t *)&view)[i]==0xa5);
    for(unsigned i=0;i<sizeof(pos);++i)CHECK(((uint8_t *)&pos)[i]==0xa5);
#undef BOUND
}
static void independent_checks(lua_State *L)
{
    prepare(0);active_positions=NULL;incoming=false;params.server=false;mode=1;
    track_storage.t_start.tv_sec=10;track_storage.t_start.tv_nsec=750000000;
    track_storage.pos.t_last.tv_sec=12;track_storage.pos.t_last.tv_nsec=250000000;
    track_storage.pos.client.seq0=UINT32_MAX;track_storage.pos.client.seq_last=2;track_storage.pos.client.pos=0;
    track_storage.pos.client.pcounter=UINT64_MAX;track_storage.incoming_ttl=0;track_storage.hostname=NULL;
    track_storage.l7proto=L7_TLS;compare(L);
    lua_pushcfunction(L,new_view);CHECK(!lua_pcall(L,0,1,0));
    lua_getfield(L,-1,"t_start");CHECK(lua_tonumber(L,-1)==10.75);lua_pop(L,1);
    lua_getfield(L,-1,"l7proto");CHECK(!strcmp(lua_tostring(L,-1),"tls"));lua_pop(L,1);
    lua_getfield(L,-1,"incoming_ttl");CHECK(lua_isnil(L,-1));lua_pop(L,1);
    lua_getfield(L,-1,"pos");lua_getfield(L,-1,"dt");CHECK(lua_tonumber(L,-1)==1.5);lua_pop(L,1);
    lua_getfield(L,-1,"client");lua_getfield(L,-1,"pcounter");CHECK(lua_tonumber(L,-1)==-1);lua_pop(L,1);
    lua_getfield(L,-1,"tcp");lua_getfield(L,-1,"rseq");CHECK(lua_tonumber(L,-1)==3);lua_pop(L,1);
    lua_getfield(L,-1,"pos");CHECK(lua_tonumber(L,-1)==1);lua_settop(L,0);
}
struct allocator {bool armed;unsigned calls,fail_after,rejected,live;};
static void *vm_allocate(void *context,void *pointer,size_t previous,size_t next)
{
    struct allocator *a=context;
    if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}
    if(a->armed && next>previous && a->calls++>=a->fail_after){++a->rejected;return NULL;}
    bool fresh=!pointer;void *result=realloc(pointer,next);if(result && fresh)++a->live;return result;
}
static void fault_checks(void)
{
    for(mode=0;mode<3;++mode)for(unsigned limit=0;limit<48;++limit)for(unsigned side=0;side<2;++side){
        struct allocator a={.fail_after=limit};lua_State *L=lua_newstate(vm_allocate,&a);CHECK(L);params.L=L;
        create_references(L);prepare(10);incoming=true;params.server=false;
        lua_pushcfunction(L,side?new_view:old_view);a.armed=true;int status=lua_pcall(L,0,1,0);a.armed=false;
        if(status){CHECK(status==LUA_ERRMEM && a.rejected);++vm_faults;}else CHECK(!a.rejected && lua_istable(L,-1));
        lua_close(L);CHECK(!a.live);++fault_cases;
    }
    params.L=NULL;CHECK(vm_faults>=64);
}
int main(void)
{
    lua_State *L=luaL_newstate();CHECK(L);params.L=L;luaL_openlibs(L);
    luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);CHECK(!luaL_dostring(L,same));create_references(L);
    for(unsigned seed=0;seed<4096;++seed){prepare(seed);
        for(unsigned flags=0;flags<4;++flags){incoming=flags&1;params.server=(flags&2)!=0;
            for(mode=0;mode<3;++mode)compare(L);}}
    for(unsigned protocol=0;protocol<256;++protocol){prepare(protocol);track_storage.pos.ipproto=(uint8_t)protocol;mode=0;compare(L);}
    for(unsigned flags=0;flags<4;++flags)for(mode=1;mode<3;++mode){incoming=flags&1;params.server=(flags&2)!=0;active_track=NULL;active_positions=(void *)1;compare(L);}
    independent_checks(L);guarded_checks(L);boundary_checks();params.L=NULL;lua_close(L);fault_checks();
    printf("PASS lua_conntrack_view functions=2 position_cases=%u track_cases=%u alias_checks=%u guarded=%u boundaries=%u vm_allocation_faults=%u fault_cases=%u real_luajit=1 input_preserved=1 vm_allocations_released=1\n",position_cases,track_cases,alias_checks,guarded,boundaries,vm_faults,fault_cases);
    return 0;
}
