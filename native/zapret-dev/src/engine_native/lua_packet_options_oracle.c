/* MIT. Real LuaJIT option publication and complete marker API comparison. */
#include <iphlpapi.h>
#include "params.h"
#include "engine_lua.h"
#include <lualib.h>
#include <luajit.h>
#undef main
struct params_s params;
#include "lua_packet_options_common.inc"
#define lua_reconstruct_extract_options reference_reconstruct_options
#define lua_rawsend_extract_options reference_rawsend_options
#define luacall_resolve_pos reference_resolve_pos
#define luacall_resolve_multi_pos reference_resolve_multi_pos
#define luacall_resolve_range reference_resolve_range
#include "lua_packet_options_reference.inc"
#undef lua_reconstruct_extract_options
#undef lua_rawsend_extract_options
#undef luacall_resolve_pos
#undef luacall_resolve_multi_pos
#undef luacall_resolve_range
#include "lua_packet_options_windows.inc"
#include "windows_lua_packet_positions_abi.h"
static unsigned option_cases,position_cases,errors,reentries,boundaries,fault_cases,vm_faults,checkpoints;
static unsigned position_gc_reentries, rust_position_faults, position_recoveries;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL Lua packet options option_cases=%u position_cases=%u line=%d: %s\n",option_cases,position_cases,__LINE__,#v);exit(1);}}while(0)
struct allocator{bool armed;unsigned limit,calls,rejected,live;};static struct allocator *fault_allocator;
static void *allocate(void *context,void *pointer,size_t previous,size_t next){struct allocator *a=context;if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}if(a->armed && next>previous && a->calls++>=a->limit){++a->rejected;return NULL;}bool fresh=!pointer;void *result=realloc(pointer,next);if(result && fresh)++a->live;return result;}
struct outputs{bool flags[3];uint8_t protocol;int repeats;uint32_t mark;bool has_interface;char ifout[128];};
struct sample{struct outputs out;const char *ifout;unsigned mode,mask,behavior,nested,trace_count,stop;bool alias,rust,normal;int status;uint32_t mark_after,nested_hash;size_t trace_length;char trace[1024],message[512];};static struct sample *active;
static int trace(lua_State *L){const char *key=lua_tostring(L,1);size_t n=strlen(key);CHECK(active->trace_length+n+2<sizeof(active->trace));memcpy(active->trace+active->trace_length,key,n);active->trace_length+=n;active->trace[active->trace_length++]=';';active->trace[active->trace_length]=0;++active->trace_count;if(active->stop==active->trace_count)return luaL_error(L,"option checkpoint");return 0;}
static int setmark(lua_State *L){params.desync_fwmark=(uint32_t)lua_tointeger(L,1);return 0;}
static void invoke(lua_State *L,int idx,struct sample *s){bool *a=s->mask&1?&s->out.flags[0]:NULL,*b=s->mask&2?&s->out.flags[s->alias?0:1]:NULL,*c=s->mask&4?&s->out.flags[s->alias?0:2]:NULL;
    if(s->mode==0){if(s->rust)lua_reconstruct_extract_options(L,idx,a,b,c,s->mask&8?&s->out.protocol:NULL);else reference_reconstruct_options(L,idx,a,b,c,s->mask&8?&s->out.protocol:NULL);}
    else if(s->rust)lua_rawsend_extract_options(L,idx,s->mask&1?&s->out.repeats:NULL,s->mask&2?&s->out.mark:NULL,s->mask&4?&s->ifout:NULL);
    else reference_rawsend_options(L,idx,s->mask&1?&s->out.repeats:NULL,s->mask&2?&s->out.mark:NULL,s->mask&4?&s->ifout:NULL);
}
static int reenter(lua_State *L){if(active->nested)return 0;struct sample *saved=active,inner={.mode=saved->mode,.mask=saved->mask,.rust=saved->rust,.alias=saved->alias};saved->nested=1;active=&inner;invoke(L,1,&inner);active=saved;saved->nested_hash=inner.out.repeats^(inner.out.mark<<1)^inner.out.protocol;return 0;}
static const char *factory=
"function OPTION_CASE(mode,variant,shape,behavior) "
"local values={false,true,0,1,-1,255,256,65535,4294967295,4294967296,-4294967296,2147483648,3.75,'3','-1','bad','',{},function()end,math.huge,0/0,'wifi'..string.char(0)..'tail'} "
"local keys=mode==0 and {'keepsum','badsum','ip6_preserve_next','ip6_last_proto'} or {'repeats','fwmark','ifout'} "
"local t={} for i,k in ipairs(keys) do t[k]=values[(variant+i-1)%23] end "
"if behavior==5 then t=mode==0 and {keepsum=true,badsum=false,ip6_preserve_next=0,ip6_last_proto=17} or {repeats=2,fwmark=3,ifout='wifi'} end "
"if shape==0 then return nil elseif shape==1 then return false elseif shape==2 then return 1 elseif shape==3 then return 'x' elseif shape==4 then return function()end end "
"if behavior==0 then return t end local retained={} return setmetatable({},{__index=function(_,k) TRACE(k) "
"if behavior==2 then MARK(2048+variant);if k==keys[1] then t[keys[2]]=7 end end "
"if behavior==3 and k==keys[variant%#keys+1] then error('option lookup failed: '..k) end "
"if behavior==4 and k==keys[1] then REENTER(t) end "
"if behavior==5 then retained[#retained+1]=string.rep(k..#retained,4096);collectgarbage('step',1) end "
"return t[k] end}) end";
static lua_State *new_vm(struct allocator *a){lua_State *L=a?lua_newstate(allocate,a):luaL_newstate();CHECK(L);luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);lua_register(L,"TRACE",trace);lua_register(L,"MARK",setmark);lua_register(L,"REENTER",reenter);CHECK(!luaL_dostring(L,factory));return L;}
static int option_call(lua_State *L){int top=lua_gettop(L);invoke(L,1,active);CHECK(lua_gettop(L)==top);active->normal=true;return 0;}
static void execute(lua_State *L,unsigned variant,unsigned shape,struct sample *s){lua_settop(L,0);lua_pushcfunction(L,option_call);if(shape!=6){lua_getglobal(L,"OPTION_CASE");lua_pushinteger(L,s->mode);lua_pushinteger(L,variant);lua_pushinteger(L,shape);lua_pushinteger(L,s->behavior);CHECK(!lua_pcall(L,4,1,0));}active=s;s->out=(struct outputs){.flags={true,false,true},.protocol=201,.repeats=37,.mark=0xaabbccdd};s->ifout="initial";params.desync_fwmark=0x100;
    if(fault_allocator){fault_allocator->armed=true;fault_allocator->calls=fault_allocator->rejected=0;}s->status=lua_pcall(L,shape==6?0:1,0,0);if(fault_allocator)fault_allocator->armed=false;s->mark_after=params.desync_fwmark;
    if(s->status){const char *msg=lua_tostring(L,-1);snprintf(s->message,sizeof(s->message),"%s",msg?msg:"");}s->out.has_interface=s->ifout!=NULL;if(s->ifout)snprintf(s->out.ifout,sizeof(s->out.ifout),"%s",s->ifout);lua_settop(L,0);
}
static void compare_option(lua_State *L,unsigned mode,unsigned variant,unsigned shape,unsigned behavior,unsigned mask,bool alias){struct sample a={.mode=mode,.mask=mask,.behavior=behavior,.alias=alias},b=a;b.rust=true;execute(L,variant,shape,&a);execute(L,variant,shape,&b);if(a.status!=b.status || a.normal!=b.normal || memcmp(&a.out,&b.out,sizeof(a.out)) || a.mark_after!=b.mark_after || a.nested!=b.nested || a.nested_hash!=b.nested_hash || strcmp(a.trace,b.trace) || strcmp(a.message,b.message)){fprintf(stderr,"DETAIL mode=%u variant=%u shape=%u behavior=%u mask=%u alias=%u olderr=%d newerr=%d\noldtrace=%s\nnewtrace=%s\noldmsg=%s\nnewmsg=%s\n",mode,variant,shape,behavior,mask,alias,a.status,b.status,a.trace,b.trace,a.message,b.message);CHECK(false);}++option_cases;if(a.status)++errors;reentries+=a.nested;}
struct position_sample{int status,type;unsigned count;lua_Integer values[128];char message[512];};
static lua_CFunction resolver(bool rust,unsigned mode){return mode==0?(rust?luacall_resolve_pos:reference_resolve_pos):mode==1?(rust?luacall_resolve_multi_pos:reference_resolve_multi_pos):(rust?luacall_resolve_range:reference_resolve_range);}
static void positions(lua_State *L,bool rust,unsigned mode,const char *data,size_t length,const char *payload,size_t payload_len,const char *markers,size_t marker_len,unsigned flags,unsigned argc,unsigned bad,struct position_sample *s){lua_settop(L,0);lua_pushcfunction(L,resolver(rust,mode));for(unsigned i=1;i<=argc;++i){if(i==bad){lua_pushinteger(L,42);continue;}if(i==1)lua_pushlstring(L,data,length);else if(i==2)lua_pushlstring(L,payload,payload_len);else if(i==3)lua_pushlstring(L,markers,marker_len);else lua_pushboolean(L,flags&(1u<<(i-4)));}
    if(fault_allocator){fault_allocator->armed=true;fault_allocator->calls=fault_allocator->rejected=0;}s->status=lua_pcall(L,argc,1,0);if(fault_allocator)fault_allocator->armed=false;CHECK(lua_gettop(L)==1);if(s->status){const char *message=lua_tostring(L,-1);snprintf(s->message,sizeof(s->message),"%s",message?message:"");}else{s->type=lua_type(L,-1);if(s->type==LUA_TTABLE){s->count=lua_objlen(L,-1);CHECK(s->count<=128);for(unsigned i=0;i<s->count;++i){lua_rawgeti(L,-1,i+1);s->values[i]=lua_tointeger(L,-1);lua_pop(L,1);}}else if(s->type==LUA_TNUMBER){s->count=1;s->values[0]=lua_tointeger(L,-1);}else CHECK(s->type==LUA_TNIL);}lua_settop(L,0);}
static void compare_position(lua_State *L,unsigned mode,const char *data,size_t length,const char *payload,size_t plen,const char *markers,size_t mlen,unsigned flags,unsigned argc,unsigned bad){struct position_sample a={0},b={0};positions(L,false,mode,data,length,payload,plen,markers,mlen,flags,argc,bad,&a);positions(L,true,mode,data,length,payload,plen,markers,mlen,flags,argc,bad,&b);if(memcmp(&a,&b,sizeof(a))){fprintf(stderr,"POSITION mode=%u length=%zu payload=%s markers=%s flags=%u argc=%u bad=%u olderr=%d newerr=%d oldtype=%d newtype=%d oldcount=%u newcount=%u\noldmsg=%s\nnewmsg=%s\n",mode,length,payload,markers,flags,argc,bad,a.status,b.status,a.type,b.type,a.count,b.count,a.message,b.message);CHECK(false);}++position_cases;if(a.status)++errors;}

static void expect_position_table(lua_State *L, const lua_Integer *values, int count)
{
    CHECK(lua_istable(L, -1) && lua_objlen(L, -1) == (size_t)count);
    for (int index = 0; index < count; ++index) {
        lua_rawgeti(L, -1, index + 1);
        CHECK(lua_type(L, -1) == LUA_TNUMBER && lua_tointeger(L, -1) == values[index]);
        lua_pop(L, 1);
    }
}

static int position_finalizer(lua_State *L)
{
    int top = lua_gettop(L);
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_pushliteral(L, "abcdef");
    lua_pushliteral(L, "unknown");
    lua_pushliteral(L, "1,4");
    CHECK(!lua_pcall(L, 3, 1, 0));
    expect_position_table(L, (lua_Integer[]){2, 5}, 2);
    lua_pop(L, 1);
    CHECK(lua_gettop(L) == top);
    ++position_gc_reentries;
    return 0;
}

static void position_reentry(void)
{
    for (unsigned mode = 1; mode <= 2; ++mode) {
        for (unsigned side = 0; side <= 1; ++side) {
            lua_State *L = new_vm(NULL);
            lua_gc(L, LUA_GCSTOP, 0);
            lua_pushcfunction(L, resolver(side != 0, mode));
            lua_pushliteral(L, "abcd");
            lua_pushliteral(L, "unknown");
            lua_pushstring(L, mode == 1 ? "0,2,3" : "0,-1");
            lua_newuserdata(L, 1);
            lua_createtable(L, 0, 1);
            lua_pushcfunction(L, resolver(side != 0, mode));
            lua_pushcclosure(L, position_finalizer, 1);
            lua_setfield(L, -2, "__gc");
            lua_setmetatable(L, -2);
            lua_pop(L, 1);

            // Run the now-unreachable finalizer from the resolver's table creation.
            unsigned before = position_gc_reentries;
            lua_gc(L, LUA_GCSETSTEPMUL, 0);
            lua_gc(L, LUA_GCRESTART, 0);
            CHECK(!lua_pcall(L, 3, 1, 0));
            CHECK(position_gc_reentries == before + 1 && lua_gettop(L) == 1);
            if (mode == 1)
                expect_position_table(L, (lua_Integer[]){1, 3, 4}, 3);
            else
                expect_position_table(L, (lua_Integer[]){1, 4}, 2);
            lua_close(L);
        }
    }
}

struct guard{uint8_t *base,*end;};static struct guard guard_new(void){struct guard g;g.base=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(g.base);g.end=g.base+4096;DWORD old;CHECK(VirtualProtect(g.end,4096,PAGE_NOACCESS,&old));return g;}
static void boundaries_check(void){_Alignas(8)uint8_t storage[2048];memset(storage,0xa5,sizeof(storage));zapret_lua_option_cursor cursor;zapret_lua_option_field field;zapret_lua_option_value value={0};zapret_lua_option_targets t={0};
    CHECK(zapret_lua_packet_options_begin(2,0,&t,&cursor,&field)==2);++boundaries;CHECK(zapret_lua_packet_options_begin(0,2,&t,&cursor,&field)==2);++boundaries;CHECK(zapret_lua_packet_options_begin(0,0,NULL,&cursor,&field)==2);++boundaries;CHECK(zapret_lua_packet_options_begin(0,0,&t,NULL,&field)==2);++boundaries;CHECK(zapret_lua_packet_options_begin(0,0,&t,&cursor,NULL)==2);++boundaries;CHECK(zapret_lua_packet_options_begin(0,0,(void *)(storage+1),&cursor,&field)==2);++boundaries;
    t.repeats=(void *)(storage+1);CHECK(zapret_lua_packet_options_begin(1,0,&t,&cursor,&field)==2);++boundaries;t=(zapret_lua_option_targets){.mark=(void *)storage};CHECK(zapret_lua_packet_options_begin(1,0,&t,&cursor,&field)==2);++boundaries;
    CHECK(zapret_lua_packet_options_observe(NULL,&value,&field)==2);++boundaries;CHECK(zapret_lua_packet_options_observe(&cursor,NULL,&field)==2);++boundaries;CHECK(zapret_lua_packet_options_observe(&cursor,&value,NULL)==2);++boundaries;
    zapret_lua_position_result *out=(void *)storage;CHECK(zapret_lua_positions(3,NULL,0,"unknown","1",0,out)==5);++boundaries;CHECK(zapret_lua_positions(0,NULL,1,"unknown","1",0,out)==5);++boundaries;CHECK(zapret_lua_positions(0,NULL,0,NULL,"1",0,out)==5);++boundaries;CHECK(zapret_lua_positions(0,NULL,0,"unknown",NULL,0,out)==5);++boundaries;CHECK(zapret_lua_positions(0,NULL,0,"unknown","1",4,out)==5);++boundaries;CHECK(zapret_lua_positions(0,NULL,0,"unknown","1",0,(void *)(storage+1))==5);++boundaries;CHECK(zapret_lua_positions(0,NULL,0,"unknown","1",0,NULL)==5);++boundaries;CHECK(storage[0]==0xa5);
    struct guard g=guard_new(),metadata=guard_new();uint8_t *data=g.end-4;memcpy(data,"abcd",4);zapret_lua_position_result *guarded=(void *)(metadata.end-sizeof(*guarded));CHECK(!zapret_lua_positions(2,data,4,"unknown","0,-1",0,guarded));CHECK(guarded->count==2 && guarded->values[1]==4);++boundaries;
    zapret_lua_option_targets *rt=(void *)(metadata.end-sizeof(*rt));*rt=(zapret_lua_option_targets){.protocol=g.end-1};DWORD old;CHECK(VirtualProtect(metadata.base,4096,PAGE_READONLY,&old));CHECK(zapret_lua_packet_options_begin(0,0,rt,&cursor,&field)==1);CHECK(VirtualProtect(metadata.base,4096,PAGE_READWRITE,&old));zapret_lua_option_value *rv=(void *)(metadata.end-sizeof(*rv));*rv=(zapret_lua_option_value){.tag=LUA_TNUMBER,.number=257};CHECK(VirtualProtect(metadata.base,4096,PAGE_READONLY,&old));CHECK(!zapret_lua_packet_options_observe(&cursor,rv,&field) && g.end[-1]==1);CHECK(VirtualProtect(metadata.base,4096,PAGE_READWRITE,&old));boundaries+=2;CHECK(VirtualFree(g.base,0,MEM_RELEASE) && VirtualFree(metadata.base,0,MEM_RELEASE));
}
static void faults(void){for(unsigned mode=0;mode<2;++mode){struct outputs catalogue[5];unsigned count=0;char complete_trace[1024];
    for(unsigned stop=0;stop<=(mode?3:4);++stop){lua_State *L=new_vm(NULL);struct sample s={.mode=mode,.mask=mode?7:15,.behavior=5,.stop=stop};execute(L,0,5,&s);if(!stop){CHECK(s.normal);strcpy(complete_trace,s.trace);}else CHECK(s.status==LUA_ERRRUN && strstr(s.message,"option checkpoint"));catalogue[count++]=s.out;lua_close(L);}checkpoints+=count;
    for(unsigned side=0;side<2;++side)for(unsigned limit=0;limit<64;++limit){struct allocator allocator={.limit=limit};lua_State *L=new_vm(&allocator);struct sample s={.mode=mode,.mask=mode?7:15,.behavior=5,.rust=side!=0};fault_allocator=&allocator;execute(L,0,5,&s);fault_allocator=NULL;bool known=false;for(unsigned i=0;i<count;++i)if(!memcmp(&s.out,&catalogue[i],sizeof(s.out)))known=true;CHECK(known && s.trace_length<=strlen(complete_trace) && !strncmp(complete_trace,s.trace,s.trace_length));if(s.status){CHECK(s.status==LUA_ERRMEM && allocator.rejected && !s.normal);++vm_faults;}else CHECK(s.normal && !allocator.rejected);lua_close(L);CHECK(!allocator.live);++fault_cases;}
    }
}

static void position_faults(void)
{
    for (unsigned mode = 0; mode < 3; ++mode) {
        const char *markers = mode == 2 ? "0,-1" : "0,1,2,3";
        size_t marker_len = strlen(markers);
        unsigned before = rust_position_faults;
        for (unsigned side = 0; side < 2; ++side) {
            for (unsigned limit = 0; limit < 12; ++limit) {
                struct allocator allocator = {.limit = limit};
                lua_State *L = new_vm(&allocator);
                struct position_sample sample = {0};
                fault_allocator = &allocator;
                positions(L, side != 0, mode, "abcd", 4, "unknown", 7, markers,
                    marker_len, 0, 3, 0, &sample);
                fault_allocator = NULL;
                if (sample.status) {
                    CHECK(sample.status == LUA_ERRMEM && allocator.rejected);
                    ++vm_faults;
                    if (side != 0) ++rust_position_faults;
                    sample = (struct position_sample){0};
                    positions(L, side != 0, mode, "abcd", 4, "unknown", 7, markers,
                        marker_len, 0, 3, 0, &sample);
                    CHECK(!sample.status);
                    ++position_recoveries;
                }
                if (mode == 0) CHECK(sample.type == LUA_TNUMBER && sample.values[0] == 1);
                else CHECK(sample.type == LUA_TTABLE && sample.count == (mode == 1 ? 4 : 2));
                lua_close(L);
                CHECK(!allocator.live);
                ++fault_cases;
            }
        }
        if (mode != 0) CHECK(rust_position_faults > before);
    }
    CHECK(vm_faults > 20);
}

int main(void){lua_State *L=new_vm(NULL);for(unsigned mode=0;mode<2;++mode)for(unsigned variant=0;variant<23;++variant)for(unsigned shape=0;shape<7;++shape)for(unsigned behavior=0;behavior<5;++behavior)for(unsigned mask=0;mask<(mode?8:16);++mask)for(unsigned alias=0;alias<(mode?1:2);++alias)compare_option(L,mode,variant,shape,behavior,mask,alias);
    const char *http="GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";const char *payloads[]={"unknown","http_req","tls_client_hello","bad","unknown\0ignored"};const char *markers[]={"","0","-1","1,2","host,endhost","host,9999","9999,-1","9998,9999","10,1","host,,1","host+32768","0,1,2,3","1,1,-1,9999","1\0ignored","0,-1","1,2,3","abs+2","host+1","-32768","+32767"};
    for(unsigned mode=0;mode<3;++mode)for(unsigned p=0;p<5;++p)for(unsigned m=0;m<20;++m)for(unsigned flags=0;flags<4;++flags)for(unsigned argc=2;argc<=6;++argc){compare_position(L,mode,http,strlen(http),payloads[p],p==4?15:strlen(payloads[p]),markers[m],m==13?9:strlen(markers[m]),flags,argc,0);}
    for(unsigned mode=0;mode<3;++mode)for(size_t length=0;length<=strlen(http);++length)for(unsigned m=0;m<20;++m)compare_position(L,mode,http,length,"http_req",8,markers[m],strlen(markers[m]),m%4,mode==2?5:4,0);
    for(unsigned mode=0;mode<3;++mode)for(unsigned argc=0;argc<7;++argc)for(unsigned bad=1;bad<6;++bad)compare_position(L,mode,http,strlen(http),"bad",3,"bad",3,0,argc,bad);
    char marker_limit[260];for(unsigned n=127;n<=129;++n){for(unsigned i=0;i<n;++i){marker_limit[i*2]='1';marker_limit[i*2+1]=',';}marker_limit[n*2-1]=0;for(unsigned mode=1;mode<3;++mode)compare_position(L,mode,http,strlen(http),"unknown",7,marker_limit,strlen(marker_limit),0,3,0);}
    lua_close(L);boundaries_check();faults();position_faults();position_reentry();
    printf("PASS lua_packet_options apis=5 option_cases=%u position_cases=%u vm_errors=%u "
        "reentries=%u boundaries=%u fault_cases=%u vm_allocation_faults=%u checkpoints=%u "
        "position_gc_reentries=%u rust_position_faults=%u position_recoveries=%u rust_position_entries=3 "
        "real_luajit=1 exact_lookup_order=1 exact_partial_outputs=1 live_fwmark=1 aliased_outputs=1 "
        "protected_vm_unwind=1 vm_allocations_released=1\n",
        option_cases,position_cases,errors,reentries,boundaries,fault_cases,vm_faults,checkpoints,
        position_gc_reentries,rust_position_faults,position_recoveries);
    return 0;
}
