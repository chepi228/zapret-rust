/* MIT. Real LuaJIT differential checks for the complete registration catalog. */
#include <iphlpapi.h>
#include "params.h"
#include "engine_lua.h"
#include "nfqws.h"
#include <luajit.h>
#include <limits.h>
#include <stdarg.h>
#undef main
struct params_s params;
int lua_absindex(lua_State *L,int index){return index>0 || index<=LUA_REGISTRYINDEX?index:lua_gettop(L)+index+1;}
static unsigned cases,fault_cases,faults,mutations,finalizers,boundaries,guarded;
static unsigned mode,variant,seed,writes;
static bool native_side;
static char diagnostic[32768],trace[32768];
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL Lua registry mode=%u variant=%u seed=%u line=%d: %s\n",mode,variant,seed,__LINE__,#v);exit(1);}}while(0)
static void append(char *buffer,size_t size,const char *format,va_list args)
{size_t used=strlen(buffer);CHECK(used<size);int count=vsnprintf(buffer+used,size-used,format,args);CHECK(count>=0 && (size_t)count<size-used);}
int DLOG(const char *format,...){va_list args;va_start(args,format);append(diagnostic,sizeof(diagnostic),format,args);va_end(args);return 0;}
int DLOG_ERR(const char *format,...){va_list args;va_start(args,format);append(diagnostic,sizeof(diagnostic),format,args);va_end(args);return 0;}
static void record(const char *format,...){va_list args;va_start(args,format);append(trace,sizeof(trace),format,args);va_end(args);}
#include "lua_registry_stubs.inc"
#include "lua_registry_names.inc"
int lua_cfunc_zstream_gc(lua_State *L){(void)L;++finalizers;return 0;}
#include "lua_registry_context.inc"
#define lua_mt_init_desync_ctx reference_context_mt
#define lua_mt_init_zstream reference_stream_mt
#define lua_init_const reference_constants
#define lua_init_functions reference_functions
#define lua_init_mt reference_metatables
#include "lua_registry_reference.inc"
#undef lua_mt_init_desync_ctx
#undef lua_mt_init_zstream
#undef lua_init_const
#undef lua_init_functions
#undef lua_init_mt
#define ZAPRET_LUA_REGISTRY_VM 1
#include "lua_registry_windows.h"
#include "lua_registry_vm_sources.inc"

static uint64_t bytes_hash(const void *bytes,size_t length)
{uint64_t value=UINT64_C(14695981039346656037);const uint8_t *p=bytes;for(size_t i=0;i<length;++i)value=(value^p[i])*UINT64_C(1099511628211);return value;}
static uint64_t value_hash(lua_State *L,int index)
{
    int type=lua_type(L,index);uint64_t value=(uint64_t)(type+2)*UINT64_C(0x9e3779b185ebca87);
    switch(type){
        case LUA_TSTRING:{size_t length;const char *text=lua_tolstring(L,index,&length);return value^bytes_hash(text,length);}
        case LUA_TNUMBER:{lua_Number number=lua_tonumber(L,index);return value^bytes_hash(&number,sizeof(number));}
        case LUA_TBOOLEAN:return value^(uint64_t)lua_toboolean(L,index);
        case LUA_TFUNCTION:{lua_CFunction fn=lua_tocfunction(L,index);return value^bytes_hash(&fn,sizeof(fn));}
        case LUA_TUSERDATA:return value^(uint64_t)lua_objlen(L,index);
        default:return value;
    }
}
static uint64_t table_hash(lua_State *L,int index,unsigned *count)
{
    index=lua_absindex(L,index);uint64_t hash=0;*count=0;lua_pushnil(L);
    while(lua_next(L,index)){
        hash^=value_hash(L,-2)*UINT64_C(0x9e3779b185ebca87)+value_hash(L,-1);++*count;lua_pop(L,1);
    }return hash;
}
static int publication(lua_State *L)
{
    ++writes;const char *key=lua_tostring(L,2);CHECK(key);
    record("%s:%s:%016llx;",lua_tostring(L,lua_upvalueindex(1)),key,(unsigned long long)value_hash(L,3));
    if(variant==4 || variant==7){
        strcpy(params.verstr,"changed version");params.desync_fwmark+=0x1020304;
        params.debug=!params.debug;params.daemon=!params.daemon;params.server=!params.server;
        params.cache_hostname=!params.cache_hostname;params.ctrack_disable=!params.ctrack_disable;++mutations;
    }
    if(variant==5 && writes==1+seed%226)return luaL_error(L,"registration refused at %s",key);
    if(variant!=2){lua_pushvalue(L,2);lua_pushvalue(L,3);lua_rawset(L,1);}
    return 0;
}
static void intercept(lua_State *L,const char *name)
{
    lua_newtable(L);lua_pushstring(L,name);lua_pushcclosure(L,publication,1);lua_setfield(L,-2,"__newindex");lua_setmetatable(L,-2);
}
static void prepare(lua_State *L)
{
    memset(&params,0,sizeof(params));params.L=L;
    strcpy(params.verstr,seed%7==0?"":seed%3==0?"v0-версия":"v0");
    params.desync_fwmark=seed%2?UINT32_MAX:seed*UINT32_C(0x1020304);
    params.debug=!!(seed&1);params.daemon=!!(seed&2);params.server=!!(seed&4);
    params.cache_hostname=!!(seed&8);params.ctrack_disable=!!(seed&16);
    writes=mutations=finalizers=0;diagnostic[0]=trace[0]=0;
    if(variant==3){
        for(unsigned i=0;i<sizeof(catalog_names)/sizeof(*catalog_names);++i){lua_pushboolean(L,false);lua_setglobal(L,catalog_names[i]);}
    }
    if(variant!=0 && variant!=3){lua_pushvalue(L,LUA_GLOBALSINDEX);intercept(L,"global");lua_pop(L,1);}
    if(variant>=6){
        for(unsigned index=0;index<2;++index){
            lua_newtable(L);lua_pushinteger(L,37);lua_setfield(L,-2,"keep");intercept(L,index?"context":"stream");
            lua_setfield(L,LUA_REGISTRYINDEX,index?"desync_ctx":"userdata_zstream");
        }
    }
}
static int invoke(lua_State *L)
{
    (void)L;
    if(mode==0 || mode==3)(native_side?lua_init_const:reference_constants)();
    if(mode==1 || mode==3)(native_side?lua_init_functions:reference_functions)();
    if(mode==2 || mode==3)(native_side?lua_init_mt:reference_metatables)();
    return 0;
}
struct allocator {bool armed;unsigned calls,limit,rejected,live;};
static void *allocate(void *context,void *pointer,size_t previous,size_t next)
{
    struct allocator *a=context;
    if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}
    if(a->armed && next>previous && a->calls++>=a->limit){++a->rejected;return NULL;}
    bool fresh=!pointer;void *result=realloc(pointer,next);if(result && fresh)++a->live;return result;
}
struct sample {int status,stack;char error[512],log[32768],trace[32768];uint64_t globals,metatables,context;unsigned count,writes,mutations,finalizers,rejected,mark,flags;};
static struct sample left,right;
static void execute(bool native,unsigned limit,struct sample *out)
{
    struct allocator a={.limit=limit};lua_State *L=lua_newstate(allocate,&a);CHECK(L);native_side=native;
    prepare(L);lua_pushcfunction(L,invoke);a.armed=limit!=UINT_MAX;
    out->status=lua_pcall(L,0,LUA_MULTRET,0);a.armed=false;out->error[0]=0;
    if(out->status){const char *error=lua_tostring(L,-1);snprintf(out->error,sizeof(out->error),"%s",error?error:"nonstring error");lua_pop(L,1);}
    if(!out->status && variant==7){lua_pushcfunction(L,invoke);out->status=lua_pcall(L,0,0,0);if(out->status){snprintf(out->error,sizeof(out->error),"%s",lua_tostring(L,-1));lua_pop(L,1);}}
    out->stack=lua_gettop(L);CHECK(!out->stack);
    out->globals=table_hash(L,LUA_GLOBALSINDEX,&out->count);out->metatables=0;
    for(unsigned index=0;index<2;++index){
        lua_getfield(L,LUA_REGISTRYINDEX,index?"desync_ctx":"userdata_zstream");
        if(lua_istable(L,-1)){unsigned count;out->metatables^=table_hash(L,-1,&count)*(index+1)+count;}else out->metatables^=value_hash(L,-1);
        lua_pop(L,1);
    }
    out->context=0;
    if(params.ref_desync_ctx){
        lua_rawgeti(L,LUA_REGISTRYINDEX,params.ref_desync_ctx);CHECK(lua_isuserdata(L,-1));
        t_lua_desync_context *ctx=lua_touserdata(L,-1);
        CHECK(lua_objlen(L,-1)==sizeof(*ctx) && !ctx->func_n && !ctx->func && !ctx->instance && !ctx->dp && !ctx->dis && !ctx->ctrack && !ctx->incoming && !ctx->cancel && !ctx->valid);
        out->context=lua_objlen(L,-1);lua_pop(L,1);
    }
    out->writes=writes;out->mutations=mutations;out->mark=params.desync_fwmark;
    out->flags=!!params.debug | (!!params.daemon<<1) | (!!params.server<<2) | (!!params.cache_hostname<<3) | (!!params.ctrack_disable<<4);
    strcpy(out->log,diagnostic);strcpy(out->trace,trace);out->rejected=a.rejected;
    lua_getfield(L,LUA_REGISTRYINDEX,"userdata_zstream");
    if(lua_istable(L,-1)){
        lua_getfield(L,-1,"__gc");bool installed=lua_tocfunction(L,-1)==lua_cfunc_zstream_gc;lua_pop(L,1);
        if(installed){lua_newuserdata(L,1);lua_pushvalue(L,-2);lua_setmetatable(L,-2);lua_pop(L,1);}
    }lua_pop(L,1);
    lua_close(L);CHECK(!a.live);out->finalizers=finalizers;
}
static void compare(unsigned limit)
{
    execute(false,limit,&left);execute(true,limit,&right);
    if(left.status!=right.status || strcmp(left.error,right.error) || strcmp(left.log,right.log) || strcmp(left.trace,right.trace)){
        fprintf(stderr,"DETAIL status=%d/%d error=%s/%s\noldlog=%s\nnewlog=%s\noldtrace=%s\nnewtrace=%s\n",left.status,right.status,left.error,right.error,left.log,right.log,left.trace,right.trace);CHECK(false);
    }
    CHECK(left.stack==right.stack && left.globals==right.globals && left.count==right.count && left.metatables==right.metatables && left.context==right.context);
    CHECK(left.writes==right.writes && left.mutations==right.mutations && left.finalizers==right.finalizers && left.mark==right.mark && left.flags==right.flags);
    if(limit==UINT_MAX)++cases;
    else{++fault_cases;if(left.rejected || right.rejected){CHECK(left.status==LUA_ERRMEM && right.status==LUA_ERRMEM);++faults;}}
}
static void boundary_checks(void)
{
    _Alignas(8) uint8_t bytes[128]={0};zapret_lua_registry_values values={0};
    zapret_lua_registry_value value={.value=37};zapret_lua_registry_binding fn={.slot=41};zapret_lua_registry_mt mt={.action=43};
#define BOUND(v) do{CHECK(v);++boundaries;}while(0)
    BOUND(zapret_lua_registry_constant(0,0,NULL,&value)==2);
    BOUND(zapret_lua_registry_constant(0,0,&values,NULL)==2);
    BOUND(zapret_lua_registry_constant(0,0,(void *)(bytes+1),&value)==2);
    BOUND(zapret_lua_registry_constant(0,0,&values,(void *)(bytes+1))==2);
    BOUND(zapret_lua_registry_constant(3,0,&values,&value)==2);
    BOUND(zapret_lua_registry_constant(1,SIZE_MAX,&values,&value)==2);
    BOUND(zapret_lua_registry_constant(0,1,&values,&value)==0 && value.value==37);
    BOUND(zapret_lua_registry_function(0,101,NULL)==2);
    BOUND(zapret_lua_registry_function(0,101,(void *)(bytes+1))==2);
    BOUND(zapret_lua_registry_function(0,100,&fn)==2 && fn.slot==41);
    BOUND(zapret_lua_registry_function(0,102,&fn)==2);
    BOUND(zapret_lua_registry_function(SIZE_MAX,101,&fn)==2);
    BOUND(zapret_lua_registry_function(101,101,&fn)==0 && fn.slot==41);
    BOUND(zapret_lua_registry_metatable(0,NULL)==2);
    BOUND(zapret_lua_registry_metatable(0,(void *)(bytes+1))==2);
    BOUND(zapret_lua_registry_metatable(SIZE_MAX,&mt)==2);
    BOUND(zapret_lua_registry_metatable(3,&mt)==0 && mt.action==43);
#undef BOUND
    uint8_t *memory=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(memory);DWORD previous;
    CHECK(VirtualProtect(memory+4096,4096,PAGE_NOACCESS,&previous));
    zapret_lua_registry_values *at=(void *)(memory+4096-sizeof(*at));*at=values;
    CHECK(VirtualProtect(memory,4096,PAGE_READONLY,&previous));
    for(unsigned group=0;group<3;++group)for(size_t index=0;;++index){uint32_t status=zapret_lua_registry_constant(group,index,at,&value);CHECK(status<2);++guarded;if(!status)break;}
    CHECK(VirtualFree(memory,0,MEM_RELEASE));
}
int main(void)
{
    for(mode=0;mode<4;++mode)for(variant=0;variant<8;++variant)for(seed=0;seed<128;++seed)compare(UINT_MAX);
    variant=1;seed=31;
    for(mode=0;mode<4;++mode)for(unsigned limit=0;limit<256;++limit)compare(limit);
    CHECK(faults>=128);boundary_checks();
    printf("PASS lua_registry functions=5 numeric=119 callbacks=101 booleans=5 cases=%u fault_cases=%u vm_allocation_faults=%u boundaries=%u guarded=%u real_luajit=1 callback_identities=1 group_snapshots=1 duplicate_writes=1 metatable_order=1 vm_allocations_released=1 rust_seh_unwind=1\n",cases,fault_cases,faults,boundaries,guarded);
    return 0;
}
