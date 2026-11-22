/* MIT. C performs each native/VM operation only after the Rust step returns. */
#include "lua_lifetime_windows.h"
typedef struct {uint32_t phase;int32_t index;}zapret_lua_vm_init;
typedef struct {int32_t kind,top;uint32_t ok;}zapret_lua_vm_feedback;
typedef struct {uint64_t now;uint32_t phase;}zapret_lua_gc;
typedef struct {const char *format,*edition;uint32_t major,minor;}zapret_lua_version;
uint32_t zapret_lua_vm_init_step(zapret_lua_vm_init *,const zapret_lua_vm_feedback *);
bool zapret_lua_vm_created(zapret_lua_vm_init *,uint32_t);
uint32_t zapret_lua_vm_cleanup_step(uint32_t *,uint32_t,uint32_t);
uint32_t zapret_lua_gc_step(zapret_lua_gc *,uint64_t,uint64_t,uint64_t);
void zapret_lua_vm_version(uint32_t,bool,bool,zapret_lua_version *);
_Static_assert(sizeof(zapret_lua_vm_init)==8 && sizeof(zapret_lua_vm_feedback)==12 && sizeof(zapret_lua_gc)==16 &&
    sizeof(zapret_lua_version)==24 && offsetof(zapret_lua_version,major)==16,"Rust Lua VM ABI");
void lua_cleanup(lua_State *L)
{
    uint32_t state=0;
    for(;;)switch(zapret_lua_vm_cleanup_step(&state,0,1)){
        case 0:return;
        case 1:lua_desync_ctx_destroy(L);break;
        case 2:ConntrackPoolDestroy(&params.conntrack);break;
        case 3:TimerPoolDestroy(&params.timers);break;
        default:DLOG_ERR("invalid Lua cleanup plan\n");return;
    }
}
void lua_shutdown(void)
{
    uint32_t state=0;
    for(;;)switch(zapret_lua_vm_cleanup_step(&state,1,params.L!=NULL)){
        case 0:return;
        case 4:DLOG(zapret_lua_vm_text(LUA_VM_SHUTDOWN));break;
        case 5:zapret_lua_vm_detach(params.L);break;
        case 6:lua_cleanup(params.L);break;
        case 7:lua_close(params.L);break;
        case 8:params.L=NULL;break;
        default:DLOG_ERR("invalid Lua shutdown plan\n");return;
    }
}
static void native_lua_version(void)
{
    unsigned int version;
#if LUA_VERSION_NUM >= 504
    version=(unsigned int)lua_version(params.L);
#elif LUA_VERSION_NUM >= 502
    version=(unsigned int)*lua_version(params.L);
#else
    version=LUA_VERSION_NUM;
#endif
    zapret_lua_version view;
#ifdef LUAJIT_VERSION
#ifdef OPENRESTY_LUAJIT
    const bool openresty=true;
#else
    const bool openresty=false;
#endif
    zapret_lua_vm_version(version,true,openresty,&view);
    DLOG_CONDUP(view.format,view.major,view.minor,LUAJIT_VERSION,view.edition);
#else
    zapret_lua_vm_version(version,false,false,&view);
    DLOG_CONDUP(view.format,view.major,view.minor);
#endif
}
static bool lua_basic_init(void)
{
    zapret_lua_vm_init state={0};zapret_lua_vm_feedback value={0};const char *text=NULL;
    for(;;)switch(zapret_lua_vm_init_step(&state,&value)){
        case 0:return true;
        case 1:lua_shutdown();break;
        case 2:params.L=luaL_newstate();if(!zapret_lua_vm_created(&state,params.L!=NULL))return false;break;
        case 3:native_lua_version();break;
        case 4:
#if LUA_VERSION_NUM >= 504
            lua_setwarnf(params.L,lua_warn,NULL);
#endif
            lua_atpanic(params.L,lua_panic);break;
        case 5:luaL_openlibs(params.L);break;
        case 6:value.ok=!!rust_ring_register(params.L);break;
        case 7:lua_close(params.L);break;
        case 8:params.L=NULL;break;
        case 9:return false;
        case 10:lua_getfield(params.L,LUA_REGISTRYINDEX,zapret_lua_vm_text(LUA_VM_LOADED));value.kind=lua_type(params.L,-1);break;
        case 11:lua_getfield(params.L,-1,zapret_lua_vm_text(LUA_VM_JIT));value.kind=lua_type(params.L,-1);break;
        case 12:lua_getfield(params.L,-1,zapret_lua_vm_text(LUA_VM_JIT_STATUS));value.kind=lua_type(params.L,-1);value.top=lua_gettop(params.L);break;
        case 13:lua_call(params.L,0,LUA_MULTRET);break;
        case 14:DLOG_CONDUP(zapret_lua_vm_jit_status(lua_toboolean(params.L,state.index)!=0));break;
        case 15:text=lua_tostring(params.L,state.index);value.ok=text!=NULL;break;
        case 16:DLOG_CONDUP(zapret_lua_vm_text(LUA_VM_JIT_ARGUMENT),text);break;
        case 17:DLOG_CONDUP(zapret_lua_vm_text(LUA_VM_JIT_END));break;
        case 18:lua_settop(params.L,0);break;
        case 20:DLOG_ERR(zapret_lua_vm_text(LUA_VM_INIT_ERROR));break;
        default:DLOG_ERR("invalid Lua VM initialization plan\n");return false;
    }
}
static uint64_t gc_time=0;
void lua_do_gc(void)
{
    zapret_lua_gc state={0};uint64_t now=0;int before=0,after=0;
    for(;;)switch(zapret_lua_gc_step(&state,params.lua_gc,now,gc_time)){
        case 0:return;
        case 1:now=boottime_ms();break;
        case 2:before=lua_gc(params.L,LUA_GCCOUNT,0);break;
        case 3:lua_gc(params.L,LUA_GCCOLLECT,0);break;
        case 4:after=lua_gc(params.L,LUA_GCCOUNT,0);break;
        case 5:DLOG(zapret_lua_vm_text(LUA_VM_GC),before,after);break;
        case 6:gc_time=state.now;break;
        default:DLOG_ERR("invalid Lua GC plan\n");return;
    }
}
