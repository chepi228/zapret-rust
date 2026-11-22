/* MIT. Rust plans and applies edits between Lua-owned userdata operations. */
typedef struct{struct fake_tls_mod options;uint32_t mode;size_t length,capacity;}zapret_lua_tls_workspace;
const char *zapret_lua_tls_text(uint32_t);
bool zapret_lua_tls_payload(int32_t,bool,int32_t);
uint32_t zapret_lua_tls_prepare(const char *,size_t,zapret_lua_tls_workspace *);
bool zapret_lua_tls_apply(const zapret_lua_tls_workspace *,const uint8_t *,const uint8_t *,size_t,uint8_t *,size_t *,void (*)(const char *));
_Static_assert(sizeof(zapret_lua_tls_workspace) == 264 + 2 * sizeof(void *) &&
    offsetof(zapret_lua_tls_workspace, length) == 264 &&
    LUA_TNIL==0,"Rust Lua TLS workspace ABI");
static void native_lua_tls_report(const char *message){DLOG_ERR("%s",message);}
static int luacall_tls_mod(lua_State *L)
{
    lua_check_argc_range(L,zapret_lua_tls_text(0),2,3);
    LUA_STACK_GUARD_ENTER(L)
    int argc=lua_gettop(L);size_t length,payload_length=0;
    const uint8_t *data=(const uint8_t *)lua_reqlstring(L,1,&length);const char *modlist=lua_reqstring(L,2);
    const uint8_t *payload=NULL;
    if(zapret_lua_tls_payload(argc,false,0) && zapret_lua_tls_payload(argc,true,lua_type(L,3)))
        payload=(const uint8_t *)lua_reqlstring(L,3,&payload_length);
    zapret_lua_tls_workspace workspace;
    switch(zapret_lua_tls_prepare(modlist,length,&workspace)){
    case 0:lua_pushlstring(L,(const char *)data,length);break;
    case 1:{uint8_t *output=lua_newuserdata(L,workspace.capacity);size_t written;
        if(zapret_lua_tls_apply(&workspace,data,payload,payload_length,output,&written,native_lua_tls_report)){DLOG(zapret_lua_tls_text(1),workspace.options.mod);lua_pushlstring(L,(const char *)output,written);}else lua_pushnil(L);
        lua_remove(L,-2);break;}
    case 2:return luaL_error(L,zapret_lua_tls_text(2),modlist);
    default:return luaL_error(L,zapret_lua_tls_text(3));
    }
    LUA_STACK_GUARD_RETURN(L,1)
}
