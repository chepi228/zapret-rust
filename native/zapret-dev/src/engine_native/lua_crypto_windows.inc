/* MIT. Borrowed argument state; every VM operation occurs after Rust returns. */
typedef struct {const uint8_t *data;size_t length;}zapret_lua_crypto_span;
typedef struct {zapret_lua_crypto_span key,iv,input,associated;uint8_t *output;uint32_t mode,phase,encrypt,success;uint8_t tag[16],block[16];}zapret_lua_crypto_state;
typedef struct {const char *name;const uint8_t *data;size_t length;int32_t index;uint32_t kind;int32_t minimum,maximum;uint32_t error,count;}zapret_lua_crypto_action;
typedef struct {zapret_lua_crypto_span span;uint32_t truth;}zapret_lua_crypto_value;
typedef struct {bool (*block)(bool,const uint8_t *,size_t,const uint8_t *,uint8_t *);bool (*ctr)(const uint8_t *,size_t,const uint8_t *,const uint8_t *,size_t,uint8_t *);bool (*gcm)(bool,const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *,size_t,uint8_t *,uint8_t *);}zapret_lua_crypto_ops;
bool zapret_lua_crypto_begin(uint32_t,zapret_lua_crypto_state *,zapret_lua_crypto_action *);
bool zapret_lua_crypto_step(zapret_lua_crypto_state *,const zapret_lua_crypto_value *,zapret_lua_crypto_action *,const zapret_lua_crypto_ops *);
#ifndef ZAPRET_LUA_CRYPTO_OPS
#define ZAPRET_LUA_CRYPTO_OPS NULL
#endif
_Static_assert(sizeof(zapret_lua_crypto_state) == 9 * sizeof(void *) + 48 &&
    offsetof(zapret_lua_crypto_state, block) == 9 * sizeof(void *) + 32 &&
    sizeof(zapret_lua_crypto_action) == 3 * sizeof(void *) + 24 &&
    sizeof(zapret_lua_crypto_value) == 3 * sizeof(void *) &&
    sizeof(zapret_lua_crypto_ops) == 3 * sizeof(void *), "Rust Lua crypto entry ABI");
static int native_lua_crypto(lua_State *L,uint32_t mode)
{
    LUA_STACK_GUARD_ENTER(L)
    zapret_lua_crypto_state state;zapret_lua_crypto_action action;zapret_lua_crypto_value value={0};
    if(!zapret_lua_crypto_begin(mode,&state,&action))return luaL_error(L,"invalid Lua crypto entry");
    for(;;){
        switch(action.kind){
        case 0:LUA_STACK_GUARD_RETURN(L,(int)action.count)
        case 1:if(action.minimum==action.maximum)lua_check_argc(L,action.name,action.minimum);else lua_check_argc_range(L,action.name,action.minimum,action.maximum);break;
        case 2:value.truth=!!lua_toboolean(L,action.index);break;
        case 3:value.span.data=(const uint8_t *)lua_reqlstring(L,action.index,&value.span.length);break;
        case 4:value.span.data=(const uint8_t *)luaL_checklstring(L,action.index,&value.span.length);break;
        case 5:if(lua_isnoneornil(L,action.index)){value.span.data=NULL;value.span.length=0;}else value.span.data=(const uint8_t *)lua_reqlstring(L,action.index,&value.span.length);break;
        case 6:value.span.length=action.length;value.span.data=lua_newuserdata(L,action.length);break;
        case 7:lua_pushlstring(L,(const char *)action.data,action.length);break;
        case 8:lua_pushnil(L);break;
        case 9:lua_remove(L,action.index);break;
        case 10:switch(action.error){
            case 1:return luaL_error(L,(const char *)action.data,action.name,(unsigned)action.length);
            case 2:case 4:return luaL_error(L,(const char *)action.data,(unsigned)action.length);
            case 3:return luaL_error(L,(const char *)action.data);
            }
        default:return luaL_error(L,"invalid Lua crypto action");
        }
        if(!zapret_lua_crypto_step(&state,&value,&action,ZAPRET_LUA_CRYPTO_OPS))return luaL_error(L,"invalid Lua crypto state");
    }
}
static int luacall_aes(lua_State *L){return native_lua_crypto(L,0);}
static int luacall_aes_ctr(lua_State *L){return native_lua_crypto(L,1);}
static int luacall_aes_gcm(lua_State *L){return native_lua_crypto(L,2);}
