/* MIT. Only VM access/coercion and protected error unwinding remain in C. */
typedef struct {
    uint8_t *output;const void *fields;size_t capacity,used,next_offset;
    int64_t item;uint32_t phase,mode;uint8_t kind,next,protocol,preserve;
} zapret_lua_header_list_state;
typedef struct {int64_t item;uint32_t operation,pop;const char *name;size_t length;} zapret_lua_header_list_action;
typedef struct {const uint8_t *data;size_t length;int64_t number;int32_t tag;} zapret_lua_header_list_value;
bool zapret_lua_header_list_begin(uint32_t,uint8_t *,size_t,const void *,uint8_t,uint8_t,zapret_lua_header_list_state *,zapret_lua_header_list_action *);
bool zapret_lua_header_list_step(zapret_lua_header_list_state *,const zapret_lua_header_list_value *,zapret_lua_header_list_action *);
_Static_assert(sizeof(zapret_lua_header_list_state) == (sizeof(void *) == 8 ? 64 : 48) &&
    offsetof(zapret_lua_header_list_state, item) == (sizeof(void *) == 8 ? 40 : 24) &&
    offsetof(zapret_lua_header_list_state, phase) == offsetof(zapret_lua_header_list_state, item) + 8 &&
    sizeof(zapret_lua_header_list_action) == 16 + 2 * sizeof(void *) &&
    offsetof(zapret_lua_header_list_action, name) == 16 &&
    sizeof(zapret_lua_header_list_value) == 16 + 2 * sizeof(void *) &&
    LUA_TNIL == 0 && LUA_TNUMBER == 3 && LUA_TSTRING == 4 && LUA_TTABLE == 5 &&
    sizeof(lua_Integer) == sizeof(ptrdiff_t), "Rust Lua header list ABI");
static bool native_lua_header_list(lua_State *L,int index,uint32_t mode,void *output,size_t *length,
    const void *fields,uint8_t protocol,bool preserve)
{
    const int top=lua_gettop(L);zapret_lua_header_list_state state;zapret_lua_header_list_action action;
    if(!zapret_lua_header_list_begin(mode,output,*length,fields,protocol,preserve,&state,&action))return luaL_error(L,"invalid Lua header list storage"),false;
    for(;;){
        if(action.pop)lua_pop(L,action.pop);
        if(action.operation==0){*length=action.length;return true;}
        if(action.operation==6){lua_settop(L,top);return false;}
        zapret_lua_header_list_value value={0};
        switch(action.operation){
        case 1:lua_getfield(L,index,action.name);value.tag=lua_type(L,-1);break;
        case 2:lua_rawgeti(L,-1,action.item);value.tag=lua_type(L,-1);break;
        case 3:lua_getfield(L,-1,action.name);value.tag=lua_type(L,-1);value.number=lua_tointeger(L,-1);lua_pop(L,1);break;
        case 4:lua_getfield(L,-1,action.name);value.tag=lua_type(L,-1);if(value.tag==LUA_TNUMBER)value.number=lua_tointeger(L,-1);lua_pop(L,1);break;
        case 5:lua_getfield(L,-1,action.name);value.tag=lua_type(L,-1);if(value.tag==LUA_TSTRING)value.data=(const uint8_t *)lua_tolstring(L,-1,&value.length);break;
        default:return luaL_error(L,"invalid Lua header list action"),false;
        }
        if(!zapret_lua_header_list_step(&state,&value,&action))return luaL_error(L,"invalid Lua header list state"),false;
    }
}
