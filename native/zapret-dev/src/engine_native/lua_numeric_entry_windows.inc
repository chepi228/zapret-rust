/* MIT. Rust selects entry policy; only C enters Lua or raises VM errors. */
typedef struct {const uint8_t *data;size_t length;}zapret_lua_numeric_span;
typedef struct {zapret_lua_numeric_span input;int64_t offset;uint8_t bytes[6];uint32_t mode,count,phase;}zapret_lua_numeric_state;
typedef struct {const uint8_t *data;const char *name;int64_t integer;size_t length;uint32_t kind,count;int32_t minimum,maximum;}zapret_lua_numeric_action;
typedef struct {zapret_lua_numeric_span span;const int64_t *numbers;int64_t integer;int32_t count,kind;}zapret_lua_numeric_value;
bool zapret_lua_numeric_entry_begin(uint32_t,int32_t,zapret_lua_numeric_state *,zapret_lua_numeric_action *);
bool zapret_lua_numeric_entry_step(zapret_lua_numeric_state *,const zapret_lua_numeric_value *,zapret_lua_numeric_action *);
_Static_assert(sizeof(zapret_lua_numeric_state) == 2 * sizeof(void *) + 32 &&
    offsetof(zapret_lua_numeric_state, mode) == 2 * sizeof(void *) + 16 &&
    sizeof(zapret_lua_numeric_action) == 2 * sizeof(void *) + 32 &&
    sizeof(zapret_lua_numeric_value) == 2 * sizeof(void *) + 24, "Rust Lua numeric entry ABI");
static int native_lua_numeric_entry(lua_State *L,uint32_t mode)
{
    zapret_lua_numeric_state state;zapret_lua_numeric_action action;zapret_lua_numeric_value value={0};int64_t numbers[100];
    if(!zapret_lua_numeric_entry_begin(mode,lua_gettop(L),&state,&action))return luaL_error(L,"invalid Lua numeric entry");
    for(;;){
        switch(action.kind){
        case 0:return (int)action.count;
        case 1:return luaL_error(L,(const char *)action.data,action.name,action.minimum,(int)action.count);
        case 2:return luaL_error(L,(const char *)action.data,action.name,action.minimum,action.maximum,(int)action.count);
        case 3:value.count=lua_gettop(L);break;
        case 4:value.span.data=(const uint8_t *)lua_reqlstring(L,1,&value.span.length);break;
        case 5:value.integer=(int64_t)luaL_checklint(L,1);break;
        case 6:for(uint32_t index=0;index<action.count;++index)numbers[index]=(int64_t)luaL_checklint(L,(int)index+1);value.numbers=numbers;value.count=(int32_t)action.count;break;
        case 7:value.kind=lua_type(L,2);break;
        case 8:value.integer=(int64_t)luaL_checkinteger(L,2);break;
        case 9:lua_pushlint(L,action.integer);break;
        case 10:lua_pushlstring(L,(const char *)action.data,action.length);break;
        case 11:lua_pushnil(L);break;
        case 12:return luaL_error(L,(const char *)action.data);
        default:return luaL_error(L,"invalid Lua numeric action");
        }
        if(!zapret_lua_numeric_entry_step(&state,&value,&action))return luaL_error(L,"invalid Lua numeric state");
    }
}
#define NATIVE_NUMERIC_ENTRY(name,mode) static int luacall_##name(lua_State *L){return native_lua_numeric_entry(L,mode);}
NATIVE_NUMERIC_ENTRY(bitlshift,0)
NATIVE_NUMERIC_ENTRY(bitrshift,1)
NATIVE_NUMERIC_ENTRY(bitand,2)
NATIVE_NUMERIC_ENTRY(bitor,3)
NATIVE_NUMERIC_ENTRY(bitxor,4)
NATIVE_NUMERIC_ENTRY(bitnot8,5)
NATIVE_NUMERIC_ENTRY(bitnot16,6)
NATIVE_NUMERIC_ENTRY(bitnot24,7)
NATIVE_NUMERIC_ENTRY(bitnot32,8)
NATIVE_NUMERIC_ENTRY(bitnot48,9)
NATIVE_NUMERIC_ENTRY(bitget,10)
NATIVE_NUMERIC_ENTRY(bitset,11)
NATIVE_NUMERIC_ENTRY(swap16,12)
NATIVE_NUMERIC_ENTRY(swap24,13)
NATIVE_NUMERIC_ENTRY(swap32,14)
NATIVE_NUMERIC_ENTRY(swap48,15)
NATIVE_NUMERIC_ENTRY(u8add,16)
NATIVE_NUMERIC_ENTRY(u16add,17)
NATIVE_NUMERIC_ENTRY(u24add,18)
NATIVE_NUMERIC_ENTRY(u32add,19)
NATIVE_NUMERIC_ENTRY(u48add,20)
NATIVE_NUMERIC_ENTRY(divint,21)
NATIVE_NUMERIC_ENTRY(u8,22)
NATIVE_NUMERIC_ENTRY(u16,23)
NATIVE_NUMERIC_ENTRY(u24,24)
NATIVE_NUMERIC_ENTRY(u32,25)
NATIVE_NUMERIC_ENTRY(u48,26)
NATIVE_NUMERIC_ENTRY(bu8,27)
NATIVE_NUMERIC_ENTRY(bu16,28)
NATIVE_NUMERIC_ENTRY(bu24,29)
NATIVE_NUMERIC_ENTRY(bu32,30)
NATIVE_NUMERIC_ENTRY(bu48,31)
#undef NATIVE_NUMERIC_ENTRY
