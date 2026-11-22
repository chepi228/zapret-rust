/* MIT. C queries/coerces Lua values only after the Rust schema step returns. */
typedef struct{void *target;uint32_t index,kind;}zapret_lua_header_cursor;
typedef struct{const char *name;uint32_t conversion;}zapret_lua_header_field;
typedef struct{const uint8_t *data;size_t length;int64_t number;int32_t tag;}zapret_lua_header_value;
typedef struct{const char *options_field;size_t minimum;int32_t table_tag,options_tag;}zapret_lua_header_write_api;
zapret_lua_header_write_api zapret_lua_header_write_entry(uint32_t);
bool zapret_lua_header_begin(uint32_t,void *,size_t,zapret_lua_header_cursor *);
uint32_t zapret_lua_header_next(const zapret_lua_header_cursor *,zapret_lua_header_field *);
uint32_t zapret_lua_header_observe(zapret_lua_header_cursor *,const zapret_lua_header_value *);
const char *zapret_lua_header_field_error_format(uint32_t);
_Static_assert(sizeof(zapret_lua_header_cursor)==16 && sizeof(zapret_lua_header_field)==16 && sizeof(zapret_lua_header_value)==32 &&
    offsetof(zapret_lua_header_value,number)==16 && offsetof(zapret_lua_header_value,tag)==24 &&
    sizeof(zapret_lua_header_write_api)==24 && offsetof(zapret_lua_header_write_api,minimum)==8 &&
    LUA_TNIL==0 && LUA_TNUMBER==3 && LUA_TSTRING==4 && LUA_TTABLE==5 && sizeof(lua_Integer)==8,"Rust Lua header field ABI");
static bool native_lua_header_fields(lua_State *L,int index,uint32_t kind,void *fields,size_t size)
{
    zapret_lua_header_cursor cursor;zapret_lua_header_field field;uint32_t status;
    if(!zapret_lua_header_begin(kind,fields,size,&cursor)){luaL_error(L,"invalid Lua header descriptor");return false;}
    while((status=zapret_lua_header_next(&cursor,&field))==1){
        lua_getfield(L,index,field.name);zapret_lua_header_value value={.tag=lua_type(L,-1)};
        switch(field.conversion){
            case 1:value.number=lua_tointeger(L,-1);break;
            case 2:case 3:if(value.tag==LUA_TNUMBER)value.number=lua_tolint(L,-1);break;
            case 4:if(value.tag==LUA_TSTRING)value.data=(const uint8_t *)lua_tolstring(L,-1,&value.length);break;
            case 5:if(value.tag==LUA_TNUMBER)value.number=luaL_checkinteger(L,-1);break;
            default:luaL_error(L,"invalid Lua header conversion");return false;
        }
        uint32_t error=zapret_lua_header_observe(&cursor,&value);
        if(error==2 || error==3){luaL_error(L,zapret_lua_header_field_error_format(error));return false;}
        lua_pop(L,1);if(error)return false;
    }
    if(status!=0){luaL_error(L,"invalid Lua header cursor");return false;}
    return true;
}
