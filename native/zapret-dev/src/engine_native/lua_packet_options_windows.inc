/* MIT. The VM owns values; Rust publishes each option before the next VM call. */
typedef struct{bool *keepsum,*badsum,*preserve;uint8_t *protocol;int *repeats;uint32_t *mark;const char **ifout;const uint32_t *default_mark;}zapret_lua_option_targets;
typedef struct{zapret_lua_option_targets targets;uint32_t index,mode;}zapret_lua_option_cursor;
typedef struct{const char *name;uint32_t kind;}zapret_lua_option_field;
typedef struct{const char *data;int64_t number;int32_t tag;uint32_t truth;}zapret_lua_option_value;
uint32_t zapret_lua_packet_options_begin(uint32_t,uint32_t,const zapret_lua_option_targets *,zapret_lua_option_cursor *,zapret_lua_option_field *);
uint32_t zapret_lua_packet_options_observe(zapret_lua_option_cursor *,const zapret_lua_option_value *,zapret_lua_option_field *);
const char *zapret_lua_packet_option_error_format(uint32_t);
_Static_assert(sizeof(zapret_lua_option_targets) == 8 * sizeof(void *) &&
    sizeof(zapret_lua_option_cursor) == 8 * sizeof(void *) + 8 &&
    sizeof(zapret_lua_option_field) == 2 * sizeof(void *) && sizeof(zapret_lua_option_value) == 24 &&
    sizeof(int) == 4 && sizeof(bool) == 1 && sizeof(lua_Integer) == sizeof(ptrdiff_t) &&
    LUA_TNIL == 0 && LUA_TBOOLEAN == 1 && LUA_TSTRING == 4, "Rust packet option ABI");
static void native_lua_packet_options(lua_State *L,int idx,uint32_t mode,const zapret_lua_option_targets *targets)
{
    bool absent=lua_isnoneornil(L,idx);if(!absent)luaL_checktype(L,idx,LUA_TTABLE);
    zapret_lua_option_cursor cursor;zapret_lua_option_field field;
    uint32_t status=zapret_lua_packet_options_begin(mode,absent,targets,&cursor,&field);
    while(status==1){
        lua_getfield(L,idx,field.name);zapret_lua_option_value value={.tag=lua_type(L,-1)};
        switch(field.kind){
        case 1:if(value.tag==LUA_TBOOLEAN)value.truth=lua_toboolean(L,-1);break;
        case 2:if(value.tag!=LUA_TNIL)value.number=lua_tointeger(L,-1);break;
        case 3:value.number=lua_tointeger(L,-1);break;
        case 4:value.number=lua_tolint(L,-1);break;
        case 5:if(value.tag==LUA_TSTRING)value.data=lua_tostring(L,-1);break;
        default:luaL_error(L,"invalid packet option field");return;
        }
        status=zapret_lua_packet_options_observe(&cursor,&value,&field);
        if(status==2 || status==3){luaL_error(L,zapret_lua_packet_option_error_format(status));return;}
        lua_pop(L,1);
    }
    if(status)luaL_error(L,"invalid packet option storage");
}
static void lua_reconstruct_extract_options(lua_State *L,int idx,bool *keepsum,bool *badsum,bool *preserve,uint8_t *protocol)
{
    zapret_lua_option_targets targets={.keepsum=keepsum,.badsum=badsum,.preserve=preserve,.protocol=protocol};
    native_lua_packet_options(L,idx,0,&targets);
}
static void lua_rawsend_extract_options(lua_State *L,int idx,int *repeats,uint32_t *mark,const char **ifout)
{
    zapret_lua_option_targets targets={.repeats=repeats,.mark=mark,.ifout=ifout,.default_mark=&params.desync_fwmark};
    native_lua_packet_options(L,idx,1,&targets);
}
