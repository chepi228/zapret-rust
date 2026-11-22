/* MIT. VM ownership protects Rust output when Lua string allocation longjmps. */
typedef struct {uint8_t *data;size_t length,capacity;bool finished;} zapret_zstream_output;
typedef struct {const char *name;int32_t minimum,maximum,results;} zapret_zstream_entry;
enum {
    ZSTREAM_ARITY, ZSTREAM_STREAM, ZSTREAM_INPUT, ZSTREAM_COUNT,
    ZSTREAM_INPUT_OMITTED, ZSTREAM_HINT, ZSTREAM_PROCESS, ZSTREAM_PROCESS_WITH_HINT,
    ZSTREAM_DROP_OUTPUT, ZSTREAM_NIL_RESULTS, ZSTREAM_PUBLISH, ZSTREAM_DONE,
};
zapret_zstream_entry zapret_lua_zstream_entry(bool);
const char *zapret_lua_zstream_output_label(bool);
uint32_t zapret_lua_zstream_next(uint32_t,bool,int32_t,int64_t);
int zapret_lua_zstream_process(z_stream *,bool,const uint8_t *,size_t,uint64_t,bool,void *,const void *);
void zapret_lua_zstream_release(void *);
_Static_assert(sizeof(zapret_zstream_output) == 4 * sizeof(void *) &&
    offsetof(zapret_zstream_output, finished) == 3 * sizeof(void *) &&
    sizeof(zapret_zstream_entry) == 2 * sizeof(void *) + 8 &&
    offsetof(zapret_zstream_entry, results) == sizeof(void *) + 8, "Rust zstream ABI");
static int native_zstream_output_gc(lua_State *L)
{zapret_lua_zstream_release(luaL_checkudata(L,1,zapret_lua_zstream_output_label(false)));return 0;}
static zapret_zstream_output *native_zstream_buffer(lua_State *L)
{
    zapret_zstream_output *output=lua_newuserdata(L,sizeof(*output));memset(output,0,sizeof(*output));
    if(luaL_newmetatable(L,zapret_lua_zstream_output_label(false))){
        lua_pushcfunction(L,native_zstream_output_gc);lua_setfield(L,-2,zapret_lua_zstream_output_label(true));
    }
    lua_setmetatable(L,-2);return output;
}
static int native_zstream_entry(lua_State *L,bool inflating)
{
    const zapret_zstream_entry entry=zapret_lua_zstream_entry(inflating);
    lua_check_argc_range(L,entry.name,entry.minimum,entry.maximum);
    LUA_STACK_GUARD_ENTER(L)
    struct userdata_zs *stream=NULL;zapret_zstream_output *output=NULL;
    const uint8_t *input=NULL;size_t length=0;
    int32_t argc=0;int64_t value=0;uint64_t hint=0;
    for(uint32_t action=zapret_lua_zstream_next(ZSTREAM_ARITY,inflating,argc,value);;
        action=zapret_lua_zstream_next(action,inflating,argc,value)){
        switch(action){
            case ZSTREAM_STREAM:stream=lua_uzs(L,1,inflating);break;
            case ZSTREAM_INPUT:input=(const uint8_t *)luaL_checklstring(L,2,&length);break;
            case ZSTREAM_COUNT:argc=lua_gettop(L);break;
            case ZSTREAM_INPUT_OMITTED:value=lua_isnil(L,2);break;
            case ZSTREAM_HINT:value=luaL_checkinteger(L,3);hint=(uint64_t)value;break;
            case ZSTREAM_PROCESS:
            case ZSTREAM_PROCESS_WITH_HINT:
                output=native_zstream_buffer(L);
                value=zapret_lua_zstream_process(&stream->zs,inflating,input,length,hint,
                    action==ZSTREAM_PROCESS_WITH_HINT,output,NULL);break;
            case ZSTREAM_DROP_OUTPUT:lua_pop(L,1);break;
            case ZSTREAM_NIL_RESULTS:lua_pushnil(L);lua_pushnil(L);break;
            case ZSTREAM_PUBLISH:{
                const bool finished=output->finished;
                lua_pushlstring(L,(const char *)output->data,output->length);
                zapret_lua_zstream_release(output);lua_remove(L,-2);lua_pushboolean(L,finished);break;
            }
            case ZSTREAM_DONE:LUA_STACK_GUARD_RETURN(L,entry.results)
            default:return luaL_error(L,"invalid Lua zstream action");
        }
    }
}
static int luacall_gunzip_inflate(lua_State *L){return native_zstream_entry(L,true);}
static int luacall_gzip_deflate(lua_State *L){return native_zstream_entry(L,false);}
