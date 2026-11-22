/* MIT. Native codec callbacks cannot call Lua or unwind across Rust. */
typedef struct {int32_t values[3];uint32_t index,role,argc;}zapret_lua_codec_options;
typedef struct {voidpf (*allocate)(voidpf,uInt,uInt);void (*release)(voidpf,voidpf);}zapret_lua_codec_allocators;
typedef struct {int (*inflate)(z_stream *,int);int (*deflate)(z_stream *,int,int,int,int,int);int (*end_inflate)(z_stream *);int (*end_deflate)(z_stream *);}zapret_lua_codec_ops;
bool zapret_lua_codec_options_begin(uint32_t,uint32_t,zapret_lua_codec_options *);
uint32_t zapret_lua_codec_options_next(const zapret_lua_codec_options *,int32_t *);
bool zapret_lua_codec_options_observe(zapret_lua_codec_options *,uint32_t,int64_t);
uint32_t zapret_lua_codec_validate(const struct userdata_zs *,uint32_t);
int zapret_lua_codec_initialize(struct userdata_zs *,const zapret_lua_codec_options *,const zapret_lua_codec_allocators *,const zapret_lua_codec_ops *);
int zapret_lua_codec_finish(struct userdata_zs *,uint32_t,const zapret_lua_codec_ops *);
#ifndef ZAPRET_LUA_CODEC_OPS
#define ZAPRET_LUA_CODEC_OPS NULL
#endif
static void *z_alloc(voidpf,uInt,uInt);
static void z_free(voidpf,voidpf);
_Static_assert(sizeof(struct userdata_zs) == sizeof(z_stream) + sizeof(void *) &&
    offsetof(struct userdata_zs, zs) == sizeof(void *) && sizeof(zapret_lua_codec_options) == 24 &&
    sizeof(zapret_lua_codec_allocators) == 2 * sizeof(void *) &&
    sizeof(zapret_lua_codec_ops) == 4 * sizeof(void *), "Rust Lua codec lifecycle ABI");
static int lua_cfunc_zstream_gc(lua_State *L)
{zapret_lua_codec_finish(luaL_checkudata(L,1,"userdata_zstream"),2,ZAPRET_LUA_CODEC_OPS);return 0;}
static struct userdata_zs *lua_uzs(lua_State *L,int index,bool inflating)
{
    struct userdata_zs *stream=luaL_checkudata(L,index,"userdata_zstream");
    uint32_t status=zapret_lua_codec_validate(stream,inflating);
    if(status)luaL_error(L,status==1?"gzip stream is not valid":status==2?"gzip stream role mismatch":"invalid codec metadata");
    return stream;
}
static int native_lua_codec_init(lua_State *L,bool inflating)
{
    lua_check_argc_range(L,inflating?"gunzip_init":"gzip_init",0,inflating?1:3);LUA_STACK_GUARD_ENTER(L)
    zapret_lua_codec_options options;int32_t index;uint32_t status;
    if(!zapret_lua_codec_options_begin(inflating,(uint32_t)lua_gettop(L),&options))return luaL_error(L,"invalid codec options");
    while((status=zapret_lua_codec_options_next(&options,&index))==1){bool absent=lua_isnil(L,index);lua_Integer number=absent?0:luaL_checkinteger(L,index);if(!zapret_lua_codec_options_observe(&options,absent,(int64_t)number))return luaL_error(L,"invalid codec option");}
    if(status)return luaL_error(L,"invalid codec options");
    struct userdata_zs *stream=lua_newuserdata(L,sizeof(*stream));
    const zapret_lua_codec_allocators callbacks={z_alloc,z_free};
    if(zapret_lua_codec_initialize(stream,&options,&callbacks,ZAPRET_LUA_CODEC_OPS)==Z_OK){
        if(inflating)luaL_getmetatable(L,"userdata_zstream");else luaL_newmetatable(L,"userdata_zstream");lua_setmetatable(L,-2);
    }else{lua_pop(L,1);lua_pushnil(L);}
    LUA_STACK_GUARD_RETURN(L,1)
}
static int native_lua_codec_end(lua_State *L,bool inflating)
{
    lua_check_argc(L,inflating?"gunzip_end":"gzip_end",1);LUA_STACK_GUARD_ENTER(L)
    struct userdata_zs *stream=lua_uzs(L,1,inflating);zapret_lua_codec_finish(stream,inflating,ZAPRET_LUA_CODEC_OPS);
    LUA_STACK_GUARD_RETURN(L,0)
}
static int luacall_gunzip_init(lua_State *L){return native_lua_codec_init(L,true);}
static int luacall_gzip_init(lua_State *L){return native_lua_codec_init(L,false);}
static int luacall_gunzip_end(lua_State *L){return native_lua_codec_end(L,true);}
static int luacall_gzip_end(lua_State *L){return native_lua_codec_end(L,false);}
