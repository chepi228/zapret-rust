/* MIT. Native callbacks used by Rust cannot enter Lua or unwind. */
typedef struct {FILE *(*open)(const char *,const char *);int (*close)(FILE *);bool (*probe)(FILE *);void *(*allocate)(size_t);void (*release)(void *);int (*read)(FILE *,char **,size_t *,size_t);}zapret_lua_file_ops;
typedef struct {uint32_t phase;int32_t status;}zapret_lua_file_flow;
typedef struct {int32_t status;uint32_t found,gzip;}zapret_lua_file_feedback;
static const zapret_lua_file_ops native_lua_file_ops={fopen,fclose,is_gzip,malloc,free,z_readfile};
bool zapret_lua_file_probe(const char *,bool *,char *,size_t,const zapret_lua_file_ops *);
uint32_t zapret_lua_file_read(const char *,char **,size_t *,const zapret_lua_file_ops *);
uint32_t zapret_lua_file_step(zapret_lua_file_flow *,const zapret_lua_file_feedback *);
_Static_assert(sizeof(zapret_lua_file_ops) == 6 * sizeof(void *) &&
    offsetof(zapret_lua_file_ops, read) == 5 * sizeof(void *) &&
    sizeof(zapret_lua_file_flow) == 8 && sizeof(zapret_lua_file_feedback) == 12 &&
    LUA_ERRFILE == 6, "Rust Lua file ABI");
static bool lua_file_open_test(const char *filename,bool *gzip,char *resolved)
{return zapret_lua_file_probe(filename,gzip,resolved,resolved?PATH_MAX:0,&native_lua_file_ops);}
static int luaL_doZfile(lua_State *L,const char *filename)
{
    zapret_lua_file_flow state={0};zapret_lua_file_feedback value={0};bool gzip=false;
    char resolved[PATH_MAX],*bytes=NULL;size_t size=0;
    for(;;)switch(zapret_lua_file_step(&state,&value)){
        case 0:return state.status;
        case 1:value.found=lua_file_open_test(filename,&gzip,resolved);value.gzip=gzip;break;
        case 2:value.status=luaL_dofile(L,resolved);break;
        case 3:value.status=(int32_t)zapret_lua_file_read(resolved,&bytes,&size,&native_lua_file_ops);break;
        case 4:value.status=luaL_loadbuffer(L,bytes,size,resolved);break;
        case 5:free(bytes);bytes=NULL;break;
        case 6:value.status=lua_pcall(L,0,LUA_MULTRET,0);break;
        case 7:lua_pushfstring(L,"could not open lua file '%s' or '%s.gz'",filename,filename);return LUA_ERRFILE;
        case 8:lua_pushfstring(L,"could not open lua file '%s'",resolved);return LUA_ERRFILE;
        case 9:lua_pushfstring(L,"could not unzip lua file '%s'",resolved);return LUA_ERRFILE;
        default:return luaL_error(L,"invalid Lua file plan");
    }
}
