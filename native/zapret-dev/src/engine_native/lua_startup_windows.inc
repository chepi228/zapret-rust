/* MIT. All VM calls occur after the resource-free Rust startup step returns. */
#include "blob_windows.h"
#include "runtime_log_windows.h"
typedef struct {const char *text;bool file;char preview[128];}zapret_lua_script;
typedef struct {const struct str_list *current;bool yielded;}zapret_lua_scripts;
typedef struct {const struct desync_profile_list *profile;const struct func_list *rule;bool yielded,started;}zapret_lua_functions;
typedef struct {const char *global,*field,*nested;}zapret_lua_harden_path;
typedef struct {struct blob_item *expected;const char *name;const uint8_t *data;size_t length;}zapret_lua_blob_view;
enum {
    LUA_STARTUP_INIT, LUA_STARTUP_DONE, LUA_STARTUP_REMOVE, LUA_STARTUP_REMOVE_END,
    LUA_STARTUP_BAD_GLOBAL, LUA_STARTUP_BAD_FIELD, LUA_STARTUP_BLOB_CHANGED,
};
const char *zapret_lua_startup_text(uint32_t);
bool zapret_lua_script_view(const char *,bool,zapret_lua_script *);
uint32_t zapret_lua_script_next(zapret_lua_scripts *,bool,bool,zapret_lua_script *);
bool zapret_lua_test_init_scripts(const struct str_list *,bool (*)(const char *,bool *,char *),zapret_log_sink);
void zapret_lua_script_report(const zapret_lua_script *,zapret_log_sink);
void zapret_lua_harden_report(const zapret_lua_harden_path *,zapret_log_sink);
void zapret_lua_startup_blob_report(const zapret_lua_blob_view *,zapret_log_sink);
void zapret_lua_report_missing_function(const char *,zapret_log_sink);
uint32_t zapret_lua_function_next(zapret_lua_functions *,const char **);
uint32_t zapret_lua_harden_next(uint32_t *,zapret_lua_harden_path *);
uint32_t zapret_lua_startup_blob(const struct blob_collection_head *,zapret_lua_blob_view *);
bool zapret_lua_startup_blob_commit(struct blob_collection_head *,struct blob_item *,const zapret_blob_allocator *);
uint32_t zapret_lua_startup_step(uint32_t *,bool);
_Static_assert(sizeof(zapret_lua_script)==144 && offsetof(zapret_lua_script,preview)==9 &&
    sizeof(zapret_lua_scripts)==16 && sizeof(zapret_lua_functions)==24 && sizeof(zapret_lua_harden_path)==24 &&
    sizeof(zapret_lua_blob_view)==32 && sizeof(struct str_list)==24 && offsetof(struct str_list,next.le_next)==8 &&
    offsetof(struct desync_profile_list,dp)==0 && offsetof(struct desync_profile_list,next.le_next)==184 &&
    offsetof(struct desync_profile,lua_desync)==160 && offsetof(struct func_list,next.le_next)==64,
    "Rust Lua startup cursor ABI");
static bool lua_desync_functions_exist(void)
{
    zapret_lua_functions cursor={.profile=LIST_FIRST(&params.desync_profiles)};
    const char *name;uint32_t status;
    while((status=zapret_lua_function_next(&cursor,&name))==1){
        lua_getglobal(params.L,name);
        if(!lua_isfunction(params.L,-1)){lua_pop(params.L,1);zapret_lua_report_missing_function(name,DLOG_ERR);return false;}
        lua_pop(params.L,1);
    }
    return status==0;
}
bool lua_test_init_script_files(void)
{
    return zapret_lua_test_init_scripts(LIST_FIRST(&params.lua_init_scripts),lua_file_open_test,DLOG_ERR);
}
static bool lua_init_scripts(void)
{
    zapret_lua_scripts cursor={.current=LIST_FIRST(&params.lua_init_scripts)};
    zapret_lua_script script;uint32_t status;
    while((status=zapret_lua_script_next(&cursor,bQuit,params.debug,&script))==1){
        if(params.debug)zapret_lua_script_report(&script,DLOG);
        int result=script.file?luaL_doZfile(params.L,script.text):luaL_dostring(params.L,script.text);
        if(result){lua_perror(params.L);return false;}
    }
    return status==0;
}
static void lua_sec_harden(void)
{
    LUA_STACK_GUARD_ENTER(params.L)
    DLOG(zapret_lua_startup_text(LUA_STARTUP_REMOVE));
    uint32_t index=0,status;zapret_lua_harden_path path;
    while((status=zapret_lua_harden_next(&index,&path))==1){
        if(path.field){
            lua_getglobal(params.L,path.global);
            if(!lua_istable(params.L,-1)){luaL_error(params.L,zapret_lua_startup_text(LUA_STARTUP_BAD_GLOBAL),path.global);return;}
            if(path.nested){
                lua_getfield(params.L,-1,path.field);
                if(!lua_istable(params.L,-1)){luaL_error(params.L,zapret_lua_startup_text(LUA_STARTUP_BAD_FIELD),path.global,path.field);return;}
                lua_pushstring(params.L,path.nested);
            }
            else lua_pushstring(params.L,path.field);
            zapret_lua_harden_report(&path,DLOG);
            lua_pushnil(params.L);lua_rawset(params.L,-3);lua_pop(params.L,1+!!path.nested);
        }else{lua_pushnil(params.L);lua_setglobal(params.L,path.global);zapret_lua_harden_report(&path,DLOG);}
    }
    if(status==2){luaL_error(params.L,"invalid Lua sandbox state");return;}
    DLOG(zapret_lua_startup_text(LUA_STARTUP_REMOVE_END));
    LUA_STACK_GUARD_LEAVE(params.L,0)
}
static void lua_init_blobs(void)
{
    LUA_STACK_GUARD_ENTER(params.L)
    zapret_lua_blob_view blob;uint32_t status;
    while((status=zapret_lua_startup_blob(&params.blobs,&blob))==1){
        zapret_lua_startup_blob_report(&blob,DLOG);
        lua_pushlstring(params.L,(const char *)blob.data,blob.length);lua_setglobal(params.L,blob.name);
        if(!zapret_lua_startup_blob_commit(&params.blobs,blob.expected,&native_blob_allocator)){
            luaL_error(params.L,zapret_lua_startup_text(LUA_STARTUP_BLOB_CHANGED));return;
        }
    }
    if(status==2){luaL_error(params.L,"invalid startup blob state");return;}
    LUA_STACK_GUARD_LEAVE(params.L,0)
}
