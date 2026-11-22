/* MIT. Lua and native CRT calls run in C after every resource-free Rust step. */
typedef struct {
    const char *name,*data; int64_t integer; double number; uint32_t kind; uint8_t text[128];
} zapret_lua_system_value;
typedef struct {struct tm time;uint32_t index;} zapret_lua_time_cursor;
bool zapret_lua_system_field(uint32_t,uint32_t,const void *,zapret_lua_system_value *);
uint32_t zapret_lua_time_begin(int32_t,zapret_lua_time_cursor *);
uint32_t zapret_lua_time_next(const zapret_lua_time_cursor *,const char **);
uint32_t zapret_lua_time_observe(zapret_lua_time_cursor *,int32_t,int64_t);
const char *zapret_lua_time_error_format(uint32_t,bool);
_Static_assert(sizeof(zapret_lua_system_value) == 2 * sizeof(void *) + 152 &&
    offsetof(zapret_lua_system_value, text) == 2 * sizeof(void *) + 20 &&
    sizeof(struct tm)==36 && offsetof(struct tm,tm_year)==20 && offsetof(struct tm,tm_isdst)==32 &&
    sizeof(zapret_lua_time_cursor)==40 && sizeof(struct timespec)==16 && offsetof(struct timespec,tv_nsec)==8 &&
    sizeof(wf_file_info)==48 && offsetof(wf_file_info,modified)==32 &&
    sizeof(struct utsname)==516 && offsetof(struct utsname,nodename)==65 && offsetof(struct utsname,machine)==451,
    "Rust Lua system/time snapshot ABI");
static int native_lua_system_project(lua_State *L,uint32_t mode,const void *source)
{
    zapret_lua_system_value field;
    for(uint32_t index=0;;++index){
        if(!zapret_lua_system_field(mode,index,source,&field))return luaL_error(L,"invalid system view metadata");
        switch(field.kind){
        case 0:return (int)field.integer;
        case 1:lua_createtable(L,0,(int)field.integer);break;
        case 2:lua_pushf_lint(L,field.name,field.integer);break;
        case 3:lua_pushf_number(L,field.name,field.number);break;
        case 4:lua_pushf_str(L,field.name,field.data);break;
        case 5:lua_pushf_str(L,field.name,(const char *)field.text);break;
        case 6:lua_pushlint(L,field.integer);break;
        case 7:lua_pushnumber(L,field.number);break;
        case 8:lua_pushnil(L);break;
        default:return luaL_error(L,"invalid system view field");
        }
    }
}
#ifndef ZAPRET_LUA_SCALAR_OUTER_RUST
static int luacall_uname(lua_State *L)
{
    lua_check_argc(L,"uname",0);LUA_STACK_GUARD_ENTER(L)
    struct utsname data;int count=native_lua_system_project(L,1,uname(&data)?NULL:&data);
    LUA_STACK_GUARD_RETURN(L,count)
}
static int native_lua_clock(lua_State *L,uint32_t mode,const char *name)
{
    lua_check_argc(L,name,0);LUA_STACK_GUARD_ENTER(L)
    struct timespec time;int count=native_lua_system_project(L,mode,clock_gettime(CLOCK_REALTIME,&time)?NULL:&time);
    LUA_STACK_GUARD_RETURN(L,count)
}
static int luacall_clock_gettime(lua_State *L){return native_lua_clock(L,4,"clock_gettime");}
static int luacall_clock_getfloattime(lua_State *L){return native_lua_clock(L,5,"clock_getfloattime");}
static int luacall_stat(lua_State *L)
{
    lua_check_argc(L,"stat",1);wf_file_info info;
    if(wf_file_stat(luaL_checkstring(L,1),&info)){
        lua_pushnil(L);const char *error=strerror(errno);
        if(error){lua_pushstring(L,error);lua_pushinteger(L,errno);return 3;}
        return 1;
    }
    return native_lua_system_project(L,0,&info);
}
static void lua_xtime(lua_State *L,struct tm *(*convert)(const time_t *,struct tm *))
{
    struct tm time;time_t seconds=(time_t)luaL_checklint(L,1);
    native_lua_system_project(L,convert==gmtime_r?3:2,convert(&seconds,&time)?&time:NULL);
}
static int luacall_localtime(lua_State *L){lua_check_argc(L,"localtime",1);lua_xtime(L,localtime_r);return 1;}
static int luacall_gmtime(lua_State *L){lua_check_argc(L,"gmtime",1);lua_xtime(L,gmtime_r);return 1;}
#endif
static void lua_timex(lua_State *L,time_t (*convert)(struct tm *))
{
    zapret_lua_time_cursor cursor;uint32_t status=zapret_lua_time_begin(lua_type(L,1),&cursor);
    if(status)return (void)luaL_error(L,zapret_lua_time_error_format(status,false));
    const char *name;
    while((status=zapret_lua_time_next(&cursor,&name))==1){
        lua_getfield(L,1,name);int tag=lua_type(L,-1);
        status=zapret_lua_time_observe(&cursor,tag,tag==LUA_TNUMBER?(int64_t)lua_tointeger(L,-1):0);
        if(status)return (void)luaL_error(L,zapret_lua_time_error_format(status,true),name);
        lua_pop(L,1);
    }
    if(status)return (void)luaL_error(L,zapret_lua_time_error_format(status,false));
    time_t seconds=convert(&cursor.time);native_lua_system_project(L,6,&seconds);
}
#ifndef ZAPRET_LUA_SCALAR_OUTER_RUST
static int luacall_timelocal(lua_State *L){lua_check_argc(L,"timelocal",1);lua_timex(L,mktime);return 1;}
static int luacall_timegm(lua_State *L){lua_check_argc(L,"timegm",1);lua_timex(L,timegm);return 1;}
#endif
