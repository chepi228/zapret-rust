/* MIT. Complete old/new entries through real LuaJIT; no live packet/driver I/O. */
#include "params.h"
#include "engine_lua.h"
#include <sys/utsname.h>
#include <luajit.h>
#undef main
static unsigned cases,errors,reentries,boundaries,fault_cases,vm_faults,real_cases,calendar_cases;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL system tables cases=%u boundaries=%u line=%d: %s\n",cases,boundaries,__LINE__,#v);exit(1);}}while(0)
struct atom {int type;double number;size_t length;char text[520];};
struct sample {int status,arity,errno_after;unsigned nested,native_calls;struct atom values[14];char trace[4096],message[512];};
static struct sample *active;
static unsigned native_variant;static bool real_native;
static void trace(const char *text){if(!active)return;size_t have=strlen(active->trace),size=strlen(text);CHECK(have+size+2<sizeof(active->trace));memcpy(active->trace+have,text,size);active->trace[have+size]=';';active->trace[have+size+1]=0;}
#ifdef ZAPRET_LUA_SCALAR_ORACLE
#include "lua_scalar_observation.inc"
#endif
static void traced_rawset(lua_State *L,int index){trace(lua_tostring(L,-2));lua_rawset(L,index);}
#define lua_rawset traced_rawset
#include "lua_system_tables_common.inc"
#undef lua_rawset
static const char *native_file="lua-system-\xd0\xb4\xd0\xb0\xd0\xbd\xd0\xbd\xd1\x8b\xd0\xb5-\xc3\xa9-\xe4\xb8\xad.fixture";
static int native_stat(const char *path,wf_file_info *out){trace("stat");++active->native_calls;trace(path);if(real_native)return wf_file_stat(path,out);if(native_variant%7==0){errno=EACCES;return -1;}memset(out,0,sizeof(*out));out->st_dev=native_variant%3==0?UINT64_MAX:0x100000000ULL+native_variant;out->st_ino=native_variant%3==1?0x8000000000000001ULL:42;out->st_size=native_variant%2?-123:INT64_MAX;out->st_mode=native_variant%2?_S_IFDIR:_S_IFREG;out->modified.tv_sec=native_variant%3==0?INT64_MIN:native_variant%3==1?-2:1700000000;out->modified.tv_nsec=native_variant%2?999999999:-1;return 0;}
static const char *native_strerror(int error){trace("strerror");if(native_variant%3==0)return NULL;if(native_variant%3==1)errno=ERANGE;return strerror(error);}
static int native_uname(struct utsname *out){trace("uname");++active->native_calls;if(native_variant%7==0)return -1;memset(out,0,sizeof(*out));memset(out->sysname,'S',sizeof(out->sysname)-1);memset(out->nodename,'N',native_variant%2?sizeof(out->nodename)-1:0);snprintf(out->release,sizeof(out->release),"10.%u",native_variant);strcpy(out->version,"version\r\n\xc3\xa9");strcpy(out->machine,"x86_64");return 0;}
static int native_clock(clockid_t id,struct timespec *out){CHECK(id==CLOCK_REALTIME);trace("clock");++active->native_calls;if(native_variant%7==0)return -1;out->tv_sec=native_variant%3==0?INT64_MAX:native_variant%3==1?INT64_MIN:1700000000;out->tv_nsec=native_variant%3==0?999999999:native_variant%3==1?-1:123456789;return 0;}
static struct tm *native_xtime(const time_t *seconds,struct tm *out,bool utc){trace(utc?"gmtime":"localtime");++active->native_calls;if(real_native)return (utc?gmtime_s(out,seconds):localtime_s(out,seconds))?NULL:out;if(native_variant%7==0)return NULL;memset(out,0,sizeof(*out));out->tm_sec=native_variant%2?20:-1;out->tm_min=13;out->tm_hour=22;out->tm_mday=native_variant%3==0?2:14;out->tm_mon=native_variant%3==0?0:10;out->tm_year=native_variant%4==0?-1901:native_variant%4==1?123:native_variant%4==2?INT_MAX-1900:INT_MIN;out->tm_wday=2;out->tm_yday=317;out->tm_isdst=(int)(native_variant%3)-1;return out;}
static struct tm *native_localtime(const time_t *seconds,struct tm *out){return native_xtime(seconds,out,false);}
static struct tm *native_gmtime(const time_t *seconds,struct tm *out){return native_xtime(seconds,out,true);}
static time_t native_timex(struct tm *time,bool utc){trace(utc?"timegm":"timelocal");++active->native_calls;char text[256];snprintf(text,sizeof(text),"%d,%d,%d,%d,%d,%d,%d",time->tm_sec,time->tm_min,time->tm_hour,time->tm_mday,time->tm_mon,time->tm_year,time->tm_isdst);trace(text);if(real_native)return utc?_mkgmtime(time):mktime(time);uint64_t value=0;const int values[]={time->tm_sec,time->tm_min,time->tm_hour,time->tm_mday,time->tm_mon,time->tm_year,time->tm_isdst};for(unsigned i=0;i<7;++i)value=value*16777619u^(uint32_t)values[i];memset(time,0xa5,sizeof(*time));return native_variant%5==0?-1:(time_t)(int64_t)value;}
static time_t native_timelocal(struct tm *time){return native_timex(time,false);}
static time_t native_timegm(struct tm *time){return native_timex(time,true);}
#define wf_file_stat native_stat
#define strerror native_strerror
#define uname native_uname
#define clock_gettime native_clock
#undef localtime_r
#undef gmtime_r
#undef timegm
#define localtime_r native_localtime
#define gmtime_r native_gmtime
#define timegm native_timegm
#define mktime native_timelocal
#ifdef ZAPRET_LUA_SCALAR_ORACLE
#include "lua_scalar_comparison.inc"
#else
#define lua_xtime reference_lua_xtime
#define lua_timex reference_lua_timex
#define luacall_stat reference_luacall_stat
#define luacall_uname reference_luacall_uname
#define luacall_clock_gettime reference_luacall_clock_gettime
#define luacall_clock_getfloattime reference_luacall_clock_getfloattime
#define luacall_localtime reference_luacall_localtime
#define luacall_gmtime reference_luacall_gmtime
#define luacall_timelocal reference_luacall_timelocal
#define luacall_timegm reference_luacall_timegm
#include "lua_system_tables_reference.inc"
#undef lua_xtime
#undef lua_timex
#undef luacall_stat
#undef luacall_uname
#undef luacall_clock_gettime
#undef luacall_clock_getfloattime
#undef luacall_localtime
#undef luacall_gmtime
#undef luacall_timelocal
#undef luacall_timegm
#include "lua_system_tables_windows.inc"
#endif
#ifdef ZAPRET_LUA_SCALAR_ORACLE
#include "lua_scalar_observation_end.inc"
#endif

struct allocator {bool armed;unsigned attempts,rejected,limit,live;};
static struct allocator *fault_allocator;
static void *allocate(void *context,void *pointer,size_t previous,size_t next){struct allocator *state=context;if(!next){if(pointer){CHECK(state->live);--state->live;}free(pointer);return NULL;}if(state->armed && next>previous && state->attempts++>=state->limit){++state->rejected;return NULL;}bool fresh=!pointer;void *result=realloc(pointer,next);if(result && fresh)++state->live;return result;}
static lua_CFunction resolver(bool rust,unsigned api){const lua_CFunction old[]={reference_luacall_stat,reference_luacall_uname,reference_luacall_clock_gettime,reference_luacall_clock_getfloattime,reference_luacall_localtime,reference_luacall_gmtime,reference_luacall_timelocal,reference_luacall_timegm};const lua_CFunction current[]={luacall_stat,luacall_uname,luacall_clock_gettime,luacall_clock_getfloattime,luacall_localtime,luacall_gmtime,luacall_timelocal,luacall_timegm};CHECK(api<8);return rust?current[api]:old[api];}
static unsigned current_api;static bool current_rust;
static int lua_trace(lua_State *L){trace(lua_tostring(L,1));return 0;}
static int lua_reenter(lua_State *L){int top=lua_gettop(L);lua_pushcfunction(L,resolver(current_rust,current_api));lua_pushvalue(L,1);int status=lua_pcall(L,1,LUA_MULTRET,0);char text[64];snprintf(text,sizeof(text),"nested:%d:%d",status,lua_gettop(L)-top);trace(text);++active->nested;lua_settop(L,top);return 0;}
static const char *factory=
"FIELDS={'sec','min','hour','mday','mon','year','isdst'} "
"function SYSTEM_CASE(api,shape,field,variant,behavior) "
"local values={false,true,0,-1,59,60,255,-2147483648,2147483647,4294967296,4294969319,3.75,'2023','bad','',{},function()end,math.huge,-math.huge,0/0} "
"local v=variant==0 and nil or values[variant] if variant==0 then v=nil end "
"if api<6 then if shape==0 then if api==0 then return SYSTEM_FILE else return 1700000000 end "
"elseif shape==1 then return v elseif shape==2 then return '1700000000' elseif shape==3 then return 'bad' elseif shape==4 then return nil elseif shape==5 then return {} elseif shape==6 then return 0/0 elseif shape==7 then return -1 elseif shape==8 then return 32535215999 elseif shape==9 then return 32535216000 elseif shape==10 then return 3.75 else return SYSTEM_FILE..string.char(0)..'tail' end end "
"local t={sec=20,min=13,hour=22,mday=14,mon=10,year=2023,isdst=0} "
"if shape==1 then return v elseif shape==2 then return {} end "
"if field>0 then t[FIELDS[field]]=v end if behavior==0 then return t end local held={} "
"return setmetatable({},{__index=function(_,k) TRACE(k) "
"if behavior==2 and k=='sec' then t.min=(tonumber(t.min) or 0)+1 end "
"if behavior==3 and k==FIELDS[field>0 and field or 3] then error('time lookup failed: '..k) end "
"if behavior==4 and k=='sec' then REENTER(t) end "
"if behavior==5 then held[#held+1]=string.rep(k..#held,4096) collectgarbage('step',1) end "
"return t[k] end}) end";
static lua_State *new_vm(struct allocator *allocator){lua_State *L=allocator?lua_newstate(allocate,allocator):luaL_newstate();CHECK(L);luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);lua_register(L,"TRACE",lua_trace);lua_register(L,"REENTER",lua_reenter);lua_pushstring(L,native_file);lua_setglobal(L,"SYSTEM_FILE");CHECK(!luaL_dostring(L,factory));return L;}
static void atom(lua_State *L,int index,struct atom *out){out->type=lua_type(L,index);if(out->type==LUA_TNUMBER)out->number=lua_tonumber(L,index);else if(out->type==LUA_TSTRING){const char *value=lua_tolstring(L,index,&out->length);CHECK(out->length<sizeof(out->text));memcpy(out->text,value,out->length);}}
static const char *stat_names[]={"dev","inode","size","mtime","type"};
static const char *uname_names[]={"sysname","nodename","release","version","machine"};
static const char *time_names[]={"sec","min","hour","mday","mon","year","wday","yday","isdst","zone","str"};
static void execute(lua_State *L,bool rust,unsigned api,unsigned shape,unsigned field,unsigned variant,unsigned behavior,unsigned argc,struct sample *sample){lua_settop(L,0);lua_pushcfunction(L,resolver(rust,api));for(unsigned i=0;i<argc;++i){lua_getglobal(L,"SYSTEM_CASE");lua_pushinteger(L,api);lua_pushinteger(L,shape);lua_pushinteger(L,field);lua_pushinteger(L,variant);lua_pushinteger(L,behavior);CHECK(!lua_pcall(L,5,1,0));}active=sample;current_api=api;current_rust=rust;errno=EDOM;if(fault_allocator){fault_allocator->armed=true;fault_allocator->attempts=fault_allocator->rejected=0;}sample->status=lua_pcall(L,argc,LUA_MULTRET,0);if(fault_allocator)fault_allocator->armed=false;sample->errno_after=errno;sample->arity=lua_gettop(L);CHECK(sample->arity>=1 && sample->arity<=3);if(sample->status){const char *message=lua_tostring(L,-1);snprintf(sample->message,sizeof(sample->message),"%s",message?message:"");}else if(lua_type(L,1)==LUA_TTABLE){const char **names=api==0?stat_names:api==1?uname_names:time_names;unsigned count=api<2?5:11,actual=0;lua_pushnil(L);while(lua_next(L,1)){++actual;lua_pop(L,1);}CHECK(actual==count && sample->arity==1);for(unsigned i=0;i<count;++i){lua_getfield(L,1,names[i]);atom(L,-1,&sample->values[i]);lua_pop(L,1);}}else for(int i=0;i<sample->arity;++i)atom(L,i+1,&sample->values[i]);active=NULL;lua_settop(L,0);}
static void compare(lua_State *L,unsigned api,unsigned shape,unsigned field,unsigned variant,unsigned behavior,unsigned argc){struct sample left={0},right={0};execute(L,false,api,shape,field,variant,behavior,argc,&left);execute(L,true,api,shape,field,variant,behavior,argc,&right);if(memcmp(&left,&right,sizeof(left))){fprintf(stderr,"DETAIL api=%u shape=%u field=%u variant=%u native=%u behavior=%u argc=%u real=%u oldstatus=%d newstatus=%d oldarity=%d newarity=%d olderrno=%d newerrno=%d\noldmsg=%s\nnewmsg=%s\noldtrace=%s\nnewtrace=%s\n",api,shape,field,variant,native_variant,behavior,argc,real_native,left.status,right.status,left.arity,right.arity,left.errno_after,right.errno_after,left.message,right.message,left.trace,right.trace);for(unsigned i=0;i<14;++i)if(memcmp(&left.values[i],&right.values[i],sizeof(struct atom)))fprintf(stderr,"atom=%u oldtype=%d newtype=%d oldnumber=%.17g newnumber=%.17g oldtext=%s newtext=%s\n",i,left.values[i].type,right.values[i].type,left.values[i].number,right.values[i].number,left.values[i].text,right.values[i].text);CHECK(false);}++cases;if(left.status)++errors;reentries+=left.nested;if(real_native && (api==0 || api>=4))++real_cases;}
static void boundary_checks(void){_Alignas(8)uint8_t storage[256];memset(storage,0xa5,sizeof(storage));zapret_lua_system_value *out=(void *)storage;struct tm time={0};CHECK(!zapret_lua_system_field(7,0,&time,out));CHECK(storage[0]==0xa5);++boundaries;CHECK(!zapret_lua_system_field(0,0,NULL,out));++boundaries;CHECK(!zapret_lua_system_field(3,13,&time,out));++boundaries;CHECK(!zapret_lua_system_field(3,0,(uint8_t *)&time+1,out));++boundaries;CHECK(!zapret_lua_system_field(3,0,&time,NULL));++boundaries;CHECK(!zapret_lua_system_field(3,0,&time,(void *)(storage+1)));++boundaries;zapret_lua_time_cursor cursor={.index=99};const char *name=(void *)1;CHECK(zapret_lua_time_begin(LUA_TSTRING,&cursor)==1 && cursor.index==99);++boundaries;CHECK(zapret_lua_time_begin(LUA_TTABLE,NULL)==2);++boundaries;CHECK(zapret_lua_time_next(&cursor,&name)==2 && name==(void *)1);++boundaries;CHECK(zapret_lua_time_observe(&cursor,LUA_TNUMBER,0)==2 && cursor.index==99);++boundaries;CHECK(!zapret_lua_time_begin(LUA_TTABLE,&cursor));CHECK(zapret_lua_time_observe(&cursor,LUA_TSTRING,2023)==1 && cursor.index==0);++boundaries;
    uint8_t *memory=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(memory);DWORD old;CHECK(VirtualProtect(memory+4096,4096,PAGE_NOACCESS,&old));zapret_lua_system_value *guarded=(void *)(memory+4096-sizeof(*guarded));CHECK(zapret_lua_system_field(3,11,&time,guarded));CHECK(!strcmp((char *)guarded->text,"00.01.1900 00:00:00"));++boundaries;struct tm *edge=(void *)(memory+4096-sizeof(*edge));*edge=time;CHECK(VirtualProtect(memory,4096,PAGE_READONLY,&old));CHECK(zapret_lua_system_field(3,11,edge,out));++boundaries;CHECK(VirtualFree(memory,0,MEM_RELEASE));}
static void calendar_formats(void){const int values[]={INT_MIN,-10000,-1901,-1900,-100,-10,-1,0,1,9,10,99,123,9999,INT_MAX-1900};struct tm time={.tm_mday=14,.tm_mon=10,.tm_year=123,.tm_hour=22,.tm_min=13,.tm_sec=20};for(unsigned field=0;field<6;++field)for(unsigned i=0;i<sizeof(values)/sizeof(*values);++i){struct tm sample=time;int *target[]={&sample.tm_mday,&sample.tm_mon,&sample.tm_year,&sample.tm_hour,&sample.tm_min,&sample.tm_sec};*target[field]=values[i];char reference[40];snprintf(reference,sizeof(reference),"%02d.%02d.%04d %02d:%02d:%02d",sample.tm_mday,sample.tm_mon+1,sample.tm_year+1900,sample.tm_hour,sample.tm_min,sample.tm_sec);zapret_lua_system_value result;CHECK(zapret_lua_system_field(3,11,&sample,&result));CHECK(!strcmp(reference,(char *)result.text));++calendar_cases;}}
static void faults(void){real_native=false;const unsigned variants[]={1,5,7,21};for(unsigned v=0;v<4;++v){native_variant=variants[v];for(unsigned api=0;api<8;++api){unsigned argc=api==1||api==2||api==3?0:1;struct sample baseline={0};lua_State *initial=new_vm(NULL);execute(initial,false,api,0,0,0,api>=6?5:0,argc,&baseline);CHECK(!baseline.status);lua_close(initial);for(unsigned side=0;side<2;++side)for(unsigned limit=0;limit<64;++limit){struct allocator allocator={.limit=limit};lua_State *L=new_vm(&allocator);struct sample result={0};fault_allocator=&allocator;execute(L,side!=0,api,0,0,0,api>=6?5:0,argc,&result);fault_allocator=NULL;if(result.status){CHECK(result.status==LUA_ERRMEM && allocator.rejected);CHECK(strlen(result.trace)<=strlen(baseline.trace) && !strncmp(result.trace,baseline.trace,strlen(result.trace)));++vm_faults;}else CHECK(!allocator.rejected && !memcmp(&result,&baseline,sizeof(result)));lua_close(L);CHECK(!allocator.live);++fault_cases;}}}CHECK(vm_faults>100);}
#ifndef ZAPRET_LUA_SCALAR_ORACLE
int main(void){FILE *file=fopen(native_file,"wb");CHECK(file);CHECK(fwrite("a\0b\r\n",1,5,file)==5);CHECK(!fclose(file));lua_State *L=new_vm(NULL);for(native_variant=0;native_variant<24;++native_variant)for(unsigned api=0;api<8;++api)for(unsigned shape=0;shape<12;++shape)for(unsigned argc=0;argc<3;++argc)compare(L,api,shape,0,shape%21,0,argc);
    for(native_variant=0;native_variant<12;++native_variant)for(unsigned api=6;api<8;++api)for(unsigned field=0;field<=7;++field)for(unsigned variant=0;variant<=20;++variant)for(unsigned behavior=0;behavior<6;++behavior)compare(L,api,0,field,variant,behavior,1);
    real_native=true;native_variant=1;for(unsigned api=0;api<8;++api)for(unsigned shape=0;shape<12;++shape)compare(L,api,shape,0,shape%21,0,api==1||api==2||api==3?0:1);
    for(unsigned api=6;api<8;++api)for(unsigned field=1;field<=7;++field)for(unsigned variant=0;variant<=13;++variant)compare(L,api,0,field,variant,1,1);
    lua_close(L);boundary_checks();calendar_formats();faults();CHECK(!remove(native_file));printf("PASS lua_system_tables apis=8 cases=%u vm_errors=%u reentries=%u boundaries=%u native_cases=%u calendar_formats=%u fault_cases=%u vm_allocation_faults=%u real_luajit=1 exact_lookup_order=1 exact_arity=1 exact_native_fields=1 c_only_unwind=1 vm_allocations_released=1 no_live_packets=1\n",cases,errors,reentries,boundaries,real_cases,calendar_cases,fault_cases,vm_faults);return 0;}
#endif
