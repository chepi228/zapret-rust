/* MIT. Complete timer entries with real LuaJIT and the actual Rust scheduler. */
#include "params.h"
#include "engine_lua.h"
#include <luajit.h>
#include <stdarg.h>
#undef main
struct params_s params;
static unsigned cases,errors,mutations,nested_calls,identity_checks,boundaries,guarded,fault_cases,vm_faults,eager_controls;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL timer cases=%u boundaries=%u line=%d: %s\n",cases,boundaries,__LINE__,#v);exit(1);}}while(0)
struct sample {int status,arity;bool dirty;unsigned calls,unrefs,mutated,nested;uint64_t trace;size_t length,pool_length;char result[4096],pool[4096],message[512];};
static struct sample *active;
static bool native_side,entered,eager_view,eager_cursor;
static unsigned api,native_failure,view_variant,mutation_kind,nested_boundary,nested_kind,depth,meta_kind;
static zapret_timer_info *observed,shadow;
static timer_pool *detached;
static uint64_t base_id,cursor_id;
static int reference_choices[8],alternate_name,alternate_func,expected_name,expected_func;
static void nested_call(lua_State *L);
static void seed_timer(lua_State *L,const char *name,bool second);
static uint64_t hash(const void *p,size_t n){uint64_t result=1469598103934665603ULL;const uint8_t *s=p;for(size_t i=0;i<n;++i)result=(result^s[i])*1099511628211ULL;return result;}
static void event(unsigned tag,uint64_t value){if(active)active->trace=(active->trace*1099511628211ULL^tag)*1099511628211ULL^value;}
static void text_event(unsigned tag,const char *s){event(tag,s?hash(s,strlen(s)):0);}
static uint64_t token(uint64_t id){return !id || id==UINT64_MAX?id:id-base_id+1;}
static void boundary(lua_State *L,unsigned at){if(active && !depth && !entered && nested_boundary==at)nested_call(L);}
static void change(lua_State *L,unsigned point){if(!active || depth || active->mutated || mutation_kind!=point)return;if(point<=5 && !observed)return;++active->mutated;++mutations;event(91,point);
    switch(point){
    case 1:observed->name_ref=alternate_name;if(!eager_view)expected_name=alternate_name;break;
    case 2:observed->func_ref=alternate_func;if(!eager_view)expected_func=alternate_func;break;
    case 3:observed->period=UINT64_MAX;observed->oneshot=UINT32_MAX;observed->fires=1234567;break;
    case 4:observed->fires=UINT32_MAX;break;
    case 5:observed->id=UINT64_MAX;break;
    case 6:if(lua_gettop(L)>=3){lua_pushinteger(L,999);lua_replace(L,3);}break;
    case 7:if(lua_gettop(L)>=5){lua_pushliteral(L,"late replacement data");lua_replace(L,5);}break;
    case 8:params.timers_dirty=false;break;
    case 9:if(api==2){detached=params.timers;params.timers=NULL;seed_timer(L,"target",true);}break;
    }
}
static int vm_top(lua_State *L){int n=lua_gettop(L);event(1,n);return n;}
static const char *vm_checkstring(lua_State *L,int index,size_t *length){event(2,(uint32_t)index);change(L,9);return luaL_checklstring(L,index,length);}
static lua_Integer vm_checkinteger(lua_State *L,int index){event(3,(uint32_t)index);return luaL_checkinteger(L,index);}
static int vm_type(lua_State *L,int index){event(4,(uint32_t)index);return lua_type(L,index);}
static const char *vm_tolstring(lua_State *L,int index,size_t *length){event(5,(uint32_t)index);return lua_tolstring(L,index,length);}
static void vm_getfield(lua_State *L,int index,const char *name){boundary(L,1);event(6,(uint32_t)index);text_event(7,name);if(index==LUA_GLOBALSINDEX)change(L,6);lua_getfield(L,index,name);}
static void vm_pushvalue(lua_State *L,int index){event(8,(uint32_t)index);lua_pushvalue(L,index);}
static int vm_boolean(lua_State *L,int index){event(9,(uint32_t)index);return lua_toboolean(L,index);}
static int vm_ref(lua_State *L,int index){boundary(L,4);event(10,(uint32_t)index);int ref=luaL_ref(L,index);event(11,(uint32_t)ref);change(L,7);return ref;}
static void vm_string(lua_State *L,const char *s){boundary(L,3);text_event(12,s);if(s && !strcmp(s,"period"))change(L,3);if(s && !strcmp(s,"oneshot"))change(L,4);lua_pushstring(L,s);}
static void vm_bytes(lua_State *L,const char *s,size_t length){event(13,length);event(14,hash(s,length));if(length==4 && !memcmp(s,"name",4))change(L,1);if(length==4 && !memcmp(s,"func",4))change(L,2);lua_pushlstring(L,s,length);}
static void vm_table(lua_State *L,int array,int records){event(15,(uint64_t)(uint32_t)array<<32|(uint32_t)records);lua_createtable(L,array,records);}
static void vm_registry(lua_State *L,int index,int ref){boundary(L,2);event(16,(uint64_t)(uint32_t)index<<32|(uint32_t)ref);lua_rawgeti(L,index,ref);}
static void vm_rawset(lua_State *L,int index){event(17,(uint32_t)index);lua_rawset(L,index);}
static void vm_rawseti(lua_State *L,int index,int value){boundary(L,5);event(18,(uint64_t)(uint32_t)index<<32|(uint32_t)value);change(L,5);lua_rawseti(L,index,value);}
static void vm_integer(lua_State *L,lua_Integer value){event(19,(uint64_t)value);lua_pushinteger(L,value);}
static void vm_pushboolean(lua_State *L,int value){event(20,value);lua_pushboolean(L,value);}
static void vm_nil(lua_State *L){event(21,0);lua_pushnil(L);}
static int vm_error(lua_State *L,const char *format,...){char message[1024];va_list args;va_start(args,format);vsnprintf(message,sizeof(message),format,args);va_end(args);text_event(22,message);return luaL_error(L,"%s",message);}
static void log_timer(const char *format,...){char message[1024];va_list args;va_start(args,format);vsnprintf(message,sizeof(message),format,args);va_end(args);text_event(23,message);}
static uint64_t clock_timer(void){event(24,300);return 300;}
static void actual_unref(const zapret_timer_info *timer){luaL_unref(params.L,LUA_REGISTRYINDEX,timer->name_ref);luaL_unref(params.L,LUA_REGISTRYINDEX,timer->func_ref);luaL_unref(params.L,LUA_REGISTRYINDEX,timer->data_ref);}
static void timer_unref(const zapret_timer_info *timer){boundary(params.L,6);if(active)++active->unrefs;event(25,(uint32_t)timer->name_ref);event(26,(uint32_t)timer->func_ref);event(27,(uint32_t)timer->data_ref);change(params.L,8);actual_unref(timer);}
static void info_event(const zapret_timer_info *timer){event(28,timer->period);event(29,timer->fires);event(30,(uint32_t)timer->name_ref);event(31,(uint32_t)timer->func_ref);event(32,(uint32_t)timer->data_ref);event(33,timer->oneshot);}
static int timer_set(timer_pool **pool,const char *name,const zapret_timer_info *timer,uint64_t now,zapret_timer_info *old){if(active)++active->calls;text_event(34,name);info_event(timer);event(35,now);int result=native_failure==1?-1:zapret_timer_set(pool,name,timer,now,old);event(36,(uint32_t)result);if(result>=0 && !base_id){zapret_timer_info current;CHECK(zapret_timer_get(*pool,name,&current));base_id=current.id;}return result;}
static void observe(zapret_timer_info *out){observed=out;cursor_id=out->id;expected_name=out->name_ref;expected_func=out->func_ref;if(eager_view){shadow=*out;observed=&shadow;}}
static int timer_get(const timer_pool *pool,const char *name,zapret_timer_info *out){if(active)++active->calls;text_event(37,name);int result=native_failure==2?0:zapret_timer_get(pool,name,out);event(38,result);if(result){if(api==2 && view_variant){static const uint64_t periods[]={0,1,INT64_MAX,1ULL<<63,UINT64_MAX};out->period=periods[view_variant%5];out->fires=view_variant%2?UINT32_MAX:view_variant;out->oneshot=view_variant%3?UINT32_MAX:0;out->name_ref=reference_choices[view_variant%8];out->func_ref=reference_choices[(view_variant+2)%8];}observe(out);}return result;}
static int timer_remove(timer_pool **pool,uint64_t id,zapret_timer_info *out){if(active)++active->calls;event(39,token(id));int result=native_failure==3?0:zapret_timer_remove(pool,id,out);event(40,result);return result;}
static int timer_after(const timer_pool *pool,uint64_t after,zapret_timer_info *out){if(active)++active->calls;if(eager_cursor && after==UINT64_MAX)after=cursor_id;event(41,token(after));int result=native_failure==4?0:zapret_timer_after(pool,after,out);event(42,result);if(result){if(view_variant)out->name_ref=reference_choices[(view_variant+token(out->id))%8];observe(out);}return result;}

#define lua_gettop vm_top
#define luaL_checklstring vm_checkstring
#define luaL_checkinteger vm_checkinteger
#define lua_type vm_type
#define lua_tolstring vm_tolstring
#define lua_getfield vm_getfield
#define lua_pushvalue vm_pushvalue
#define lua_toboolean vm_boolean
#define luaL_ref vm_ref
#define lua_pushstring vm_string
#define lua_pushlstring vm_bytes
#define lua_createtable vm_table
#define lua_rawgeti vm_registry
#define lua_rawset vm_rawset
#define lua_rawseti vm_rawseti
#define lua_pushinteger vm_integer
#define lua_pushboolean vm_pushboolean
#define lua_pushnil vm_nil
#define luaL_error vm_error
#undef DLOG
#define DLOG log_timer
#define boottime_ms clock_timer
#define zapret_timer_unref timer_unref
#define zapret_timer_set timer_set
#define zapret_timer_get timer_get
#define zapret_timer_remove timer_remove
#define zapret_timer_after timer_after
#include "lua_timer_common.inc"
#define luacall_timer_set reference_set
#define luacall_timer_del reference_del
#define luacall_timer_info reference_info
#define luacall_timer_enum reference_enum
#include "lua_timer_reference.inc"
#undef luacall_timer_set
#undef luacall_timer_del
#undef luacall_timer_info
#undef luacall_timer_enum
#include "lua_timer_windows.inc"
#undef lua_gettop
#undef luaL_checklstring
#undef luaL_checkinteger
#undef lua_type
#undef lua_tolstring
#undef lua_getfield
#undef lua_pushvalue
#undef lua_toboolean
#undef luaL_ref
#undef lua_pushstring
#undef lua_pushlstring
#undef lua_createtable
#undef lua_rawgeti
#undef lua_rawset
#undef lua_rawseti
#undef lua_pushinteger
#undef lua_pushboolean
#undef lua_pushnil
#undef luaL_error
#undef zapret_timer_unref
#undef zapret_timer_set
#undef zapret_timer_get
#undef zapret_timer_remove
#undef zapret_timer_after

static lua_CFunction resolve(bool native,unsigned entry){const lua_CFunction before[]={reference_set,reference_del,reference_info,reference_enum},after[]={luacall_timer_set,luacall_timer_del,luacall_timer_info,luacall_timer_enum};return native?after[entry]:before[entry];}
static int callback_a(lua_State *L){(void)L;return 0;}
static int callback_b(lua_State *L){(void)L;return 0;}
static void nested_call(lua_State *L){entered=true;++depth;unsigned saved_api=api;zapret_timer_info *saved=observed;uint64_t cursor=cursor_id;int top=lua_gettop(L);api=0;
    lua_pushcfunction(L,resolve(native_side,0));lua_pushliteral(L,"nested");lua_getglobal(L,"FB");lua_pushinteger(L,nested_kind==2?9:10000);lua_pushboolean(L,true);lua_pushliteral(L,"nested data");int status=lua_pcall(L,5,0,0);event(43,status);lua_settop(L,top);api=saved_api;observed=saved;cursor_id=cursor;--depth;++active->nested;++nested_calls;if(nested_kind==3){luaL_error(L,"nested timer fixture failure");return;}lua_gc(L,LUA_GCCOLLECT,0);}
static int global_index(lua_State *L){event(44,meta_kind);if(meta_kind==2)return luaL_error(L,"timer global lookup fixture failure");if(meta_kind>=3){unsigned previous=nested_kind;nested_kind=meta_kind-2;nested_call(L);nested_kind=previous;}lua_getglobal(L,"FB");return 1;}
static const char *canonical="function CANON(v) local t=type(v);if t=='table' then local keys,out={},{};for k in pairs(v) do keys[#keys+1]=k end;table.sort(keys,function(a,b)if type(a)~=type(b) then return type(a)<type(b) end return a<b end);for _,k in ipairs(keys) do out[#out+1]=CANON(k)..'='..CANON(v[k]) end;return '{'..table.concat(out,';')..'}' elseif t=='string' then return t..#v..':'..v elseif t=='number' then return t..string.format('%.17g',v) elseif t=='function' then return v==FA and 'functionA' or v==FB and 'functionB' or 'functionOther' else return t..tostring(v) end end";
struct allocator {bool armed;unsigned attempts,rejected,limit,live;};
static void *allocate(void *context,void *pointer,size_t previous,size_t next){struct allocator *a=context;if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}if(a->armed && next>previous && a->attempts++>=a->limit){++a->rejected;return NULL;}bool fresh=!pointer;void *out=realloc(pointer,next);if(out && fresh)++a->live;return out;}
static void seed_timer(lua_State *L,const char *name,bool second){zapret_timer_info timer={.period=10000,.oneshot=second};lua_pushstring(L,name);timer.name_ref=luaL_ref(L,LUA_REGISTRYINDEX);lua_getglobal(L,second?"FB":"FA");timer.func_ref=luaL_ref(L,LUA_REGISTRYINDEX);lua_pushstring(L,second?"second data":"first data");timer.data_ref=luaL_ref(L,LUA_REGISTRYINDEX);zapret_timer_info old;CHECK(zapret_timer_set(&params.timers,name,&timer,100,&old)==0);if(!base_id){CHECK(zapret_timer_get(params.timers,name,&old));base_id=old.id;}}
static lua_State *new_vm(struct allocator *a){lua_State *L=a?lua_newstate(allocate,a):luaL_newstate();CHECK(L);params.L=L;params.timers=detached=NULL;params.timers_dirty=cases%2;active=NULL;observed=NULL;base_id=cursor_id=0;depth=0;entered=false;luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);
    lua_pushcfunction(L,callback_a);lua_setglobal(L,"FA");lua_pushcfunction(L,callback_b);lua_setglobal(L,"FB");lua_getglobal(L,"FA");lua_setglobal(L,"callback");CHECK(!luaL_dostring(L,canonical));
    reference_choices[0]=LUA_REFNIL;reference_choices[1]=LUA_NOREF;lua_pushboolean(L,false);reference_choices[2]=luaL_ref(L,LUA_REGISTRYINDEX);lua_pushboolean(L,true);reference_choices[3]=luaL_ref(L,LUA_REGISTRYINDEX);lua_pushnumber(L,123.75);reference_choices[4]=luaL_ref(L,LUA_REGISTRYINDEX);lua_pushliteral(L,"alternate name");reference_choices[5]=alternate_name=luaL_ref(L,LUA_REGISTRYINDEX);lua_newtable(L);lua_pushliteral(L,"identity");lua_setfield(L,-2,"fixture");reference_choices[6]=luaL_ref(L,LUA_REGISTRYINDEX);lua_getglobal(L,"FB");reference_choices[7]=alternate_func=luaL_ref(L,LUA_REGISTRYINDEX);
    seed_timer(L,"target",false);seed_timer(L,"sibling",true);seed_timer(L,"last",false);
    if(meta_kind){lua_pushvalue(L,LUA_GLOBALSINDEX);lua_newtable(L);lua_pushcfunction(L,global_index);lua_setfield(L,-2,"__index");lua_setmetatable(L,-2);lua_pop(L,1);}return L;
}
static size_t serialize(lua_State *L,int index,char *out,size_t capacity){index=index<0?lua_gettop(L)+index+1:index;lua_getglobal(L,"CANON");lua_pushvalue(L,index);CHECK(!lua_pcall(L,1,1,0));size_t length;const char *s=lua_tolstring(L,-1,&length);CHECK(s && length<capacity);memcpy(out,s,length);lua_pop(L,1);return length;}
static void snapshot_pool(lua_State *L,struct sample *sample){lua_settop(L,0);lua_newtable(L);zapret_timer_info timer;uint64_t after=0;int index=1;while(zapret_timer_after(params.timers,after,&timer)){lua_newtable(L);lua_rawgeti(L,LUA_REGISTRYINDEX,timer.name_ref);lua_setfield(L,-2,"name");lua_rawgeti(L,LUA_REGISTRYINDEX,timer.func_ref);lua_setfield(L,-2,"func");lua_rawgeti(L,LUA_REGISTRYINDEX,timer.data_ref);lua_setfield(L,-2,"data");lua_pushf_lint(L,"period",timer.period);lua_pushf_lint(L,"fires",timer.fires);lua_pushf_bool(L,"oneshot",timer.oneshot!=0);lua_rawseti(L,-2,index++);after=timer.id;}sample->pool_length=serialize(L,-1,sample->pool,sizeof(sample->pool));lua_settop(L,0);}
static void close_pool(timer_pool **pool){zapret_timer_info timer,removed;while(zapret_timer_after(*pool,0,&timer)){CHECK(zapret_timer_remove(pool,timer.id,&removed));actual_unref(&removed);}CHECK(!*pool);}
static void close_vm(lua_State *L){active=NULL;observed=NULL;close_pool(&params.timers);close_pool(&detached);params.L=NULL;lua_close(L);}
struct argument {int kind;const char *data;size_t length;lua_Number number;};
static struct argument string_arg(const char *s){return (struct argument){.kind=LUA_TSTRING,.data=s,.length=strlen(s)};}
static struct argument number_arg(lua_Number value){return (struct argument){.kind=LUA_TNUMBER,.number=value};}
static void push_arg(lua_State *L,struct argument a){switch(a.kind){case LUA_TSTRING:lua_pushlstring(L,a.data,a.length);break;case LUA_TNUMBER:lua_pushnumber(L,a.number);break;case LUA_TBOOLEAN:lua_pushboolean(L,a.number!=0);break;case LUA_TFUNCTION:lua_getglobal(L,a.number?"FB":"FA");break;case LUA_TTABLE:lua_newtable(L);lua_pushliteral(L,"payload");lua_setfield(L,-2,"fixture");break;case LUA_TLIGHTUSERDATA:lua_pushlightuserdata(L,(void *)(uintptr_t)1);break;case LUA_TUSERDATA:*(char *)lua_newuserdata(L,1)=0;break;case LUA_TTHREAD:lua_newthread(L);break;default:lua_pushnil(L);}}
static struct sample invoke(bool native,unsigned entry,const struct argument *args,unsigned argc,struct allocator *allocator){api=entry;lua_State *L=new_vm(allocator);struct sample sample={0};lua_pushcfunction(L,resolve(native,entry));for(unsigned i=0;i<argc;++i)push_arg(L,args[i]);native_side=native;active=&sample;if(allocator)allocator->armed=true;
    sample.status=lua_pcall(L,argc,LUA_MULTRET,0);if(allocator)allocator->armed=false;active=NULL;observed=NULL;sample.arity=lua_gettop(L);sample.dirty=params.timers_dirty;
    if(sample.status){CHECK(sample.arity==1);const char *s=lua_tostring(L,1);snprintf(sample.message,sizeof(sample.message),"%s",s?s:"");}else{CHECK(sample.arity==(entry?1:0));if(sample.arity)sample.length=serialize(L,1,sample.result,sizeof(sample.result));if(entry==2 && lua_istable(L,1) && !eager_view){lua_getfield(L,1,"name");lua_rawgeti(L,LUA_REGISTRYINDEX,expected_name);CHECK(lua_rawequal(L,-1,-2));lua_pop(L,2);lua_getfield(L,1,"func");lua_rawgeti(L,LUA_REGISTRYINDEX,expected_func);CHECK(lua_rawequal(L,-1,-2));lua_pop(L,2);++identity_checks;}}
    snapshot_pool(L,&sample);close_vm(L);if(allocator)CHECK(!allocator->live);return sample;
}
static struct sample compare(unsigned entry,const struct argument *args,unsigned argc){struct sample a=invoke(false,entry,args,argc,NULL),b=invoke(true,entry,args,argc,NULL);if(memcmp(&a,&b,sizeof(a))){fprintf(stderr,"DETAIL api=%u argc=%u fail=%u view=%u mutation=%u nest=%u/%u meta=%u old=%d/%d new=%d/%d old_trace=%llx new_trace=%llx old_error=%s new_error=%s old_result=%s new_result=%s\n",entry,argc,native_failure,view_variant,mutation_kind,nested_boundary,nested_kind,meta_kind,a.status,a.arity,b.status,b.arity,(unsigned long long)a.trace,(unsigned long long)b.trace,a.message,b.message,a.result,b.result);CHECK(false);}++cases;if(a.status)++errors;return a;}
static void abi_checks(void){_Alignas(8)uint8_t storage[256];memset(storage,0xa5,sizeof(storage));zapret_lua_timer_state *state=(void *)storage;zapret_lua_timer_action action={.kind=91};zapret_lua_timer_value value={0};
    CHECK(!zapret_lua_timer_begin(4,state,&action) && storage[0]==0xa5 && action.kind==91);++boundaries;CHECK(!zapret_lua_timer_begin(0,NULL,&action));++boundaries;CHECK(!zapret_lua_timer_begin(0,(void *)(storage+1),&action));++boundaries;CHECK(!zapret_lua_timer_begin(0,state,NULL));++boundaries;
    CHECK(zapret_lua_timer_begin(0,state,&action));CHECK(!zapret_lua_timer_step(state,NULL,&action));++boundaries;CHECK(!zapret_lua_timer_step(state,&value,NULL));++boundaries;CHECK(!zapret_lua_timer_step((void *)(storage+1),&value,&action));++boundaries;CHECK(!zapret_lua_timer_step(state,(void *)(storage+1),&action));++boundaries;
    uint8_t *pages=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(pages);DWORD old;CHECK(VirtualProtect(pages+4096,4096,PAGE_NOACCESS,&old));zapret_lua_timer_state *edge=(void *)(pages+4096-sizeof(*edge));CHECK(zapret_lua_timer_begin(3,edge,&action));CHECK(zapret_lua_timer_step(edge,&value,&action) && action.kind==21);++guarded;
    zapret_lua_timer_state local;zapret_lua_timer_action *edge_action=(void *)(pages+4096-sizeof(action));for(unsigned mode=0;mode<4;++mode){CHECK(zapret_lua_timer_begin(mode,&local,edge_action));++guarded;}
    zapret_lua_timer_value *edge_value=(void *)(pages+4096-sizeof(value));*edge_value=(zapret_lua_timer_value){.integer=3};CHECK(VirtualProtect(pages,4096,PAGE_READONLY,&old));for(unsigned mode=0;mode<4;++mode){CHECK(zapret_lua_timer_begin(mode,&local,&action));CHECK(zapret_lua_timer_step(&local,edge_value,&action));++guarded;}CHECK(VirtualFree(pages,0,MEM_RELEASE));}
int main(void){
    struct argument args[6]={string_arg("target"),{.kind=LUA_TFUNCTION},number_arg(10000),{.kind=LUA_TBOOLEAN,.number=1},string_arg("data"),number_arg(99)};
    const struct argument names[]={string_arg("target"),string_arg("new"),number_arg(123),string_arg(""),{.kind=LUA_TSTRING,.data="target\0tail",.length=11},{.kind=LUA_TNIL},{.kind=LUA_TBOOLEAN},{.kind=LUA_TTABLE}};
    const struct argument callbacks[]={{.kind=LUA_TFUNCTION},string_arg("callback"),string_arg("missing_cb"),number_arg(12),{.kind=LUA_TNIL},{.kind=LUA_TBOOLEAN},{.kind=LUA_TTABLE},{.kind=LUA_TLIGHTUSERDATA},{.kind=LUA_TTHREAD},{.kind=LUA_TSTRING,.data="callback\0tail",.length=13}};
    const struct argument periods[]={number_arg(-1),number_arg(0),number_arg(9),number_arg(9.75),number_arg(10),number_arg(10.75),number_arg(2147483648.0),number_arg(9007199254740991.0),string_arg("10.75"),string_arg("bad"),{.kind=LUA_TNIL},{.kind=LUA_TBOOLEAN},{.kind=LUA_TTABLE}};
    const struct argument optional[]={{.kind=LUA_TNIL},{.kind=LUA_TBOOLEAN},{.kind=LUA_TBOOLEAN,.number=1},number_arg(0),string_arg(""),{.kind=LUA_TTABLE},{.kind=LUA_TFUNCTION}};
    for(unsigned n=0;n<8;++n)for(unsigned c=0;c<10;++c)for(unsigned p=0;p<13;++p)for(unsigned argc=3;argc<=5;++argc){args[0]=names[n];args[1]=callbacks[c];args[2]=periods[p];args[3]=optional[(n+c+p)%7];args[4]=optional[(n+2*c+p)%7];compare(0,args,argc);}
    for(unsigned n=0;n<4;++n)for(unsigned c=0;c<2;++c)for(unsigned p=4;p<=8;++p)for(unsigned flag=0;flag<7;++flag)for(unsigned data=0;data<7;++data){args[0]=names[n];args[1]=callbacks[c];args[2]=periods[p];args[3]=optional[flag];args[4]=optional[data];compare(0,args,5);}
    for(unsigned entry=0;entry<4;++entry)for(unsigned argc=0;argc<=6;++argc){args[0]=names[0];args[1]=callbacks[0];args[2]=periods[4];compare(entry,args,argc);}
    for(unsigned entry=1;entry<=2;++entry)for(unsigned n=0;n<8;++n){args[0]=names[n];compare(entry,args,1);}
    args[0]=names[0];args[1]=callbacks[0];args[2]=number_arg(10000);args[3]=optional[2];args[4]=string_arg("data");
    for(native_failure=0;native_failure<=4;++native_failure)for(unsigned entry=0;entry<4;++entry)compare(entry,args,entry==0?5:entry==3?0:1);native_failure=0;
    for(view_variant=0;view_variant<64;++view_variant)for(unsigned entry=2;entry<4;++entry)compare(entry,args,entry==3?0:1);view_variant=0;
    for(mutation_kind=1;mutation_kind<=9;++mutation_kind)for(unsigned entry=0;entry<4;++entry)compare(entry,args,entry==0?5:entry==3?0:1);mutation_kind=0;
    for(nested_boundary=1;nested_boundary<=6;++nested_boundary)for(nested_kind=1;nested_kind<=3;++nested_kind)for(unsigned entry=0;entry<4;++entry)compare(entry,args,entry==0?5:entry==3?0:1);nested_boundary=0;
    args[1]=string_arg("missing_cb");for(meta_kind=1;meta_kind<=5;++meta_kind)compare(0,args,5);meta_kind=0;args[1]=callbacks[0];
    mutation_kind=1;struct sample live=invoke(false,2,args,1,NULL);eager_view=true;struct sample frozen=invoke(false,2,args,1,NULL);eager_view=false;CHECK(live.length!=frozen.length || memcmp(live.result,frozen.result,live.length));++eager_controls;
    mutation_kind=5;live=invoke(false,3,args,0,NULL);eager_cursor=true;frozen=invoke(false,3,args,0,NULL);eager_cursor=false;CHECK(live.length!=frozen.length || memcmp(live.result,frozen.result,live.length));++eager_controls;mutation_kind=0;
    for(unsigned entry=0;entry<4;++entry)for(unsigned side=0;side<2;++side)for(unsigned budget=0;budget<80;++budget){struct allocator allocator={.limit=budget};struct sample result=invoke(side,entry,args,entry==0?5:entry==3?0:1,&allocator);if(result.status==LUA_ERRMEM){CHECK(allocator.rejected);++vm_faults;}else CHECK(!result.status);++fault_cases;}
    abi_checks();CHECK(vm_faults>0);
    printf("PASS lua_timer apis=4 cases=%u vm_errors=%u mutable_updates=%u nested_calls=%u identity_checks=%u eager_snapshot_controls=%u guarded=%u boundaries=%u fault_cases=%u vm_allocation_faults=%u real_luajit=1 actual_rust_scheduler=1 exact_vm_order=1 exact_errors=1 exact_arity=1 exact_registry_ownership=1 exact_dirty_and_logging=1 deferred_timer_id=1 vm_allocations_released=1 c_only_unwind=1\n",cases,errors,mutations,nested_calls,identity_checks,eager_controls,guarded,boundaries,fault_cases,vm_faults);return 0;}
