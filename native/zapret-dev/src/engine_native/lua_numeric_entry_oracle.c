/* MIT. Complete previous/new entries in real protected LuaJIT calls. */
#include "params.h"
#include "engine_lua.h"
#include <stdarg.h>
#include <math.h>
#undef main

static unsigned cases, errors, function_index, scenario, fault_cases, vm_faults;
static unsigned mutable_cases, nested_calls, eager_controls, guarded, boundaries;
static unsigned nested_boundaries;
static unsigned mutation, nested_at, nested_kind, depth, top_calls, source_variant;
static int late_count = -1;
static bool native_side, entered, eager;
static uint8_t source_bytes[64], eager_bytes[64];
static const uint8_t *source_pointer;
struct event {uint32_t kind;uint64_t value;};
struct snapshot {int status, count, kind;uint64_t number;size_t length;char bytes[512];unsigned events, allocations, rejected;struct event trace[512];};
static struct snapshot *active;
#define CHECK(c) do {if(!(c)){fprintf(stderr,"FAIL numeric_entry api=%u scenario=%u case=%u mutation=%u nested=%u budget=%u line=%d: %s\n",function_index,scenario,cases,mutation,nested_at,fault_cases,__LINE__,#c);exit(1);}}while(0)
static lua_CFunction resolve(bool native,unsigned index);
static void event(unsigned kind,uint64_t value){if(active){CHECK(active->events<512);active->trace[active->events++]=(struct event){.kind=kind,.value=value};}}
static uint64_t hash(const void *input,size_t length){const uint8_t *bytes=input;uint64_t h=1469598103934665603ULL;for(size_t i=0;i<length;++i){h^=bytes[i];h*=1099511628211ULL;}return h;}
static void nested(lua_State *L)
{
    entered=true;++depth;++nested_calls;int top=lua_gettop(L);
    bool binary=nested_kind>=2, failure=nested_kind&1;
    lua_pushcfunction(L,resolve(native_side,binary?31:17));
    if(binary){if(failure)lua_pushboolean(L,false);else lua_pushinteger(L,127);}
    else{lua_pushinteger(L,65535);if(failure)lua_pushboolean(L,false);else lua_pushinteger(L,2);}
    int status=lua_pcall(L,binary?1:2,LUA_MULTRET,0);event(30,(unsigned)status);
    CHECK(failure ? status!=0 : status==0 && lua_gettop(L)==top+1);
    if(!failure){if(binary){size_t length;const char *bytes=lua_tolstring(L,-1,&length);CHECK(length==6 && !memcmp(bytes,"\0\0\0\0\0\x7F",6));}else CHECK(lua_tointeger(L,-1)==1);}
    lua_settop(L,top);--depth;
}
static void boundary(lua_State *L,unsigned where){if(active && !depth && !entered && nested_at==where){nested_boundaries|=1u<<where;nested(L);}}
static int vm_top(lua_State *L)
{
    if(!depth && ++top_calls==2){if(late_count>=0)lua_settop(L,late_count);if(source_variant==1 && mutation==1)source_bytes[0]=0xAB;boundary(L,1);}
    int count=lua_gettop(L);event(1,(uint32_t)count);return count;
}
static void vm_checktype(lua_State *L,int index,int kind){event(2,(uint64_t)(uint32_t)index<<32|(uint32_t)kind);boundary(L,2);luaL_checktype(L,index,kind);}
static const char *vm_string(lua_State *L,int index,size_t *length)
{
    event(3,(uint32_t)index);const char *bytes=lua_tolstring(L,index,length);event(4,*length);event(5,hash(bytes,*length));
    if(!depth && index==1){boundary(L,3);if(mutation==4)lua_pushinteger(L,2);if(source_variant)bytes=(const char *)source_pointer;}
    return bytes;
}
static lua_Integer vm_integer(lua_State *L,int index)
{
    event(6,(uint32_t)index);if(!depth && source_variant==1 && mutation==2 && index==2)source_bytes[1]=0xCD;
    boundary(L,5);lua_Integer result=luaL_checkinteger(L,index);event(7,(uint64_t)result);return result;
}
static int vm_type(lua_State *L,int index){event(8,(uint32_t)index);if(!depth && source_variant==1 && mutation==3)source_bytes[0]=0xEF;boundary(L,4);int kind=lua_type(L,index);event(9,(uint32_t)kind);return kind;}
static void vm_pushinteger(lua_State *L,lua_Integer value){event(10,(uint64_t)value);boundary(L,6);lua_pushinteger(L,value);}
static void vm_bytes(lua_State *L,const char *bytes,size_t length){event(11,length);event(12,hash(bytes,length));boundary(L,7);lua_pushlstring(L,bytes,length);}
static void vm_nil(lua_State *L){event(13,0);boundary(L,8);lua_pushnil(L);}
static int vm_error(lua_State *L,const char *format,...){char message[512];va_list args;va_start(args,format);vsnprintf(message,sizeof(message),format,args);va_end(args);event(14,hash(message,strlen(message)));boundary(L,9);return luaL_error(L,"%s",message);}

#ifndef ZAPRET_LUA_NUMERIC_BENCH
#define lua_gettop vm_top
#define luaL_checktype vm_checktype
#define lua_tolstring vm_string
#define luaL_checkinteger vm_integer
#define lua_type vm_type
#define lua_pushinteger vm_pushinteger
#define lua_pushlstring vm_bytes
#define lua_pushnil vm_nil
#define luaL_error vm_error
#endif
static void lua_check_argc(lua_State *L,const char *name,int count){int actual=lua_gettop(L);if(actual!=count)luaL_error(L,"%s expect exactly %d arguments, got %d",name,count,actual);}
static void lua_check_argc_range(lua_State *L,const char *name,int minimum,int maximum){int actual=lua_gettop(L);if(actual<minimum || actual>maximum)luaL_error(L,"%s expect from %d to %d arguments, got %d",name,minimum,maximum,actual);}
const char *lua_reqlstring(lua_State *L,int index,size_t *length)
{
    luaL_checktype(L,index,LUA_TSTRING);const char *bytes=lua_tolstring(L,index,length);
#ifndef ZAPRET_LUA_NUMERIC_BENCH
    if(eager && native_side && source_variant==1){CHECK(*length<=sizeof(eager_bytes));memcpy(eager_bytes,bytes,*length);bytes=(const char *)eager_bytes;}
#endif
    return bytes;
}
struct numeric_function {const char *name;lua_CFunction previous,native;};
#include "lua_numeric_entry_comparison.inc"
#undef lua_gettop
#undef luaL_checktype
#undef lua_tolstring
#undef luaL_checkinteger
#undef lua_type
#undef lua_pushinteger
#undef lua_pushlstring
#undef lua_pushnil
#undef luaL_error

static lua_CFunction resolve(bool native,unsigned index){return native?functions[index].native:functions[index].previous;}
struct argument {int kind;double number;const char *bytes;size_t length;};
static struct argument number(double value){return (struct argument){.kind=LUA_TNUMBER,.number=value};}
static struct argument binary(const char *bytes,size_t length){return (struct argument){.kind=LUA_TSTRING,.bytes=bytes,.length=length};}
static int empty(lua_State *L){(void)L;return 0;}
static void push(lua_State *L,const struct argument *arg)
{
    switch(arg->kind){
    case LUA_TNUMBER:lua_pushnumber(L,arg->number);break;
    case LUA_TSTRING:lua_pushlstring(L,arg->bytes,arg->length);break;
    case LUA_TBOOLEAN:lua_pushboolean(L,true);break;
    case LUA_TLIGHTUSERDATA:lua_pushlightuserdata(L,(void *)(uintptr_t)1);break;
    case LUA_TTABLE:lua_newtable(L);break;
    case LUA_TFUNCTION:lua_pushcfunction(L,empty);break;
    case LUA_TUSERDATA:lua_newuserdata(L,3);break;
    case LUA_TTHREAD:lua_newthread(L);break;
    default:lua_pushnil(L);break;
    }
}
struct allocator {bool armed;unsigned attempts,rejected,live,limit;};
static void *allocate(void *context,void *pointer,size_t previous,size_t next)
{
    struct allocator *a=context;
    if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}
    if(a->armed && next>previous && a->attempts++>=a->limit){++a->rejected;return NULL;}
    bool fresh=!pointer;void *out=realloc(pointer,next);if(out && fresh)++a->live;return out;
}
static struct snapshot invoke(bool native,const struct argument *args,unsigned count,int budget)
{
    struct allocator allocator={0};lua_State *L=lua_newstate(allocate,&allocator);CHECK(L);
    lua_gc(L,LUA_GCSTOP,0);CHECK(lua_checkstack(L,(int)count+32));
    lua_pushcfunction(L,resolve(native,function_index));for(unsigned i=0;i<count;++i)push(L,&args[i]);
    if(source_variant==1){CHECK(count && args[0].kind==LUA_TSTRING && args[0].length<=sizeof(source_bytes));memcpy(source_bytes,args[0].bytes,args[0].length);source_pointer=source_bytes;}
    struct snapshot out={0};native_side=native;entered=false;depth=top_calls=0;active=&out;
    allocator.armed=budget>=0;allocator.limit=(unsigned)budget;
    out.status=lua_pcall(L,(int)count,LUA_MULTRET,0);allocator.armed=false;active=NULL;
    out.allocations=allocator.attempts;out.rejected=allocator.rejected;out.count=lua_gettop(L);
    CHECK(out.count==1);out.kind=lua_type(L,1);
    if(out.kind==LUA_TNUMBER){double value=lua_tonumber(L,1);memcpy(&out.number,&value,sizeof(value));}
    else if(out.kind==LUA_TSTRING){const char *bytes=lua_tolstring(L,1,&out.length);CHECK(out.length<sizeof(out.bytes));memcpy(out.bytes,bytes,out.length);}
    lua_close(L);CHECK(!allocator.live);return out;
}
static bool same(const struct snapshot *a,const struct snapshot *b)
{
    return a->status==b->status && a->count==b->count && a->kind==b->kind && a->number==b->number && a->length==b->length
        && !memcmp(a->bytes,b->bytes,a->length) && a->events==b->events && !memcmp(a->trace,b->trace,a->events*sizeof(*a->trace))
        && a->allocations==b->allocations && a->rejected==b->rejected;
}
static void compare(const struct argument *args,unsigned count,int budget)
{
    struct snapshot old=invoke(false,args,count,budget),current=invoke(true,args,count,budget);
    if(!same(&old,&current)){
        fprintf(stderr,"%s old=%d/%d/%d events=%u new=%d/%d/%d events=%u old-bytes=%s new-bytes=%s\n",functions[function_index].name,old.status,old.count,old.kind,old.events,current.status,current.count,current.kind,current.events,old.bytes,current.bytes);
        for(unsigned i=0;i<old.events || i<current.events;++i)if(old.trace[i].kind!=current.trace[i].kind || old.trace[i].value!=current.trace[i].value){fprintf(stderr,"event=%u old=%u/%llu new=%u/%llu\n",i,old.trace[i].kind,(unsigned long long)old.trace[i].value,current.trace[i].kind,(unsigned long long)current.trace[i].value);break;}
        CHECK(false);
    }
    ++cases;if(old.status)++errors;if(budget>=0){++fault_cases;if(old.status==LUA_ERRMEM)++vm_faults;}
    if(mutation || late_count>=0)++mutable_cases;
}
static uint64_t random_state=0x251C7A3E9B4680DFULL;
static uint64_t next_random(void){random_state^=random_state<<13;random_state^=random_state>>7;random_state^=random_state<<17;return random_state;}
static unsigned width(unsigned index){static const unsigned bits[]={48,48,48,48,48,8,16,24,32,48,48,48,16,24,32,48,8,16,24,32,48,48,8,16,24,32,48,8,16,24,32,48};return bits[index];}
static unsigned seed(struct argument *args,char *data)
{
    for(unsigned i=0;i<102;++i)args[i]=number(1);
    unsigned count=function_index==11?4:function_index==10?3:function_index<3 || function_index==21?2:1;
    if(function_index==10 || function_index==11){args[1]=number(0);args[2]=number(47);}
    if(function_index>=22 && function_index<27){args[0]=binary(data,16);args[1]=number(1);}
    return count;
}

#ifndef ZAPRET_LUA_NUMERIC_BENCH
static void matrix(void)
{
    char data[64];for(unsigned i=0;i<sizeof(data);++i)data[i]=(char)(i*71+1);
    struct argument args[102];
    for(function_index=0;function_index<32;++function_index){
        unsigned bits=width(function_index);double limit=(double)((1ULL<<bits)-1);
        bool read=function_index>=22 && function_index<27;
        bool variadic=(function_index>=2 && function_index<=4) || (function_index>=16 && function_index<=20);
        for(scenario=0;scenario<256;++scenario){
            unsigned count=seed(args,data);if(variadic)count=(function_index==2?2:1)+next_random()%(function_index==2?99:100);
            for(unsigned i=0;i<count;++i)args[i]=number((double)(next_random()&((1ULL<<bits)-1))*(next_random()&1?1:-1));
            if(function_index<2)args[1]=number(next_random()%49);
            if(function_index==10 || function_index==11){unsigned from=next_random()%48;args[1]=number(from);args[2]=number(from+next_random()%(48-from));}
            if(function_index==21 && scenario%7==0)args[1]=number(0);
            if(read){count=1+scenario%2;args[0]=binary(data,sizeof(data));args[1]=scenario%3?(number(1+next_random()%(sizeof(data)-bits/8+1))):(struct argument){.kind=LUA_TNIL};}
            compare(args,count,-1);
        }
        static const unsigned counts[]={0,1,2,3,4,99,100,101};
        for(scenario=0;scenario<sizeof(counts)/sizeof(*counts);++scenario){seed(args,data);compare(args,counts[scenario],-1);}
        static const int kinds[]={LUA_TNIL,LUA_TBOOLEAN,LUA_TLIGHTUSERDATA,LUA_TTABLE,LUA_TFUNCTION,LUA_TUSERDATA,LUA_TTHREAD};
        unsigned base=seed(args,data);if(variadic)base=100;if(read)base=2;
        for(unsigned position=0;position<base;++position){
            for(unsigned kind=0;kind<sizeof(kinds)/sizeof(*kinds);++kind){seed(args,data);args[position]=(struct argument){.kind=kinds[kind]};compare(args,base,-1);}
        }
        static const char *texts[]={"17","0x1f","1.75","-3.5","invalid","","nan","inf","1\0tail"};
        for(scenario=0;scenario<sizeof(texts)/sizeof(*texts);++scenario){unsigned count=seed(args,data);unsigned position=read?1:0;if(read)count=2;args[position]=binary(texts[scenario],scenario==8?6:strlen(texts[scenario]));compare(args,count,-1);}
        const double values[]={-limit-1,-limit,-1,0,1,limit,limit+1,-9223372036854775808.0,9223372036854775808.0,NAN,INFINITY,-INFINITY,1e300,-1e300};
        for(scenario=0;scenario<sizeof(values)/sizeof(*values);++scenario){unsigned count=seed(args,data);unsigned position=read?1:0;if(read)count=2;args[position]=number(values[scenario]);compare(args,count,-1);}
        if(read){for(unsigned length=0;length<=8;++length)for(int offset=-1;offset<=10;++offset){seed(args,data);args[0]=binary(data,length);args[1]=number(offset);compare(args,2,-1);}}
        for(unsigned variation=0;variation<4;++variation)for(int budget=0;budget<24;++budget){unsigned count=seed(args,data);if(variation==1)count=0;else if(variation==2)args[0]=(struct argument){.kind=LUA_TBOOLEAN};else if(variation==3){if(read)args[0]=binary("",0);else args[0]=number(limit+1);}compare(args,count,budget);}
    }
    // Error precedence: malformed later operands beat earlier range failures.
    function_index=16;seed(args,data);args[0]=number(256);args[1]=(struct argument){.kind=LUA_TBOOLEAN};compare(args,2,-1);
    function_index=11;seed(args,data);args[1]=number(48);args[2]=number(49);args[3]=(struct argument){.kind=LUA_TBOOLEAN};compare(args,4,-1);
    // Every optional-offset decision reads the current stack, type and bytes.
    for(function_index=22;function_index<27;++function_index)for(mutation=1;mutation<=4;++mutation){seed(args,data);source_variant=1;compare(args,mutation==4?1:2,-1);}
    mutation=0;source_variant=0;
    function_index=17;for(late_count=0;late_count<=3;++late_count){seed(args,data);compare(args,3,-1);}late_count=-1;
    for(function_index=0;function_index<32;++function_index)for(nested_at=1;nested_at<=9;++nested_at)for(nested_kind=0;nested_kind<4;++nested_kind){unsigned count=seed(args,data);if(function_index>=22 && function_index<27)count=2;if(nested_at==9)count=0;if(nested_at==8 && function_index==21)args[1]=number(0);compare(args,count,-1);}
    function_index=27;nested_at=9;for(nested_kind=0;nested_kind<4;++nested_kind){seed(args,data);args[0]=number(256);compare(args,1,-1);}
    nested_at=nested_kind=0;
    function_index=23;seed(args,data);source_variant=1;mutation=1;eager=true;
    struct snapshot old=invoke(false,args,2,-1),copied=invoke(true,args,2,-1);
    CHECK(!same(&old,&copied) && old.number!=copied.number);++eager_controls;eager=false;mutation=0;source_variant=0;
    SYSTEM_INFO system;GetSystemInfo(&system);uint8_t *page=VirtualAlloc(NULL,2*system.dwPageSize,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(page);DWORD previous;CHECK(VirtualProtect(page+system.dwPageSize,system.dwPageSize,PAGE_NOACCESS,&previous));
    source_variant=2;source_pointer=page+system.dwPageSize;
    for(function_index=22;function_index<27;++function_index){
        seed(args,data);args[0]=binary(data,width(function_index)/8-1);compare(args,1,-1);++guarded;
        const double offsets[]={-9223372036854775808.0,-1,0,2,9223372036854775808.0};
        for(unsigned i=0;i<5;++i){args[0]=binary(data,width(function_index)/8);args[1]=number(offsets[i]);compare(args,2,-1);++guarded;}
    }
    source_variant=0;CHECK(VirtualFree(page,0,MEM_RELEASE));
}
static void abi(void)
{
    zapret_lua_numeric_state state={0};zapret_lua_numeric_action action={.kind=77};zapret_lua_numeric_value value={0};
    CHECK(!zapret_lua_numeric_entry_begin(32,1,&state,&action) && action.kind==77);++boundaries;
    CHECK(!zapret_lua_numeric_entry_begin(0,-1,&state,&action) && action.kind==77);++boundaries;
    CHECK(!zapret_lua_numeric_entry_begin(0,2,NULL,&action) && action.kind==77);++boundaries;
    CHECK(!zapret_lua_numeric_entry_begin(0,2,(void *)(uintptr_t)1,&action));++boundaries;
    CHECK(!zapret_lua_numeric_entry_begin(0,2,&state,NULL));++boundaries;
    CHECK(!zapret_lua_numeric_entry_begin(0,2,&state,(void *)(uintptr_t)1));++boundaries;
    CHECK(zapret_lua_numeric_entry_begin(0,2,&state,&action));
    CHECK(!zapret_lua_numeric_entry_step(NULL,&value,&action));++boundaries;
    CHECK(!zapret_lua_numeric_entry_step(&state,NULL,&action));++boundaries;
    CHECK(!zapret_lua_numeric_entry_step(&state,(void *)(uintptr_t)1,&action));++boundaries;
    CHECK(!zapret_lua_numeric_entry_step(&state,&value,(void *)(uintptr_t)1));++boundaries;
    value.count=2;CHECK(zapret_lua_numeric_entry_step(&state,&value,&action));
    CHECK(!zapret_lua_numeric_entry_step(&state,&value,&action));++boundaries;
    value.numbers=(void *)(uintptr_t)1;CHECK(!zapret_lua_numeric_entry_step(&state,&value,&action));++boundaries;
}
int main(void)
{
    matrix();abi();CHECK(vm_faults && nested_calls && mutable_cases && guarded && eager_controls && nested_boundaries==0x3FE);
    printf("PASS lua_numeric_entry apis=32 cases=%u vm_errors=%u mutable_updates=%u nested_calls=%u nested_boundary_mask=%u eager_copy_controls=%u guarded=%u boundaries=%u fault_cases=%u vm_allocation_faults=%u real_luajit=1 exact_vm_order=1 exact_errors=1 exact_arity=1 vm_allocations_released=1 c_only_unwind=1\n",cases,errors,mutable_cases,nested_calls,nested_boundaries,eager_controls,guarded,boundaries,fault_cases,vm_faults);
    return 0;
}
#else
static volatile uint64_t sink;
static double measure(lua_State *L,lua_CFunction function,const struct argument *args,unsigned count)
{
    LARGE_INTEGER frequency,start,end;QueryPerformanceFrequency(&frequency);QueryPerformanceCounter(&start);
    for(unsigned call=0;call<32768;++call){lua_pushcfunction(L,function);for(unsigned i=0;i<count;++i)push(L,&args[i]);lua_call(L,(int)count,1);sink^=lua_type(L,-1)==LUA_TNUMBER?(uint64_t)lua_tonumber(L,-1):lua_objlen(L,-1);lua_pop(L,1);}
    QueryPerformanceCounter(&end);return (double)(end.QuadPart-start.QuadPart)*1e9/frequency.QuadPart/32768;
}
int main(void)
{
    lua_State *L=luaL_newstate();CHECK(L);CHECK(lua_checkstack(L,128));char data[64];for(unsigned i=0;i<64;++i)data[i]=(char)(i*71+1);struct argument args[102];
    const unsigned indices[]={0,17,17,23,26,27,31,21};
    for(unsigned api=0;api<8;++api){function_index=indices[api];unsigned count=seed(args,data);if(api==1)count=3;if(api==2)count=100;if(api==4)count=2;if(api==7)args[1]=number(0);
        measure(L,resolve(false,function_index),args,count);measure(L,resolve(true,function_index),args,count);
        for(unsigned round=0;round<9;++round){double old,current;if(round&1){current=measure(L,resolve(true,function_index),args,count);old=measure(L,resolve(false,function_index),args,count);}else{old=measure(L,resolve(false,function_index),args,count);current=measure(L,resolve(true,function_index),args,count);}printf("BENCH numeric_entry api=%u round=%u old_ns=%.2f rust_ns=%.2f ratio=%.6f\n",api,round,old,current,current/old);}
    }
    lua_close(L);return 0;
}
#endif
