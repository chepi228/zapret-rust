/* MIT. Actual LuaJIT checks for initialization traversal and VM boundaries. */
#include <iphlpapi.h>
#include "params.h"
#include "engine_lua.h"
#include "nfqws.h"
#include <luajit.h>
#include <stdarg.h>
#undef main
struct params_s params;
_Atomic(sig_atomic_t) bQuit;
static unsigned cases,script_cases,function_cases,sandbox_cases,blob_cases,order_cases,guarded,boundaries,fault_cases,vm_faults,handled_vm_faults,head_repairs,table_repairs;
static unsigned blob_live;
#define CHECK(v) do{if(!(v)){fprintf(stderr,"FAIL Lua startup cases=%u bounds=%u line=%d: %s\n",cases,boundaries,__LINE__,#v);exit(1);}}while(0)
static void *blob_allocate(size_t size){void *out=malloc(size?size:1);if(out)++blob_live;return out;}
static void blob_release(void *value){if(value){CHECK(blob_live);--blob_live;free(value);}}
#define malloc blob_allocate
#define free blob_release
#include "blob_windows.h"
#undef malloc
#undef free
static char diagnostic[65536],opened[8192];
#ifdef ZAPRET_RUST_LUA_SCRIPTS
static lua_State *log_redirect;
#define SCRIPTS_FIXTURE
#else
#define SCRIPTS_FIXTURE static
#endif
static int log_message(const char *format,va_list args){size_t used=strlen(diagnostic);CHECK(used<sizeof(diagnostic));return vsnprintf(diagnostic+used,sizeof(diagnostic)-used,format,args);}
int DLOG(const char *format,...)
{
    va_list args;
    va_start(args,format);
    int out=log_message(format,args);
    va_end(args);
#ifdef ZAPRET_RUST_LUA_SCRIPTS
    if(log_redirect && !strcmp(format,"LUA RUN STR: %s\n"))params.L=log_redirect;
#endif
    return out;
}
int DLOG_ERR(const char *format,...){va_list args;va_start(args,format);int out=log_message(format,args);va_end(args);return out;}
SCRIPTS_FIXTURE bool lua_file_open_test(const char *filename,bool *gzip,char *resolved)
{
    (void)gzip;(void)resolved;size_t used=strlen(opened);CHECK(used+strlen(filename)+2<sizeof(opened));
    strcat(opened,filename);strcat(opened,";");return strncmp(filename,"missing",7)!=0;
}
SCRIPTS_FIXTURE int luaL_doZfile(lua_State *L,const char *filename)
{
    if(!strncmp(filename,"missing",7)){lua_pushfstring(L,"missing fixture file: %s",filename);return LUA_ERRFILE;}
    if(!strcmp(filename,"error"))return luaL_dostring(L,"error('file fixture failure')");
    if(!strcmp(filename,"bad"))return luaL_dostring(L,"this is not valid Lua !");
    if(!strcmp(filename,"quit"))return luaL_dostring(L,"QUIT() TRACE[#TRACE+1]='file quit'");
    return luaL_dostring(L,"TRACE[#TRACE+1]='file executed'");
}
SCRIPTS_FIXTURE void lua_perror(lua_State *L){if(lua_isstring(L,-1))DLOG_ERR("LUA ERROR: %s\n",lua_tostring(L,-1));lua_pop(L,1);}
#undef SCRIPTS_FIXTURE
#define lua_desync_functions_exist reference_functions
#define lua_test_init_script_files reference_files
#define lua_init_scripts(...) reference_scripts(__VA_ARGS__)
#define lua_sec_harden reference_harden
#define lua_init_blobs reference_blobs
#include "lua_startup_reference.inc"
#undef lua_desync_functions_exist
#undef lua_test_init_script_files
#undef lua_init_scripts
#undef lua_sec_harden
#undef lua_init_blobs
#ifdef ZAPRET_RUST_LUA_SCRIPTS
#define lua_test_init_script_files previous_policy_files
#define lua_init_scripts(...) previous_policy_scripts(__VA_ARGS__)
#define lua_desync_functions_exist previous_policy_functions
#endif
#ifdef ZAPRET_RUST_LUA_STARTUP
#define lua_sec_harden previous_policy_harden
#define lua_init_blobs previous_policy_blobs
#endif
#include "lua_startup_windows.inc"
#ifdef ZAPRET_RUST_LUA_SCRIPTS
#undef lua_test_init_script_files
#undef lua_init_scripts
#undef lua_desync_functions_exist
#include "windows_lua_scripts_abi.h"
#endif
#ifdef ZAPRET_RUST_LUA_STARTUP
#undef lua_sec_harden
#undef lua_init_blobs
#include "windows_lua_sandbox_sources.inc"
#endif

static struct str_list scripts[12];
static struct desync_profile_list profiles[4];
static struct func_list rules[12];
static unsigned mode,variant,mutation,observed;
static bool native_side;
static const char *factory=
    "COMMON=function()end function SAME(a,b) if type(a)~=type(b) then return false end if type(a)~='table' then return a==b end "
    "local n=0 for k,v in pairs(a)do n=n+1;if not SAME(v,b[k])then return false end end for _ in pairs(b)do n=n-1 end return n==0 end "
    "function SETUP(id) setmetatable(_G,nil) TRACE={} os={execute=COMMON,keep=17} io={popen=COMMON,keep=19} "
    "package={loadlib=COMMON,loaded={debug=COMMON,keep=23},keep=29} debug={keep=31} "
    "F1=COMMON F2=COMMON F3=false F4=nil b0=nil b1=nil b2=nil "
    "if id==1 then setmetatable(_G,{__index=function(_,k)TRACE[#TRACE+1]='get:'..k;return COMMON end}) "
    "elseif id==2 then setmetatable(_G,{__index=function(_,k)TRACE[#TRACE+1]='get:'..k;error('global lookup failure')end}) "
    "elseif id==3 then setmetatable(_G,{__index=function(_,k)TRACE[#TRACE+1]='mutate:'..k;MUTATE();return COMMON end}) "
    "elseif id==4 then setmetatable(_G,{__newindex=function(t,k,v)TRACE[#TRACE+1]='publish:'..k;OBSERVE();rawset(t,k,v)end}) "
    "elseif id==5 then setmetatable(_G,{__newindex=function(_,k,v)TRACE[#TRACE+1]='publish:'..k;OBSERVE();error('publication failure')end}) "
    "elseif id==6 then os=false elseif id==7 then package.loaded=false "
    "elseif id==8 then setmetatable(package,{__index=function(_,k)TRACE[#TRACE+1]=k;return {}end});package.loaded=nil "
    "elseif id==9 then setmetatable(package,{__index=function(_,k)error('package lookup failure')end});package.loaded=nil end end";
static int quit_function(lua_State *L){(void)L;bQuit=1;return 0;}
static int mutate_function(lua_State *L)
{
    (void)L;++mutation;
    scripts[0].next.le_next=scripts[2].str?&scripts[2]:NULL;
    rules[0].next.le_next=rules[2].func?&rules[2]:NULL;
    return 0;
}
static int observe_function(lua_State *L)
{
    (void)L;CHECK(LIST_FIRST(&params.blobs));++observed;return 0;
}
static void bindings(lua_State *L)
{
    lua_pushcfunction(L,quit_function);lua_setglobal(L,"QUIT");
    lua_pushcfunction(L,mutate_function);lua_setglobal(L,"MUTATE");
    lua_pushcfunction(L,observe_function);lua_setglobal(L,"OBSERVE");
}
static const char *texts[]={"","TRACE[#TRACE+1]='inline'","@normal","@missing","@error","@bad","@quit","QUIT()",
    "MUTATE()","return 1,'kept'","error('inline fixture failure')","this is invalid Lua !"};
static char long_script[513],non_utf8[8]={'-','-',(char)0xff,(char)0xfe,0};
static void prepare(lua_State *L,unsigned seed)
{
    CHECK(!blob_live);memset(&params,0,sizeof(params));params.L=L;params.debug=(seed&1)!=0;
    diagnostic[0]=opened[0]=0;mutation=observed=0;bQuit=0;
    memset(scripts,0,sizeof(scripts));memset(profiles,0,sizeof(profiles));memset(rules,0,sizeof(rules));
    lua_settop(L,0);lua_getglobal(L,"SETUP");lua_pushinteger(L,variant);CHECK(!lua_pcall(L,1,0,0));
    unsigned count=seed%13;
    for(unsigned n=0;n<count;++n){
        scripts[n].str=(char *)texts[(seed+n)%12];scripts[n].next.le_next=n+1<count?&scripts[n+1]:NULL;
    }
    if(seed%7==0 && count)scripts[0].str=long_script;
    if(seed%11==0 && count)scripts[0].str=non_utf8;
    params.lua_init_scripts.lh_first=count?scripts:NULL;
    static const char *names[]={"F1","F2","F3","F4","missing_rule"};
    unsigned pcount=seed%5;
    for(unsigned p=0;p<pcount;++p){
        profiles[p].dp.n=p;profiles[p].next.le_next=p+1<pcount?&profiles[p+1]:NULL;
        unsigned length=(seed+p)%4;
        profiles[p].dp.lua_desync.lh_first=length?&rules[p*3]:NULL;
        for(unsigned n=0;n<length;++n){unsigned index=p*3+n;rules[index].func=(char *)names[(seed+p+n)%5];rules[index].next.le_next=n+1<length?&rules[index+1]:NULL;}
    }
    params.desync_profiles.lh_first=pcount?profiles:NULL;
    unsigned blobs=seed%4;
    for(unsigned n=0;n<blobs;++n){
        uint8_t bytes[4096];for(unsigned k=0;k<sizeof(bytes);++k)bytes[k]=(uint8_t)(k+n);
        size_t size=n==0?0:n==1?17:4096;
        struct blob_item *blob=zapret_blob_add(&params.blobs,&native_blob_allocator,bytes,size,0);CHECK(blob);
        char name[3]={'b',(char)('0'+n),0};blob->name=blob_allocate(sizeof(name));CHECK(blob->name);memcpy(blob->name,name,sizeof(name));
    }
    if(mode==0 && seed%3==0)bQuit=1;
    diagnostic[0]=opened[0]=0;
}
static int invoke(lua_State *L)
{
    bool result=true;
    switch(mode){
        case 0:result=(native_side?lua_init_scripts:reference_scripts)();break;
        case 1:result=(native_side?lua_test_init_script_files:reference_files)();break;
        case 2:result=(native_side?lua_desync_functions_exist:reference_functions)();break;
        case 3:(native_side?lua_sec_harden:reference_harden)();break;
        case 4:(native_side?lua_init_blobs:reference_blobs)();break;
        default:CHECK(false);
    }
    lua_pushboolean(L,result);return lua_gettop(L);
}
struct sample {int status,reference,stack;char error[1024],log[65536],files[8192];unsigned live,mutations,observations;int quit;};
static struct sample left,right;
static void execute(lua_State *L,unsigned seed,bool native,struct sample *out)
{
    native_side=native;prepare(L,seed);lua_pushcfunction(L,invoke);out->status=lua_pcall(L,0,LUA_MULTRET,0);out->error[0]=0;
    if(out->status){snprintf(out->error,sizeof(out->error),"%s",lua_tostring(L,-1));lua_settop(L,0);}
    out->stack=lua_gettop(L);lua_newtable(L);
    for(int index=1;index<=out->stack;++index){lua_pushvalue(L,index);lua_rawseti(L,-2,index);}
    lua_newtable(L);lua_pushvalue(L,-2);lua_setfield(L,-2,"results");
    const char *globals[]={"TRACE","os","io","package","debug","b0","b1","b2"};
    for(unsigned n=0;n<sizeof(globals)/sizeof(*globals);++n){lua_pushvalue(L,LUA_GLOBALSINDEX);lua_pushstring(L,globals[n]);lua_rawget(L,-2);lua_remove(L,-2);lua_setfield(L,-2,globals[n]);}
    lua_newtable(L);unsigned n=0;struct blob_item *blob;
    LIST_FOREACH(blob,&params.blobs,next){lua_pushstring(L,blob->name);lua_rawseti(L,-2,++n);}
    lua_setfield(L,-2,"remaining");out->reference=luaL_ref(L,LUA_REGISTRYINDEX);lua_settop(L,0);
    strcpy(out->log,diagnostic);strcpy(out->files,opened);out->live=blob_live;out->mutations=mutation;out->observations=observed;out->quit=bQuit;
    zapret_blob_destroy_list(&params.blobs,&native_blob_allocator);CHECK(!blob_live);
}
static void compare(lua_State *L,unsigned seed)
{
    if(getenv("ZAPRET_STARTUP_TRACE") && (cases%256==0 || mode==3)){fprintf(stderr,"CASE %u mode=%u seed=%u variant=%u\n",cases,mode,seed,variant);fflush(stderr);}
    execute(L,seed,false,&left);execute(L,seed,true,&right);
    if(left.status!=right.status || strcmp(left.error,right.error)||strcmp(left.log,right.log)||strcmp(left.files,right.files)){
        fprintf(stderr,"DETAIL mode=%u seed=%u variant=%u status=%d/%d error=%s/%s\noldlog=%s\nnewlog=%s\n",mode,seed,variant,left.status,right.status,left.error,right.error,left.log,right.log);CHECK(false);
    }
    CHECK(left.stack==right.stack && left.live==right.live && left.quit==right.quit && left.mutations==right.mutations && left.observations==right.observations);
    lua_getglobal(L,"SAME");lua_rawgeti(L,LUA_REGISTRYINDEX,left.reference);lua_rawgeti(L,LUA_REGISTRYINDEX,right.reference);CHECK(!lua_pcall(L,2,1,0));CHECK(lua_toboolean(L,-1));lua_settop(L,0);
    luaL_unref(L,LUA_REGISTRYINDEX,left.reference);luaL_unref(L,LUA_REGISTRYINDEX,right.reference);
    ++cases;if(mode<=1)++script_cases;else if(mode==2)++function_cases;else if(mode==3)++sandbox_cases;else ++blob_cases;
}

#ifdef ZAPRET_RUST_LUA_SCRIPTS
static void late_vm_read(lua_State *original)
{
    lua_State *redirected=luaL_newstate();
    CHECK(redirected);
    char text[]="return 'redirected'";
    struct str_list script={.str=text};
    mode=0;
    for(unsigned side=0;side<2;++side){
        native_side=side!=0;
        params.lua_init_scripts.lh_first=&script;
        params.debug=true;
        params.L=original;
        bQuit=0;
        log_redirect=redirected;
        diagnostic[0]=0;
        lua_settop(original,0);
        lua_settop(redirected,0);
        lua_pushcfunction(original,invoke);
        CHECK(!lua_pcall(original,0,LUA_MULTRET,0));
        CHECK(lua_gettop(original)==1 && lua_toboolean(original,-1));
        CHECK(lua_gettop(redirected)==1 && !strcmp(lua_tostring(redirected,-1),"redirected"));
        CHECK(params.L==redirected && strstr(diagnostic,"LUA RUN STR:"));
    }
    log_redirect=NULL;
    params.lua_init_scripts.lh_first=NULL;
    params.L=original;
    lua_close(redirected);
}
#endif

/* Exact phase order is checked without letting basic_init replace this VM. */
static unsigned order_trace[32],order_used,fail_phase,dirty_phase;
static void order_event(unsigned event){CHECK(order_used<32);order_trace[order_used++]=event;if(event==dirty_phase)lua_pushnil(params.L);}
#ifdef ZAPRET_RUST_LUA_STARTUP
#define BOOT_FIXTURE
void boot_publish(lua_State *lua){CHECK(lua==params.L);order_event(7);}
#else
#define BOOT_FIXTURE static
#endif
BOOT_FIXTURE bool boot_basic(void){order_event(1);return fail_phase!=1;}
BOOT_FIXTURE void boot_harden(void){order_event(2);}
BOOT_FIXTURE void boot_blobs(void){order_event(3);}
BOOT_FIXTURE void boot_constants(void){order_event(4);}
BOOT_FIXTURE void boot_functions(void){order_event(5);}
BOOT_FIXTURE void boot_mt(void){order_event(6);}
BOOT_FIXTURE bool boot_scripts(void){order_event(8);return fail_phase!=8;}
BOOT_FIXTURE bool boot_exists(void){order_event(9);return fail_phase!=9;}
BOOT_FIXTURE void boot_shutdown(void){order_event(10);}
#undef BOOT_FIXTURE
#define lua_basic_init boot_basic
#define lua_sec_harden boot_harden
#define lua_init_blobs boot_blobs
#define lua_init_const boot_constants
#define lua_init_functions boot_functions
#define lua_init_mt boot_mt
#define lua_init_scripts boot_scripts
#define lua_desync_functions_exist boot_exists
#define lua_shutdown boot_shutdown
#define zapret_lua_vm_publish(L,callback) order_event(7)
#define lua_init reference_init
#include "lua_startup_order_reference.inc"
#undef lua_init
#ifndef ZAPRET_RUST_LUA_STARTUP
#include "lua_startup_order_windows.inc"
#endif
#undef lua_basic_init
#undef lua_sec_harden
#undef lua_init_blobs
#undef lua_init_const
#undef lua_init_functions
#undef lua_init_mt
#undef lua_init_scripts
#undef lua_desync_functions_exist
#undef lua_shutdown
#undef zapret_lua_vm_publish
#ifdef ZAPRET_RUST_LUA_STARTUP
#include "windows_lua_startup_abi.h"
#endif
static int order_call(lua_State *L){lua_pushboolean(L,(native_side?lua_init:reference_init)());return 1;}
static void order_checks(lua_State *L)
{
    for(fail_phase=0;fail_phase<12;++fail_phase)for(dirty_phase=0;dirty_phase<12;++dirty_phase){
        unsigned expected[32],count=0;int status[2],result[2];char errors[2][256],logs[2][65536];
        for(unsigned side=0;side<2;++side){native_side=side!=0;params.L=L;lua_settop(L,0);diagnostic[0]=0;order_used=0;
            lua_pushcfunction(L,order_call);status[side]=lua_pcall(L,0,1,0);result[side]=lua_toboolean(L,-1);
            errors[side][0]=0;if(status[side])snprintf(errors[side],256,"%s",lua_tostring(L,-1));strcpy(logs[side],diagnostic);
            if(!side){count=order_used;memcpy(expected,order_trace,sizeof(expected));}else CHECK(order_used==count && !memcmp(expected,order_trace,count*sizeof(unsigned)));
        }
        CHECK(status[0]==status[1] && result[0]==result[1] && !strcmp(errors[0],errors[1]) && !strcmp(logs[0],logs[1]));++order_cases;
    }lua_settop(L,0);
}
struct allocator {bool armed;unsigned calls,fail_after,rejected,live;};
static void *allocate(void *context,void *pointer,size_t previous,size_t next)
{
    struct allocator *a=context;if(!next){if(pointer){CHECK(a->live);--a->live;}free(pointer);return NULL;}
    if(a->armed && next>previous && a->calls++>=a->fail_after){++a->rejected;return NULL;}
    bool fresh=!pointer;void *out=realloc(pointer,next);if(out && fresh)++a->live;return out;
}
static void fault_checks(void)
{
    for(mode=0;mode<5;++mode)for(unsigned limit=0;limit<24;++limit)for(unsigned side=0;side<2;++side){
        struct allocator a={.fail_after=limit};lua_State *L=lua_newstate(allocate,&a);CHECK(L);luaL_openlibs(L);
        CHECK(!luaL_dostring(L,factory));bindings(L);variant=mode==4?4:0;native_side=side!=0;prepare(L,11);bQuit=0;
        lua_pushcfunction(L,invoke);a.armed=true;int status=lua_pcall(L,0,LUA_MULTRET,0);a.armed=false;
        if(status){CHECK(status==LUA_ERRMEM && a.rejected);++vm_faults;}
        else if(a.rejected){CHECK(mode==0 && lua_isboolean(L,-1) && !lua_toboolean(L,-1));++handled_vm_faults;}
        zapret_blob_destroy_list(&params.blobs,&native_blob_allocator);CHECK(!blob_live);lua_close(L);CHECK(!a.live);++fault_cases;
    }
    CHECK(vm_faults+handled_vm_faults>=16);
}
static void boundary_checks(void)
{
    _Alignas(8) uint8_t storage[512]={0};zapret_lua_script script;zapret_lua_scripts cursor={0};zapret_lua_functions functions={0};zapret_lua_harden_path path;zapret_lua_blob_view blob;const char *name=NULL;uint32_t index=0;
#define BOUND(v) do{CHECK(v);++boundaries;}while(0)
    BOUND(!zapret_lua_script_view(NULL,true,&script));BOUND(!zapret_lua_script_view("",true,NULL));
    BOUND(!zapret_lua_script_view("",true,(void *)(storage+1)));BOUND(zapret_lua_script_next(NULL,false,false,&script)==2);
    BOUND(zapret_lua_script_next(&cursor,false,false,NULL)==2);BOUND(zapret_lua_script_next(&cursor,true,true,&script)==0);
    cursor.current=(void *)(storage+1);BOUND(zapret_lua_script_next(&cursor,false,false,&script)==2);
    BOUND(zapret_lua_function_next(NULL,&name)==2);BOUND(zapret_lua_function_next(&functions,NULL)==2);BOUND(zapret_lua_function_next(&functions,&name)==0);
    functions.profile=(void *)(storage+1);BOUND(zapret_lua_function_next(&functions,&name)==2);
    BOUND(zapret_lua_harden_next(NULL,&path)==2);BOUND(zapret_lua_harden_next(&index,NULL)==2);index=6;BOUND(zapret_lua_harden_next(&index,&path)==2);
    BOUND(zapret_lua_startup_blob(NULL,&blob)==2);BOUND(zapret_lua_startup_blob(&params.blobs,NULL)==2);
    BOUND(!zapret_lua_startup_blob_commit(NULL,NULL,&native_blob_allocator));
    BOUND(zapret_lua_startup_step(NULL,true)==11);index=11;BOUND(zapret_lua_startup_step(&index,true)==11);
    lua_State *L=luaL_newstate();CHECK(L);luaL_openlibs(L);CHECK(!luaL_dostring(L,factory));bindings(L);mode=4;variant=0;prepare(L,3);
    CHECK(zapret_lua_startup_blob(&params.blobs,&blob)==1);struct blob_item *saved=LIST_FIRST(&params.blobs);
    BOUND(!zapret_lua_startup_blob_commit(&params.blobs,saved->next.le_next,&native_blob_allocator));CHECK(LIST_FIRST(&params.blobs)==saved);++head_repairs;
    zapret_blob_destroy_list(&params.blobs,&native_blob_allocator);CHECK(!blob_live);lua_close(L);
#undef BOUND
}
static void guarded_checks(void)
{
    uint8_t *memory=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(memory);
    uint8_t *end=memory+4096;DWORD protection;CHECK(VirtualProtect(end,4096,PAGE_NOACCESS,&protection));
    const char *texts[]={"","@","@file","--","\xff","inline"};
    for(unsigned n=0;n<6;++n)for(unsigned debug=0;debug<2;++debug){
        size_t length=strlen(texts[n])+1;char *text=(char *)end-length;memcpy(text,texts[n],length);
        CHECK(VirtualProtect(memory,4096,PAGE_READONLY,&protection));zapret_lua_script out;
        CHECK(zapret_lua_script_view(text,debug,&out));CHECK(out.file==(texts[n][0]=='@'));++guarded;
        CHECK(VirtualProtect(memory,4096,PAGE_READWRITE,&protection));
    }
    for(unsigned size=127;size<=512;++size){char *text=(char *)end-size;memset(text,'x',size);
        CHECK(VirtualProtect(memory,4096,PAGE_READONLY,&protection));zapret_lua_script out;
        CHECK(zapret_lua_script_view(text,true,&out));CHECK(out.preview[127]==0);++guarded;
        CHECK(VirtualProtect(memory,4096,PAGE_READWRITE,&protection));
    }
    CHECK(VirtualFree(memory,0,MEM_RELEASE));
}
int main(void)
{
    memset(long_script,'x',sizeof(long_script));long_script[0]='-';long_script[1]='-';long_script[512]=0;
    lua_State *L=luaL_newstate();CHECK(L);luaL_openlibs(L);luaJIT_setmode(L,0,LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);
    CHECK(!luaL_dostring(L,factory));bindings(L);
    // rawset on a non-table is undefined in the C API and crashes the pinned
    // implementation. Check these deliberate corruptions only against the
    // guarded adapter, after the defined-behavior differential matrix.
    for(mode=0;mode<5;++mode)for(unsigned seed=0;seed<192;++seed)for(variant=0;variant<10;++variant){
        if(mode==3 && (variant==6 || variant==7))continue;
        compare(L,seed);
    }
    mode=3;for(variant=6;variant<=7;++variant){
        execute(L,0,true,&right);CHECK(right.status==LUA_ERRRUN && strstr(right.error,"invalid sandbox table"));
        luaL_unref(L,LUA_REGISTRYINDEX,right.reference);++table_repairs;
    }
#ifdef ZAPRET_RUST_LUA_SCRIPTS
    late_vm_read(L);
#endif
    order_checks(L);lua_close(L);fault_checks();boundary_checks();guarded_checks();
#ifdef ZAPRET_RUST_LUA_STARTUP
    printf("PASS windows_lua_startup late_vm_read=1 rust_seh_unwind=1 direct_sandbox=1 direct_order=1 ");
#elif defined(ZAPRET_RUST_LUA_SCRIPTS)
    printf("PASS windows_lua_scripts late_vm_read=1 rust_seh_unwind=1 ");
#else
    printf("PASS lua_startup ");
#endif
    printf("functions=6 cases=%u scripts=%u functions_checked=%u sandbox=%u blobs=%u order_cases=%u guarded=%u boundaries=%u vm_allocation_faults=%u handled_vm_faults=%u fault_cases=%u blob_head_repairs=%u sandbox_table_repairs=%u real_luajit=1 lazy_lookup_order=1 blob_allocations_released=1 vm_allocations_released=1\n",cases,script_cases,function_cases,sandbox_cases,blob_cases,order_cases,guarded,boundaries,vm_faults,handled_vm_faults,fault_cases,head_repairs,table_repairs);
    return 0;
}
