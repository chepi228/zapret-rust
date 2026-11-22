/* MIT. Main preparation, C VM boundary, cleanup order and mutex release ownership. */
#include "params.h"
#include <setjmp.h>
#include <stdarg.h>
#undef main
static unsigned prepare_cases,cleanup_cases,mutex_cases,boundaries,reentries,real_cycles;
#define CHECK(value) do{if(!(value)){fprintf(stderr,"FAIL lifecycle prepare=%u cleanup=%u mutex=%u boundaries=%u line=%d: %s\n",prepare_cases,cleanup_cases,mutex_cases,boundaries,__LINE__,#value);exit(1);}}while(0)
struct state{struct params_s fields;bool vm_live,detached,reenter,release_fail;unsigned used,trace[64],init_count,freed;HANDLE guard;uint32_t observed[5];char log[256];};
static struct state *active;static jmp_buf legacy_jump;
static void trace(unsigned value){CHECK(active->used<64);active->trace[active->used++]=value;}
static bool real_release(void *handle){return ReleaseMutex(handle)!=0;}
static void real_close(void *handle){CHECK(CloseHandle(handle));}
#define lua_shutdown model_lua_shutdown
#define cleanup_args model_args
#define ConntrackPoolDestroy model_conntrack
#define dp_list_destroy model_profiles
#define zapret_list_files_destroy model_registry
#define ipcacheDestroy model_cache
#define blob_collection_destroy model_blobs
#define strlist_destroy model_strings
#define TimerPoolDestroy model_timers
#define cleanup_windivert_portfilters model_filters
#define free model_free
static void lua_shutdown(void){trace(0);active->vm_live=false;}
static void cleanup_args(void *value){CHECK(!active->vm_live && value==&active->fields);trace(1);}
static void ConntrackPoolDestroy(void *value){CHECK(!active->vm_live && value==&active->fields.conntrack);trace(2);}
static void dp_list_destroy(void *value){CHECK(!active->vm_live);if(value==&active->fields.desync_profiles)trace(3);else{CHECK(value==&active->fields.desync_templates);trace(4);}}
static void zapret_list_files_destroy(void *value){CHECK(!active->vm_live);if(value==&active->fields.hostlists)trace(5);else{CHECK(value==&active->fields.ipsets);trace(6);}}
static void ipcacheDestroy(void *value){CHECK(!active->vm_live && value==&active->fields.ipcache);trace(7);}
static void blob_collection_destroy(void *value){CHECK(!active->vm_live && value==&active->fields.blobs);trace(8);}
static void strlist_destroy(void *value){CHECK(!active->vm_live);if(value==&active->fields.lua_init_scripts)trace(9);else if(value==&active->fields.ssid_filter)trace(11);else if(value==&active->fields.nlm_filter)trace(12);else{CHECK(value==&active->fields.wf_raw_part);trace(13);}}
static void TimerPoolDestroy(void *value){CHECK(!active->vm_live && value==&active->fields.timers);trace(10);}
static void cleanup_windivert_portfilters(void *value){CHECK(!active->vm_live && value==&active->fields);trace(14);strlist_destroy(&active->fields.wf_raw_part);}
static void free(void *value){if(value){CHECK(!active->vm_live && value==(void *)(uintptr_t)0x1234);active->detached=active->fields.windivert_filter==NULL;++active->freed;trace(16);}}
#define cleanup_params reference_cleanup_params
#include "engine_cleanup_reference.inc"
#undef cleanup_params
#include "engine_cleanup_windows.inc"
static zapret_lifecycle_state cleanup_target(void){struct params_s *value=&active->fields;zapret_lifecycle_state target={value,&value->conntrack,&value->desync_profiles,&value->desync_templates,&value->hostlists,&value->ipsets,&value->ipcache,&value->blobs,&value->lua_init_scripts,&value->timers,&value->ssid_filter,&value->nlm_filter,&value->wf_raw_part,(void **)&value->windivert_filter};return target;}
#define params (active->fields)
#define DLOG model_debug
#define DLOG_CONDUP model_console
#define DLOG_ERR model_debug
#define ConntrackPoolInit model_init
static int model_log(char sink, const char *format, va_list args)
{
    if(strstr(format,"command line parameters"))trace(20);
    else if(strstr(format,"conntrack disabled"))trace(21);
    else if(strstr(format,"initializing conntrack"))trace(22);
    else if(strstr(format,"ipcache lifetime"))trace(23);
    size_t used=strlen(active->log);
    CHECK(used+1<sizeof(active->log));
    active->log[used++]=sink;
    int written=vsnprintf(active->log+used,sizeof(active->log)-used,format,args);
    CHECK(written>=0 && (size_t)written<sizeof(active->log)-used);
    return written;
}
int model_debug(const char *format,...)
{
    va_list args;va_start(args,format);
    int written=model_log('D',format,args);
    va_end(args);return written;
}
int model_console(const char *format,...)
{
    va_list args;va_start(args,format);
    int written=model_log('C',format,args);
    va_end(args);return written;
}
void ConntrackPoolInit(void *pool,time_t bins,uint32_t syn,uint32_t established,uint32_t fin,uint32_t udp){CHECK(pool==&params.conntrack && bins==10);trace(24);++active->init_count;active->observed[0]=(uint32_t)bins;active->observed[1]=syn;active->observed[2]=established;active->observed[3]=fin;active->observed[4]=udp;}
#define ReleaseMutex model_release_mutex
#define CloseHandle model_close_handle
static bool reenter_mutex(void);
BOOL WINAPI ReleaseMutex(HANDLE handle){CHECK(!active->vm_live && handle==(HANDLE)(uintptr_t)0x5555);trace(17);if(active->reenter){CHECK(!active->guard && reenter_mutex());++reentries;}return !active->release_fail;}
BOOL WINAPI CloseHandle(HANDLE handle){CHECK(!active->vm_live && handle==(HANDLE)(uintptr_t)0x5555);trace(18);return TRUE;}
static void exit_clean(int code){CHECK(!code);longjmp(legacy_jump,1);}
static bool legacy_prepare(bool bDry){if(setjmp(legacy_jump))return true;
#include "engine_prepare_reference.inc"
    return false;
}
#include "engine_lifecycle_windows.inc"
#include "engine_main_lifecycle_abi.h"
static const zapret_lifecycle_main_ops main_ops={native_lifecycle_conntrack,DLOG,DLOG_CONDUP};
static const zapret_lifecycle_mutex_ops mutex_ops={native_lifecycle_mutex_release,native_lifecycle_mutex_close};
static bool reenter_mutex(void){return zapret_lifecycle_release_mutex(&active->guard,&mutex_ops);}
static zapret_lifecycle_input prepare_target(bool dry){zapret_lifecycle_input value={&params.conntrack,{params.ctrack_t_syn,params.ctrack_t_est,params.ctrack_t_fin,params.ctrack_t_udp},params.ipcache_lifetime,dry,params.ctrack_disable};return value;}
static void same(const struct state *a,const struct state *b){CHECK(a->used==b->used && !memcmp(a->trace,b->trace,a->used*sizeof(unsigned)) && a->init_count==b->init_count && !memcmp(a->observed,b->observed,sizeof(a->observed)) && a->freed==b->freed && a->fields.windivert_filter==b->fields.windivert_filter);CHECK(!strcmp(a->log,b->log));}
static void prepare_checks(void)
{
    const uint32_t values[]={0,1,60,UINT32_MAX};
    for(unsigned repeat=0;repeat<16;++repeat)for(unsigned flags=0;flags<4;++flags)for(unsigned v=0;v<4;++v){struct state a={0},b={0},c={0};a.fields.ctrack_disable=b.fields.ctrack_disable=c.fields.ctrack_disable=flags&2;
        a.fields.ctrack_t_syn=b.fields.ctrack_t_syn=c.fields.ctrack_t_syn=values[v];a.fields.ctrack_t_est=b.fields.ctrack_t_est=c.fields.ctrack_t_est=values[(v+1)%4];a.fields.ctrack_t_fin=b.fields.ctrack_t_fin=c.fields.ctrack_t_fin=values[(v+2)%4];a.fields.ctrack_t_udp=b.fields.ctrack_t_udp=c.fields.ctrack_t_udp=values[(v+3)%4];a.fields.ipcache_lifetime=b.fields.ipcache_lifetime=c.fields.ipcache_lifetime=values[v];
        struct state rust=c;
        active=&a;bool dry=legacy_prepare(flags&1);active=&b;zapret_lifecycle_input input=prepare_target(flags&1);unsigned result=zapret_lifecycle_prepare(&input,&main_ops);active=&c;unsigned adapted=native_lifecycle_prepare(flags&1);CHECK(result==adapted && result==(dry?8u:0u));same(&a,&b);same(&b,&c);
        active=&rust;CHECK(zapret_native_lifecycle_prepare(&rust.fields,flags&1)==result);same(&c,&rust);++prepare_cases;
    }
}
static void cleanup_checks(void)
{
    for(unsigned repeat=0;repeat<64;++repeat)for(unsigned owned=0;owned<2;++owned){struct state a={0},b={0},c={0};a.vm_live=b.vm_live=c.vm_live=true;if(owned)a.fields.windivert_filter=b.fields.windivert_filter=c.fields.windivert_filter=(char *)(uintptr_t)0x1234;
        for(unsigned pass=0;pass<2;++pass){active=&a;reference_cleanup_params(&a.fields);active=&b;cleanup_params(&b.fields);active=&c;lua_shutdown();zapret_lifecycle_state target=cleanup_target();CHECK(zapret_lifecycle_cleanup(&target,&native_cleanup_ops));same(&a,&b);same(&b,&c);}
        CHECK(!b.vm_live && !b.fields.windivert_filter && b.freed==owned && c.freed==owned && (!owned || (b.detached && c.detached)));++cleanup_cases;
    }
}
static void mutex_checks(void)
{
    for(unsigned owned=0;owned<2;++owned)for(unsigned fail=0;fail<2;++fail){struct state a={0},b={0};a.release_fail=b.release_fail=fail;if(owned)a.guard=b.guard=(HANDLE)(uintptr_t)0x5555;
        active=&a;HANDLE hMutexArg=a.guard;
#include "engine_mutex_reference.inc"
        struct state rust=b;
        a.guard=NULL;active=&b;native_lifecycle_release_mutex(&b.guard);CHECK(!b.guard && a.used==b.used && !memcmp(a.trace,b.trace,a.used*sizeof(unsigned)));native_lifecycle_release_mutex(&b.guard);CHECK(a.used==b.used);
        active=&rust;zapret_native_lifecycle_release_mutex(&rust.guard);zapret_native_lifecycle_release_mutex(&rust.guard);CHECK(!rust.guard);same(&a,&rust);++mutex_cases;
    }
    struct state value={0};active=&value;value.guard=(HANDLE)(uintptr_t)0x5555;value.reenter=true;native_lifecycle_release_mutex(&value.guard);CHECK(!value.guard && value.used==2 && reentries==1);
    const zapret_lifecycle_mutex_ops real_ops={real_release,real_close};DWORD before,after;CHECK(GetProcessHandleCount(GetCurrentProcess(),&before));
    for(unsigned i=0;i<32;++i){HANDLE handle=CreateMutexA(NULL,TRUE,NULL);CHECK(handle && zapret_lifecycle_release_mutex(&handle,&real_ops) && !handle);++real_cycles;}CHECK(GetProcessHandleCount(GetCurrentProcess(),&after) && before==after);
}
static void boundary_checks(void)
{
    struct state value={0};active=&value;zapret_lifecycle_input input=prepare_target(false);_Alignas(8)unsigned char storage[256]={0};
    CHECK(zapret_lifecycle_prepare(NULL,&main_ops)==1 && !value.used);++boundaries;CHECK(zapret_lifecycle_prepare(&input,NULL)==1 && !value.used);++boundaries;CHECK(zapret_lifecycle_prepare((void *)(storage+1),&main_ops)==1 && !value.used);++boundaries;
    zapret_lifecycle_state target=cleanup_target();CHECK(!zapret_lifecycle_cleanup(NULL,&native_cleanup_ops) && !value.used);++boundaries;CHECK(!zapret_lifecycle_cleanup(&target,NULL) && !value.used);++boundaries;CHECK(!zapret_lifecycle_cleanup((void *)(storage+1),&native_cleanup_ops) && !value.used);++boundaries;
    void **slots=(void **)&target;for(unsigned i=0;i<14;++i){target=cleanup_target();slots[i]=NULL;CHECK(!zapret_lifecycle_cleanup(&target,&native_cleanup_ops) && !value.used);++boundaries;}
    target=cleanup_target();target.capture=(void *)(storage+1);CHECK(!zapret_lifecycle_cleanup(&target,&native_cleanup_ops) && !value.used);++boundaries;
    zapret_lifecycle_drop_ops missing={0};target=cleanup_target();CHECK(!zapret_lifecycle_cleanup(&target,&missing) && !value.used);++boundaries;
    missing=native_cleanup_ops;missing.timers=NULL;CHECK(!zapret_lifecycle_cleanup(&target,&missing) && !value.used);++boundaries;
    CHECK(!zapret_lifecycle_release_mutex(NULL,&mutex_ops) && !value.used);++boundaries;CHECK(!zapret_lifecycle_release_mutex(&value.guard,NULL) && !value.used);++boundaries;CHECK(!zapret_lifecycle_release_mutex((void *)(storage+1),&mutex_ops) && !value.used);++boundaries;
}
int main(void){prepare_checks();cleanup_checks();mutex_checks();boundary_checks();printf("PASS engine_lifecycle prepare_cases=%u cleanup_cases=%u mutex_cases=%u boundaries=%u reentrant_releases=%u real_private_cycles=%u cleanup_vm_closed=1 c_bridge=1 rust_entry=1 handle_counts_preserved=1 exact_log_bytes=1 typed_cleanup=1\n",prepare_cases,cleanup_cases,mutex_cases,boundaries,reentries,real_cycles);return 0;}
