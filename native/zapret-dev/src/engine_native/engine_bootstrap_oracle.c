/* MIT. No driver, process control, VM or environment mutations in this oracle. */
#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#undef main
static unsigned cases,bridge_cases,zero_error_repairs,boundaries;
#define CHECK(value) do {if(!(value)){fprintf(stderr,"FAIL bootstrap cases=%u bridges=%u line=%d: %s\n",cases,bridge_cases,__LINE__,#value);exit(1);}}while(0)
static struct {bool daemon;char pidfile[32];bool intercept;int ssid_filter,nlm_filter;bool ssid_filter_neg,nlm_filter_neg;} params;
static uint32_t w_win32_error;
typedef struct {BYTE bytes[80];} WINDIVERT_ADDRESS;
#define ZAPRET_CAPTURE_ADDRESS_COUNT 128
static const int capture_ops=123;
struct state {unsigned used,trace[16],failure,event;uint32_t error,report_error;int capture;const char *environment;};
static struct state *active;
static void trace(unsigned step){CHECK(active->used<16);active->trace[active->used++]=step;}
static void daemonize(void){trace(1);}
static bool writepid(const char *name){CHECK(!strcmp(name,"fixture.pid"));trace(2);return active->failure!=1;}
static const char *mock_getenv(const char *name){CHECK(!strcmp(name,"ZAPRET_RING_SELFTEST"));trace(3);return active->environment;}
static bool win_sandbox(void){trace(4);return active->failure!=2;}
static bool lua_init(void){trace(5);return active->failure!=3;}
static void NoInterceptLoop(void){trace(6);}
static bool win_dark_init(const void *ssid,bool ssid_neg,const void *network,bool network_neg){CHECK(ssid==&params.ssid_filter && network==&params.nlm_filter && !ssid_neg && !network_neg);trace(7);if(active->failure==4){w_win32_error=active->error;return false;}return true;}
static int zapret_capture_loop(const void *ops,void *addresses,bool intercept){CHECK(ops==&capture_ops && addresses && intercept==params.intercept);trace(9);return active->capture;}
static void win_dark_deinit(void){trace(10);}
static void lua_shutdown(void){trace(11);}
static void rawsend_cleanup(void){trace(12);}
static void original_report(const char *format,...)
{
    va_list arguments;va_start(arguments,format);
    if(!strcmp(format,"could not write pidfile")){trace(13);active->event=0;active->report_error=ERROR_TOO_MANY_OPEN_FILES;}
    else {CHECK(!strcmp(format,"win_dark_init failed. win32 error %u (0x%08X)\n"));trace(14);active->event=1;active->report_error=va_arg(arguments,unsigned int);CHECK(va_arg(arguments,unsigned int)==active->report_error);}
    va_end(arguments);
}
#undef getenv
#define getenv mock_getenv
#define DLOG_ERR original_report
#define win_main reference_win_main
#include "engine_bootstrap_reference.inc"
#undef win_main
#include "engine_bootstrap_windows.inc"
static bool pid_step(void){return writepid(params.pidfile);}
static bool selftest_step(void){const char *value=mock_getenv("ZAPRET_RING_SELFTEST");return value && !strcmp(value,"1");}
static bool network_step(void){return win_dark_init(&params.ssid_filter,false,&params.nlm_filter,false);}
static uint32_t error_step(void){return w_win32_error;}
static int capture_step(void){WINDIVERT_ADDRESS addresses[128];return zapret_capture_loop(&capture_ops,addresses,params.intercept);}
static void report_step(uint32_t event,uint32_t error){if(!event){trace(13);active->event=0;}else{trace(14);active->event=1;}active->report_error=error;}
static const zapret_boot_ops ops={daemonize,pid_step,selftest_step,win_sandbox,lua_init,NoInterceptLoop,network_step,error_step,capture_step,win_dark_deinit,lua_shutdown,rawsend_cleanup,report_step};
static bool same(const struct state *left,const struct state *right)
{return left->used==right->used && !memcmp(left->trace,right->trace,left->used*sizeof(unsigned)) && left->event==right->event;}
static void compare(bool daemon,bool pid,bool intercept,const char *environment,unsigned failure,uint32_t error,int capture)
{
    params.daemon=daemon;strcpy(params.pidfile,pid?"fixture.pid":"");params.intercept=intercept;
    struct state left={0},right={0},bridge={0};left.failure=failure;left.error=error;left.capture=capture;left.environment=environment;right=bridge=left;
    active=&left;w_win32_error=0xabcdef;int expected=reference_win_main();
    zapret_boot_input input={daemon,pid,intercept};active=&right;w_win32_error=0xabcdef;int result=zapret_engine_bootstrap(&input,&ops);
    active=&bridge;w_win32_error=0xabcdef;int adapted=win_main();
    CHECK(same(&left,&right) && same(&right,&bridge) && result==adapted && right.report_error==bridge.report_error);
    bool failed_network=false;for(unsigned i=0;i<left.used;++i)failed_network|=left.trace[i]==14;
    if(failed_network && !error){CHECK(!expected && result==ERROR_GEN_FAILURE && !left.report_error && right.report_error==ERROR_GEN_FAILURE);++zero_error_repairs;}
    else CHECK(expected==result && left.report_error==right.report_error);
    ++cases;++bridge_cases;
}
int main(void)
{
    const char *environment[]={NULL,"","1","01","true"};const uint32_t errors[]={0,ERROR_ACCESS_DENIED,ERROR_INVALID_HANDLE,ERROR_INVALID_PARAMETER,ERROR_GEN_FAILURE,ERROR_OUTOFMEMORY,0x80000000u,UINT32_MAX};const int captures[]={0,1,4,5,87,INT32_MAX,INT32_MIN,-1};
    for(unsigned daemon=0;daemon<2;++daemon)for(unsigned pid=0;pid<2;++pid)for(unsigned intercept=0;intercept<2;++intercept)for(unsigned env=0;env<5;++env)for(unsigned failure=0;failure<5;++failure)for(unsigned error=0;error<8;++error)for(unsigned capture=0;capture<8;++capture)compare(daemon,pid,intercept,environment[env],failure,errors[error],captures[capture]);
    struct state value={0};active=&value;zapret_boot_input input={0};CHECK(zapret_engine_bootstrap(NULL,&ops)==ERROR_INVALID_PARAMETER && !value.used);++boundaries;CHECK(zapret_engine_bootstrap(&input,NULL)==ERROR_INVALID_PARAMETER && !value.used);++boundaries;
    printf("PASS engine_bootstrap functions=1 cases=%u c_bridge_cases=%u zero_error_repairs=%u boundaries=%u\n",cases,bridge_cases,zero_error_repairs,boundaries);return 0;
}
