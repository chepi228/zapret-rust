/* MIT. Startup option actions and allocation faults without real file changes. */
#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <errno.h>
#undef main
static unsigned cases,atomic_repairs,close_repairs,boundaries,allocation_faults;
#define CHECK(value) do {if(!(value)){fprintf(stderr,"FAIL startup option cases=%u bounds=%u line=%d: %s\n",cases,boundaries,__LINE__,#value);exit(1);}}while(0)
enum log_target {LOG_TARGET_CONSOLE,LOG_TARGET_FILE,LOG_TARGET_SYSLOG};
enum {IDX_DEBUG,IDX_CHDIR,IDX_PIDFILE,IDX_WRITABLE,IDX_LUA_INIT,IDX_HOSTLIST_AUTO_DEBUG};
#define PATH_MAX 4096
#define LOG_PID 1
#define LOG_USER 8
static const char *progname="fixture";
struct str_list_head {void *first;};
struct model_params {bool debug;enum log_target debug_target;char debug_logfile[4096],pidfile[4096],writable_dir[4096],hostlist_auto_debuglog[4096];bool writable_dir_enable;struct str_list_head lua_init_scripts;};
struct state {struct model_params fields;unsigned used,trace[16],fault;char environment[512],observed[4096],opened[4096],script[16384];bool truncate;};
static struct state *active;static jmp_buf legacy_jump;static unsigned legacy_exit;
#define params (active->fields)
static void trace(unsigned value){CHECK(active->used<16);active->trace[active->used++]=value;}
static void initial(struct state *value,unsigned fault){memset(value,0,sizeof(*value));value->fault=fault;strcpy(value->environment,"C:/initial/exedir");strcpy(value->fields.debug_logfile,"previous-debug");strcpy(value->fields.pidfile,"previous-pid");strcpy(value->fields.writable_dir,"previous-writable");strcpy(value->fields.hostlist_auto_debuglog,"previous-auto");}
#define zapret_engine_realpath mock_engine_realpath
static uint32_t zapret_engine_realpath(const char *source,char *output,size_t capacity)
{trace(1);if(!source || !*source || active->fault==1){SetLastError(ERROR_PATH_NOT_FOUND);return ERROR_PATH_NOT_FOUND;}size_t size=strlen(source);if(size+5>capacity){SetLastError(ERROR_FILENAME_EXCED_RANGE);return ERROR_FILENAME_EXCED_RANGE;}memcpy(output,"abs/",4);memcpy(output+4,source,size+1);return 0;}
static bool realpath_any(const char *source,char *output){return !zapret_engine_realpath(source,output,4096);}
static FILE *mock_fopen(const char *path,const char *mode){trace(2);CHECK(path && strlen(path)<sizeof(active->opened) && (!strcmp(mode,"wt") || !strcmp(mode,"a+t")));strcpy(active->opened,path);active->truncate=!strcmp(mode,"wt");if(active->fault==2){SetLastError(ERROR_ACCESS_DENIED);return NULL;}return (FILE *)(uintptr_t)0x1111;}
static int mock_fclose(FILE *file){CHECK(file==(FILE *)(uintptr_t)0x1111);trace(3);if(active->fault==5){SetLastError(ERROR_WRITE_FAULT);return EOF;}return 0;}
static int mock_chdir(const char *path){trace(5);CHECK(path && strlen(path)<sizeof(active->observed));strcpy(active->observed,path);if(active->fault==4){errno=ENOENT;SetLastError(ERROR_PATH_NOT_FOUND);return -1;}return 0;}
static char *mock_getenv(const char *name){trace(4);CHECK(!strcmp(name,"EXEDIR"));return active->fault==6?NULL:active->environment;}
static void mock_openlog(const char *name,int options,int facility){CHECK(!strcmp(name,progname) && options==LOG_PID && facility==LOG_USER);trace(7);}
static void *strlist_add_tail(struct str_list_head *head,const char *text){trace(8);CHECK(head==&params.lua_init_scripts && text && strlen(text)<sizeof(active->script));if(active->fault==3)return NULL;strcpy(active->script,text);return (void *)(uintptr_t)0x2222;}
static int mock_trace(const char *format,...)
{
    CHECK(!strcmp(format,"changing dir to '%s'\n"));
    va_list args;
    va_start(args,format);
    CHECK(va_arg(args,const char *));
    va_end(args);
    trace(6);
    if(active->fault==7)strcpy(active->environment,"mutated-exedir");
    return 0;
}
static bool observe_diagnostic;
static char sink, diagnostic[128];
static int observe(char channel, const char *format, va_list args)
{
    if (!observe_diagnostic) return 0;
    sink=channel;
    return vsnprintf(diagnostic,sizeof(diagnostic),format,args);
}
static int quiet(const char *format,...)
{
    va_list args;
    va_start(args,format);
    int result=observe('E',format,args);
    va_end(args);
    return result;
}
static int startup_perror(const char *label)
{
    if (!observe_diagnostic) return 0;
    CHECK(errno==ENOENT);
    sink='P';
    return snprintf(diagnostic,sizeof(diagnostic),"%s",label);
}
static int quiet_vfprintf(FILE *file,const char *format,va_list args)
{
    CHECK(file==stderr);
    return observe('S',format,args);
}
static int quiet_fprintf(FILE *file,const char *format,...)
{
    va_list args;
    va_start(args,format);
    int result=quiet_vfprintf(file,format,args);
    va_end(args);
    return result;
}
static void exit_clean(int code){legacy_exit=(unsigned)code;longjmp(legacy_jump,1);}
#define fopen mock_fopen
#define fclose mock_fclose
#define chdir mock_chdir
#define getenv mock_getenv
#define openlog mock_openlog
#define DLOG mock_trace
#define DLOG_ERR quiet
#define DLOG_PERROR startup_perror
#define fprintf quiet_fprintf
#define vfprintf quiet_vfprintf
static bool legacy(unsigned index,const char *optarg)
{
    legacy_exit=0;if(setjmp(legacy_jump))return false;
    switch(index){
#include "cli_startup_options_reference.inc"
    default:CHECK(false);
    }
    return true;
}
#include "cli_startup_options_windows.inc"
#undef fopen
#undef fclose
#undef chdir
#undef getenv
#undef openlog
#undef DLOG
#undef DLOG_ERR
#undef DLOG_PERROR
#undef fprintf
#undef vfprintf
#include "cli_stderr_oracle.h"
#ifndef STARTUP_INTEGRATED_CHECK
void zapret_fixture_fail_after(intptr_t);
#endif
static zapret_startup_target target_for(unsigned kind)
{
    zapret_startup_target target={0};target.capacity=4096;
    switch(kind){case 0:target.path=params.debug_logfile;target.debug=&params.debug;target.log_target=(int *)&params.debug_target;break;case 2:target.path=params.pidfile;break;case 3:target.path=params.writable_dir;target.enabled=&params.writable_dir_enable;break;case 4:target.scripts=&params.lua_init_scripts;break;case 5:target.path=params.hostlist_auto_debuglog;break;}
    return target;
}
static const zapret_startup_option_ops ops={zapret_engine_realpath,native_startup_touch,native_startup_cwd,mock_getenv,native_startup_syslog,mock_trace,native_startup_append};
static bool same_effects(const struct state *left,const struct state *right)
{return left->used==right->used && !memcmp(left->trace,right->trace,left->used*sizeof(unsigned)) && !strcmp(left->opened,right->opened) && !strcmp(left->observed,right->observed) && !strcmp(left->script,right->script) && left->truncate==right->truncate;}
static void compare(unsigned kind,const char *text,unsigned fault)
{
    struct state left,right,bridge;initial(&left,fault);initial(&right,fault);initial(&bridge,fault);
    active=&left;bool expected=legacy(kind,text);active=&right;zapret_startup_target target=target_for(kind);zapret_startup_detail detail={0};unsigned result=zapret_cli_startup_option(kind,text,&target,&ops,&detail);
    active=&bridge;int adapted=engine_startup_option((int)kind,text);CHECK((adapted==1)==!result && same_effects(&right,&bridge) && !memcmp(&right.fields,&bridge.fields,sizeof(right.fields)));
    CHECK(same_effects(&left,&right));bool atomic_change=memcmp(&left.fields,&right.fields,sizeof(left.fields))!=0;
    if(fault==5 && (kind==0 || kind==5) && left.used && left.trace[left.used-1]==3){CHECK(expected && result==5 && !strcmp(right.fields.debug_logfile,"previous-debug") && !strcmp(right.fields.hostlist_auto_debuglog,"previous-auto"));++close_repairs;}
    else {CHECK(expected==!result);if(atomic_change){CHECK(result && ((kind==0 && fault==2) || (kind==5 && fault==2) || (kind==3 && text && (!*text || fault==1))));++atomic_repairs;}else CHECK(!memcmp(&left.fields,&right.fields,sizeof(left.fields)));}
    ++cases;
}
static void boundary_checks(void)
{
    struct state state;initial(&state,0);active=&state;zapret_startup_target target=target_for(2);zapret_startup_detail detail={0};
    CHECK(zapret_cli_startup_option(2,"file",NULL,&ops,&detail)==1 && detail.error==ERROR_INVALID_PARAMETER && !state.used);++boundaries;
    CHECK(zapret_cli_startup_option(2,"file",&target,NULL,&detail)==1 && !state.used);++boundaries;
    target.capacity=SIZE_MAX;CHECK(zapret_cli_startup_option(2,"file",&target,&ops,&detail)==1 && !state.used);++boundaries;
    target=target_for(0);_Alignas(4) BYTE storage[8]={0};target.log_target=(int *)(storage+1);CHECK(zapret_cli_startup_option(0,"1",&target,&ops,&detail)==1 && !state.used);++boundaries;
#ifndef STARTUP_INTEGRATED_CHECK
    for(unsigned kind=0;kind<6;++kind){initial(&state,0);active=&state;target=target_for(kind);const char *text=kind==0?"@file":kind==4?"@file":"file";zapret_fixture_fail_after(0);unsigned result=zapret_cli_startup_option(kind,text,&target,&ops,&detail);zapret_fixture_fail_after(-1);CHECK(result==6 && !state.used && !strcmp(state.fields.pidfile,"previous-pid") && !state.fields.writable_dir_enable);++allocation_faults;}
#endif
    initial(&state,7);active=&state;target=target_for(1);CHECK(!zapret_cli_startup_option(1,NULL,&target,&ops,&detail) && !strcmp(state.observed,"C:/initial/exedir") && !strcmp(state.environment,"mutated-exedir"));++boundaries;
    initial(&state,0);active=&state;target=target_for(4);char script[]="literal code";CHECK(!zapret_cli_startup_option(4,script,&target,&ops,&detail));memset(script,'x',sizeof(script)-1);CHECK(!strcmp(state.script,"literal code"));++boundaries;
}

static size_t check_native_diagnostics(void)
{
    const struct {
        unsigned kind, fault;
        const char *text, *stderr_text, *log_text;
        char channel;
    } inputs[] = {
        {0, 2, "@bad-%s-\xff", "cannot create bad-%s-\xff\n", "", 0},
        {0, 0, "bad-%s-\xff", "invalid debug mode : bad-%s-\xff\n", "", 0},
        {5, 5, "list.log", "", "cannot create list.log\n", 'E'},
        {1, 4, "path", "", "chdir", 'P'},
    };
    struct state state;
    active = &state;
    for (size_t i = 0; i < sizeof(inputs)/sizeof(*inputs); ++i) {
        initial(&state, inputs[i].fault);
        sink = 0;
        diagnostic[0] = 0;
        unsigned kind = inputs[i].kind;
        const char *text = inputs[i].text;
        zapret_startup_target target = target_for(kind);
        zapret_startup_detail detail = {0};
        cli_stderr_capture capture = cli_capture_stderr();
        unsigned status = zapret_cli_startup_option(kind, text, &target, &ops, &detail);
        int result = zapret_cli_startup_report(kind, status, text, detail.argument_offset,
            quiet, NULL, startup_perror);
        cli_expect_stderr(capture, inputs[i].stderr_text);
        CHECK(result == -1 && sink == inputs[i].channel && !strcmp(diagnostic, inputs[i].log_text));
    }
    return sizeof(inputs)/sizeof(*inputs);
}

int main(void)
{
    const char *arguments[]={NULL,"","0","1","00","01","10","1junk","0x10","04294967296","syslog","SYSLOG","@file","@","данные-é-中","@данные-é-中","relative/path","literal code","bad-\xff"};
    for(unsigned repeat=0;repeat<8;++repeat)for(unsigned kind=0;kind<6;++kind)for(unsigned argument=0;argument<19;++argument)for(unsigned fault=0;fault<7;++fault){if(!arguments[argument] && (kind==2 || kind==4 || kind==5))continue;compare(kind,arguments[argument],fault);}
    struct state state;
    active=&state;
    observe_diagnostic=true;
    initial(&state,2);
    CHECK(engine_startup_option(IDX_DEBUG,"@bad-\xff")==-1);
    CHECK(sink=='S' && !strcmp(diagnostic,"cannot create bad-\xff\n"));
    initial(&state,5);
    CHECK(engine_startup_option(IDX_HOSTLIST_AUTO_DEBUG,"list.log")==-1);
    CHECK(sink=='E' && !strcmp(diagnostic,"cannot create list.log\n"));
    initial(&state,4);
    CHECK(engine_startup_option(IDX_CHDIR,"path")==-1);
    CHECK(sink=='P' && !strcmp(diagnostic,"chdir"));
    size_t native_diagnostics = check_native_diagnostics();
    observe_diagnostic=false;
    boundary_checks();printf("PASS cli_startup_options functions=6 cases=%u atomic_repairs=%u close_error_repairs=%u boundaries=%u allocation_faults=%u diagnostic_cases=3 ucrt_stderr_cases=%zu c_bridge=1 owned_environment=1 copied_script=1\n",cases,atomic_repairs,close_repairs,boundaries,allocation_faults,native_diagnostics);return 0;
}
