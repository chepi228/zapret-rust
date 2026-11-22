/* MIT. Project startup option fields and bind Windows file and logging calls. */
#include "cli_stderr_windows.h"

typedef struct {char *path;size_t capacity;bool *enabled,*debug;int *log_target;void *scripts;} zapret_startup_target;
typedef struct {
    uint32_t (*resolve)(const char *,char *,size_t);
    uint32_t (*touch)(const char *,bool),(*cwd)(const char *);
    char *(*environment)(const char *);
    void (*syslog)(int,int);
    zapret_log_sink trace_directory;
    bool (*append)(void *,const char *);
} zapret_startup_option_ops;
typedef struct {uint32_t error,argument_offset;} zapret_startup_detail;
uint32_t zapret_cli_startup_option(uint32_t,const char *,const zapret_startup_target *,const zapret_startup_option_ops *,zapret_startup_detail *);
uint32_t zapret_cli_startup_touch(const char *,bool,FILE *(*)(const char *,const char *),int (*)(FILE *));
uint32_t zapret_cli_startup_cwd(const char *,int (*)(const char *));
int zapret_cli_startup_report(uint32_t,uint32_t,const char *,uint32_t,zapret_log_sink,zapret_log_sink,int (*)(const char *));
uint32_t zapret_engine_realpath(const char *,char *,size_t);
_Static_assert(sizeof(zapret_startup_target) == 6 * sizeof(void *) &&
    sizeof(zapret_startup_option_ops) == 7 * sizeof(void *) && sizeof(zapret_startup_detail) == 8 &&
    PATH_MAX == 4096 && sizeof(params.debug_target) == 4 &&
    LOG_TARGET_CONSOLE == 0 && LOG_TARGET_FILE == 1 && LOG_TARGET_SYSLOG == 2 &&
    LOG_PID == 1 && LOG_USER == 8, "Rust startup option ABI");
static uint32_t native_startup_touch(const char *path,bool truncate)
{return zapret_cli_startup_touch(path,truncate,fopen,fclose);}
static uint32_t native_startup_cwd(const char *path)
{return zapret_cli_startup_cwd(path,chdir);}
static void native_startup_syslog(int options, int facility){openlog(progname,options,facility);}
static bool native_startup_append(void *head,const char *text){return strlist_add_tail(head,text);}
static int engine_startup_option(int index,const char *text)
{
    uint32_t kind;zapret_startup_target target={0};
    switch(index){
        case IDX_DEBUG:kind=0;target.path=params.debug_logfile;target.capacity=sizeof(params.debug_logfile);target.debug=&params.debug;target.log_target=(int *)&params.debug_target;break;
        case IDX_CHDIR:kind=1;break;
        case IDX_PIDFILE:kind=2;target.path=params.pidfile;target.capacity=sizeof(params.pidfile);break;
        case IDX_WRITABLE:kind=3;target.path=params.writable_dir;target.capacity=sizeof(params.writable_dir);target.enabled=&params.writable_dir_enable;break;
        case IDX_LUA_INIT:kind=4;target.scripts=&params.lua_init_scripts;break;
        case IDX_HOSTLIST_AUTO_DEBUG:kind=5;target.path=params.hostlist_auto_debuglog;target.capacity=sizeof(params.hostlist_auto_debuglog);break;
        default:return 0;
    }
    static const zapret_startup_option_ops ops={zapret_engine_realpath,native_startup_touch,native_startup_cwd,getenv,native_startup_syslog,DLOG,native_startup_append};
    zapret_startup_detail detail={0};
    uint32_t status=zapret_cli_startup_option(kind,text,&target,&ops,&detail);
    return zapret_cli_startup_report(kind,status,text,detail.argument_offset,DLOG_ERR,native_cli_stderr,DLOG_PERROR);
}
