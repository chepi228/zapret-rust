/* MIT. Complete original/new entries; instrument only native execution. */
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include "native_logging_entry_abi.h"
#define CHECK(c) do{if(!(c)){fprintf(stderr,"FAIL native_logging_entry line=%d case=%u: %s\n",__LINE__,cases,#c);exit(1);}}while(0)
enum{LOG_TARGET_CONSOLE,LOG_TARGET_FILE,LOG_TARGET_SYSLOG};
#define LOG_ERR 3
#define LOG_DEBUG 7
struct parameters{bool debug;int debug_target;char debug_logfile[32],hostlist_auto_debuglog[32];};
struct fixture{struct parameters fields;char trace[65536];size_t used;unsigned calls,mutation;int native_result,open_failure,close_failure;struct tm calendar;};
static struct fixture *active;static unsigned cases;
#define params (active->fields)
static void record(const char *kind,const char *text,int code){int size=snprintf(active->trace+active->used,sizeof(active->trace)-active->used,"%s[%d]:%s|",kind,code,text);CHECK(size>=0&&(size_t)size<sizeof(active->trace)-active->used);active->used+=(size_t)size;}
static void mutation(void){if(++active->calls!=1)return;switch(active->mutation){case 1:params.debug=false;break;case 2:params.debug=true;params.debug_target=LOG_TARGET_SYSLOG;break;case 3:params.debug=true;params.debug_target=LOG_TARGET_FILE;strcpy(params.debug_logfile,"late.log");break;case 4:params.debug_target=LOG_TARGET_CONSOLE;break;default:break;}}
static int model_vfprintf(FILE *file,const char *format,va_list args){char text[16384];int size=vsnprintf(text,sizeof(text),format,args);record(file==stderr?"stderr":file==stdout?"stdout":"file",text,active->native_result);mutation();return active->native_result==INT32_MIN?size:active->native_result;}
static int model_fprintf(FILE *file,const char *format,...){va_list args;va_start(args,format);int result=model_vfprintf(file,format,args);va_end(args);return result;}
static FILE *model_fopen(const char *name,const char *mode){record("open",name,(int)strlen(mode));return active->open_failure?NULL:(FILE *)(uintptr_t)1;}
static int model_fclose(FILE *file){CHECK(file==(FILE *)(uintptr_t)1);record("close","",active->close_failure);return active->close_failure;}
static time_t model_time(time_t *result){record("time","",0);if(result)*result=123;return 123;}
static struct tm *model_localtime(const time_t *now,struct tm *value){CHECK(*now==123);record("localtime","",0);*value=active->calendar;return value;}
static void model_syslog(int priority,const char *format,...){va_list args;va_start(args,format);char text[16384];vsnprintf(text,sizeof(text),format,args);va_end(args);record("syslog",text,priority);mutation();}
static void model_syslog_line(int priority,const char *line){model_syslog(priority,"%s",line);}
typedef void (*f_log_function)(int,const char *);
static void log_buffered(f_log_function writer,int priority,const char *format,va_list args){char text[4095];int size=vsnprintf(text,sizeof(text),format,args);record("buffer",size>0?text:"",priority);mutation();if(size>0)writer(priority,text);}
#define fopen model_fopen
#define wf_fopen model_fopen
#define fclose model_fclose
#define fprintf model_fprintf
#define vfprintf model_vfprintf
#define time model_time
#define localtime_r model_localtime
#define zapret_localtime_r model_localtime
#define syslog model_syslog
#define zapret_system_syslog model_syslog_line
#define fprint_localtime reference_fprint_localtime
#define DLOG_FILE_VA reference_DLOG_FILE_VA
#define DLOG_CON_VA reference_DLOG_CON_VA
#define DLOG_FILENAME_VA reference_DLOG_FILENAME_VA
#define syslog_log_function reference_syslog_log_function
#define DLOG_FILENAME reference_DLOG_FILENAME
#define file_log_function reference_file_log_function
#define DLOG_VA reference_DLOG_VA
#define DLOG reference_DLOG
#define DLOG_CONDUP reference_DLOG_CONDUP
#define DLOG_ERR reference_DLOG_ERR
#define DLOG_PERROR reference_DLOG_PERROR
#define LOG_APPEND reference_LOG_APPEND
#define HOSTLIST_DEBUGLOG_APPEND reference_HOSTLIST_DEBUGLOG_APPEND
#include "native_logging_reference.inc"
#undef fprint_localtime
#undef DLOG_FILE_VA
#undef DLOG_CON_VA
#undef DLOG_FILENAME_VA
#undef syslog_log_function
#undef DLOG_FILENAME
#undef file_log_function
#undef DLOG_VA
#undef DLOG
#undef DLOG_CONDUP
#undef DLOG_ERR
#undef DLOG_PERROR
#undef LOG_APPEND
#undef HOSTLIST_DEBUGLOG_APPEND
#define fprint_localtime selected_fprint_localtime
#include "native_logging_selected.inc"
#undef fprintf
#undef vfprintf
#undef fopen
#undef wf_fopen
#undef fclose
#include "native_logging_stdio_file_fixture.inc"
static int invoke(bool rust,unsigned kind,const char *format,...){va_list args;va_start(args,format);int result;switch(kind){
    case 0:result=rust?DLOG_VA(format,7,false,args):reference_DLOG_VA(format,7,false,args);break;
    case 1:result=rust?DLOG_VA(format,3,true,args):reference_DLOG_VA(format,3,true,args);break;
    case 2:result=rust?LOG_APPEND("append.log",format,args):reference_LOG_APPEND("append.log",format,args);break;
    case 3:result=rust?DLOG(format,-19,"data"):reference_DLOG(format,-19,"data");break;
    case 4:result=rust?DLOG_CONDUP(format,-19,"data"):reference_DLOG_CONDUP(format,-19,"data");break;
    case 5:result=rust?DLOG_ERR(format,-19,"data"):reference_DLOG_ERR(format,-19,"data");break;
    case 6:result=rust?DLOG_PERROR("failure"):reference_DLOG_PERROR("failure");break;
    case 7:result=rust?DLOG_FILENAME("direct.log",format,-19,"data"):reference_DLOG_FILENAME("direct.log",format,-19,"data");break;
    case 8:result=rust?HOSTLIST_DEBUGLOG_APPEND(format,-19,"data"):reference_HOSTLIST_DEBUGLOG_APPEND(format,-19,"data");break;
    case 9:result=rust?DLOG_FILE_VA(stdout,format,args):reference_DLOG_FILE_VA(stdout,format,args);break;
    case 10:result=rust?DLOG_CON_VA(format,-5,args):reference_DLOG_CON_VA(format,-5,args);break;
    case 11:result=rust?DLOG_FILENAME_VA("va.log",format,args):reference_DLOG_FILENAME_VA("va.log",format,args);break;
    default:result=rust?fprint_localtime(stdout):reference_fprint_localtime(stdout);break;
    }va_end(args);return result;}
static void compare(struct fixture initial,unsigned kind){struct fixture left=initial,right=initial;active=&left;errno=EACCES;int expected=invoke(false,kind,"value=%d %s\n",-19,"data");active=&right;errno=EACCES;int actual=invoke(true,kind,"value=%d %s\n",-19,"data");CHECK(actual==expected);CHECK(!strcmp(left.trace,right.trace));CHECK(!memcmp(&left.fields,&right.fields,sizeof(left.fields)));CHECK(left.calls==right.calls);++cases;}
int main(void){for(unsigned debug=0;debug<2;debug++)for(int target=-1;target<4;target++)for(unsigned mutation=0;mutation<5;mutation++)for(unsigned native=0;native<3;native++)for(unsigned kind=0;kind<13;kind++)for(unsigned fault=0;fault<4;fault++){struct fixture input={0};input.fields.debug=debug;input.fields.debug_target=target;strcpy(input.fields.debug_logfile,"early.log");strcpy(input.fields.hostlist_auto_debuglog,"host.log");input.mutation=mutation;input.native_result=native==0?INT32_MIN:native==1?0:-13;input.open_failure=fault&1;input.close_failure=fault&2;input.calendar=(struct tm){.tm_mday=7,.tm_mon=0,.tm_year=126,.tm_hour=1,.tm_min=2,.tm_sec=3};compare(input,kind);}
    for(unsigned enabled=0;enabled<2;enabled++){struct fixture left={0},right={0};if(enabled){strcpy(left.fields.hostlist_auto_debuglog,"x");strcpy(right.fields.hostlist_auto_debuglog,"x");}left.native_result=right.native_result=INT32_MIN;active=&left;int a=reference_HOSTLIST_DEBUGLOG_APPEND("%s","body");active=&right;int b=HOSTLIST_DEBUGLOG_APPEND("%s","body");CHECK(a==b&&!strcmp(left.trace,right.trace));++cases;}
    printf("PASS native_logging_entry complete_cases=%u entries=15 deferred_debug_target_path=1 native_variadics=1\n",cases);check_native_logging_stdio();return 0;}
