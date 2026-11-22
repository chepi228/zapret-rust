/* MIT. Mock transitions; real sandbox operations affect only this fixture. */
#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#undef main
static unsigned job_cases,sandbox_cases,create_repairs,zero_repairs,boundaries,reentries,threaded;
#define CHECK(value) do {if(!(value)){fprintf(stderr,"FAIL security sandbox jobs=%u transitions=%u boundary=%u line=%d error=%lu: %s\n",job_cases,sandbox_cases,boundaries,__LINE__,(unsigned long)GetLastError(),#value);exit(1);}}while(0)
uint32_t w_win32_error;
typedef struct {
    HANDLE (WINAPI *create)(const SECURITY_ATTRIBUTES *,const WCHAR *);
    BOOL (WINAPI *set)(HANDLE,JOBOBJECTINFOCLASS,const void *,DWORD);
    BOOL (WINAPI *assign)(HANDLE,HANDLE);
    HANDLE (WINAPI *process)(void);
    BOOL (WINAPI *close)(HANDLE);
    DWORD (WINAPI *error)(void);
} job_ops;
typedef uint32_t (*step)(const void *);
typedef struct {step remove,label,low,job;} sandbox_ops;
_Static_assert(sizeof(job_ops)==48 && sizeof(sandbox_ops)==32 && sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION)==64 && sizeof(JOBOBJECT_BASIC_UI_RESTRICTIONS)==4,"Rust job and transition ABI");
uint32_t zapret_security_job(const void *);
uint32_t zapret_security_sandbox(bool (*)(void),uint32_t *,const void *);
struct job_state {unsigned used,trace[8],failure,closed;DWORD error,noise;};
static struct job_state *active_job;
static void job_trace(unsigned value){CHECK(active_job->used<8);active_job->trace[active_job->used++]=value;}
static DWORD WINAPI mock_error(void){return GetLastError();}
static HANDLE WINAPI mock_create(const SECURITY_ATTRIBUTES *attributes,const WCHAR *name)
{job_trace(1);CHECK(!attributes && !name);if(active_job->failure==1){SetLastError(active_job->error);return NULL;}return (HANDLE)(uintptr_t)0x2222;}
static BOOL WINAPI mock_set(HANDLE handle,JOBOBJECTINFOCLASS kind,const void *value,DWORD length)
{
    CHECK(handle==(HANDLE)(uintptr_t)0x2222 && value);
    if(kind==JobObjectBasicLimitInformation){job_trace(2);CHECK(length==sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION));const JOBOBJECT_BASIC_LIMIT_INFORMATION *limit=value;
        CHECK(limit->LimitFlags==JOB_OBJECT_LIMIT_ACTIVE_PROCESS && limit->ActiveProcessLimit==1 && !limit->PerProcessUserTimeLimit.QuadPart && !limit->PerJobUserTimeLimit.QuadPart && !limit->MinimumWorkingSetSize && !limit->MaximumWorkingSetSize && !limit->Affinity && !limit->PriorityClass && !limit->SchedulingClass);
    }else{CHECK(kind==JobObjectBasicUIRestrictions && length==sizeof(JOBOBJECT_BASIC_UI_RESTRICTIONS));job_trace(3);CHECK(((const JOBOBJECT_BASIC_UI_RESTRICTIONS *)value)->UIRestrictionsClass==0xff);}
    if(active_job->failure==active_job->trace[active_job->used-1]){SetLastError(active_job->error);return FALSE;}return TRUE;
}
static HANDLE WINAPI mock_process(void){job_trace(4);return (HANDLE)(uintptr_t)0x1111;}
static BOOL WINAPI mock_assign(HANDLE job,HANDLE process){job_trace(5);CHECK(job==(HANDLE)(uintptr_t)0x2222 && process==(HANDLE)(uintptr_t)0x1111);if(active_job->failure==4){SetLastError(active_job->error);return FALSE;}return TRUE;}
static BOOL WINAPI mock_close(HANDLE handle){job_trace(6);CHECK(handle==(HANDLE)(uintptr_t)0x2222);++active_job->closed;SetLastError(active_job->noise);return TRUE;}
static const job_ops jobs={mock_create,mock_set,mock_assign,mock_process,mock_close,mock_error};
#define CreateJobObjectW mock_create
#define SetInformationJobObject mock_set
#define AssignProcessToJobObject mock_assign
#define GetCurrentProcess mock_process
#define CloseHandle mock_close
#define JobSandbox reference_JobSandbox
#include "security_job_reference.inc"
#undef CreateJobObjectW
#undef SetInformationJobObject
#undef AssignProcessToJobObject
#undef GetCurrentProcess
#undef CloseHandle
#undef JobSandbox
static void compare_job(unsigned failure,DWORD error,DWORD noise,DWORD stale)
{
    struct job_state left={0},right={0};left.failure=failure;left.error=error;left.noise=noise;right=left;
    active_job=&left;SetLastError(stale);w_win32_error=0xabcdef;BOOL expected=reference_JobSandbox();DWORD old_error=w_win32_error;
    active_job=&right;SetLastError(stale);DWORD result=zapret_security_job(&jobs);
    CHECK(!!expected==!result && left.used==right.used && !memcmp(left.trace,right.trace,left.used*sizeof(unsigned)) && left.closed==right.closed && right.closed==(failure!=1));
    if(failure==1){CHECK(result==(error?error:ERROR_GEN_FAILURE) && old_error==0xabcdef);++create_repairs;}
    else if(failure && !error){CHECK(result==ERROR_GEN_FAILURE && !old_error);++zero_repairs;}
    else if(failure)CHECK(result==old_error);else CHECK(!result);
    ++job_cases;
}
struct sandbox_state {unsigned used,trace[16],failure;DWORD error;bool present,reenter;uint32_t *state;};
static struct sandbox_state *active;
static const sandbox_ops steps;
static bool filter(void){CHECK(active->used<16);active->trace[active->used++]=2;return active->present;}
static uint32_t transition(unsigned value,const void *input)
{
    CHECK(!input && active->used<16);active->trace[active->used++]=value;
    if(active->reenter && value==1){CHECK(zapret_security_sandbox(filter,active->state,&steps)==ERROR_BUSY);++reentries;}
    DWORD result=active->failure==value?active->error:0;if(result)w_win32_error=result;return result;
}
static uint32_t remove_step(const void *input){return transition(1,input);}
static uint32_t label_step(const void *input){return transition(3,input);}
static uint32_t low_step(const void *input){return transition(4,input);}
static uint32_t job_step(const void *input){return transition(5,input);}
static const sandbox_ops steps={remove_step,label_step,low_step,job_step};
static BOOL reference_remove(void){return !remove_step(NULL);}
static BOOL reference_low(void){return !low_step(NULL);}
static BOOL reference_job(void){return !job_step(NULL);}
static BOOL reference_device(const char *path,DWORD rid,DWORD flags){CHECK(!strcmp(path,"\\\\.\\WinDivert") && rid==SECURITY_MANDATORY_LOW_RID && !flags);return !label_step(NULL);}
static bool reference_ready;
#define b_sandbox_set reference_ready
#define win_sandbox reference_win_sandbox
#define RemoveTokenPrivs reference_remove
#define SetMandatoryLabelFile reference_device
#define LowMandatoryLevel reference_low
#define JobSandbox reference_job
#define logical_net_filter_present filter
#define WINDIVERT_DEVICE_NAME "WinDivert"
#include "security_sandbox_reference.inc"
#undef b_sandbox_set
#undef win_sandbox
#undef RemoveTokenPrivs
#undef SetMandatoryLabelFile
#undef LowMandatoryLevel
#undef JobSandbox
#undef logical_net_filter_present
#undef WINDIVERT_DEVICE_NAME
static void compare_sandbox(bool present,unsigned failure,DWORD error,unsigned repetitions)
{
    struct sandbox_state left={0},right={0};uint32_t state=0;left.failure=failure;left.error=error;left.present=present;right=left;reference_ready=false;
    for(unsigned i=0;i<repetitions;++i){left.used=right.used=0;active=&left;w_win32_error=0;BOOL expected=reference_win_sandbox();DWORD expected_error=w_win32_error;
        active=&right;DWORD result=zapret_security_sandbox(filter,&state,&steps);CHECK(!!expected==!result && (!result || result==expected_error) && reference_ready==(state==2));
        CHECK(left.used==right.used && !memcmp(left.trace,right.trace,left.used*sizeof(unsigned)));++sandbox_cases;}
    if(state!=2){left.failure=right.failure=0;left.used=right.used=0;active=&left;CHECK(reference_win_sandbox());active=&right;CHECK(!zapret_security_sandbox(filter,&state,&steps) && state==2 && reference_ready && left.used==right.used && !memcmp(left.trace,right.trace,left.used*sizeof(unsigned)));++sandbox_cases;}
}
static HANDLE entered,release_step;static uint32_t parallel_state;
static LONG parallel_calls;static DWORD WINAPI owner(void *unused);
static uint32_t blocking_remove(const void *input){CHECK(!input);InterlockedIncrement(&parallel_calls);CHECK(SetEvent(entered) && WaitForSingleObject(release_step,5000)==WAIT_OBJECT_0);return 0;}
static uint32_t parallel_ok(const void *input){CHECK(!input);InterlockedIncrement(&parallel_calls);return 0;}
static bool parallel_filter(void){InterlockedIncrement(&parallel_calls);return true;}
static const sandbox_ops parallel_ops={blocking_remove,parallel_ok,parallel_ok,parallel_ok};
static DWORD WINAPI owner(void *unused){(void)unused;return zapret_security_sandbox(parallel_filter,&parallel_state,&parallel_ops);}
static DWORD WINAPI contender(void *unused){(void)unused;return zapret_security_sandbox(parallel_filter,&parallel_state,&parallel_ops);}
static void concurrency(void)
{
    entered=CreateEventW(NULL,TRUE,FALSE,NULL);release_step=CreateEventW(NULL,TRUE,FALSE,NULL);CHECK(entered && release_step);
    HANDLE first=CreateThread(NULL,0,owner,NULL,0,NULL);CHECK(first && WaitForSingleObject(entered,5000)==WAIT_OBJECT_0);
    HANDLE others[16];for(unsigned i=0;i<16;++i){others[i]=CreateThread(NULL,0,contender,NULL,0,NULL);CHECK(others[i]);}
    for(unsigned i=0;i<16;++i){DWORD exit_code=0;CHECK(WaitForSingleObject(others[i],5000)==WAIT_OBJECT_0 && GetExitCodeThread(others[i],&exit_code) && exit_code==ERROR_BUSY && CloseHandle(others[i]));++threaded;}
    CHECK(parallel_calls==1 && SetEvent(release_step));DWORD exit_code=1;CHECK(WaitForSingleObject(first,5000)==WAIT_OBJECT_0 && GetExitCodeThread(first,&exit_code) && !exit_code && parallel_state==2 && parallel_calls==5 && CloseHandle(first));
    for(unsigned i=0;i<16;++i){CHECK(!zapret_security_sandbox(parallel_filter,&parallel_state,&parallel_ops) && parallel_calls==5);++threaded;}
    CHECK(CloseHandle(entered) && CloseHandle(release_step));
}
static bool logical_net_filter_present(void);
#include "security_sandbox_windows.inc"
static bool logical_net_filter_present(void){return false;}
static HANDLE real_job;
static HANDLE WINAPI real_create(const SECURITY_ATTRIBUTES *attributes,const WCHAR *name){HANDLE handle=CreateJobObjectW((SECURITY_ATTRIBUTES *)attributes,name);if(handle)CHECK(DuplicateHandle(GetCurrentProcess(),handle,GetCurrentProcess(),&real_job,JOB_OBJECT_QUERY,FALSE,0));return handle;}
static BOOL WINAPI real_set(HANDLE handle,JOBOBJECTINFOCLASS kind,const void *value,DWORD length){return SetInformationJobObject(handle,kind,(void *)value,length);}
static BOOL WINAPI reject_assignment(HANDLE job,HANDLE process){CHECK(process==GetCurrentProcess());return AssignProcessToJobObject(job,NULL);}
static void real(void)
{
    job_ops actual={real_create,real_set,AssignProcessToJobObject,GetCurrentProcess,CloseHandle,GetLastError};
    DWORD before=0,after=0;CHECK(GetProcessHandleCount(GetCurrentProcess(),&before));actual.assign=reject_assignment;
    for(unsigned i=0;i<512;++i){CHECK(zapret_security_job(&actual)==ERROR_INVALID_HANDLE && real_job && CloseHandle(real_job));real_job=NULL;}
    CHECK(GetProcessHandleCount(GetCurrentProcess(),&after) && before==after);actual.assign=AssignProcessToJobObject;
    DWORD result=zapret_security_job(&actual);if(result){SetLastError(result);}CHECK(!result);
    JOBOBJECT_BASIC_LIMIT_INFORMATION limit;JOBOBJECT_BASIC_UI_RESTRICTIONS ui;CHECK(real_job && QueryInformationJobObject(real_job,JobObjectBasicLimitInformation,&limit,sizeof(limit),NULL) && QueryInformationJobObject(real_job,JobObjectBasicUIRestrictions,&ui,sizeof(ui),NULL));CHECK(limit.LimitFlags==JOB_OBJECT_LIMIT_ACTIVE_PROCESS && limit.ActiveProcessLimit==1 && ui.UIRestrictionsClass==0xff);
    BOOL in_job=FALSE;CHECK(IsProcessInJob(GetCurrentProcess(),real_job,&in_job) && in_job);WCHAR system[32768],command[32768];UINT length=GetSystemDirectoryW(system,32768);CHECK(length && length<32700);swprintf(command,32768,L"\"%ls\\cmd.exe\" /d /c exit 0",system);STARTUPINFOW startup={0};startup.cb=sizeof(startup);PROCESS_INFORMATION process={0};BOOL created=CreateProcessW(NULL,command,NULL,NULL,FALSE,CREATE_NO_WINDOW|CREATE_SUSPENDED,NULL,NULL,&startup,&process);DWORD error=GetLastError();if(created){TerminateProcess(process.hProcess,1);WaitForSingleObject(process.hProcess,5000);CloseHandle(process.hThread);CloseHandle(process.hProcess);}CHECK(!created && error==ERROR_NOT_ENOUGH_QUOTA);
    CHECK(CloseHandle(real_job));printf("PASS security_sandbox_real private_job=1 process_limit=1 ui_limits=255 assigned=1 child_rejected=1 failure_handle_cycles=512\n");
}
static void real_transition(void)
{
    CHECK(win_sandbox());
    HANDLE token=NULL;CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token));
    BYTE data[2048];DWORD size=0;CHECK(GetTokenInformation(token,TokenIntegrityLevel,data,sizeof(data),&size));TOKEN_MANDATORY_LABEL *label=(TOKEN_MANDATORY_LABEL *)data;CHECK(IsValidSid(label->Label.Sid) && *GetSidSubAuthority(label->Label.Sid,*GetSidSubAuthorityCount(label->Label.Sid)-1)==SECURITY_MANDATORY_LOW_RID);
    CHECK(GetTokenInformation(token,TokenPrivileges,data,sizeof(data),&size));TOKEN_PRIVILEGES *privileges=(TOKEN_PRIVILEGES *)data;LUID keep;CHECK(LookupPrivilegeValueW(NULL,L"SeChangeNotifyPrivilege",&keep));for(DWORD i=0;i<privileges->PrivilegeCount;++i)CHECK(privileges->Privileges[i].Luid.LowPart==keep.LowPart && privileges->Privileges[i].Luid.HighPart==keep.HighPart);CHECK(CloseHandle(token));
    JOBOBJECT_BASIC_LIMIT_INFORMATION limit;JOBOBJECT_BASIC_UI_RESTRICTIONS ui;CHECK(QueryInformationJobObject(NULL,JobObjectBasicLimitInformation,&limit,sizeof(limit),NULL) && QueryInformationJobObject(NULL,JobObjectBasicUIRestrictions,&ui,sizeof(ui),NULL) && limit.LimitFlags==JOB_OBJECT_LIMIT_ACTIVE_PROCESS && limit.ActiveProcessLimit==1 && ui.UIRestrictionsClass==0xff);
    for(unsigned i=0;i<64;++i)CHECK(win_sandbox());
    printf("PASS security_sandbox_transition private_process=1 low_integrity=4096 restricted_privileges=1 process_limit=1 repeated=64\n");
}
int main(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"--real")){real();return 0;}if(argc==2 && !strcmp(argv[1],"--real-transition")){real_transition();return 0;}CHECK(argc==1);
    const DWORD errors[]={0,ERROR_ACCESS_DENIED,ERROR_INVALID_HANDLE,ERROR_INVALID_PARAMETER,ERROR_PRIVILEGE_NOT_HELD,ERROR_GEN_FAILURE,ERROR_IO_DEVICE,UINT32_MAX};
    for(unsigned failure=0;failure<5;++failure)for(unsigned error=0;error<8;++error)for(unsigned noise=0;noise<2;++noise)for(unsigned stale=0;stale<8;++stale)compare_job(failure,errors[error],noise?ERROR_BAD_LENGTH:0,errors[stale]);
    for(unsigned present=0;present<2;++present)for(unsigned failure=0;failure<=5;++failure)for(unsigned error=1;error<8;++error)for(unsigned repeat=1;repeat<=8;++repeat)compare_sandbox(present!=0,failure,errors[error],repeat);
    uint32_t state=0;struct sandbox_state value={0};active=&value;value.present=true;value.reenter=true;value.state=&state;CHECK(!zapret_security_sandbox(filter,&state,&steps) && state==2 && reentries==1);
    state=1;value.used=0;CHECK(zapret_security_sandbox(filter,&state,&steps)==ERROR_BUSY && !value.used && state==1);++boundaries;
    state=3;CHECK(zapret_security_sandbox(filter,&state,&steps)==ERROR_INVALID_DATA && !value.used && state==3);++boundaries;
    CHECK(zapret_security_sandbox(NULL,&state,&steps)==ERROR_INVALID_PARAMETER);++boundaries;
    _Alignas(4) unsigned char unaligned[8]={0};CHECK(zapret_security_sandbox(filter,(uint32_t *)(unaligned+1),&steps)==ERROR_INVALID_PARAMETER);++boundaries;
    concurrency();printf("PASS security_sandbox functions=2 job_cases=%u transition_cases=%u create_error_repairs=%u zero_error_repairs=%u boundaries=%u reentries=%u threaded=%u\n",job_cases,sandbox_cases,create_repairs,zero_repairs,boundaries,reentries,threaded);return 0;
}
