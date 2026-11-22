/* MIT. Callback-isolated token comparisons; real changes stay in owned children. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#undef main
static unsigned cases,boundaries,improvements,mutations,logical_errors,wide_cases;
#define CHECK(condition) do {if(!(condition)){fprintf(stderr,"FAIL security token cases=%u boundaries=%u line=%d: %s\n",cases,boundaries,__LINE__,#condition);exit(1);}}while(0)
uint32_t w_win32_error;
typedef struct {
    HANDLE (WINAPI *process)(void);
    BOOL (WINAPI *open)(HANDLE,DWORD,HANDLE *);
    BOOL (WINAPI *query)(HANDLE,TOKEN_INFORMATION_CLASS,void *,DWORD,DWORD *);
    BOOL (WINAPI *lookup)(LPCSTR,LPCSTR,LUID *);
    BOOL (WINAPI *adjust)(HANDLE,BOOL,const TOKEN_PRIVILEGES *,DWORD,TOKEN_PRIVILEGES *,DWORD *);
    BOOL (WINAPI *set)(HANDLE,TOKEN_INFORMATION_CLASS,const void *,DWORD);
    BOOL (WINAPI *close)(HANDLE);
    DWORD (WINAPI *error)(void);
    void (WINAPI *set_error)(DWORD);
    BOOL (WINAPI *lookup_w)(LPCWSTR,LPCWSTR,LUID *);
} token_ops;
uint32_t zapret_security_adjust(HANDLE,const char *const *,bool,const void *);
uint32_t zapret_security_adjust_current(const char *const *,bool,const void *);
uint32_t zapret_security_adjust_w(HANDLE,const WCHAR *const *,bool,const void *);
uint32_t zapret_security_adjust_current_w(const WCHAR *const *,bool,const void *);
uint32_t zapret_security_remove(const void *);
uint32_t zapret_security_low(const void *);
_Static_assert(sizeof(token_ops)==80,"Rust token callback table ABI");
struct state {
    DWORD count,error,fail,adjust_error,close_error,malformed,growth,queries,adjusts,sets,closes,access;
    LUID_AND_ATTRIBUTES records[64],observed[64];DWORD observed_count,low_length;BYTE low_sid[32];
    unsigned trace[1024],used;
};
static struct state *active;
static void trace(unsigned operation){CHECK(active->used<1024);active->trace[active->used++]=operation;}
static HANDLE WINAPI mock_process(void){return (HANDLE)(uintptr_t)0x1111;}
static BOOL WINAPI mock_open(HANDLE process,DWORD access,HANDLE *output){trace(1);CHECK(process==mock_process());active->access=access;if(active->fail==2){active->error=ERROR_ACCESS_DENIED;return FALSE;}*output=(HANDLE)(uintptr_t)0x2222;return TRUE;}
static BOOL WINAPI mock_close(HANDLE handle){trace(6);CHECK(handle==(HANDLE)(uintptr_t)0x2222);++active->closes;if(active->close_error)active->error=active->close_error;return TRUE;}
static DWORD WINAPI mock_error(void){return active->error;}
static void WINAPI mock_set_error(DWORD error){active->error=error;}
static BOOL WINAPI mock_query(HANDLE token,TOKEN_INFORMATION_CLASS kind,void *output,DWORD capacity,DWORD *length)
{
    CHECK(token==(HANDLE)(uintptr_t)0x2222 && kind==TokenPrivileges);++active->queries;
    DWORD needed=(DWORD)offsetof(TOKEN_PRIVILEGES,Privileges)+active->count*sizeof(LUID_AND_ATTRIBUTES);
    if(!output){trace(2);*length=needed;active->error=ERROR_INSUFFICIENT_BUFFER;
        if(active->fail==3){active->error=ERROR_ACCESS_DENIED;return FALSE;}
        if(active->malformed==1){active->error=0;return TRUE;}
        if(active->malformed==2)*length=3;
        if(active->malformed==3)*length=2*1024*1024;
        return FALSE;
    }
    trace(3);
    if(active->fail==4){active->error=ERROR_INVALID_HANDLE;return FALSE;}
    if(active->growth){--active->growth;CHECK(active->count<64);++active->count;*length=needed+sizeof(LUID_AND_ATTRIBUTES);active->error=ERROR_INSUFFICIENT_BUFFER;return FALSE;}
    CHECK(capacity>=needed);memset(output,0,needed);TOKEN_PRIVILEGES *privileges=output;privileges->PrivilegeCount=active->count;memcpy(privileges->Privileges,active->records,active->count*sizeof(LUID_AND_ATTRIBUTES));*length=needed;active->error=0;
    if(active->malformed==4)*length=capacity+1;
    if(active->malformed==5)privileges->PrivilegeCount=UINT32_MAX;
    if(active->malformed==6)*length=3;
    if(active->malformed==7){*length=capacity;active->error=ERROR_INSUFFICIENT_BUFFER;return FALSE;}
    return TRUE;
}
static BOOL WINAPI mock_lookup(LPCSTR system,LPCSTR name,LUID *output)
{
    trace(4);CHECK(!system && name);if(active->fail==1 || !strcmp(name,"bad_lookup")){active->error=ERROR_NO_SUCH_PRIVILEGE;return FALSE;}
    if(!strcmp(name,"SeChangeNotifyPrivilege")){*output=(LUID){.LowPart=41,.HighPart=7};return TRUE;}
    CHECK(name[0]=='p');*output=(LUID){.LowPart=40+(DWORD)atoi(name+1),.HighPart=7};return TRUE;
}
static BOOL WINAPI mock_adjust(HANDLE token,BOOL all,const TOKEN_PRIVILEGES *input,DWORD bytes,TOKEN_PRIVILEGES *previous,DWORD *returned)
{
    (void)bytes;trace(5);CHECK(token==(HANDLE)(uintptr_t)0x2222 && !all && input && !previous && !returned && input->PrivilegeCount<=64);
    ++active->adjusts;active->observed_count=input->PrivilegeCount;memcpy(active->observed,input->Privileges,input->PrivilegeCount*sizeof(LUID_AND_ATTRIBUTES));
    if(active->fail==5){active->error=ERROR_PRIVILEGE_NOT_HELD;return FALSE;}active->error=active->adjust_error;return TRUE;
}
static BOOL WINAPI mock_set(HANDLE token,TOKEN_INFORMATION_CLASS kind,const void *input,DWORD bytes)
{
    trace(7);CHECK(token==(HANDLE)(uintptr_t)0x2222 && kind==TokenIntegrityLevel && bytes>=sizeof(TOKEN_MANDATORY_LABEL));++active->sets;
    const TOKEN_MANDATORY_LABEL *label=input;CHECK(label->Label.Attributes==SE_GROUP_INTEGRITY && IsValidSid(label->Label.Sid));
    DWORD size=GetLengthSid(label->Label.Sid);CHECK(size==12);memcpy(active->low_sid,label->Label.Sid,size);active->low_length=bytes;
    if(active->fail==6){active->error=ERROR_ACCESS_DENIED;return FALSE;}return TRUE;
}
static BOOL WINAPI mock_lookup_w(LPCWSTR system,LPCWSTR name,LUID *output)
{
    CHECK(!system && name);char narrow[64];unsigned index=0;
    while(index<63 && name[index]){if(name[index]>127){trace(4);active->error=ERROR_NO_SUCH_PRIVILEGE;return FALSE;}narrow[index]=(char)name[index];++index;}
    if(name[index]){trace(4);active->error=ERROR_NO_SUCH_PRIVILEGE;return FALSE;}narrow[index]=0;
    return mock_lookup(NULL,narrow,output);
}
static const token_ops ops={mock_process,mock_open,mock_query,mock_lookup,mock_adjust,mock_set,mock_close,mock_error,mock_set_error,mock_lookup_w};
#define GetCurrentProcess mock_process
#define OpenProcessToken mock_open
#define CloseHandle mock_close
#define GetTokenInformation mock_query
#undef LookupPrivilegeValue
#define LookupPrivilegeValue mock_lookup
#define AdjustTokenPrivileges mock_adjust
#define SetTokenInformation mock_set
#define GetLastError mock_error
#define AdjustPrivileges reference_AdjustPrivileges
#define AdjustPrivilegesForCurrentProcess reference_AdjustPrivilegesForCurrentProcess
#define RemoveTokenPrivs reference_RemoveTokenPrivs
#define LowMandatoryLevel reference_LowMandatoryLevel
static SID_IDENTIFIER_AUTHORITY label_authority=SECURITY_MANDATORY_LABEL_AUTHORITY;
#include "security_token_reference.inc"
#undef GetCurrentProcess
#undef OpenProcessToken
#undef CloseHandle
#undef GetTokenInformation
#undef LookupPrivilegeValue
#define LookupPrivilegeValue LookupPrivilegeValueA
#undef AdjustTokenPrivileges
#undef SetTokenInformation
#undef GetLastError
#undef AdjustPrivileges
#undef AdjustPrivilegesForCurrentProcess
#undef RemoveTokenPrivs
#undef LowMandatoryLevel
#include "security_token_windows.inc"
static struct state initial(unsigned count,unsigned failure)
{
    struct state value={0};value.count=count;value.fail=failure;
    for(unsigned index=0;index<64;++index)value.records[index]=(LUID_AND_ATTRIBUTES){.Luid={.LowPart=40+index,.HighPart=7},.Attributes=(index&3)|((index&4)?SE_PRIVILEGE_USED_FOR_ACCESS:0)};
    return value;
}
static bool same(const struct state *left,const struct state *right)
{
    return left->used==right->used && !memcmp(left->trace,right->trace,left->used*sizeof(unsigned)) &&
        left->closes==right->closes && left->access==right->access && left->adjusts==right->adjusts &&
        left->observed_count==right->observed_count && !memcmp(left->observed,right->observed,left->observed_count*sizeof(LUID_AND_ATTRIBUTES)) &&
        left->sets==right->sets && !memcmp(left->low_sid,right->low_sid,sizeof(left->low_sid));
}
static void compare(unsigned operation,unsigned count,unsigned failure,bool enable,const char *const *names)
{
    struct state left=initial(count,failure),right=left;BOOL expected=FALSE;active=&left;w_win32_error=0;
    if(operation==0)expected=reference_AdjustPrivileges((HANDLE)(uintptr_t)0x2222,names,enable);
    if(operation==1)expected=reference_AdjustPrivilegesForCurrentProcess(names,enable);
    if(operation==2)expected=reference_RemoveTokenPrivs();if(operation==3)expected=reference_LowMandatoryLevel();DWORD error=w_win32_error;
    active=&right;uint32_t status=0;
    if(operation==0)status=zapret_security_adjust((HANDLE)(uintptr_t)0x2222,names,enable,&ops);
    if(operation==1)status=zapret_security_adjust_current(names,enable,&ops);
    if(operation==2)status=zapret_security_remove(&ops);if(operation==3)status=zapret_security_low(&ops);
    bool missing=false;for(unsigned index=0;names[index];++index)if(names[index][0]=='p' && (unsigned)atoi(names[index]+1)>=count)missing=true;
    if(operation==1 && missing && (failure==0 || failure==5 || failure==6)) {
        /* C overwrites its logical error with a successful API's last-error. */
        CHECK(expected && !error && status==ERROR_PRIVILEGE_NOT_HELD && same(&left,&right));++logical_errors;
    } else CHECK(!!expected==!status && error==status && same(&left,&right));
    if(operation==3 && right.sets)CHECK(right.low_length==sizeof(TOKEN_MANDATORY_LABEL)+12);
    if(operation<2){
        struct state wide=initial(count,failure);active=&wide;
        WCHAR strings[4][64];const WCHAR *words[5]={0};unsigned word=0;
        for(;names[word];++word){CHECK(word<4);unsigned index=0;for(;names[word][index];++index){CHECK(index<63);strings[word][index]=(unsigned char)names[word][index];}strings[word][index]=0;words[word]=strings[word];}
        uint32_t wide_status=operation?zapret_security_adjust_current_w(words,enable,&ops):zapret_security_adjust_w((HANDLE)(uintptr_t)0x2222,words,enable,&ops);
        CHECK(wide_status==status && same(&right,&wide));++wide_cases;
    }
    ++cases;
}
static void real_duplicate(void)
{
    /* Initialize the Windows privilege lookup cache before handle accounting. */
    LUID warm;CHECK(LookupPrivilegeValueA(NULL,"SeChangeNotifyPrivilege",&warm));
    DWORD before,after;CHECK(GetProcessHandleCount(GetCurrentProcess(),&before));
    for(unsigned iteration=0;iteration<256;++iteration){HANDLE primary,duplicate;
        CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE,&primary));
        CHECK(DuplicateTokenEx(primary,TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES,NULL,SecurityImpersonation,TokenImpersonation,&duplicate));
        const char *names[]={"SeChangeNotifyPrivilege",NULL};const WCHAR *wide[]={L"SeChangeNotifyPrivilege",NULL};CHECK(!zapret_security_adjust(duplicate,names,false,NULL));CHECK(!zapret_security_adjust_w(duplicate,wide,true,NULL));
        CHECK(CloseHandle(duplicate) && CloseHandle(primary));
    }
    CHECK(GetProcessHandleCount(GetCurrentProcess(),&after));
    if(before!=after)fprintf(stderr,"token handle count before=%lu after=%lu\n",(unsigned long)before,(unsigned long)after);
    CHECK(before==after);
    printf("PASS security_token_real duplicate_transitions=512 handles_preserved=1\n");
}
static void real_low(void)
{
    CHECK(!zapret_security_remove(NULL));HANDLE token;CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token));DWORD size=0;
    CHECK(!GetTokenInformation(token,TokenPrivileges,NULL,0,&size) && GetLastError()==ERROR_INSUFFICIENT_BUFFER);TOKEN_PRIVILEGES *privileges=malloc(size);CHECK(privileges && GetTokenInformation(token,TokenPrivileges,privileges,size,&size));
    LUID keep;CHECK(LookupPrivilegeValueA(NULL,"SeChangeNotifyPrivilege",&keep));for(DWORD index=0;index<privileges->PrivilegeCount;++index)CHECK(!memcmp(&privileges->Privileges[index].Luid,&keep,sizeof(keep)));
    DWORD count=privileges->PrivilegeCount;free(privileges);CHECK(CloseHandle(token));CHECK(!zapret_security_low(NULL));CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token));
    size=0;CHECK(!GetTokenInformation(token,TokenIntegrityLevel,NULL,0,&size) && GetLastError()==ERROR_INSUFFICIENT_BUFFER);TOKEN_MANDATORY_LABEL *label=malloc(size);CHECK(label && GetTokenInformation(token,TokenIntegrityLevel,label,size,&size));
    CHECK(IsValidSid(label->Label.Sid));BYTE subauthorities=*GetSidSubAuthorityCount(label->Label.Sid);CHECK(subauthorities && *GetSidSubAuthority(label->Label.Sid,subauthorities-1)==SECURITY_MANDATORY_LOW_RID);free(label);CHECK(CloseHandle(token));
    printf("PASS security_token_real removed_except_notify=1 remaining=%lu low_integrity=4096\n",(unsigned long)count);
}
int main(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"--real-duplicate")){real_duplicate();return 0;}if(argc==2 && !strcmp(argv[1],"--real-low")){real_low();return 0;}CHECK(argc==1);
    const char *empty[]={NULL},*single[]={"p0",NULL},*pair[]={"p0","p1",NULL},*missing[]={"p63",NULL},*bad[]={"bad_lookup",NULL};
    const char *const *lists[]={empty,single,pair,missing,bad};
    for(unsigned count=0;count<=32;++count)for(unsigned failure=0;failure<=6;++failure)for(unsigned enable=0;enable<2;++enable)for(unsigned names=0;names<5;++names)for(unsigned operation=0;operation<4;++operation)compare(operation,count,failure,enable!=0,lists[names]);
    struct state value=initial(4,0);active=&value;value.adjust_error=ERROR_NOT_ALL_ASSIGNED;w_win32_error=0;
    CHECK(reference_RemoveTokenPrivs());value=initial(4,0);value.adjust_error=ERROR_NOT_ALL_ASSIGNED;CHECK(zapret_security_remove(&ops)==ERROR_NOT_ALL_ASSIGNED && value.closes==1);++improvements;
    value=initial(4,5);value.close_error=ERROR_BAD_LENGTH;CHECK(zapret_security_remove(&ops)==ERROR_PRIVILEGE_NOT_HELD && value.closes==1);++improvements;
    value=initial(4,6);value.close_error=ERROR_BAD_LENGTH;CHECK(zapret_security_low(&ops)==ERROR_ACCESS_DENIED && value.closes==1);++improvements;
    for(unsigned malformed=1;malformed<=7;++malformed){value=initial(4,0);value.malformed=malformed;CHECK(zapret_security_remove(&ops)!=0 && value.closes==1 && !value.adjusts);++boundaries;}
    value=initial(4,0);value.growth=2;CHECK(!zapret_security_remove(&ops) && value.count==6 && value.queries==4 && value.closes==1 && value.adjusts==1);++mutations;
    value=initial(4,0);value.growth=4;CHECK(zapret_security_remove(&ops)==ERROR_INSUFFICIENT_BUFFER && value.queries==4 && value.closes==1 && !value.adjusts);++boundaries;
    value=initial(4,0);const char *unterminated[257];for(unsigned index=0;index<257;++index)unterminated[index]="p0";
    CHECK(zapret_security_adjust((HANDLE)(uintptr_t)0x2222,unterminated,true,&ops)==ERROR_INVALID_PARAMETER && !value.adjusts);++boundaries;
    CHECK(zapret_security_adjust(NULL,empty,true,&ops)==ERROR_INVALID_PARAMETER);++boundaries;
    CHECK(zapret_security_adjust((HANDLE)(uintptr_t)0x2222,NULL,true,&ops)==ERROR_INVALID_PARAMETER);++boundaries;
    printf("PASS security_token functions=4 cases=%u wide_cases=%u boundary_cases=%u growing_snapshots=%u failure_improvements=%u logical_error_repairs=%u\n",cases,wide_cases,boundaries,mutations,improvements,logical_errors);return 0;
}
