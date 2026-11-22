/* MIT. OS writes are mocked except for explicitly owned real fixture paths. */
#include <windows.h>
#include <initguid.h>
#include <knownfolders.h>
#include <shlobj.h>
#include <aclapi.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "win_files.h"
#undef main
static unsigned cases,folder_cases,boundaries,cleanup_repairs,com_cases;
#define CHECK(condition) do {if(!(condition)){fprintf(stderr,"FAIL security label cases=%u folders=%u boundaries=%u line=%d error=%lu: %s\n",cases,folder_cases,boundaries,__LINE__,(unsigned long)GetLastError(),#condition);exit(1);}}while(0)
uint32_t w_win32_error;
typedef struct {
    BOOL (WINAPI *initialize_acl)(ACL *,DWORD,DWORD);
    BOOL (WINAPI *add)(ACL *,DWORD,DWORD,DWORD,void *);
    DWORD (WINAPI *attributes)(const WCHAR *);
    DWORD (WINAPI *named)(const WCHAR *,SE_OBJECT_TYPE,DWORD,void *,void *,const ACL *,const ACL *);
    DWORD (WINAPI *object)(HANDLE,SE_OBJECT_TYPE,DWORD,void *,void *,const ACL *,const ACL *);
    DWORD (WINAPI *error)(void);
    HRESULT (WINAPI *folder)(const GUID *,DWORD,HANDLE,WCHAR **);
    void (WINAPI *release)(const void *);
    BOOL (WINAPI *environment)(const WCHAR *,const WCHAR *);
    HRESULT (WINAPI *initialize_com)(const void *,DWORD);
    void (WINAPI *uninitialize_com)(void);
} label_ops;
_Static_assert(sizeof(label_ops)==88,"Rust label callback ABI");
uint32_t zapret_security_label_w(const WCHAR *,uint32_t,uint32_t,const void *);
uint32_t zapret_security_label_file(const char *,uint32_t,uint32_t,const void *);
uint32_t zapret_security_label_object(HANDLE,int,uint32_t,uint32_t,uint32_t,const void *);
uint32_t zapret_security_ensure(const char *,bool,const void *);
uint32_t zapret_security_appdata(const void *);
struct state {
    unsigned failure,used,trace[32],writes,aligned,frees,env_writes,initializations,uninitializations;
    DWORD attributes;HRESULT folder_result,com_result;bool allocate_on_failure,invalid_utf16,empty_path,null_folder;size_t folder_units;
    WCHAR path[512],environment[512];BYTE acl[32];DWORD acl_used;WCHAR *allocation;
};
static struct state *active;
static void trace(unsigned value){CHECK(active->used<32);active->trace[active->used++]=value;}
static DWORD WINAPI mock_error(void){return GetLastError();}
static DWORD WINAPI mock_attributes(const WCHAR *path){trace(1);CHECK(path);if(active->failure==1){SetLastError(ERROR_FILE_NOT_FOUND);return INVALID_FILE_ATTRIBUTES;}return active->attributes;}
static BOOL WINAPI mock_initialize(ACL *acl,DWORD size,DWORD revision){trace(2);CHECK(size==32 && revision==ACL_REVISION);active->aligned=((uintptr_t)acl%4)==0;if(active->failure==2){SetLastError(ERROR_INVALID_ACL);return FALSE;}return InitializeAcl(acl,size,revision);}
static BOOL WINAPI mock_add(ACL *acl,DWORD revision,DWORD flags,DWORD policy,void *sid){trace(3);CHECK(policy==SYSTEM_MANDATORY_LABEL_NO_WRITE_UP);if(active->failure==3){SetLastError(ERROR_INVALID_SID);return FALSE;}return AddMandatoryAce(acl,revision,flags,policy,sid);}
static void capture_acl(const ACL *acl)
{
    ACL_SIZE_INFORMATION size;CHECK(GetAclInformation((ACL *)acl,&size,sizeof(size),AclSizeInformation) && size.AceCount==1 && size.AclBytesInUse<=32);active->acl_used=size.AclBytesInUse;memcpy(active->acl,acl,size.AclBytesInUse);
}
static DWORD WINAPI mock_named(const WCHAR *path,SE_OBJECT_TYPE kind,DWORD info,void *owner,void *group,const ACL *dacl,const ACL *sacl)
{trace(4);CHECK(path && kind==SE_FILE_OBJECT && info==LABEL_SECURITY_INFORMATION && !owner && !group && !dacl && sacl);wcsncpy(active->path,path,511);active->path[511]=0;capture_acl(sacl);++active->writes;return active->failure==4?ERROR_ACCESS_DENIED:ERROR_SUCCESS;}
static DWORD WINAPI mock_object(HANDLE handle,SE_OBJECT_TYPE kind,DWORD info,void *owner,void *group,const ACL *dacl,const ACL *sacl)
{trace(5);CHECK(handle==(HANDLE)(uintptr_t)0x2222 && kind==SE_KERNEL_OBJECT && info==LABEL_SECURITY_INFORMATION && !owner && !group && !dacl && sacl);capture_acl(sacl);++active->writes;return active->failure==4?ERROR_ACCESS_DENIED:ERROR_SUCCESS;}
static HRESULT WINAPI mock_folder(const GUID *id,DWORD flags,HANDLE token,WCHAR **path)
{
    trace(6);CHECK(!memcmp(id,&FOLDERID_LocalAppDataLow,sizeof(*id)) && !flags && !token);*path=NULL;
    if(active->null_folder)return active->folder_result;
    if(SUCCEEDED(active->folder_result) || active->allocate_on_failure){
        static const WCHAR value[]=L"C:\\private\\данные-é-中";size_t bytes=active->folder_units?(active->folder_units+1)*sizeof(WCHAR):sizeof(value);WCHAR *output=CoTaskMemAlloc(bytes);CHECK(output);
        if(active->folder_units){for(size_t i=0;i<active->folder_units;++i)output[i]=L'x';output[active->folder_units]=0;}else memcpy(output,value,bytes);
        if(active->invalid_utf16){output[0]=0xd800;output[1]=0;}if(active->empty_path)output[0]=0;active->allocation=output;*path=output;
    }
    return active->folder_result;
}
static void WINAPI mock_release(const void *path){trace(7);CHECK(path && path==active->allocation);++active->frees;CoTaskMemFree((void *)path);active->allocation=NULL;if(active->failure==7)SetLastError(ERROR_BAD_LENGTH);}
static BOOL WINAPI mock_environment(const WCHAR *name,const WCHAR *value){trace(8);CHECK(!wcscmp(name,L"APPDATALOW") && value);if(active->failure==6){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}wcsncpy(active->environment,value,511);active->environment[511]=0;++active->env_writes;return TRUE;}
static int mock_environment_utf8(const char *name,const char *value,int overwrite)
{CHECK(!strcmp(name,"APPDATALOW") && overwrite==1);WCHAR wide[512];CHECK(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value,-1,wide,512));return mock_environment(L"APPDATALOW",wide)?0:-1;}
static HRESULT WINAPI mock_com(const void *reserved,DWORD flags){CHECK(!reserved && flags==COINIT_APARTMENTTHREADED);++active->initializations;return active->com_result;}
static void WINAPI mock_uninitialize(void){++active->uninitializations;if(active->failure==7)SetLastError(ERROR_BAD_LENGTH);}
static const label_ops ops={mock_initialize,mock_add,mock_attributes,mock_named,mock_object,mock_error,mock_folder,mock_release,mock_environment,mock_com,mock_uninitialize};
#define GetFileAttributesW mock_attributes
#define InitializeAcl mock_initialize
#define AddMandatoryAce mock_add
#define SetNamedSecurityInfoW mock_named
#define SetSecurityInfo mock_object
#define SHGetKnownFolderPath mock_folder
#define CoTaskMemFree mock_release
#define wf_setenv mock_environment_utf8
#define SetMandatoryLabelFileW reference_SetMandatoryLabelFileW
#define SetMandatoryLabelFile reference_SetMandatoryLabelFile
#define SetMandatoryLabelObject reference_SetMandatoryLabelObject
#define ensure_file_access reference_ensure_file_access
#define ensure_dir_access reference_ensure_dir_access
#define prepare_low_appdata reference_prepare_low_appdata
static SID_IDENTIFIER_AUTHORITY label_authority=SECURITY_MANDATORY_LABEL_AUTHORITY;
#include "security_label_reference.inc"
#undef GetFileAttributesW
#undef InitializeAcl
#undef AddMandatoryAce
#undef SetNamedSecurityInfoW
#undef SetSecurityInfo
#undef SHGetKnownFolderPath
#undef CoTaskMemFree
#undef wf_setenv
#undef SetMandatoryLabelFileW
#undef SetMandatoryLabelFile
#undef SetMandatoryLabelObject
#undef ensure_file_access
#undef ensure_dir_access
#undef prepare_low_appdata
#include "security_label_windows.inc"
static bool same(const struct state *left,const struct state *right)
{return left->used==right->used && !memcmp(left->trace,right->trace,left->used*sizeof(unsigned)) && left->writes==right->writes && left->acl_used==right->acl_used && !memcmp(left->acl,right->acl,left->acl_used) && !wcscmp(left->path,right->path);}
static void compare(unsigned operation,const char *name,const WCHAR *wide,DWORD attributes,DWORD rid,DWORD revision,DWORD flags,unsigned failure)
{
    struct state left={0},right={0};left.failure=right.failure=failure;left.attributes=right.attributes=attributes;BOOL expected=FALSE;uint32_t status=0;SetLastError(0);w_win32_error=0;active=&left;
    switch(operation){case 0:expected=reference_SetMandatoryLabelFile(name,rid,flags);break;case 1:expected=reference_SetMandatoryLabelFileW(wide,rid,flags);break;case 2:expected=reference_SetMandatoryLabelObject((HANDLE)(uintptr_t)0x2222,SE_KERNEL_OBJECT,rid,revision,flags);break;case 3:expected=reference_ensure_file_access(name);break;case 4:expected=reference_ensure_dir_access(name);break;}
    DWORD error=w_win32_error;SetLastError(0);active=&right;
    switch(operation){case 0:status=zapret_security_label_file(name,rid,flags,&ops);break;case 1:status=zapret_security_label_w(wide,rid,flags,&ops);break;case 2:status=zapret_security_label_object((HANDLE)(uintptr_t)0x2222,SE_KERNEL_OBJECT,rid,revision,flags,&ops);break;case 3:status=zapret_security_ensure(name,false,&ops);break;case 4:status=zapret_security_ensure(name,true,&ops);break;}
    CHECK(!!expected==!status && error==status && same(&left,&right));if(right.used>1 || right.writes)CHECK(right.aligned);++cases;
}
static void compare_folder(unsigned failure,HRESULT result,HRESULT apartment,bool allocate,bool invalid,bool empty)
{
    struct state left={0},right={0};left.failure=failure;left.folder_result=result;left.com_result=apartment;left.allocate_on_failure=allocate;left.invalid_utf16=invalid;left.empty_path=empty;right=left;
    active=&left;SetLastError(0);BOOL expected=reference_prepare_low_appdata();
    active=&right;SetLastError(0);uint32_t status=zapret_security_appdata(&ops);
    CHECK(right.initializations==1 && right.uninitializations==(SUCCEEDED(apartment)?1:0));
    if(FAILED(apartment) && apartment!=RPC_E_CHANGED_MODE){CHECK(status && !right.used && !right.env_writes);++com_cases;}
    else if(empty && SUCCEEDED(result)){CHECK(expected && status==ERROR_INVALID_DATA && !right.env_writes && right.frees==1);++boundaries;}
    else {CHECK(!!expected==!status && left.env_writes==right.env_writes && !wcscmp(left.environment,right.environment));++folder_cases;}
    if(FAILED(result) && allocate && (SUCCEEDED(apartment)||apartment==RPC_E_CHANGED_MODE)){CHECK(left.frees==0 && right.frees==1);++cleanup_repairs;}
    if(left.allocation)CoTaskMemFree(left.allocation);CHECK(!right.allocation);
}
static void folder_boundaries(void)
{
    struct state value={0};active=&value;value.null_folder=true;
    CHECK(zapret_security_appdata(&ops)==ERROR_INVALID_DATA && !value.env_writes && !value.allocation && value.uninitializations==1);++boundaries;
    memset(&value,0,sizeof(value));value.folder_units=32767;
    CHECK(!zapret_security_appdata(&ops) && value.env_writes==1 && value.frees==1 && !value.allocation && value.uninitializations==1);++boundaries;
    memset(&value,0,sizeof(value));value.folder_units=32768;
    CHECK(zapret_security_appdata(&ops)==ERROR_FILENAME_EXCED_RANGE && !value.env_writes && value.frees==1 && !value.allocation && value.uninitializations==1);++boundaries;
    memset(&value,0,sizeof(value));value.folder_result=(HRESULT)0x80070000;value.allocate_on_failure=true;value.failure=7;
    CHECK(zapret_security_appdata(&ops)==ERROR_GEN_FAILURE && !value.env_writes && value.frees==1 && !value.allocation && value.uninitializations==1);++boundaries;
    memset(&value,0,sizeof(value));value.folder_result=HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);value.allocate_on_failure=true;value.failure=7;
    CHECK(zapret_security_appdata(&ops)==ERROR_PATH_NOT_FOUND && !value.env_writes && value.frees==1 && !value.allocation && value.uninitializations==1);++boundaries;
    memset(&value,0,sizeof(value));value.com_result=(HRESULT)0x80070000;
    CHECK(zapret_security_appdata(&ops)==ERROR_GEN_FAILURE && !value.used && !value.env_writes && !value.frees && !value.uninitializations);++boundaries;
}
static DWORD read_label(const WCHAR *path,HANDLE object,DWORD *flags)
{
    PSECURITY_DESCRIPTOR descriptor=NULL;PACL sacl=NULL;DWORD error=path?GetNamedSecurityInfoW((WCHAR *)path,SE_FILE_OBJECT,LABEL_SECURITY_INFORMATION,NULL,NULL,NULL,&sacl,&descriptor):GetSecurityInfo(object,SE_KERNEL_OBJECT,LABEL_SECURITY_INFORMATION,NULL,NULL,NULL,&sacl,&descriptor);CHECK(!error && descriptor && sacl);
    SYSTEM_MANDATORY_LABEL_ACE *ace=NULL;CHECK(GetAce(sacl,0,(void **)&ace));CHECK(ace->Header.AceType==SYSTEM_MANDATORY_LABEL_ACE_TYPE && ace->Mask==SYSTEM_MANDATORY_LABEL_NO_WRITE_UP);PSID sid=&ace->SidStart;CHECK(IsValidSid(sid));DWORD rid=*GetSidSubAuthority(sid,*GetSidSubAuthorityCount(sid)-1);*flags=ace->Header.AceFlags;LocalFree(descriptor);return rid;
}
static void real(void)
{
    WCHAR original[32768],directory[32768];DWORD length=GetTempPathW(32768,directory);CHECK(length && length<32672 && GetCurrentDirectoryW(32768,original));
    swprintf(directory+length,32768-length,L"zapret-private-label-%lu-%llu",(unsigned long)GetCurrentProcessId(),(unsigned long long)GetTickCount64());CHECK(CreateDirectoryW(directory,NULL) && SetCurrentDirectoryW(directory));
    HANDLE file=CreateFileW(L"данные-é-中.bin",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);CHECK(file!=INVALID_HANDLE_VALUE && CloseHandle(file));
    CHECK(SetMandatoryLabelFile("данные-é-中.bin",SECURITY_MANDATORY_LOW_RID,0));DWORD flags=0;CHECK(read_label(L"данные-é-中.bin",NULL,&flags)==SECURITY_MANDATORY_LOW_RID && !flags);
    CHECK(SetMandatoryLabelFileW(L"данные-é-中.bin",SECURITY_MANDATORY_LOW_RID,0) && ensure_file_access("данные-é-中.bin"));
    CHECK(ensure_dir_access("."));CHECK(read_label(L".",NULL,&flags)==SECURITY_MANDATORY_LOW_RID && (flags&3)==3);
    WCHAR event_name[128];swprintf(event_name,128,L"Local\\zapret-private-label-%lu-%llu",(unsigned long)GetCurrentProcessId(),(unsigned long long)GetTickCount64());
    HANDLE event=CreateEventW(NULL,TRUE,FALSE,event_name);CHECK(event && GetLastError()!=ERROR_ALREADY_EXISTS);CHECK(SetMandatoryLabelObject(event,SE_KERNEL_OBJECT,SECURITY_MANDATORY_LOW_RID,ACL_REVISION,0));CHECK(read_label(NULL,event,&flags)==SECURITY_MANDATORY_LOW_RID && !flags);CHECK(CloseHandle(event));
    CHECK(SUCCEEDED(CoInitializeEx(NULL,COINIT_MULTITHREADED)));SetEnvironmentVariableW(L"APPDATALOW",L"fixture sentinel");HRESULT hr;WCHAR *expected=NULL;hr=SHGetKnownFolderPath(&FOLDERID_LocalAppDataLow,0,NULL,&expected);
    BOOL initialized=prepare_low_appdata();if(SUCCEEDED(hr)){WCHAR value[32768];CHECK(initialized && GetEnvironmentVariableW(L"APPDATALOW",value,32768) && !wcscmp(value,expected));}else CHECK(!initialized);CoTaskMemFree(expected);
    APTTYPE type;APTTYPEQUALIFIER qualifier;CHECK(SUCCEEDED(CoGetApartmentType(&type,&qualifier)) && type==APTTYPE_MTA);CoUninitialize();
    CHECK(DeleteFileW(L"данные-é-中.bin") && SetCurrentDirectoryW(original) && RemoveDirectoryW(directory));
    printf("PASS security_label_real private_files=1 private_directories=1 private_objects=1 existing_com_preserved=1\n");
}
int main(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"--real")){real();return 0;}CHECK(argc==1);
    const char *names[]={"данные-é-中.bin","\\\\.\\WinDivert","",NULL,"bad-\xff-path"};const WCHAR *wide[]={L"данные-é-中.bin",L"\\\\.\\WinDivert",L"",L"missing",L"bad-path"};
    const DWORD rids[]={0,4096,8192,12288,UINT32_MAX};
    for(unsigned name=0;name<5;++name)for(unsigned directory=0;directory<2;++directory)for(unsigned rid=0;rid<5;++rid)for(DWORD flags=0;flags<16;++flags)for(unsigned failure=0;failure<=4;++failure)for(unsigned operation=0;operation<5;++operation)compare(operation,names[name],wide[name],directory?FILE_ATTRIBUTE_DIRECTORY:0,rids[rid],directory?ACL_REVISION_DS:ACL_REVISION,flags,failure);
    const HRESULT apartments[]={S_OK,S_FALSE,RPC_E_CHANGED_MODE,E_OUTOFMEMORY};const HRESULT results[]={S_OK,S_FALSE,E_FAIL,HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND)};
    for(unsigned apartment=0;apartment<4;++apartment)for(unsigned query=0;query<4;++query)for(unsigned allocation=0;allocation<2;++allocation)for(unsigned invalid=0;invalid<2;++invalid)for(unsigned failure=0;failure<2;++failure)compare_folder(failure?6:0,results[query],apartments[apartment],allocation!=0,invalid!=0,false);
    compare_folder(0,S_OK,S_OK,false,false,true);compare_folder(7,S_OK,S_OK,false,false,false);
    folder_boundaries();
    struct state value={0};active=&value;CHECK(zapret_security_label_w(NULL,4096,0,&ops)==ERROR_INVALID_PARAMETER);++boundaries;CHECK(zapret_security_label_object(NULL,SE_KERNEL_OBJECT,4096,ACL_REVISION,0,&ops)==ERROR_INVALID_PARAMETER);++boundaries;
    printf("PASS security_label functions=6 cases=%u folder_cases=%u boundaries=%u failed_query_releases=%u com_failures=%u\n",cases,folder_cases,boundaries,cleanup_repairs,com_cases);return 0;
}
