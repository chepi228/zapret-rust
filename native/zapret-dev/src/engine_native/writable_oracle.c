/* MIT. Reference side effects are mocked; real writes use an owned TEMP tree. */
#include <windows.h>
#include <aclapi.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <errno.h>
#include "win_files.h"
#undef main
static unsigned cases,boundaries,publication_repairs,file_repairs,truncation_repairs,growing_reads;
#define CHECK(value) do {if(!(value)){fprintf(stderr,"FAIL writable cases=%u boundary=%u line=%d error=%lu: %s\n",cases,boundaries,__LINE__,(unsigned long)GetLastError(),#value);exit(1);}}while(0)
uint32_t w_win32_error;
typedef struct {
    DWORD (WINAPI *getenv)(const WCHAR *,WCHAR *,DWORD);
    BOOL (WINAPI *mkdir)(const WCHAR *,const SECURITY_ATTRIBUTES *);
    DWORD (WINAPI *attributes)(const WCHAR *);
    uint32_t (*label)(const WCHAR *);
    BOOL (WINAPI *environment)(const WCHAR *,const WCHAR *);
    DWORD (WINAPI *error)(void);
} writable_ops;
_Static_assert(sizeof(writable_ops)==48,"Rust writable callback ABI");
uint32_t zapret_writable_prepare(const char *,const void *);
static struct {char writable_dir[4096];} params;
struct state {unsigned used,trace[16],failure,attributes_calls,environment_writes,get_calls,growth;DWORD directory_attributes,probe_size;bool missing,invalid_utf16,malformed;char base[16384];WCHAR directory[8192],published[8192];};
static struct state *active;
static void trace(unsigned step){CHECK(active->used<16);active->trace[active->used++]=step;}
static DWORD WINAPI mock_error(void){return GetLastError();}
static DWORD WINAPI mock_getenv(const WCHAR *name,WCHAR *output,DWORD capacity)
{
    CHECK(!wcscmp(name,L"APPDATALOW"));++active->get_calls;if(!output)trace(1);
    if(active->missing || active->failure==1){SetLastError(ERROR_ENVVAR_NOT_FOUND);return 0;}
    if(!output && active->probe_size)return active->probe_size;
    WCHAR wide[32768];int needed=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,active->base,-1,wide,32768);CHECK(needed);
    if(!*active->base){SetLastError(0);return 0;}
    if(active->invalid_utf16){wide[0]=0xd800;wide[1]=0;needed=2;}
    if(!output)return (DWORD)needed;
    if(active->growth && active->get_calls<=active->growth+1)return capacity+1;
    if(capacity<(DWORD)needed)return (DWORD)needed;
    memcpy(output,wide,needed*sizeof(WCHAR));if(active->malformed)output[needed-1]=L'x';return (DWORD)needed-1;
}
static BOOL WINAPI mock_mkdir(const WCHAR *path,const SECURITY_ATTRIBUTES *attributes)
{
    trace(2);CHECK(!attributes && wcslen(path)<8192);wcscpy(active->directory,path);
    if(active->failure==2 || active->failure==3 || active->failure==7){SetLastError(active->failure==3?ERROR_ALREADY_EXISTS:active->failure==7?0:ERROR_ACCESS_DENIED);return FALSE;}return TRUE;
}
static DWORD WINAPI mock_attributes(const WCHAR *path){CHECK(!wcscmp(path,active->directory));++active->attributes_calls;if(active->failure==4){SetLastError(ERROR_FILE_NOT_FOUND);return INVALID_FILE_ATTRIBUTES;}return active->directory_attributes;}
static uint32_t mock_label(const WCHAR *path){trace(4);CHECK(!wcscmp(path,active->directory));return active->failure==5?ERROR_ACCESS_DENIED:0;}
static BOOL WINAPI mock_environment(const WCHAR *name,const WCHAR *value)
{trace(5);CHECK(!wcscmp(name,L"WRITABLE") && value && wcslen(value)<8192);if(active->failure==6){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}wcscpy(active->published,value);++active->environment_writes;return TRUE;}
static const writable_ops ops={mock_getenv,mock_mkdir,mock_attributes,mock_label,mock_environment,mock_error};
static char *reference_getenv(const char *name){CHECK(!strcmp(name,"APPDATALOW"));trace(1);if(active->missing || active->failure==1){SetLastError(ERROR_ENVVAR_NOT_FOUND);return NULL;}return active->base;}
static int reference_mkdir(const char *path,int mode){CHECK(mode==0755);WCHAR *wide=wf_path_utf16(path);CHECK(wide);BOOL result=mock_mkdir(wide,NULL);free(wide);if(!result)errno=active->failure==3?EEXIST:EACCES;return result?0:-1;}
static bool reference_ensure(const char *path){WCHAR *wide=wf_path_utf16(path);CHECK(wide);DWORD attributes=mock_attributes(wide);DWORD result=attributes==INVALID_FILE_ATTRIBUTES?GetLastError():mock_label(wide);free(wide);SetLastError(result);return !result;}
static int reference_setenv(const char *name,const char *value,int overwrite){CHECK(!strcmp(name,"WRITABLE") && overwrite==1);WCHAR wide[8192];CHECK(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value,-1,wide,8192));return mock_environment(L"WRITABLE",wide)?0:-1;}
#undef getenv
#undef mkdir
#undef setenv
#define getenv reference_getenv
#define mkdir reference_mkdir
#define setenv reference_setenv
#define ensure_dir_access reference_ensure
#define make_writable_dir reference_make_writable_dir
#include "writable_reference.inc"
#undef getenv
#undef mkdir
#undef setenv
#undef ensure_dir_access
#undef make_writable_dir
static void compare(const char *configured,const char *base,unsigned failure)
{
    struct state left={0},right={0};left.failure=failure;left.directory_attributes=FILE_ATTRIBUTE_DIRECTORY;strcpy(left.base,base);right=left;strcpy(params.writable_dir,configured);
    active=&left;SetLastError(0);BOOL expected=reference_make_writable_dir();DWORD error=GetLastError();
    active=&right;SetLastError(0);DWORD result=zapret_writable_prepare(configured,&ops);
    CHECK(left.used==right.used && !memcmp(left.trace,right.trace,left.used*sizeof(unsigned)) && !wcscmp(left.directory,right.directory) && !wcscmp(left.published,right.published) && left.environment_writes==right.environment_writes && left.attributes_calls==right.attributes_calls);
    if(failure==6 && left.used && left.trace[left.used-1]==5){CHECK(expected && result==ERROR_ACCESS_DENIED && !right.environment_writes);++publication_repairs;}
    else CHECK(!!expected==!result && (!result || result==(error?error:ERROR_GEN_FAILURE)));
    ++cases;
}
static void boundary_checks(void)
{
    struct state value={0};active=&value;value.directory_attributes=FILE_ATTRIBUTE_DIRECTORY;strcpy(value.base,"C:\\private");
    CHECK(zapret_writable_prepare(NULL,&ops)==ERROR_INVALID_PARAMETER && !value.used);++boundaries;
    CHECK(zapret_writable_prepare("bad-\xff",&ops)==ERROR_NO_UNICODE_TRANSLATION && !value.used);++boundaries;
    char too_long[4097];memset(too_long,'x',4096);too_long[4096]=0;CHECK(zapret_writable_prepare(too_long,&ops)==ERROR_FILENAME_EXCED_RANGE && !value.used);++boundaries;
    value.probe_size=32769;CHECK(zapret_writable_prepare("",&ops)==ERROR_FILENAME_EXCED_RANGE && value.used==1);++boundaries;
    memset(&value,0,sizeof(value));value.directory_attributes=FILE_ATTRIBUTE_DIRECTORY;value.missing=true;CHECK(zapret_writable_prepare("",&ops)==ERROR_ENVVAR_NOT_FOUND && value.used==1 && !value.environment_writes);++boundaries;
    memset(&value,0,sizeof(value));value.directory_attributes=FILE_ATTRIBUTE_DIRECTORY;CHECK(zapret_writable_prepare("",&ops)==ERROR_INVALID_DATA && value.used==1 && !value.environment_writes);++boundaries;
    memset(&value,0,sizeof(value));value.directory_attributes=FILE_ATTRIBUTE_DIRECTORY;strcpy(value.base,"C:\\private");value.invalid_utf16=true;CHECK(zapret_writable_prepare("",&ops)==ERROR_NO_UNICODE_TRANSLATION && value.used==1);++boundaries;
    memset(&value,0,sizeof(value));value.directory_attributes=FILE_ATTRIBUTE_DIRECTORY;strcpy(value.base,"C:\\private");value.malformed=true;CHECK(zapret_writable_prepare("",&ops)==ERROR_INVALID_DATA && value.used==1);++boundaries;
    for(unsigned growth=1;growth<=4;++growth){memset(&value,0,sizeof(value));value.directory_attributes=FILE_ATTRIBUTE_DIRECTORY;strcpy(value.base,"C:\\private");value.growth=growth;DWORD result=zapret_writable_prepare("",&ops);CHECK(growth<3?(!result && value.environment_writes==1):(result==ERROR_MORE_DATA && !value.environment_writes));++growing_reads;}
    memset(&value,0,sizeof(value));value.failure=3;strcpy(value.base,"C:\\private");strcpy(params.writable_dir,"occupied-file");active=&value;CHECK(reference_make_writable_dir());memset(&value,0,sizeof(value));value.failure=3;CHECK(zapret_writable_prepare("occupied-file",&ops)==ERROR_DIRECTORY && !value.environment_writes && value.used==1);++file_repairs;
    for(unsigned extra=0;extra<3;++extra){struct state old={0};old.directory_attributes=FILE_ATTRIBUTE_DIRECTORY;memset(old.base,'x',4087+extra);old.base[4087+extra]=0;active=&old;*params.writable_dir=0;BOOL expected=reference_make_writable_dir();struct state next={0};next.directory_attributes=FILE_ATTRIBUTE_DIRECTORY;strcpy(next.base,old.base);active=&next;DWORD result=zapret_writable_prepare("",&ops);CHECK(expected);if(extra){CHECK(result==ERROR_FILENAME_EXCED_RANGE && next.used==1 && !next.environment_writes);++truncation_repairs;}else CHECK(!result && next.environment_writes==1);++boundaries;}
}
#include "writable_windows.inc"
static void label_check(const WCHAR *path)
{
    PSECURITY_DESCRIPTOR descriptor=NULL;PACL sacl=NULL;CHECK(!GetNamedSecurityInfoW((WCHAR *)path,SE_FILE_OBJECT,LABEL_SECURITY_INFORMATION,NULL,NULL,NULL,&sacl,&descriptor) && descriptor && sacl);SYSTEM_MANDATORY_LABEL_ACE *ace=NULL;CHECK(GetAce(sacl,0,(void **)&ace) && ace->Header.AceType==SYSTEM_MANDATORY_LABEL_ACE_TYPE && (ace->Header.AceFlags&3)==3 && *GetSidSubAuthority((PSID)&ace->SidStart,0)==SECURITY_MANDATORY_LOW_RID);LocalFree(descriptor);
}
static void real(void)
{
    WCHAR original[32768],directory[32768];DWORD length=GetTempPathW(32768,directory);CHECK(length && length<32640 && GetCurrentDirectoryW(32768,original));swprintf(directory+length,32768-length,L"zapret-private-writable-%lu-%llu",(unsigned long)GetCurrentProcessId(),(unsigned long long)GetTickCount64());CHECK(CreateDirectoryW(directory,NULL) && SetCurrentDirectoryW(directory));
    CHECK(SetEnvironmentVariableW(L"WRITABLE",L"previous sentinel"));strcpy(params.writable_dir,"данные-é-中");CHECK(make_writable_dir());WCHAR value[32768];CHECK(GetEnvironmentVariableW(L"WRITABLE",value,32768) && !wcscmp(value,L"данные-é-中"));label_check(L"данные-é-中");CHECK(make_writable_dir());
    HANDLE file=CreateFileW(L"occupied-file",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);CHECK(file!=INVALID_HANDLE_VALUE && CloseHandle(file));strcpy(params.writable_dir,"occupied-file");CHECK(!make_writable_dir() && w_win32_error==ERROR_DIRECTORY);CHECK(GetEnvironmentVariableW(L"WRITABLE",value,32768) && !wcscmp(value,L"данные-é-中"));
    CHECK(SetEnvironmentVariableW(L"APPDATALOW",directory));*params.writable_dir=0;CHECK(make_writable_dir());WCHAR expected[32768];swprintf(expected,32768,L"%ls/zapret2",directory);CHECK(GetEnvironmentVariableW(L"WRITABLE",value,32768) && !wcscmp(value,expected));label_check(L"zapret2");
    CHECK(SetEnvironmentVariableW(L"APPDATALOW",NULL));CHECK(!make_writable_dir() && w_win32_error==ERROR_ENVVAR_NOT_FOUND);CHECK(GetEnvironmentVariableW(L"WRITABLE",value,32768) && !wcscmp(value,expected));
    *params.writable_dir=0;for(unsigned i=0;i<10;++i){size_t used=strlen(params.writable_dir);snprintf(params.writable_dir+used,sizeof(params.writable_dir)-used,"%slong-%02u-abcdefghijklmnopqrstuv",i?"/":"",i);if(i<9)CHECK(!wf_mkdir(params.writable_dir,0755));}
    CHECK(strlen(params.writable_dir)>260 && make_writable_dir());WCHAR *long_wide=wf_path_utf16(params.writable_dir);CHECK(long_wide);label_check(long_wide);free(long_wide);CHECK(GetEnvironmentVariableW(L"WRITABLE",value,32768) && MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,params.writable_dir,-1,expected,32768) && !wcscmp(value,expected));CHECK(make_writable_dir());
    for(unsigned i=0;i<10;++i){CHECK(!wf_remove(params.writable_dir));char *slash=strrchr(params.writable_dir,'/');if(slash)*slash=0;else *params.writable_dir=0;}
    CHECK(DeleteFileW(L"occupied-file") && RemoveDirectoryW(L"данные-é-中") && RemoveDirectoryW(L"zapret2") && SetCurrentDirectoryW(original) && RemoveDirectoryW(directory));
    printf("PASS writable_real private_directories=12 existing_directory=2 existing_file_rejected=1 previous_environment_preserved=1 unicode_paths=1 long_paths=1\n");
}
int main(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"--real")){real();return 0;}CHECK(argc==1);
    const char *names[]={"","данные-é-中","relative/path","C:\\private\\state","/cygdrive/C/private","with space/next","prefix/../state","\\\\server\\share\\state"};
    const char *bases[]={"C:\\low","данные-é-中","D:/path with spaces/","/cygdrive/C/low"};
    for(unsigned repeat=0;repeat<16;++repeat)for(unsigned name=0;name<8;++name)for(unsigned base=0;base<4;++base)for(unsigned failure=0;failure<8;++failure)compare(names[name],bases[base],failure);
    boundary_checks();printf("PASS writable functions=1 cases=%u boundaries=%u publish_error_repairs=%u existing_file_repairs=%u truncation_repairs=%u growing_reads=%u\n",cases,boundaries,publication_repairs,file_repairs,truncation_repairs,growing_reads);return 0;
}
