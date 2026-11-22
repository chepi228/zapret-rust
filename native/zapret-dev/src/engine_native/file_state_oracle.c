/* MIT. Native metadata, reset-on-error, Unicode paths and non-mutating probes. */
#include "helpers.h"
#include "win_files.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#undef main
static unsigned metadata_cases,probes,paths,environments,boundaries;
#define CHECK(condition) do {if(!(condition)){ \
 fprintf(stderr,"FAIL file state metadata=%u probes=%u paths=%u line=%d: %s\n",metadata_cases,probes,paths,__LINE__,#condition);exit(1);}}while(0)
#define file_size reference_file_size
#define file_mod_signature reference_file_mod_signature
#define file_open_test reference_file_open_test
#define set_env_exedir reference_set_env_exedir
#define realpath_any reference_realpath_any
#include "file_state_reference.inc"
#undef file_size
#undef file_mod_signature
#undef file_open_test
#undef set_env_exedir
#undef realpath_any
#include "file_state_windows.inc"
static const char *file="данные-é-中.bin";
static const WCHAR *wide=L"данные-é-中.bin";
static void compare_metadata(const char *name)
{
    off_t a=0x69696969,b=a;errno=91;bool expected=reference_file_size(name,&a);int error=errno;
    errno=91;bool actual=file_size(name,&b);CHECK(expected==actual && a==b);if(!actual)CHECK(error==errno);++metadata_cases;
    CHECK(reference_file_size(name,NULL)==file_size(name,NULL));++metadata_cases;
    struct {uint64_t before;file_mod_sig value;uint64_t after;} left,right;memset(&left,0x69,sizeof(left));right=left;
    errno=91;expected=reference_file_mod_signature(name,&left.value);error=errno;
    errno=91;actual=file_mod_signature(name,&right.value);
    CHECK(expected==actual && FILE_MOD_COMPARE(&left.value,&right.value));if(!actual)CHECK(error==errno);
    CHECK(left.before==right.before && left.after==right.after);
    if(!actual){file_mod_sig zero={0};CHECK(!memcmp(&left.value,&zero,sizeof(zero)) && !memcmp(&right.value,&zero,sizeof(zero)));}++metadata_cases;
}
static void compare_probe(const char *name,int flags)
{
    errno=91;bool expected=reference_file_open_test(name,flags);int error=errno;
    errno=91;bool actual=file_open_test(name,flags);CHECK(expected==actual);if(!actual)CHECK(error==errno);++probes;
}
static void compare_path(const char *name)
{
    char a[PATH_MAX+16],b[PATH_MAX+16];memset(a,0x69,sizeof(a));memcpy(b,a,sizeof(a));
    errno=91;bool expected=reference_realpath_any(name,a+8);int error=errno;
    errno=91;bool actual=realpath_any(name,b+8);CHECK(expected==actual && !memcmp(a,b,sizeof(a)));if(!actual)CHECK(error==errno);++paths;
}
int main(void)
{
    WCHAR directory[96];swprintf(directory,96,L"file-state-%lu-%llu",(unsigned long)GetCurrentProcessId(),(unsigned long long)GetTickCount64());
    CHECK(CreateDirectoryW(directory,NULL) && SetCurrentDirectoryW(directory));
    const char *names[]={file,"./данные-é-中.bin",".\\данные-é-中.bin",".","..","absent.bin","missing/child.bin","",NULL,"bad-\xff-name"};
    uint8_t bytes[1024];for(unsigned index=0;index<sizeof(bytes);++index)bytes[index]=(uint8_t)(index*131);
    const uint64_t times[]={0,UINT64_C(116444736000000000),UINT64_C(132537600001234567),UINT64_C(157469184009999999)};
    for(size_t size=0;size<=sizeof(bytes);size+=64){
        FILE *stream=fopen(file,"wb");CHECK(stream && fwrite(bytes,1,size,stream)==size && !fclose(stream));
        HANDLE handle=CreateFileW(wide,FILE_WRITE_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);CHECK(handle!=INVALID_HANDLE_VALUE);
        uint64_t ticks=times[(size/64)%4];FILETIME time={.dwLowDateTime=(DWORD)ticks,.dwHighDateTime=(DWORD)(ticks>>32)};CHECK(SetFileTime(handle,NULL,NULL,&time) && CloseHandle(handle));
        for(unsigned index=0;index<sizeof(names)/sizeof(*names);++index){compare_metadata(names[index]);compare_probe(names[index],O_RDONLY);compare_probe(names[index],O_RDWR);compare_path(names[index]);}
    }
    CHECK(SetFileAttributesW(wide,FILE_ATTRIBUTE_READONLY));compare_probe(file,O_WRONLY);compare_metadata(file);CHECK(SetFileAttributesW(wide,FILE_ATTRIBUTE_NORMAL));
    HANDLE lock=CreateFileW(wide,GENERIC_READ,0,NULL,OPEN_EXISTING,0,NULL);CHECK(lock!=INVALID_HANDLE_VALUE);
    compare_probe(file,O_RDONLY);compare_metadata(file);compare_path(file);CHECK(CloseHandle(lock));
    const char *previous=getenv("EXEDIR");char *saved=previous?strdup(previous):NULL;CHECK(!previous || saved);
    for(unsigned round=0;round<8;++round){CHECK(SetEnvironmentVariableW(L"EXEDIR",L"old fixture value"));
        CHECK(reference_set_env_exedir("ignored"));const char *expected=getenv("EXEDIR");CHECK(expected);char *copy=strdup(expected);CHECK(copy);
        CHECK(SetEnvironmentVariableW(L"EXEDIR",L"different fixture value") && set_env_exedir(NULL));CHECK(!strcmp(copy,getenv("EXEDIR")));free(copy);++environments;
    }
    if(saved){CHECK(!setenv("EXEDIR",saved,1));free(saved);}else CHECK(SetEnvironmentVariableW(L"EXEDIR",NULL));
    char output[32];memset(output,0x69,sizeof(output));char before[32];memcpy(before,output,sizeof(output));
    CHECK(zapret_engine_realpath(file,output,1)==ERROR_FILENAME_EXCED_RANGE && !memcmp(output,before,sizeof(output)));++boundaries;
    CHECK(zapret_engine_realpath(file,NULL,32)==ERROR_INVALID_PARAMETER);++boundaries;
    CHECK(zapret_engine_realpath(file,output,SIZE_MAX)==ERROR_INVALID_PARAMETER && !memcmp(output,before,sizeof(output)));++boundaries;
    CHECK(zapret_engine_file_stamp(file,NULL)==ERROR_INVALID_PARAMETER);++boundaries;
    CHECK(zapret_engine_file_probe("must-not-exist.bin",O_CREAT|O_RDWR)==ERROR_INVALID_PARAMETER);CHECK(GetFileAttributesW(L"must-not-exist.bin")==INVALID_FILE_ATTRIBUTES);++boundaries;
    CHECK(zapret_engine_file_probe(file,O_TRUNC|O_WRONLY)==ERROR_INVALID_PARAMETER);++boundaries;
    CHECK(zapret_engine_file_probe(file,_O_TEMPORARY|O_RDONLY)==ERROR_INVALID_PARAMETER);++boundaries;
    FILE *stream=fopen(file,"rb");CHECK(stream);uint8_t actual[1024];CHECK(fread(actual,1,sizeof(actual),stream)==sizeof(actual) && !memcmp(actual,bytes,sizeof(bytes)) && !fclose(stream));
    DWORD before_handles,after_handles;CHECK(GetProcessHandleCount(GetCurrentProcess(),&before_handles));
    for(unsigned iteration=0;iteration<512;++iteration){off_t size;file_mod_sig stamp;char path[PATH_MAX];CHECK(file_size(file,&size) && size==1024 && file_mod_signature(file,&stamp) && file_open_test(file,O_RDONLY) && realpath_any(file,path));}
    CHECK(GetProcessHandleCount(GetCurrentProcess(),&after_handles) && before_handles==after_handles);
    CHECK(DeleteFileW(wide) && SetCurrentDirectoryW(L"..") && RemoveDirectoryW(directory));
    printf("PASS file_state functions=5 metadata_cases=%u access_probes=%u paths=%u environment_cases=%u boundaries=%u handle_cycles=512\n",metadata_cases,probes,paths,environments,boundaries);
    return 0;
}
