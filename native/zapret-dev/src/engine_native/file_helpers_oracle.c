/* MIT. Exact file bytes, Unicode paths, sharing failures and handle cleanup. */
#include "helpers.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#undef main
static unsigned reads, writes, appends, failures;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL file helpers reads=%u writes=%u appends=%u failures=%u line=%d: %s\n", reads, writes, appends, failures, __LINE__, #condition); exit(1); } \
} while (0)
#include "stdio_windows.inc"
#define load_file reference_load_file
#define save_file reference_save_file
#define append_to_list_file reference_append_to_list_file
#include "file_helpers_reference.inc"
#undef load_file
#undef save_file
#undef append_to_list_file
#include "file_helpers_windows.inc"

static const char *left_name = "старое-é-中.bin", *right_name = "новое-é-中.bin";
static const WCHAR *left_wide = L"старое-é-中.bin", *right_wide = L"новое-é-中.bin";
static void same_files(void)
{
    FILE *left = fopen(left_name, "rb"), *right = fopen(right_name, "rb"); CHECK(left && right);
    uint8_t a[65536],b[65536]; size_t ca=fread(a,1,sizeof(a),left), cb=fread(b,1,sizeof(b),right);
    CHECK(ca==cb && !memcmp(a,b,ca) && !ferror(left) && !ferror(right)); CHECK(!fclose(left) && !fclose(right));
}
static void compare_read(off_t offset, size_t count)
{
    uint8_t a[8192],b[8192]; memset(a,0x69,sizeof(a)); memcpy(b,a,sizeof(a)); size_t ca=count,cb=count;
    bool expected=reference_load_file(left_name,offset,a+8,&ca), actual=load_file(right_name,offset,b+8,&cb);
    CHECK(expected==actual && ca==cb && !memcmp(a,b,sizeof(a))); ++reads;
}
int main(void)
{
    WCHAR directory[96];
    swprintf(directory,96,L"owned-file-helpers-%lu-%llu",(unsigned long)GetCurrentProcessId(),(unsigned long long)GetTickCount64());
    CHECK(CreateDirectoryW(directory,NULL) && SetCurrentDirectoryW(directory));
    uint8_t data[4096]; for(unsigned index=0;index<sizeof(data);++index)data[index]=(uint8_t)(index*131);
    for(size_t size=0;size<=sizeof(data);size+=64){
        CHECK(reference_save_file(left_name,data,size)==save_file(right_name,data,size)); same_files(); ++writes;
        compare_read(0,size+17); compare_read(size/2,37); compare_read(size+3,17);
    }
    CHECK(reference_save_file(left_name,data,sizeof(data)) && save_file(right_name,data,sizeof(data)));
    for(size_t count=0;count<512;count+=7) for(off_t offset=0;offset<4096;offset+=257) compare_read(offset,count);
    compare_read(INT64_C(1)<<32,17); compare_read(-1,17);
    CHECK(reference_save_file(left_name,data,0) && save_file(right_name,data,0));
    CHECK(!zapret_engine_save_file(right_name,NULL,0));
    const char *lines[]={"", "plain", "русский-é-中", "one\ntwo", "one\r\ntwo", "\r\n", "\x1a", "a\xff" "b"};
    for(unsigned index=0;index<sizeof(lines)/sizeof(*lines);++index){
        CHECK(reference_append_to_list_file(left_name,lines[index])==append_to_list_file(right_name,lines[index])); same_files(); ++appends;
    }
    FILE *written=fopen(right_name,"rb"); CHECK(written); uint8_t bytes[128]; size_t count=fread(bytes,1,sizeof(bytes),written); CHECK(!fclose(written));
    static const uint8_t expected[]="\r\nplain\r\nрусский-é-中\r\none\r\ntwo\r\none\r\r\ntwo\r\n\r\r\n\r\n\x1a\r\na\xff" "b\r\n";
    CHECK(count==sizeof(expected)-1 && !memcmp(bytes,expected,count));
    CHECK(SetFileAttributesW(left_wide,FILE_ATTRIBUTE_READONLY) && SetFileAttributesW(right_wide,FILE_ATTRIBUTE_READONLY));
    CHECK(!reference_save_file(left_name,data,16) && !save_file(right_name,data,16)); ++failures;
    CHECK(!reference_append_to_list_file(left_name,"lost") && !append_to_list_file(right_name,"lost")); ++failures;
    CHECK(SetFileAttributesW(left_wide,FILE_ATTRIBUTE_NORMAL) && SetFileAttributesW(right_wide,FILE_ATTRIBUTE_NORMAL)); same_files();
    HANDLE lock_left=CreateFileW(left_wide,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    HANDLE lock_right=CreateFileW(right_wide,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    CHECK(lock_left!=INVALID_HANDLE_VALUE && lock_right!=INVALID_HANDLE_VALUE);
    CHECK(!reference_save_file(left_name,data,16) && !save_file(right_name,data,16)); ++failures;
    CHECK(!reference_append_to_list_file(left_name,"lost") && !append_to_list_file(right_name,"lost")); ++failures;
    CHECK(CloseHandle(lock_left) && CloseHandle(lock_right)); same_files();
    for(unsigned index=0;index<2;++index){
        const char *missing=index ? "missing/child.bin" : "absent.bin"; uint8_t output[16]; size_t ca=16,cb=16;
        CHECK(!reference_load_file(missing,0,output,&ca) && !load_file(missing,0,output,&cb) && ca==cb); ++failures;
    }
    CHECK(!reference_save_file("missing/child.bin",data,16) && !save_file("missing/child.bin",data,16)); ++failures;
    CHECK(!reference_append_to_list_file("missing/child.bin","lost") && !append_to_list_file("missing/child.bin","lost")); ++failures;
    CHECK(zapret_engine_load_file(right_name,0,NULL,NULL)==ERROR_INVALID_PARAMETER); ++failures;
    /* Invalid arguments are rejected before truncating an existing file. */
    uint8_t output[16]; size_t requested=SIZE_MAX;
    CHECK(zapret_engine_load_file(right_name,0,output,&requested)==ERROR_INVALID_PARAMETER && requested==SIZE_MAX); ++failures;
    CHECK(zapret_engine_save_file(right_name,NULL,16)==ERROR_INVALID_PARAMETER); ++failures;
    CHECK(zapret_engine_save_file(right_name,data,SIZE_MAX)==ERROR_INVALID_PARAMETER); ++failures;
    CHECK(zapret_engine_append_line(right_name,NULL)==ERROR_INVALID_PARAMETER); ++failures; same_files();
    DWORD before=0,after=0; CHECK(GetProcessHandleCount(GetCurrentProcess(),&before));
    for(unsigned index=0;index<512;++index){size_t count=sizeof(output); CHECK(load_file(right_name,0,output,&count));}
    CHECK(GetProcessHandleCount(GetCurrentProcess(),&after) && after==before);
    CHECK(DeleteFileW(left_wide) && DeleteFileW(right_wide));
    CHECK(SetCurrentDirectoryW(L"..") && RemoveDirectoryW(directory));
    printf("PASS engine_file_helpers functions=3 reads=%u writes=%u appends=%u failures=%u handle_cycles=512 unicode_paths=2\n",reads,writes,appends,failures);
    return 0;
}
