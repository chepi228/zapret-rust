/* MIT. Compare raw instance bytes and prove input/output bounds with guard pages. */
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef main
static unsigned cases,guarded,boundaries;
#define CHECK(value) do {if(!(value)){fprintf(stderr,"FAIL lua instance cases=%u guarded=%u boundary=%u line=%d: %s\n",cases,guarded,boundaries,__LINE__,#value);exit(1);}}while(0)
#define desync_instance reference_desync_instance
#include "lua_instance_reference.inc"
#undef desync_instance
#include "lua_instance_windows.inc"
static void compare(const char *name,unsigned profile,unsigned number,size_t capacity,size_t offset)
{
    BYTE left[512],right[512];CHECK(capacity+offset<sizeof(left));memset(left,0xa5,sizeof(left));memset(right,0xa5,sizeof(right));reference_desync_instance(name,profile,number,(char *)left+offset,capacity);desync_instance(name,profile,number,(char *)right+offset,capacity);CHECK(!memcmp(left,right,sizeof(left)));++cases;
}
static void guards(void)
{
    SYSTEM_INFO system;GetSystemInfo(&system);size_t page=system.dwPageSize;CHECK(page>=4096);
    BYTE *source=VirtualAlloc(NULL,page*2,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE),*left=VirtualAlloc(NULL,page*2,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE),*right=VirtualAlloc(NULL,page*2,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);CHECK(source && left && right);DWORD previous;
    CHECK(VirtualProtect(source+page,page,PAGE_NOACCESS,&previous) && VirtualProtect(left+page,page,PAGE_NOACCESS,&previous) && VirtualProtect(right+page,page,PAGE_NOACCESS,&previous));
    for(size_t length=1;length<=64;++length){char *name=(char *)source+page-length-1;memset(name,'f',length);name[length]=0;for(size_t capacity=1;capacity<=64;++capacity){memset(left,0xa5,page);memset(right,0xa5,page);reference_desync_instance(name,UINT32_MAX,UINT32_MAX,(char *)left+page-capacity,capacity);desync_instance(name,UINT32_MAX,UINT32_MAX,(char *)right+page-capacity,capacity);CHECK(!memcmp(left,right,page));++guarded;}}
    reference_desync_instance("f",1,2,NULL,0);desync_instance("f",1,2,NULL,0);++boundaries;
    desync_instance((const char *)(source+page),1,2,(char *)(right+page),0);++boundaries;
    CHECK(VirtualFree(source,0,MEM_RELEASE) && VirtualFree(left,0,MEM_RELEASE) && VirtualFree(right,0,MEM_RELEASE));
}
typedef void (*formatter)(const char *,unsigned,unsigned,char *,size_t);
static volatile uint64_t sink;
static double measure(formatter function,LARGE_INTEGER frequency)
{
    char output[256]={0};LARGE_INTEGER begin,end;uint64_t sum=0;const unsigned calls=131072;CHECK(QueryPerformanceCounter(&begin));
    for(unsigned i=0;i<calls;++i){function("multidisorder_function",i*2654435761u,i^0x5a5a5a5au,output,sizeof(output));sum+=(unsigned char)output[0]+(unsigned char)output[8]+(unsigned char)output[17];}
    CHECK(QueryPerformanceCounter(&end));sink+=sum;return (end.QuadPart-begin.QuadPart)*1e9/frequency.QuadPart/calls;
}
static int order(const void *a,const void *b){double left=*(const double *)a,right=*(const double *)b;return (left>right)-(left<right);}
static void bench(void)
{
    LARGE_INTEGER frequency;CHECK(QueryPerformanceFrequency(&frequency));double c[9],rust[9];measure(reference_desync_instance,frequency);measure(desync_instance,frequency);
    for(unsigned i=0;i<9;++i){if(i&1){rust[i]=measure(desync_instance,frequency);c[i]=measure(reference_desync_instance,frequency);}else{c[i]=measure(reference_desync_instance,frequency);rust[i]=measure(desync_instance,frequency);}}
    qsort(c,9,sizeof(double),order);qsort(rust,9,sizeof(double),order);printf("BENCH lua_instance format c_ns=%.2f rust_ns=%.2f rounds=9 calls_per_round=131072\n",c[4],rust[4]);
}
int main(void)
{
    char long248[249],long256[257],long4096[4097];memset(long248,'f',248);long248[248]=0;memset(long256,'g',256);long256[256]=0;memset(long4096,'h',4096);long4096[4096]=0;
    const char *names[]={"","fooling","multidisorder","данные-é-中","bad-\xff",long248,long256,long4096};
    const unsigned numbers[]={0,1,9,10,99,100,0x80000000u,UINT32_MAX};
    for(unsigned name=0;name<8;++name)for(size_t capacity=0;capacity<=272;++capacity)for(unsigned profile=0;profile<8;++profile)for(unsigned number=0;number<8;++number)for(size_t offset=0;offset<8;++offset)compare(names[name],numbers[profile],numbers[number],capacity,offset);
    guards();char output[8];memset(output,0xa5,sizeof(output));desync_instance(NULL,1,2,output,4);CHECK(!output[0] && (BYTE)output[1]==0xa5);++boundaries;memset(output,0xa5,sizeof(output));desync_instance("f",1,2,output,SIZE_MAX);CHECK((BYTE)output[0]==0xa5);++boundaries;desync_instance("f",1,2,NULL,8);++boundaries;
    printf("PASS lua_instance functions=1 cases=%u guarded=%u boundaries=%u raw_non_utf8=1 unaligned=8\n",cases,guarded,boundaries);bench();return 0;
}
