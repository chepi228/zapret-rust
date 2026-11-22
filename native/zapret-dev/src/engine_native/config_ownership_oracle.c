/* MIT. Compare argv bytes, ownership failures and real bounded config input. */
#include "helpers.h"
#include "wordexp.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <stdarg.h>
#undef main
static unsigned cases, faults, configs, boundaries, allocations, fail_at, live, expansion_calls;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr,"FAIL config ownership cases=%u faults=%u configs=%u boundaries=%u line=%d: %s\n",cases,faults,configs,boundaries,__LINE__,#condition); exit(1); } \
} while(0)
typedef union header {
    struct { size_t size; uint64_t magic; } value;
    long double alignment;
} header;
static void *guarded_allocate(size_t size)
{
    if (++allocations == fail_at) return NULL;
    CHECK(size && size < 8*1024*1024);
    header *block = malloc(sizeof(header)+size+16); CHECK(block);
    block->value.size=size; block->value.magic=UINT64_C(0x39f18d7652aceb04);
    memset(block+1,0x6d,size+16); ++live; return block+1;
}
static void guarded_release(void *pointer)
{
    if(!pointer) return;
    header *block=(header *)pointer-1; CHECK(block->value.magic==UINT64_C(0x39f18d7652aceb04) && live);
    for(unsigned index=0;index<16;++index) CHECK(((uint8_t *)pointer)[block->value.size+index]==0x6d);
    block->value.magic=0; --live; free(block);
}
static void *guarded_calloc(size_t count,size_t size)
{ CHECK(!size || count<=SIZE_MAX/size); void *pointer=guarded_allocate(count*size); if(pointer)memset(pointer,0,count*size); return pointer; }
static int counted_expand(const unsigned char *input,size_t length,unsigned char *output,size_t capacity,size_t *required,size_t *count)
{ ++expansion_calls; return zapret_wordexp(input,length,output,capacity,required,count); }
#define malloc guarded_allocate
#define calloc guarded_calloc
#define free guarded_release
#define zapret_wordexp counted_expand
#define wordexp reference_wordexp
#define wordfree reference_wordfree
void reference_wordfree(wordexp_t *);
#include "wordexp_reference.inc"
#undef malloc
#undef calloc
#undef free
#undef zapret_wordexp
#undef wordexp
#undef wordfree
#include "file_helpers_windows.inc"
typedef struct {
    void *(*allocate)(size_t);
    void (*release)(void *);
} zapret_word_allocator;
int zapret_native_wordexp(const char *, wordexp_t *, int, const zapret_word_allocator *);
void zapret_native_wordfree(wordexp_t *, const zapret_word_allocator *);
int zapret_native_config_file(const char *, wordexp_t *, uint32_t *, const zapret_word_allocator *);
_Static_assert(sizeof(wordexp_t) == 24 && offsetof(wordexp_t,we_wordv) == 8 &&
    offsetof(wordexp_t,we_offs) == 16,"Rust argv ownership ABI");
static const zapret_word_allocator guarded_allocator={guarded_allocate,guarded_release};
static void reset_allocations(unsigned failure) { allocations=0; fail_at=failure; }
static void same_words(const wordexp_t *left,const wordexp_t *right)
{
    CHECK(left->we_wordc==right->we_wordc && left->we_offs==right->we_offs && !!left->we_wordv==!!right->we_wordv);
    if(left->we_wordv) {
        for(size_t index=0;index<left->we_wordc;++index) CHECK(!strcmp(left->we_wordv[index],right->we_wordv[index]));
        CHECK(!left->we_wordv[left->we_wordc] && !right->we_wordv[right->we_wordc]);
    }
}
static void compare_words(const char *input,int flags,unsigned failure)
{
    wordexp_t left={0},right={0};
    reset_allocations(failure); int expected=reference_wordexp(input,&left,flags);
    reset_allocations(failure); int actual=zapret_native_wordexp(input,&right,flags,&guarded_allocator);
    CHECK(expected==actual); same_words(&left,&right);
    reference_wordfree(&left); zapret_native_wordfree(&right,&guarded_allocator); CHECK(!live);
    if(failure)++faults; else ++cases;
}
#define MAX_CONFIG_FILE_SIZE 16384
static struct { wordexp_t wexp; } params;
static jmp_buf exit_target;
static unsigned logged_errors;
static DWORD reported_error, log_error;
static char last_log[512];
static int fixture_error(const char *format,...)
{
    va_list args;
    va_start(args,format);
    int n=vsnprintf(last_log,sizeof(last_log),format,args);
    va_end(args);
    CHECK(n>=0 && (size_t)n<sizeof(last_log));
    ++logged_errors;
    log_error=reported_error;
    return n;
}
static void fixture_set_error(DWORD code) { reported_error=code; }
bool zapret_native_config_read(const char *, wordexp_t *, const void *, void (*)(DWORD), int (*)(const char *, ...));
static void fixture_exit(int code) { CHECK(code==1); longjmp(exit_target,1); }
#undef DLOG_ERR
#define DLOG_ERR fixture_error
#define exit_clean fixture_exit
#define wordexp reference_wordexp
#define config_from_file reference_config_from_file
#include "config_file_reference.inc"
#undef config_from_file
#undef wordexp
#undef exit_clean
static const char *config_path="config-русский-é-中.txt";
static void compare_config(const void *data,size_t size)
{
    CHECK(save_file(config_path,data,size));
    reset_allocations(0); logged_errors=0; memset(&params,0,sizeof(params));
    int failed=setjmp(exit_target);
    if(!failed)reference_config_from_file(config_path);
    wordexp_t actual={0}; uint32_t error=99;
    reset_allocations(0); int status=zapret_native_config_file(config_path,&actual,&error,&guarded_allocator);
    CHECK(!!failed==!!status && !error);
    if(!failed)same_words(&params.wexp,&actual); else CHECK(logged_errors==1 && status==2);
    reference_wordfree(&params.wexp); zapret_native_wordfree(&actual,&guarded_allocator); CHECK(!live); ++configs;
}
static int compare_double(const void *left,const void *right)
{ double a=*(const double *)left,b=*(const double *)right; return (a>b)-(a<b); }
static void benchmark(void)
{
    const char *input="x --dry-run --intercept=0 --name='two words' --debug=0 --new --comment=quoted --wf-dup-check=0";
    LARGE_INTEGER frequency,start,end; CHECK(QueryPerformanceFrequency(&frequency));
    double times[2][9]; reset_allocations(0);
    for(unsigned round=0;round<9;++round)for(unsigned turn=0;turn<2;++turn) {
        unsigned variant=turn^(round&1); CHECK(QueryPerformanceCounter(&start));
        for(unsigned index=0;index<128;++index) {
            wordexp_t result={0};
            if(variant) { CHECK(!zapret_native_wordexp(input,&result,WRDE_NOCMD,&guarded_allocator)); zapret_native_wordfree(&result,&guarded_allocator); }
            else { CHECK(!reference_wordexp(input,&result,WRDE_NOCMD)); reference_wordfree(&result); }
        }
        CHECK(QueryPerformanceCounter(&end)); CHECK(!live);
        times[variant][round]=(double)(end.QuadPart-start.QuadPart)*1e9/(double)frequency.QuadPart/128.0;
    }
    qsort(times[0],9,sizeof(double),compare_double); qsort(times[1],9,sizeof(double),compare_double);
    printf("BENCH config_ownership argv8 c_ns=%.2f rust_ns=%.2f rounds=9 calls_per_round=128\n",times[0][4],times[1][4]);
}
int main(void)
{
    WCHAR directory[96]; swprintf(directory,96,L"config-ownership-%lu-%llu",(unsigned long)GetCurrentProcessId(),(unsigned long long)GetTickCount64());
    CHECK(CreateDirectoryW(directory,NULL) && SetCurrentDirectoryW(directory));
    CHECK(save_file("glob-alpha.txt","",0) && save_file("glob-русский.txt","",0));
    CHECK(!_putenv_s("ZAPRET_CONFIG_ORACLE","environment value"));
    CHECK(SetEnvironmentVariableW(L"ZAPRET_CONFIG_ORACLE",L"environment value"));
    const char *inputs[]={"", "x", "  \t\r\n", "x '' \"\"", "x 'quoted words'", "x \"русский-é-中\"", "x a\\ b", "x *.txt", "x glob-*.txt", "x $ZAPRET_CONFIG_ORACLE", "x ${ZAPRET_CONFIG_ORACLE}", "x {1..16}", "x \"$((3*7))\"", "x $(unexecuted)", "x `unexecuted`", "x 'broken", "x \xff", "x {1..1000000000}"};
    for(unsigned round=0;round<8;++round)for(unsigned index=0;index<sizeof(inputs)/sizeof(*inputs);++index)compare_words(inputs[index],WRDE_NOCMD,0);
    for(int flags=0;flags<64;++flags)compare_words("x 'two words'",flags,0);
    compare_words(NULL,WRDE_NOCMD,0);
    for(unsigned failure=1;failure<=2;++failure)for(unsigned index=0;index<sizeof(inputs)/sizeof(*inputs);++index)compare_words(inputs[index],WRDE_NOCMD,failure);
    for(unsigned failure=0;failure<=2;++failure) {
        wordexp_t left={0},right={0}; reset_allocations(0);
        CHECK(!reference_wordexp("x previous",&left,WRDE_NOCMD));
        CHECK(!zapret_native_wordexp("x previous",&right,WRDE_NOCMD,&guarded_allocator));
        reset_allocations(failure); int expected=reference_wordexp("x replacement words",&left,WRDE_NOCMD|WRDE_REUSE);
        reset_allocations(failure); int actual=zapret_native_wordexp("x replacement words",&right,WRDE_NOCMD|WRDE_REUSE,&guarded_allocator);
        CHECK(expected==actual); same_words(&left,&right);
        reference_wordfree(&left); zapret_native_wordfree(&right,&guarded_allocator); CHECK(!live); ++boundaries;
    }
    reset_allocations(0); wordexp_t empty={0}; wordfree(&empty); wordfree(&empty); wordfree(NULL);
    CHECK(wordexp(NULL,NULL,WRDE_NOCMD)==WRDE_NOSPACE); ++boundaries;
    CHECK(!wordexp("winws 'two words'",&empty,WRDE_NOCMD));
    CHECK(empty.we_wordc==2 && !strcmp(empty.we_wordv[1],"two words") && !empty.we_wordv[2]);
    wordfree(&empty);
    CHECK(!empty.we_wordc && !empty.we_wordv && !empty.we_offs); ++boundaries;
    char *long_input=malloc(65538); CHECK(long_input); memset(long_input,' ',65537); long_input[65537]=0;
    compare_words(long_input,WRDE_NOCMD,0); long_input[65536]=0; compare_words(long_input,WRDE_NOCMD,0); free(long_input);
    for(unsigned index=0;index<sizeof(inputs)/sizeof(*inputs);++index)compare_config(inputs[index],strlen(inputs[index]));
    const char multiline[]="--name=\"line\nwith\tspaces\"\r\n--debug=0";
    compare_config(multiline,sizeof(multiline)-1);
    const char nul[]="--debug=0\0 ignored 'broken"; compare_config(nul,sizeof(nul)-1);
    char *large=malloc(MAX_CONFIG_FILE_SIZE+32); CHECK(large); memset(large,' ',MAX_CONFIG_FILE_SIZE+32); memcpy(large,"--debug=0",9);
    for(size_t size=16370;size<=16381;++size)compare_config(large,size);
    wordexp_t retained={0}; reset_allocations(0); CHECK(!zapret_native_wordexp("x previous",&retained,WRDE_NOCMD,&guarded_allocator));
    char **original=retained.we_wordv; uint32_t error=99;
    CHECK(save_file(config_path,large,16382));
    CHECK(zapret_native_config_file(config_path,&retained,&error,&guarded_allocator)==3 && !error && retained.we_wordv==original); ++boundaries;
    logged_errors=reported_error=0;
    CHECK(!zapret_native_config_read(config_path,&retained,&guarded_allocator,fixture_set_error,fixture_error));
    CHECK(logged_errors==1 && !log_error && strstr(last_log,"exceeds 16381 bytes") && retained.we_wordv==original);
    /* Demonstrate that the previous loader accepted the truncated prefix. */
    reset_allocations(0); memset(&params,0,sizeof(params)); CHECK(!setjmp(exit_target)); reference_config_from_file(config_path);
    CHECK(params.wexp.we_wordc==2 && !strcmp(params.wexp.we_wordv[1],"--debug=0")); reference_wordfree(&params.wexp); ++boundaries;
    CHECK(zapret_native_config_file("missing.txt",&retained,&error,&guarded_allocator)==1 && error==ERROR_FILE_NOT_FOUND && retained.we_wordv==original); ++boundaries;
    logged_errors=reported_error=0;
    CHECK(!zapret_native_config_read("missing.txt",&retained,&guarded_allocator,fixture_set_error,fixture_error));
    CHECK(logged_errors==1 && log_error==ERROR_FILE_NOT_FOUND && strstr(last_log,"could not load config file") && retained.we_wordv==original);
    CHECK(save_file(config_path,"'broken",7));
    CHECK(zapret_native_config_file(config_path,&retained,&error,&guarded_allocator)==2 && !error && retained.we_wordv==original); ++boundaries;
    CHECK(save_file(config_path,"--debug=0",9));
    for(unsigned failure=1;failure<=2;++failure) {
        reset_allocations(failure); CHECK(zapret_native_config_file(config_path,&retained,&error,&guarded_allocator)==2 && !error && retained.we_wordv==original && live==2); ++boundaries;
    }
    reset_allocations(0); CHECK(!zapret_native_config_file(config_path,&retained,&error,&guarded_allocator) && retained.we_wordc==2 && live==2); ++boundaries;
    zapret_native_wordfree(&retained,&guarded_allocator); CHECK(!live); free(large);
    CHECK(DeleteFileW(L"glob-alpha.txt") && DeleteFileW(L"glob-русский.txt") && DeleteFileW(L"config-русский-é-中.txt"));
    CHECK(SetCurrentDirectoryW(L"..") && RemoveDirectoryW(directory));
    printf("PASS config_ownership functions=3 word_cases=%u allocation_faults=%u config_cases=%u boundaries=%u\n",cases,faults,configs,boundaries);
    benchmark();
    return 0;
}
