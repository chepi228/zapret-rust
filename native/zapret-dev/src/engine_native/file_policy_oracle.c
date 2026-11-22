/* MIT. Entire C file facade entries against Rust policy, native operations observed. */
#define WIN_FILES_IMPLEMENTATION
#include "win_files.h"
#include <errno.h>
#include <string.h>
#include <wchar.h>
#include <inttypes.h>
#undef main
#define FACADE_DECLARATIONS(prefix) \
    void prefix##wf_error(DWORD); \
    wchar_t *prefix##wf_path_utf16(const char *); \
    char *prefix##wf_wide_to_utf8(const wchar_t *); \
    char *prefix##wf_realpath(const char *,char *); \
    bool prefix##wf_realpath_any(const char *,char *); \
    int prefix##wf_file_stat(const char *,wf_file_info *); \
    bool prefix##wf_set_exedir(void); \
    char *prefix##wf_getenv(const char *); \
    int prefix##wf_setenv(const char *,const char *,int); \
    FILE *prefix##wf_fopen(const char *,const char *); \
    int prefix##wf_open(const char *,int,...); \
    int prefix##wf_chdir(const char *); \
    char *prefix##wf_getcwd(char *,size_t); \
    int prefix##wf_mkdir(const char *,int); \
    int prefix##wf_unlink(const char *); \
    int prefix##wf_remove(const char *); \
    int prefix##wf_rename(const char *,const char *);
FACADE_DECLARATIONS(reference_)
FACADE_DECLARATIONS(selected_)
#undef FACADE_DECLARATIONS
typedef struct {unsigned op;uint64_t a,b;} event;
static struct {event events[256];unsigned count,allocations,fail_at;DWORD error,last;int descriptor_fail,file_fail,chdir_result;char text[5200];} fixture;
static uint64_t cases;
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL file_policy case=%"PRIu64" line=%u: %s\n",cases,__LINE__,#x);exit(1);}}while(0)
static void record(unsigned op,uint64_t a,uint64_t b){CHECK(fixture.count<256);fixture.events[fixture.count++]=(event){op,a,b};}
void *file_fixture_malloc(size_t size){record(1,size,0);if(++fixture.allocations==fixture.fail_at)return NULL;return malloc(size);}
void *file_fixture_calloc(size_t n,size_t size){record(2,n,size);if(++fixture.allocations==fixture.fail_at)return NULL;return calloc(n,size);}
char *file_fixture_strdup(const char *s){record(3,strlen(s),0);if(++fixture.allocations==fixture.fail_at)return NULL;return strdup(s);}
void file_fixture_free(void *p){record(4,p!=NULL,0);free(p);}
int file_fixture_descriptor(intptr_t handle,int flags){record(5,(uintptr_t)handle,(unsigned)flags);if(fixture.descriptor_fail){errno=91;return -1;}return 7;}
FILE *file_fixture_fdopen(int fd,const wchar_t *mode){record(6,fd,(unsigned)mode[0]|((uint64_t)mode[1]<<16)|((uint64_t)mode[2]<<32));if(fixture.file_fail){errno=92;return NULL;}return (FILE *)(uintptr_t)1;}
int file_fixture_close(int fd){record(7,fd,0);errno=777;return 0;}
int file_fixture_chdir(const wchar_t *path){record(8,path[0],0);if(fixture.chdir_result)errno=ENOENT;return fixture.chdir_result;}
BOOL file_fixture_close_handle(HANDLE handle){record(9,(uintptr_t)handle,0);errno=778;return TRUE;}
void file_fixture_lock(SRWLOCK *lock){(void)lock;record(10,0,0);}
void file_fixture_unlock(SRWLOCK *lock){(void)lock;record(11,0,0);}
void file_fixture_last_error(DWORD error){record(12,error,0);fixture.last=error;}
typedef void *(*allocator)(size_t);
typedef struct{uint64_t device,inode;int64_t size,seconds;uint32_t nanos,directory;} metadata;
static DWORD copy_text(allocator alloc,char **out){if(fixture.error)return fixture.error;size_t n=strlen(fixture.text)+1;char *p=alloc(n);if(!p)return ERROR_NOT_ENOUGH_MEMORY;memcpy(p,fixture.text,n);*out=p;return 0;}
DWORD file_fixture_path(const char *path,allocator alloc,wchar_t **out){record(20,path!=NULL,0);if(fixture.error)return fixture.error;size_t n=strlen(fixture.text)+1;wchar_t *p=alloc(n*2);if(!p)return ERROR_NOT_ENOUGH_MEMORY;for(size_t i=0;i<n;++i)p[i]=(unsigned char)fixture.text[i];*out=p;return 0;}
DWORD file_fixture_utf8(const wchar_t *s,allocator alloc,char **out){record(21,s!=NULL,0);return copy_text(alloc,out);}
DWORD file_fixture_realpath(const char *path,int missing,allocator alloc,char **out){record(22,path!=NULL,missing);return copy_text(alloc,out);}
DWORD file_fixture_stat(const char *path,metadata *out){record(23,path!=NULL,0);if(fixture.error)return fixture.error;*out=(metadata){13,17,-31,1234567,987654321,(unsigned)fixture.text[0]&1};return 0;}
DWORD file_fixture_exedir(allocator alloc,char **out){record(24,0,0);return copy_text(alloc,out);}
DWORD file_fixture_getenv(const char *name,allocator alloc,char **out){record(25,name!=NULL,0);return copy_text(alloc,out);}
DWORD file_fixture_setenv(const char *name,const char *value){record(26,strlen(name),strlen(value));return fixture.error;}
DWORD file_fixture_open(const char *path,int flags,int mode,HANDLE *out){record(27,path!=NULL,(unsigned)flags);record(28,(unsigned)mode,0);if(fixture.error)return fixture.error;*out=(HANDLE)(uintptr_t)0x4455;return 0;}
DWORD file_fixture_getcwd(allocator alloc,char **out){record(29,0,0);return copy_text(alloc,out);}
DWORD file_fixture_mkdir(const char *path){record(30,path!=NULL,0);return fixture.error;}
DWORD file_fixture_unlink(const char *path){record(31,path!=NULL,0);return fixture.error;}
DWORD file_fixture_remove(const char *path){record(32,path!=NULL,0);return fixture.error;}
DWORD file_fixture_rename(const char *a,const char *b){record(33,a!=NULL,b!=NULL);return fixture.error;}
typedef struct{intptr_t value;int error;DWORD last;bool stable;char text[4200];wf_file_info info;unsigned count;event events[256];} result;
static const char *mode,*name,*value;
static unsigned code;
static size_t capacity;
static int overwrite,open_flags;
#define CALL(fn,...) (reference?reference_##fn(__VA_ARGS__):selected_##fn(__VA_ARGS__))
static result run(bool reference)
{
    fixture.count=fixture.allocations=0;fixture.last=0x9876;errno=93;
    result r;memset(&r,0,sizeof(r));memset(r.text,0x69,sizeof(r.text));memset(&r.info,0x69,sizeof(r.info));
    char *p=NULL;wchar_t *wide=NULL;
    switch(code){
    case 0:CALL(wf_error,fixture.error);break;
    case 1:wide=CALL(wf_path_utf16,name);r.value=wide!=NULL;if(wide){size_t n=wcslen(wide);CHECK(n*2+2<=sizeof(r.text));memcpy(r.text,wide,n*2+2);free(wide);}break;
    case 2:p=CALL(wf_wide_to_utf8,L"input");goto owned;
    case 3:p=CALL(wf_realpath,name,capacity?r.text:NULL);if(capacity){r.value=p!=NULL;break;}goto owned;
    case 4:r.value=CALL(wf_realpath_any,name,r.text);break;
    case 5:r.value=CALL(wf_file_stat,name,&r.info);break;
    case 6:r.value=CALL(wf_set_exedir);break;
    case 7:p=CALL(wf_getenv,name);r.value=p!=NULL;if(p){CHECK(strlen(p)<sizeof(r.text));strcpy(r.text,p);r.stable=p==CALL(wf_getenv,name);}break;
    case 8:r.value=CALL(wf_setenv,name,value,overwrite);break;
    case 9:r.value=CALL(wf_fopen,name,mode)!=NULL;break;
    case 10:r.value=CALL(wf_open,name,open_flags,_S_IREAD|_S_IWRITE);break;
    case 11:r.value=CALL(wf_chdir,name);break;
    case 12:p=CALL(wf_getcwd,capacity==SIZE_MAX?NULL:r.text,capacity);if(capacity!=SIZE_MAX){r.value=p!=NULL;break;}goto owned;
    case 13:r.value=CALL(wf_mkdir,name,0700);break;
    case 14:r.value=CALL(wf_unlink,name);break;
    case 15:r.value=CALL(wf_remove,name);break;
    case 16:r.value=CALL(wf_rename,name,"target");break;
    owned:r.value=p!=NULL;if(p){CHECK(strlen(p)<sizeof(r.text));strcpy(r.text,p);free(p);}break;
    }
    r.error=errno;r.last=fixture.last;r.count=fixture.count;memcpy(r.events,fixture.events,sizeof(r.events));return r;
}
static void compare(void){result a=run(true),b=run(false);if(memcmp(&a,&b,sizeof(a))){fprintf(stderr,"entry=%u native=%lu fail=%u events=%u/%u errno=%d/%d value=%lld/%lld\n",code,(unsigned long)fixture.error,fixture.fail_at,a.count,b.count,a.error,b.error,(long long)a.value,(long long)b.value);CHECK(0);}++cases;}

static void check_native_facade(void)
{
    const char *directory = "file-policy-данные";
    const char *source = "тест.bin";
    const char *target = "переименован.bin";
    const char *variable = "ZAPRET_FILE_POLICY_FIXTURE";
    const unsigned char bytes[] = { 0, 10, 26, 255 };

    errno = 93;
    SetLastError(0x9876);
    CHECK(wf_state_result(ERROR_SUCCESS));
    CHECK(GetLastError() == 0x9876 && errno == 93);
    CHECK(!wf_state_result(ERROR_ARITHMETIC_OVERFLOW));
    CHECK(GetLastError() == 0x9876 && errno == EOVERFLOW);
    wf_error(ERROR_SHARING_VIOLATION);
    CHECK(GetLastError() == ERROR_SHARING_VIOLATION && errno == EACCES);
    CHECK(!wf_fopen(source, "invalid") && errno == EINVAL);

    char *cwd = wf_getcwd(NULL, 0);
    CHECK(cwd && *cwd);
    char tiny = 'i';
    CHECK(!wf_getcwd(&tiny, 1) && errno == ERANGE && tiny == 'i');
    wchar_t *wide = wf_path_utf16(directory);
    CHECK(wide);
    char *roundtrip = wf_wide_to_utf8(wide);
    CHECK(roundtrip && strstr(roundtrip, directory));
    free(roundtrip);
    free(wide);
    CHECK(!wf_mkdir(directory, 0700));
    wf_file_info info;
    CHECK(!wf_file_stat(directory, &info) && info.st_mode == _S_IFDIR);
    CHECK(!wf_chdir(directory));

    FILE *file = wf_fopen(source, "wbe");
    CHECK(file && fwrite(bytes, 1, sizeof(bytes), file) == sizeof(bytes) && !fclose(file));
    memset(&info, 0x69, sizeof(info));
    CHECK(!wf_file_stat(source, &info) && info.st_mode == _S_IFREG && info.st_size == sizeof(bytes));
    CHECK(info.modified.tv_nsec >= 0 && info.modified.tv_nsec < 1000000000);
    const unsigned char *raw = (const unsigned char *)&info;
    for (size_t offset = 28; offset != 32; ++offset) CHECK(raw[offset] == 0x69);
    for (size_t offset = 44; offset != 48; ++offset) CHECK(raw[offset] == 0x69);

    char *resolved = wf_realpath(source, NULL);
    CHECK(resolved && strstr(resolved, source));
    free(resolved);
    char missing[4096];
    CHECK(wf_realpath_any(target, missing) && strstr(missing, target));
    CHECK(!wf_rename(source, target));
    CHECK(!wf_fopen(source, "rb") && errno == ENOENT && GetLastError() == ERROR_FILE_NOT_FOUND);
    file = wf_fopen(target, "rb");
    unsigned char read[sizeof(bytes)];
    CHECK(file && fread(read, 1, sizeof(read), file) == sizeof(read) && !fclose(file));
    CHECK(!memcmp(read, bytes, sizeof(bytes)));
    CHECK(!wf_unlink(target));
    CHECK(!wf_chdir(cwd));
    free(cwd);
    CHECK(!wf_remove(directory));

    CHECK(!wf_setenv(variable, "значение", 1));
    char *cached = wf_getenv(variable);
    CHECK(cached && !strcmp(cached, "значение"));
    CHECK(wf_getenv("zapret_file_policy_fixture") == cached);
    CHECK(!wf_setenv(variable, "new", 0) && wf_getenv(variable) == cached);
    CHECK(!wf_setenv(variable, "new", 1));
    CHECK(!strcmp(wf_getenv(variable), "new"));
    CHECK(wf_set_exedir());
    CHECK(wf_getenv("EXEDIR"));
    printf("PASS file_policy_native entries=17 shared_ucrt=1 unicode=1 stat_layout=1\n");
}

int main(void)
{
    const DWORD errors[]={0,2,3,15,5,1314,32,33,183,80,17,267,145,112,39,8,14,206,1113,123,87,534,203,0xffffffff};
    const char *names[]={"path","",NULL};strcpy(fixture.text,"abc");name="path";mode="rb";value="new";capacity=4096;overwrite=1;open_flags=_O_CREAT|_O_RDWR;
    for(unsigned entry=0;entry<=16;++entry){code=entry;for(unsigned e=0;e<sizeof(errors)/sizeof(*errors);++e){fixture.error=errors[e];for(unsigned f=0;f<=3;++f){fixture.fail_at=f;for(unsigned n=0;n<3;++n){if(entry==7||entry==8){static char key[80];snprintf(key,sizeof(key),"facade-%u-%u-%u-%u",entry,e,f,n);name=key;}else name=names[n];compare();}}}}
    fixture.error=fixture.fail_at=0;name="path";
    code=11;fixture.chdir_result=-1;compare();fixture.chdir_result=0;
    const char *modes[]={NULL,"","br","r","w","a","rt","rb","r+","w+","a+","rbt+xe","wtexe","aunknown","rtq","wxt+e","aetb+xx","r\0be+"};
    code=9;for(unsigned i=0;i<sizeof(modes)/sizeof(*modes);++i){mode=modes[i];for(unsigned failure=0;failure<4;++failure){fixture.descriptor_fail=failure&1;fixture.file_fail=failure&2;compare();}}
    fixture.descriptor_fail=fixture.file_fail=0;
    const size_t sizes[]={0,1,2,3,4,4096,SIZE_MAX};
    code=12;for(unsigned i=0;i<sizeof(sizes)/sizeof(*sizes);++i){capacity=sizes[i];compare();}
    for(unsigned length=4094;length<=4097;++length){memset(fixture.text,'x',length);fixture.text[length]=0;code=3;capacity=4096;compare();code=4;compare();code=12;capacity=4096;compare();}
    strcpy(fixture.text,"abc");code=8;const char *invalid[]={NULL,"","bad=name","normal"};for(unsigned i=0;i<4;++i)for(unsigned j=0;j<2;++j)for(unsigned replace=0;replace<2;++replace){name=invalid[i];value=j?NULL:"new";overwrite=replace;compare();}
    code=10;name="path";for(unsigned bits=0;bits<512;++bits){open_flags=bits|((bits&1)?_O_TEXT:0)|((bits&2)?_O_BINARY:0);compare();}
    printf("PASS file_policy entries=17 cases=%"PRIu64" full_traces=1 errno_and_lasterror=1 native_failures=1 allocation_failures=1\n",cases);
    check_native_facade();
    return 0;
}
