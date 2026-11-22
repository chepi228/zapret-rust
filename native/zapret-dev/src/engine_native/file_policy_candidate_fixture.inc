/* MIT. Inject observed native operations into the Rust facade for conformance. */
#ifndef WIN_FILES_IMPLEMENTATION
#define WIN_FILES_IMPLEMENTATION
#endif
#include "win_files.h"
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>
typedef struct {uint64_t device,inode;int64_t size,seconds;uint32_t nanoseconds,directory;} wf_rust_metadata;
typedef void *(*wf_alloc)(size_t);
uint32_t zapret_wf_path(const char *,wf_alloc,wchar_t **);
uint32_t zapret_wf_utf8(const wchar_t *,wf_alloc,char **);
uint32_t zapret_wf_realpath(const char *,int,wf_alloc,char **);
uint32_t zapret_wf_stat(const char *,wf_rust_metadata *);
uint32_t zapret_wf_exedir(wf_alloc,char **);
uint32_t zapret_wf_getenv(const char *,wf_alloc,char **);
uint32_t zapret_wf_setenv(const char *,const char *);
uint32_t zapret_wf_open(const char *,int,int,HANDLE *);
uint32_t zapret_wf_getcwd(wf_alloc,char **);
uint32_t zapret_wf_mkdir(const char *);
uint32_t zapret_wf_unlink(const char *);
uint32_t zapret_wf_remove(const char *);
uint32_t zapret_wf_rename(const char *,const char *);
typedef struct {int append,text,binary,noinherit,rdwr,rdonly,wronly,create,truncate,exclusive,directory,regular;} zapret_file_flags;
typedef struct {
    wf_alloc allocate;
    __typeof__(zapret_wf_realpath) *realpath;
    __typeof__(zapret_wf_stat) *stat;
    __typeof__(zapret_wf_exedir) *exedir;
    __typeof__(zapret_wf_getenv) *getenv;
    __typeof__(zapret_wf_setenv) *setenv;
    __typeof__(zapret_wf_open) *open;
    __typeof__(zapret_wf_getcwd) *getcwd;
    __typeof__(zapret_wf_path) *path;
    __typeof__(zapret_wf_utf8) *utf8;
    void *(*allocate_zeroed)(size_t, size_t);
    char *(*duplicate)(const char *);
    void (*release)(void *);
    int (*compare_names)(const char *, const char *);
    void (*lock_environment)(bool);
    int (*read_errno)(void);
    void (*write_errno)(int);
    void (*report_error)(DWORD);
    int (*descriptor)(intptr_t, int);
    BOOL (WINAPI *close_handle)(HANDLE);
    FILE *(*fdopen)(int, const wchar_t *);
    int (*close_descriptor)(int);
    void (*publish_stat)(wf_file_info *, const wf_rust_metadata *, uint32_t);
    void (*write_errno_class)(uint32_t);
    int (*chdir)(const wchar_t *);
} zapret_file_io;
uintptr_t zapret_file_facade(uint32_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t,
    const zapret_file_flags *,const zapret_file_io *);
uint32_t zapret_file_error_class(uint32_t);
bool zapret_file_open_mode_needed(int,const zapret_file_flags *);
static const zapret_file_flags file_flags={_O_APPEND,_O_TEXT,_O_BINARY,_O_NOINHERIT,_O_RDWR,_O_RDONLY,_O_WRONLY,_O_CREAT,_O_TRUNC,_O_EXCL,_S_IFDIR,_S_IFREG};
static const int file_errors[]={EIO,ENOENT,EACCES,EEXIST,EXDEV,ENOTDIR,ENOTEMPTY,ENOSPC,ENOMEM,ENAMETOOLONG,EILSEQ,EINVAL,EOVERFLOW,ERANGE};
typedef struct wf_environment {struct wf_environment *next;char *name,*value;} wf_environment;
static wf_environment *environment;
static SRWLOCK environment_lock=SRWLOCK_INIT;
_Static_assert(sizeof(zapret_file_flags)==48 && sizeof(wf_rust_metadata)==40 && sizeof(wf_environment)==24,"Rust file facade ABI");
_Static_assert(sizeof(zapret_file_io) == 200, "Rust file operation bindings ABI");
_Static_assert(sizeof(wchar_t)==2 && offsetof(wf_environment,value)==16,"Rust file facade native fields");
void wf_error(DWORD error){errno=file_errors[zapret_file_error_class(error)];SetLastError(error);}
static void file_lock_environment(bool acquire)
{
    if (acquire) AcquireSRWLockExclusive(&environment_lock);
    else ReleaseSRWLockExclusive(&environment_lock);
}
static int file_read_errno(void) { return errno; }
static void file_write_errno(int error) { errno=error; }
static void file_write_errno_class(uint32_t category) { errno=file_errors[category]; }
static void file_publish_stat(wf_file_info *out,const wf_rust_metadata *raw,uint32_t mode)
{
    out->st_dev=raw->device;
    out->st_ino=raw->inode;
    out->st_size=raw->size;
    out->st_mode=mode;
    out->modified.tv_sec=raw->seconds;
    out->modified.tv_nsec=(long)raw->nanoseconds;
}
static const zapret_file_io file_io = {
    .allocate = malloc,
    .realpath = zapret_wf_realpath,
    .stat = zapret_wf_stat,
    .exedir = zapret_wf_exedir,
    .getenv = zapret_wf_getenv,
    .setenv = zapret_wf_setenv,
    .open = zapret_wf_open,
    .getcwd = zapret_wf_getcwd,
    .path = zapret_wf_path,
    .utf8 = zapret_wf_utf8,
    .allocate_zeroed = calloc,
    .duplicate = strdup,
    .release = free,
    .compare_names = strcasecmp,
    .lock_environment = file_lock_environment,
    .read_errno = file_read_errno,
    .write_errno = file_write_errno,
    .report_error = wf_error,
    .descriptor = _open_osfhandle,
    .close_handle = CloseHandle,
    .fdopen = _wfdopen,
    .close_descriptor = _close,
    .publish_stat = file_publish_stat,
    .write_errno_class = file_write_errno_class,
    .chdir = _wchdir,
};
static uintptr_t file_policy(uint32_t op,uintptr_t a,uintptr_t b,uintptr_t c,uintptr_t d)
{return zapret_file_facade(op,a,b,c,d,&file_flags,&file_io);}
static int wf_status(DWORD error){return (int)(intptr_t)file_policy(0,error,0,0,0);}
wchar_t *wf_path_utf16(const char *path){return (wchar_t *)file_policy(10,(uintptr_t)path,0,0,0);}
char *wf_wide_to_utf8(const wchar_t *text){return (char *)file_policy(11,(uintptr_t)text,0,0,0);}
char *wf_realpath(const char *path,char *out){return (char *)file_policy(1,(uintptr_t)path,(uintptr_t)out,0,0);}
bool wf_realpath_any(const char *path,char *out){return file_policy(1,(uintptr_t)path,(uintptr_t)out,1,0)!=0;}
int wf_file_stat(const char *path,wf_file_info *out){return (int)(intptr_t)file_policy(2,(uintptr_t)path,(uintptr_t)out,0,0);}
bool wf_set_exedir(void){return file_policy(3,(uintptr_t)&environment,0,0,0)!=0;}
char *wf_getenv(const char *name){return (char *)file_policy(4,(uintptr_t)name,(uintptr_t)&environment,0,0);}
int wf_setenv(const char *name,const char *value,int overwrite){return (int)(intptr_t)file_policy(5,(uintptr_t)name,(uintptr_t)value,(uintptr_t)overwrite,(uintptr_t)&environment);}
FILE *wf_fopen(const char *path,const char *mode){return (FILE *)file_policy(6,(uintptr_t)path,(uintptr_t)mode,_S_IREAD|_S_IWRITE,0);}
int wf_open(const char *path,int flags,...)
{
    int mode=0;
    if(zapret_file_open_mode_needed(flags,&file_flags)){va_list args;va_start(args,flags);mode=va_arg(args,int);va_end(args);}
    return (int)(intptr_t)file_policy(7,(uintptr_t)path,(uintptr_t)flags,(uintptr_t)mode,0);
}
int wf_chdir(const char *path){return (int)(intptr_t)file_policy(12,(uintptr_t)path,0,0,0);}
char *wf_getcwd(char *out,size_t size){return (char *)file_policy(8,(uintptr_t)out,size,0,0);}
int wf_mkdir(const char *path,int mode){(void)mode;return wf_status(zapret_wf_mkdir(path));}
int wf_unlink(const char *path){return wf_status(zapret_wf_unlink(path));}
int wf_remove(const char *path){return wf_status(zapret_wf_remove(path));}
int wf_rename(const char *from,const char *to){return wf_status(zapret_wf_rename(from,to));}
bool wf_state_result(DWORD error){return file_policy(9,error,0,0,0)!=0;}
