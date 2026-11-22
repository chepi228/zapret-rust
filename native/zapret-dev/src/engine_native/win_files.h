#ifndef ZAPRET_WIN_FILES_H
#define ZAPRET_WIN_FILES_H

#include <windows.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <io.h>
#include <direct.h>
#include <time.h>

typedef struct wf_file_info {
    uint64_t st_dev;
    uint64_t st_ino;
    int64_t st_size;
    unsigned st_mode;
    struct timespec modified;
} wf_file_info;

void wf_error(DWORD error);
bool wf_state_result(DWORD error);
char *wf_wide_to_utf8(const wchar_t *text);
wchar_t *wf_path_utf16(const char *path);
int wf_file_stat(const char *path, wf_file_info *info);
char *wf_realpath(const char *path, char *resolved);
bool wf_realpath_any(const char *path, char *resolved);
bool wf_set_exedir(void);
char *wf_getenv(const char *name);
int wf_setenv(const char *name, const char *value, int overwrite);
FILE *wf_fopen(const char *path, const char *mode);
int wf_open_mode(const char *path, int flags, int mode);
int wf_chdir(const char *path);
char *wf_getcwd(char *buffer, size_t size);
int wf_mkdir(const char *path, int mode);
int wf_unlink(const char *path);
int wf_remove(const char *path);
int wf_rename(const char *source, const char *destination);

/* Apply the same UTF-8 path and replacing-rename semantics to the engine and
 * the statically linked LuaJIT standard libraries. FILE stays in the UCRT. */
#ifndef WIN_FILES_IMPLEMENTATION
#define fopen wf_fopen
#define WF_OPEN_WITHOUT_MODE(path,flags) wf_open_mode((path),(flags),0)
#define WF_OPEN_SELECT(path,flags,mode,selected,...) selected
#define open(...) WF_OPEN_SELECT(__VA_ARGS__,wf_open_mode,WF_OPEN_WITHOUT_MODE,0)(__VA_ARGS__)
#define chdir wf_chdir
#define getcwd wf_getcwd
#define mkdir wf_mkdir
#define unlink wf_unlink
#define remove wf_remove
#define rename wf_rename
#define realpath wf_realpath
#define getenv wf_getenv
#define setenv wf_setenv
#define fseek _fseeki64
#define ftell _ftelli64
#endif

#endif
