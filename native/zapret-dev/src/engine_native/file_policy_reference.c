/* MIT. Complete file facade retained as a conformance reference. */
#ifndef WIN_FILES_IMPLEMENTATION
#define WIN_FILES_IMPLEMENTATION
#endif
#include "win_files.h"

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>

/* Match the buffers in the pinned Cygwin engine. UTF-16 filesystem operations
 * remain dynamically sized. APIs returning engine-owned buffers reject excess. */
#define WF_PATH_MAX 4096

void wf_error(DWORD error)
{
    switch (error) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_DRIVE:
        errno = ENOENT;
        break;
    case ERROR_ACCESS_DENIED:
    case ERROR_PRIVILEGE_NOT_HELD:
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
        errno = EACCES;
        break;
    case ERROR_ALREADY_EXISTS:
    case ERROR_FILE_EXISTS:
        errno = EEXIST;
        break;
    case ERROR_NOT_SAME_DEVICE:
        errno = EXDEV;
        break;
    case ERROR_DIRECTORY:
        errno = ENOTDIR;
        break;
    case ERROR_DIR_NOT_EMPTY:
        errno = ENOTEMPTY;
        break;
    case ERROR_DISK_FULL:
    case ERROR_HANDLE_DISK_FULL:
        errno = ENOSPC;
        break;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:
        errno = ENOMEM;
        break;
    case ERROR_FILENAME_EXCED_RANGE:
        errno = ENAMETOOLONG;
        break;
    case ERROR_NO_UNICODE_TRANSLATION:
        errno = EILSEQ;
        break;
    case ERROR_INVALID_NAME:
    case ERROR_INVALID_PARAMETER:
        errno = EINVAL;
        break;
    default:
        errno = EIO;
        break;
    }
    SetLastError(error);
}

/* The allocations returned through this ABI use the caller's UCRT heap. */
typedef void *(*wf_alloc)(size_t);
typedef struct {
    uint64_t device, inode;
    int64_t size, seconds;
    uint32_t nanoseconds, directory;
} wf_rust_metadata;
_Static_assert(sizeof(wf_rust_metadata) == 40, "Rust file metadata size");
_Static_assert(offsetof(wf_rust_metadata, nanoseconds) == 32, "Rust file metadata layout");

uint32_t zapret_wf_path(const char *, wf_alloc, wchar_t **);
uint32_t zapret_wf_utf8(const wchar_t *, wf_alloc, char **);
uint32_t zapret_wf_realpath(const char *, int, wf_alloc, char **);
uint32_t zapret_wf_stat(const char *, wf_rust_metadata *);
uint32_t zapret_wf_exedir(wf_alloc, char **);
uint32_t zapret_wf_getenv(const char *, wf_alloc, char **);
uint32_t zapret_wf_setenv(const char *, const char *);
uint32_t zapret_wf_open(const char *, int, int, HANDLE *);
uint32_t zapret_wf_getcwd(wf_alloc, char **);
uint32_t zapret_wf_mkdir(const char *);
uint32_t zapret_wf_unlink(const char *);
uint32_t zapret_wf_remove(const char *);
uint32_t zapret_wf_rename(const char *, const char *);

static int wf_status(DWORD error)
{
    if (!error) return 0;
    wf_error(error);
    return -1;
}

wchar_t *wf_path_utf16(const char *path)
{
    wchar_t *result = NULL;
    wf_status(zapret_wf_path(path, malloc, &result));
    return result;
}

char *wf_wide_to_utf8(const wchar_t *text)
{
    char *result = NULL;
    wf_status(zapret_wf_utf8(text, malloc, &result));
    return result;
}

static char *wf_resolve(const char *path, char *resolved, int allow_missing_leaf)
{
    char *result = NULL;
    if (wf_status(zapret_wf_realpath(path, allow_missing_leaf, malloc, &result))) return NULL;
    if (!resolved) return result;
    size_t size = strlen(result) + 1;
    if (size > WF_PATH_MAX) {
        free(result);
        wf_error(ERROR_FILENAME_EXCED_RANGE);
        return NULL;
    }
    memcpy(resolved, result, size);
    free(result);
    return resolved;
}

char *wf_realpath(const char *path, char *resolved)
{
    return wf_resolve(path, resolved, 0);
}

bool wf_realpath_any(const char *path, char *resolved)
{
    return wf_resolve(path, resolved, 1) != NULL;
}

int wf_file_stat(const char *path, wf_file_info *info)
{
    wf_rust_metadata raw;
    DWORD error = zapret_wf_stat(path, &raw);
    if (error == ERROR_ARITHMETIC_OVERFLOW) {
        errno = EOVERFLOW;
        return -1;
    }
    if (wf_status(error)) return -1;
    info->st_dev = raw.device;
    info->st_ino = raw.inode;
    info->st_size = raw.size;
    info->st_mode = raw.directory ? _S_IFDIR : _S_IFREG;
    info->modified.tv_sec = raw.seconds;
    info->modified.tv_nsec = (long)raw.nanoseconds;
    return 0;
}

bool wf_set_exedir(void)
{
    char *utf8 = NULL;
    if (wf_status(zapret_wf_exedir(malloc, &utf8))) return false;
    bool result = wf_setenv("EXEDIR", utf8, 1) == 0;
    free(utf8);
    return result;
}

/* Keep the UCRT getenv pointer lifetime and case-insensitive cache for C callers. */
typedef struct wf_environment {
    struct wf_environment *next;
    char *name;
    char *value;
} wf_environment;

static SRWLOCK environment_lock = SRWLOCK_INIT;
static wf_environment *environment;

char *wf_getenv(const char *name)
{
    char *utf8 = NULL;
    DWORD error = zapret_wf_getenv(name, malloc, &utf8);
    if (error == ERROR_ENVVAR_NOT_FOUND || wf_status(error)) return NULL;

    AcquireSRWLockExclusive(&environment_lock);
    wf_environment *entry = environment;
    while (entry && strcasecmp(entry->name, name)) entry = entry->next;
    if (!entry) {
        entry = calloc(1, sizeof(*entry));
        if (entry) entry->name = strdup(name);
        if (!entry || !entry->name) {
            free(entry);
            free(utf8);
            ReleaseSRWLockExclusive(&environment_lock);
            wf_error(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }
        entry->next = environment;
        environment = entry;
    }
    if (entry->value && !strcmp(entry->value, utf8)) {
        free(utf8);
    } else {
        free(entry->value);
        entry->value = utf8;
    }
    char *result = entry->value;
    ReleaseSRWLockExclusive(&environment_lock);
    return result;
}

int wf_setenv(const char *name, const char *value, int overwrite)
{
    if (!name || !*name || strchr(name, '=') || !value) {
        wf_error(ERROR_INVALID_PARAMETER);
        return -1;
    }
    if (!overwrite && wf_getenv(name)) return 0;
    return wf_status(zapret_wf_setenv(name, value));
}

static int wf_open_descriptor(const char *path, int flags, int mode)
{
    HANDLE file;
    if (wf_status(zapret_wf_open(path, flags, mode, &file))) return -1;
    int descriptor_flags = flags & (_O_APPEND | _O_TEXT | _O_BINARY | _O_NOINHERIT);
    int descriptor = _open_osfhandle((intptr_t)file, descriptor_flags);
    if (descriptor < 0) {
        int error = errno;
        CloseHandle(file);
        errno = error;
    }
    return descriptor;
}

FILE *wf_fopen(const char *path, const char *mode)
{
    if (!mode || !*mode || !strchr("rwa", *mode)) {
        errno = EINVAL;
        return NULL;
    }
    bool update = strchr(mode, '+') != NULL;
    bool text = strchr(mode, 't') && !strchr(mode, 'b');
    int flags = update ? _O_RDWR : (*mode == 'r' ? _O_RDONLY : _O_WRONLY);
    if (*mode == 'w') flags |= _O_CREAT | _O_TRUNC;
    if (*mode == 'a') flags |= _O_CREAT | _O_APPEND;
    if (*mode != 'r' && strchr(mode, 'x')) flags |= _O_EXCL;
    if (strchr(mode, 'e')) flags |= _O_NOINHERIT;
    flags |= text ? _O_TEXT : _O_BINARY;

    /* Newlib tolerates unknown trailing mode letters. Canonicalize its flags
     * before entering UCRT, whose invalid-parameter handler can exit the engine. */
    wchar_t canonical_mode[4] = {(wchar_t)*mode, text ? L't' : L'b', L'\0', L'\0'};
    if (update) canonical_mode[2] = L'+';
    int descriptor = wf_open_descriptor(path, flags, _S_IREAD | _S_IWRITE);
    if (descriptor < 0) return NULL;
    FILE *file = _wfdopen(descriptor, canonical_mode);
    if (!file) {
        int error = errno;
        _close(descriptor);
        errno = error;
    }
    return file;
}

int wf_open(const char *path, int flags, ...)
{
    int mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }
    if (!(flags & _O_TEXT)) flags |= _O_BINARY;
    return wf_open_descriptor(path, flags, mode);
}

int wf_chdir(const char *path)
{
    wchar_t *wide = wf_path_utf16(path);
    if (!wide) return -1;
    int result = _wchdir(wide);
    free(wide);
    return result;
}

char *wf_getcwd(char *buffer, size_t size)
{
    char *utf8 = NULL;
    if (wf_status(zapret_wf_getcwd(malloc, &utf8))) return NULL;
    if (!buffer) return utf8;
    if (strlen(utf8) >= size) {
        free(utf8);
        errno = ERANGE;
        return NULL;
    }
    strcpy(buffer, utf8);
    free(utf8);
    return buffer;
}

int wf_mkdir(const char *path, int mode)
{
    (void)mode; /* Windows inherits the parent DACL. The engine sets its label. */
    return wf_status(zapret_wf_mkdir(path));
}

int wf_unlink(const char *path)
{
    return wf_status(zapret_wf_unlink(path));
}

int wf_remove(const char *path)
{
    return wf_status(zapret_wf_remove(path));
}

int wf_rename(const char *source, const char *destination)
{
    return wf_status(zapret_wf_rename(source, destination));
}
