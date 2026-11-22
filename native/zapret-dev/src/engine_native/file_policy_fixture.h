/* MIT. Native facade observations for old/new complete-entry comparisons. */
#pragma once
#define WIN_FILES_IMPLEMENTATION
#include "win_files.h"
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>
void *file_fixture_malloc(size_t);
void *file_fixture_calloc(size_t,size_t);
char *file_fixture_strdup(const char *);
void file_fixture_free(void *);
int file_fixture_descriptor(intptr_t,int);
FILE *file_fixture_fdopen(int,const wchar_t *);
int file_fixture_close(int);
int file_fixture_chdir(const wchar_t *);
BOOL file_fixture_close_handle(HANDLE);
void file_fixture_lock(SRWLOCK *);
void file_fixture_unlock(SRWLOCK *);
void file_fixture_last_error(DWORD);
#define malloc file_fixture_malloc
#define calloc file_fixture_calloc
#define strdup file_fixture_strdup
#define free file_fixture_free
#define _open_osfhandle file_fixture_descriptor
#define _wfdopen file_fixture_fdopen
#define _close file_fixture_close
#define _wchdir file_fixture_chdir
#define CloseHandle file_fixture_close_handle
#define AcquireSRWLockExclusive file_fixture_lock
#define ReleaseSRWLockExclusive file_fixture_unlock
#define SetLastError file_fixture_last_error
