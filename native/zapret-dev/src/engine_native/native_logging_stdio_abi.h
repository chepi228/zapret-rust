/* MIT. The caller owns the live MinGW variadic frame. */
#pragma once
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(__MINGW32__) || !(defined(__i386__) || defined(__x86_64__)) || \
    !defined(_UCRT) || __USE_MINGW_ANSI_STDIO != 1
#error Expected the pinned MinGW UCRT printf ABI on x86 or x64
#endif
_Static_assert(sizeof(va_list) == sizeof(void *) && _Alignof(va_list) == _Alignof(void *) &&
    __builtin_types_compatible_p(va_list, char *), "Rust logging requires the MinGW variadic cursor");

typedef void (*zapret_log_writer)(int32_t, const char *);
typedef struct {
    FILE *(*stream)(unsigned int);
    FILE *(*open)(const char *, const char *);
    int (*vprint)(FILE *, const char *, va_list);
    int (*print)(FILE *, const char *, ...);
    int (*timestamp)(FILE *);
    int (*close)(FILE *);
} zapret_log_io;
typedef struct {
    const bool *debug;
    const int32_t *target;
    void (*buffer)(zapret_log_writer, int32_t, const char *, va_list);
    zapret_log_writer file, event;
} zapret_log_route;

_Static_assert(sizeof(zapret_log_io) == 6 * sizeof(void *) &&
    sizeof(zapret_log_route) == 5 * sizeof(void *), "Rust logging ABI");
int zapret_crt_log_file(FILE *, const char *, va_list, const zapret_log_io *);
int zapret_crt_log_console(const char *, int32_t, va_list, const zapret_log_io *);
int zapret_crt_log_path(const char *, const char *, va_list, bool, const zapret_log_io *);
void zapret_crt_log_line(const char *, const char *, const zapret_log_io *);
void zapret_crt_log_buffered(zapret_log_writer, int32_t, const char *, va_list);
int zapret_crt_log_dispatch(const char *, int32_t, bool, va_list, const zapret_log_route *, const zapret_log_io *);
