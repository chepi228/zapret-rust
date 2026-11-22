/* MIT. Native Windows declarations used by the pinned POSIX-oriented engine. */
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <limits.h>
#undef PATH_MAX
#define PATH_MAX 4096
#include <sys/types.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <pthread_time.h>
#include <sys/param.h>

typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint32_t in_addr_t;
typedef uint16_t in_port_t;
#ifndef __packed
#define __packed __attribute__((__packed__))
#endif
#ifndef __BEGIN_DECLS
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif
#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 4
#endif
#ifndef ESHUTDOWN
#define ESHUTDOWN WSAESHUTDOWN
#endif

int32_t zapret_random(void);
void zapret_srandom(uint32_t seed);
intptr_t zapret_getrandom(unsigned char *buffer,size_t length,unsigned int flags);
void *zapret_memmem(const void *haystack,size_t length,const void *needle,size_t needle_length);
_Static_assert(sizeof(time_t) == sizeof(int64_t), "Rust calendar time ABI");
struct tm *zapret_localtime_r(const time_t *value,struct tm *output);
struct tm *zapret_gmtime_r(const time_t *value,struct tm *output);
#define random zapret_random
#define srandom zapret_srandom
#define memmem zapret_memmem
#define timegm _mkgmtime
#define localtime_r zapret_localtime_r
#define gmtime_r zapret_gmtime_r

int zapret_engine_main(int argc,char **argv);
#define main zapret_engine_main

#include "win_files.h"
