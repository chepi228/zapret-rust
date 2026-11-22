/* MIT. The six zlib calls used by the pinned engine, backed by zlib-rs. */
#pragma once
#include <stddef.h>

#define z_const const
typedef unsigned char Bytef;
typedef unsigned int uInt;
typedef void *voidpf;

typedef struct {
    const Bytef *next_in;
    uInt avail_in;
    unsigned long total_in;
    Bytef *next_out;
    uInt avail_out;
    unsigned long total_out;
    char *msg;
    void *state;
    voidpf (*zalloc)(voidpf, uInt, uInt);
    void (*zfree)(voidpf, voidpf);
    voidpf opaque;
    int data_type;
    unsigned long adler;
    unsigned long reserved;
} z_stream;

#if defined(_WIN64)
_Static_assert(sizeof(z_stream) == 88 && offsetof(z_stream, next_out) == 16 &&
    offsetof(z_stream, zalloc) == 48 && offsetof(z_stream, data_type) == 72,
    "zlib-rs Win64 stream ABI");
#elif defined(_WIN32)
_Static_assert(sizeof(z_stream) == 56 && offsetof(z_stream, next_out) == 12 &&
    offsetof(z_stream, zalloc) == 32 && offsetof(z_stream, data_type) == 44,
    "zlib-rs Win32 stream ABI");
#endif

#define Z_NO_FLUSH 0
#define Z_FINISH 4
#define Z_OK 0
#define Z_STREAM_END 1
#define Z_ERRNO (-1)
#define Z_DATA_ERROR (-3)
#define Z_MEM_ERROR (-4)
#define Z_BUF_ERROR (-5)
#define Z_DEFLATED 8
#define Z_DEFAULT_STRATEGY 0

int zapret_inflate_init(z_stream *, int);
int zapret_inflate(z_stream *, int);
int zapret_inflate_end(z_stream *);
int zapret_deflate_init(z_stream *, int, int, int, int, int);
int zapret_deflate(z_stream *, int);
int zapret_deflate_end(z_stream *);

#define inflateInit2 zapret_inflate_init
#define inflate zapret_inflate
#define inflateEnd zapret_inflate_end
#define deflateInit2 zapret_deflate_init
#define deflate zapret_deflate
#define deflateEnd zapret_deflate_end
