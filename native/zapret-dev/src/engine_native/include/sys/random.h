/* MIT. BCrypt through the shared Rust Windows support library. */
#pragma once
#include <errno.h>
#define GRND_NONBLOCK 1
#define GRND_RANDOM 2
static inline ssize_t getrandom(void *buffer,size_t length,unsigned int flags)
{
    intptr_t result=zapret_getrandom(buffer,length,flags);
    if(result<0)errno=EIO;
    return (ssize_t)result;
}
