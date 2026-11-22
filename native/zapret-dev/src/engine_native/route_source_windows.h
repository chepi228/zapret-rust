/* MIT. Source-address socket ownership is entirely inside the Rust call. */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
typedef struct{
    uintptr_t (*socket)(int,int,int);
    int (*connect)(uintptr_t,const void *,int);
    int (*name)(uintptr_t,void *,int *);
    int (*close)(uintptr_t);
}zapret_route_source_ops;
bool zapret_route_source(uint32_t,const uint8_t *,uint8_t *,const zapret_route_source_ops *);
uint32_t zapret_lua_source_ip(const uint8_t *,size_t,uint8_t *,const zapret_route_source_ops *);
_Static_assert(sizeof(zapret_route_source_ops) == 4 * sizeof(void *) &&
    offsetof(zapret_route_source_ops, close) == 3 * sizeof(void *) &&
    sizeof(struct sockaddr_in) == 16 && sizeof(struct sockaddr_in6) == 28, "Rust source address ABI");
