/* MIT. Check the public engine structures borrowed by native Rust exports. */
#pragma once
#include "helpers.h"
#include "engine_lua_arguments_abi.h"
#include "blob_windows.h"

_Static_assert(sizeof(time_t) == 8 && sizeof(off_t) == 8 && sizeof(struct timespec) == 16 &&
    offsetof(struct timespec, tv_nsec) == 8 && sizeof(((struct timespec *)0)->tv_nsec) == 4 &&
    sizeof(file_mod_sig) == 24 && offsetof(file_mod_sig, size) == 16 &&
    CLOCK_BOOT_OR_UPTIME == 1 && PATH_MAX == 4096 && O_RDONLY == 0,
    "Rust file and boot clock ABI");
_Static_assert(sizeof(ipset) == 2 * sizeof(void *) && offsetof(ipset, ips6) == sizeof(void *) &&
    offsetof(struct cidr4, preflen) == 4 && offsetof(struct cidr6, preflen) == 16 &&
    sizeof(ip_cache) == 2 * sizeof(void *) && offsetof(ip_cache, ipcache6) == sizeof(void *),
    "Rust address pool ABI");
_Static_assert(sizeof(struct str_list) == 3 * sizeof(void *) &&
    offsetof(struct str_list, next) == sizeof(void *) && sizeof(struct packet_range) == 20,
    "Rust string collection ABI");
_Static_assert(sizeof(struct port_filter_item) == 8 + 2 * sizeof(void *) &&
    offsetof(struct port_filter_item, next) == 8 &&
    sizeof(struct icmp_filter_item) == 3 * sizeof(void *) &&
    offsetof(struct icmp_filter_item, next) == sizeof(void *) &&
    sizeof(struct ipp_filter_item) == 3 * sizeof(void *) &&
    offsetof(struct ipp_filter_item, next) == sizeof(void *),
    "Rust filter collection ABI");
