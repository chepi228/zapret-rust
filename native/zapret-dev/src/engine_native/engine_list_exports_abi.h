/* MIT. Check the active Windows fields borrowed by the Rust list entries. */
#pragma once
#include "windows_startup_params_abi.h"
#include "engine_profile_exports_abi.h"

_Static_assert(sizeof(struct zapret_list_file) == (sizeof(void *) == 4 ? 48 : 56) &&
    _Alignof(struct zapret_list_file) == 8 &&
    offsetof(struct zapret_list_file, filename) == 0 &&
    offsetof(struct zapret_list_file, mod_sig) == 8 &&
    offsetof(struct zapret_list_file, hostlist) == 32 &&
    offsetof(struct zapret_list_file, ipset) == 32 + sizeof(void *) &&
    sizeof(ipset) == 2 * sizeof(void *) && offsetof(ipset, ips6) == sizeof(void *), "Rust list file ABI");
_Static_assert(sizeof(struct cidr4) == 8 && _Alignof(struct cidr4) == 4 &&
    offsetof(struct cidr4, preflen) == 4 && sizeof(struct cidr6) == 18 &&
    _Alignof(struct cidr6) == 2 && offsetof(struct cidr6, preflen) == 16, "Rust list CIDR ABI");
