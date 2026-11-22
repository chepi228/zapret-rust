/* MIT. List facade policy only. Native callbacks never enter the Lua VM. */
#pragma once
#include <stdint.h>
#include <stddef.h>
typedef uintptr_t (*zapret_list_native)(uint32_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t);
uintptr_t zapret_list_lifecycle(uint32_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t,uintptr_t,zapret_list_native);
