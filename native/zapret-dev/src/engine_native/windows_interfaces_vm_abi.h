/* MIT. Windows SDK records used by Rust's local interface table projection. */
#pragma once
#include <stddef.h>

_Static_assert(sizeof(ULONG) == 4 && sizeof(lua_Integer) == sizeof(ptrdiff_t) &&
    offsetof(IP_ADAPTER_ADDRESSES, Next) == 8, "Rust Lua interface snapshot ABI");
#ifdef _WIN64
_Static_assert(sizeof(IP_ADAPTER_ADDRESSES) == 448 &&
    offsetof(IP_ADAPTER_ADDRESSES, PhysicalAddress) == 80 &&
    offsetof(IP_ADAPTER_ADDRESSES, TransmitLinkSpeed) == 184 &&
    offsetof(IP_ADAPTER_ADDRESSES, ConnectionType) == 268 &&
    offsetof(IP_ADAPTER_UNICAST_ADDRESS_LH, Address) == 16, "Win64 adapter ABI");
#else
_Static_assert(sizeof(IP_ADAPTER_ADDRESSES) == 376 &&
    offsetof(IP_ADAPTER_ADDRESSES, PhysicalAddress) == 44 &&
    offsetof(IP_ADAPTER_ADDRESSES, TransmitLinkSpeed) == 144 &&
    offsetof(IP_ADAPTER_ADDRESSES, ConnectionType) == 212 &&
    offsetof(IP_ADAPTER_UNICAST_ADDRESS_LH, Address) == 12, "Win32 adapter ABI");
#endif

int lua_get_ifaddrs(lua_State *);
