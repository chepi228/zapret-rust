/* MIT. Supply compiler metadata to the Rust banner entry. */
#pragma once
#include "windows_startup_params_abi.h"

typedef struct {
    const char *version, *revision;
    uint32_t lua_compat;
    bool pinned;
} zapret_engine_banner_data;

_Static_assert(sizeof(zapret_engine_banner_data) == (sizeof(void *) == 8 ? 24 : 16) &&
    offsetof(zapret_engine_banner_data, lua_compat) == 2 * sizeof(void *), "Rust startup banner ABI");

extern const zapret_engine_banner_data zapret_engine_banner;

void zapret_native_main_version(bool pinned, const char *version, const char *revision, uint32_t lua_compat);

#define ZAPRET_BANNER_STRING_IMPL(value) #value
#define ZAPRET_BANNER_STRING(value) ZAPRET_BANNER_STRING_IMPL(value)
#if defined(ZAPRET_GH_VER) || defined(ZAPRET_GH_HASH)
#define native_main_version() zapret_native_main_version(true, \
    ZAPRET_BANNER_STRING(ZAPRET_GH_VER), ZAPRET_BANNER_STRING(ZAPRET_GH_HASH), LUA_COMPAT_VER)
#else
#define native_main_version() zapret_native_main_version(false, __DATE__, __TIME__, LUA_COMPAT_VER)
#endif
