/* MIT. Compiler metadata and ABI checks for the Rust main. */
#include "engine_banner_abi.h"
#include "engine_host_main_abi.h"
#include "conntrack_windows.h"
#include "conntrack_engine_abi.h"
#include "windows_packet_layout_abi.h"

_Static_assert(
    sizeof(WINDIVERT_ADDRESS) == 80 && _Alignof(WINDIVERT_ADDRESS) == 8 &&
    offsetof(WINDIVERT_ADDRESS, Network.IfIdx) == 16 &&
    offsetof(WINDIVERT_ADDRESS, Network.SubIfIdx) == 20 &&
    sizeof(((struct sockaddr *)0)->sa_family) == 2 &&
    WINDIVERT_LAYER_NETWORK == 0 && EIO == 5 && EINVAL == 22 && ESHUTDOWN == 10058 &&
    IFNAMSIZ == 44 && VERDICT_PASS == 0 && FUZZ_MAX_PACKET_SIZE == 69632 &&
    IDX_BLOB == 17 && WF_COUNT == 16 && WINDIVERT_MAX == 65536 &&
    ZAPRET_CAPTURE_ADDRESS_COUNT == 128,
    "Rust main banner and capture layout");

_Static_assert(LUA_COMPAT_VER == 6, "Rust engine banner compatibility version");

const zapret_engine_banner_data zapret_engine_banner = {
#if defined(ZAPRET_GH_VER) || defined(ZAPRET_GH_HASH)
    ZAPRET_BANNER_STRING(ZAPRET_GH_VER), ZAPRET_BANNER_STRING(ZAPRET_GH_HASH), LUA_COMPAT_VER, true
#else
    __DATE__, __TIME__, LUA_COMPAT_VER, false
#endif
};
