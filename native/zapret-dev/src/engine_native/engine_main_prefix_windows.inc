/* MIT. Operations that can leave the startup frame run after the Rust step. */
#include "engine_prefix_abi.h"
#include "engine_banner_abi.h"
#include "engine_main_prefix_abi.h"

_Static_assert(IDX_BLOB == 17, "Rust residual blob option");
static bool native_main_prefix(int *argc, char ***argv, unsigned *hashes,
    native_profile_flow *profiles, struct desync_profile_list **entry, struct desync_profile **profile)
{
    zapret_native_prefix_cursor cursor = {0};
    const zapret_native_prefix_slots slots = {argc, argv, hashes, profiles, entry, profile};
    for (;;) switch (zapret_native_main_prefix_step(&cursor, &slots)) {
        case NATIVE_PREFIX_SERVICE: cursor.available = service_run(*argc, *argv); break;
        case NATIVE_PREFIX_PARAMS: init_params(&params); break;
        case NATIVE_PREFIX_BANNER: native_main_version(); break;
        case NATIVE_PREFIX_HELP: exithelp(); break;
        case NATIVE_PREFIX_BLOBS: ApplyDefaultBlobs(&params.blobs); break;
        case NATIVE_PREFIX_PROFILE: native_profile_exit(native_profile_next(profiles, NULL), NULL); break;
        case NATIVE_PREFIX_EXIT: exit_clean(1); return false;
        case NATIVE_PREFIX_READY: return true;
        default: return false;
    }
}
