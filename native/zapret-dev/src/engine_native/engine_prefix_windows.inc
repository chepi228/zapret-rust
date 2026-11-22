#include "engine_prefix_abi.h"

#define NATIVE_VERSION_STRINGIFY(value) #value
#define NATIVE_VERSION_STRING(value) NATIVE_VERSION_STRINGIFY(value)
static void native_main_version(void)
{
    /* The C toolchain supplies the build metadata and the UCRT print sink. */
#if defined(ZAPRET_GH_VER) || defined(ZAPRET_GH_HASH)
    zapret_engine_version(params.verstr, sizeof(params.verstr), true,
        NATIVE_VERSION_STRING(ZAPRET_GH_VER), NATIVE_VERSION_STRING(ZAPRET_GH_HASH), LUA_COMPAT_VER, printf);
#else
    zapret_engine_version(params.verstr, sizeof(params.verstr), false, __DATE__, __TIME__, LUA_COMPAT_VER, printf);
#endif
}
#undef NATIVE_VERSION_STRING
#undef NATIVE_VERSION_STRINGIFY

_Static_assert(IDX_BLOB == 17, "Rust residual blob option");
static bool native_main_prefix(int *argc, char ***argv, unsigned *hashes,
    native_profile_flow *profiles, struct desync_profile_list **entry, struct desync_profile **profile)
{
    uint32_t phase = 0;
    bool available = false;
    uint8_t first = 0;
    while ((phase = zapret_engine_prefix_next(phase, available, *argc, first, DLOG_ERR))) {
        switch (phase) {
        case 1: available = service_run(*argc, *argv); break;
        case 2: return false;
        case 3: WinSetIcon(); break;
        case 4: init_params(&params); break;
        case 5: native_main_version(); break;
        case 6: exithelp(); break;
        case 7: srandom(time(NULL)); break;
        case 8: set_env_exedir((*argv)[0]); break;
        case 9: set_console_io_buffering(); break;
        case 10: mask_from_bitcount6_prepare(); break;
        case 11: memset(hashes, 0, WF_COUNT * sizeof(*hashes)); break;
        case 12: prepare_low_appdata(); break;
        case 13: ApplyDefaultBlobs(&params.blobs); break;
        case 14:
            *profiles = (native_profile_flow){.profiles = &params.desync_profiles, .templates = &params.desync_templates};
            native_profile_exit(native_profile_next(profiles, NULL), NULL);
            *entry = profiles->current;
            *profile = &(*entry)->dp;
            break;
        case 15: first = (uint8_t)(*argv)[1][0]; break;
        case 16:
            config_from_file((*argv)[1] + 1);
            *argv = params.wexp.we_wordv;
            *argc = params.wexp.we_wordc;
            break;
        case 17:
            params.windivert_filter = calloc(1, zapret_engine_capture_capacity());
            available = params.windivert_filter != NULL;
            break;
        case 18: available = alloc_windivert_portfilters(&params); break;
        case 19: exit_clean(1); return false;
        case 20: return true;
        }
    }
    return false;
}

