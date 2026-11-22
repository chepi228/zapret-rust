/* MIT. Execute host actions after the Rust phase returns. */
#include "engine_banner_abi.h"
#include "engine_host_main_abi.h"

_Static_assert(IDX_BLOB == 17, "Rust residual blob option");

int main(int argc, char **argv)
{
    static const zapret_native_main_ops ops = {
        .option_count = zapret_native_cli_count,
        .environment = getenv,
        .read_blob = zapret_native_cli_read_blob,
        .prefix = zapret_native_main_prefix_step,
        .finish = {
            native_profile_finish, cleanup_args, native_startup_validate,
            zapret_native_lifecycle_prepare, zapret_native_lifecycle_release_mutex, close_std,
        },
    };
    zapret_native_main_state state;
    zapret_native_main_begin(&state, argc, argv);
    for (;;) {
        switch (zapret_native_main_advance(&state, &params, &ops)) {
        case NATIVE_PREFIX_STOP: return 0;
        case NATIVE_PREFIX_SERVICE: state.prefix.available = service_run(state.argc, state.argv); break;
        case NATIVE_PREFIX_PARAMS: init_params(&params); break;
        case NATIVE_PREFIX_BANNER: native_main_version(); break;
        case NATIVE_PREFIX_HELP: exithelp(); break;
        case NATIVE_PREFIX_BLOBS: ApplyDefaultBlobs(&params.blobs); break;
        case NATIVE_PREFIX_PROFILE: native_profile_exit(native_profile_next(&state.profiles, NULL), NULL); break;
        case NATIVE_PREFIX_EXIT: exit_clean(1); return 0;
        case MAIN_ARGUMENT_HELP: exithelp_clean(); break;
        case MAIN_ARGUMENT_EXIT: exit_clean(state.exit_code); break;
        case MAIN_FINISH_BASE + FINISH_PROFILE_ERROR:
            native_profile_exit(state.finish.feedback.status, state.profile->name);
            break;
        case MAIN_FINISH_BASE + FINISH_CAPTURE: {
            zapret_capture_cli *capture = &state.capture;
            zapret_capture_prepare_result prepared = native_capture_prepare(*capture->index,
                *capture->sub_index, *capture->ipv4, *capture->ipv6, *capture->lan,
                *capture->loopback, *capture->empty, *capture->duplicate, state.options.dry,
                capture->save, capture->hashes, &state.finish.mutex);
            state.finish.feedback.status = prepared.status;
            break;
        }
        case MAIN_FINISH_BASE + FINISH_RUN:
            state.finish.feedback.result = win_main();
            break;
        case MAIN_FINISH_BASE + FINISH_CLEANUP: cleanup_params(&params); break;
        case MAIN_FINISH_BASE + FINISH_RETURN: return state.finish.flow.result;
        case MAIN_FINISH_BASE + FINISH_EXIT_SUCCESS: exit_clean(0); break;
        case MAIN_FINISH_BASE + FINISH_EXIT_ERROR: exit_clean(1); break;
        default:
            DLOG_ERR("invalid main finish state\n");
            exit_clean(1);
            break;
        }
    }
}
