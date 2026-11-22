/* MIT. Execute effects that can leave the host frame after Rust returns. */
#include "engine_main_bindings_abi.h"

static int native_engine_finish(native_profile_flow *profiles, struct desync_profile *profile,
    zapret_capture_cli *capture, bool *dry, int *argc, char ***argv)
{
    static const zapret_native_finish_ops ops = {
        native_profile_finish, cleanup_args, native_startup_validate,
        zapret_native_lifecycle_prepare, zapret_native_lifecycle_release_mutex, close_std,
    };
    zapret_native_finish_state state = {0};
    for (;;) {
        uint32_t action = zapret_native_finish_advance(&state, &params, profiles, dry, argc, argv, &ops);
        switch (action) {
        case FINISH_PROFILE_ERROR:
            native_profile_exit(state.feedback.status, profile->name);
            break;
        case FINISH_CAPTURE: {
            zapret_capture_prepare_result prepared = native_capture_prepare(*capture->index,
                *capture->sub_index, *capture->ipv4, *capture->ipv6, *capture->lan,
                *capture->loopback, *capture->empty, *capture->duplicate, *dry,
                capture->save, capture->hashes, &state.mutex);
            state.feedback.status = prepared.status;
            break;
        }
        case FINISH_RUN:
            state.feedback.result = win_main();
            break;
        case FINISH_CLEANUP:
            cleanup_params(&params);
            break;
        case FINISH_RETURN:
            return state.flow.result;
        case FINISH_EXIT_SUCCESS:
            exit_clean(0);
            break;
        case FINISH_EXIT_ERROR:
            exit_clean(1);
            break;
        default:
            DLOG_ERR("invalid main finish state\n");
            exit_clean(1);
            break;
        }
    }
}
