/* MIT. Perform terminating or blob operations after the Rust scan returns. */
#include "cli_stderr_windows.h"

static void native_engine_arguments(native_engine_cli *state, int argc, char **argv)
{
    zapret_engine_scan_cursor cursor = zapret_engine_scan_begin(getenv);
    const zapret_engine_scan_ops ops = {
        .options = long_options,
        .count = zapret_native_cli_count(),
        .context = state,
        .category = native_engine_option_category,
        .argument = &state->text,
        .index = &state->index,
        .stderr_sink = native_cli_stderr,
        .dry = state->dry,
    };
    for (;;) {
        zapret_engine_scan_event event = zapret_engine_scan_arguments(argc, argv, &cursor, &ops);
        switch (event.route.action) {
            case ENTRY_PARSE_DONE: return;
            case ENTRY_PARSE_HELP: exithelp_clean(); return;
            case ENTRY_LOAD_BLOB:
                load_blob_to_collection(state->text, &params.blobs, event.blob_maximum, event.blob_reserve);
                break;
            default:
                native_engine_apply_option_result(state, event.route);
                return;
        }
    }
}

static int native_engine_main(int argc, char **argv)
{
    zapret_engine_main_options options;
    zapret_engine_main_defaults(&options);
    unsigned hashes[WF_COUNT];
    native_profile_flow profile_flow;
    struct desync_profile_list *entry;
    struct desync_profile *profile;
    if (!native_main_prefix(&argc, &argv, hashes, &profile_flow, &entry, &profile)) return 0;

    zapret_capture_cli capture = {
        options.save, sizeof(options.save), &options.ipv4, &options.ipv6, &options.lan, &options.loopback,
        &options.empty, &options.duplicate, &options.index, &options.sub_index, hashes,
    };
    native_engine_cli route = {
        .flow = &profile_flow, .entry = &entry, .profile = &profile,
        .anonymous = {&options.anonymous[0], &options.anonymous[1], &options.anonymous[2], &options.anonymous[3]},
        .payload = &options.payload, .incoming = &options.incoming, .outgoing = &options.outgoing,
        .dry = &options.dry, .capture = &capture,
    };
    native_engine_arguments(&route, argc, argv);
    return native_engine_finish(&profile_flow, profile, &capture, &options.dry, &argc, &argv);
}
