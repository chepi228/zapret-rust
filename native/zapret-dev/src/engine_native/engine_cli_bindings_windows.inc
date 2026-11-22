/* MIT. Bind the comparison fixtures to their synthetic option effects. */
#include "engine_cli_dispatch_abi.h"

const zapret_cli_entry_bindings zapret_native_cli_bindings = {
    .numeric = engine_numeric_option,
    .startup = engine_startup_option,
    .lists = engine_list_option,
    .profile = engine_profile_filter,
    .capture = engine_capture_option,
    .control = engine_control_option,
    .options = zapret_native_cli_options,
};
