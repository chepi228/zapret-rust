/* MIT. Main parser field projections and late-bound option parsers. */
#pragma once

typedef struct {
    int (*numeric)(int, const char *, struct desync_profile *);
    int (*startup)(int, const char *);
    int (*lists)(int, const char *, struct desync_profile *, bool,
        struct zapret_list_file **, struct zapret_list_file **,
        struct zapret_list_file **, struct zapret_list_file **);
    int (*profile)(int, const char *, struct desync_profile *, uint64_t *,
        struct packet_range *, struct packet_range *);
    int (*capture)(int, const char *, zapret_capture_cli *);
    int (*control)(int, const char *, native_profile_flow *, struct desync_profile_list **,
        struct desync_profile **, struct zapret_list_file **, struct zapret_list_file **,
        struct zapret_list_file **, struct zapret_list_file **, uint64_t *,
        struct packet_range *, struct packet_range *, bool *);
    const struct option *(*options)(void);
} zapret_cli_entry_bindings;

_Static_assert(sizeof(zapret_cli_entry_bindings) == 7 * sizeof(void *) &&
    _Alignof(zapret_cli_entry_bindings) == _Alignof(void *) &&
    offsetof(zapret_cli_entry_bindings, numeric) == 0 &&
    offsetof(zapret_cli_entry_bindings, startup) == sizeof(void *) &&
    offsetof(zapret_cli_entry_bindings, lists) == 2 * sizeof(void *) &&
    offsetof(zapret_cli_entry_bindings, profile) == 3 * sizeof(void *) &&
    offsetof(zapret_cli_entry_bindings, capture) == 4 * sizeof(void *) &&
    offsetof(zapret_cli_entry_bindings, control) == 5 * sizeof(void *) &&
    offsetof(zapret_cli_entry_bindings, options) == 6 * sizeof(void *) &&
    sizeof(struct option) == 4 * sizeof(void *) &&
    offsetof(struct option, name) == 0 && offsetof(struct option, has_arg) == sizeof(void *) &&
    offsetof(struct option, flag) == 2 * sizeof(void *) && offsetof(struct option, val) == 3 * sizeof(void *) &&
    offsetof(struct desync_profile, name) == sizeof(void *) &&
    offsetof(native_profile_flow, skip) == 3 * sizeof(void *) + 8 &&
    ENTRY_READ_OPTION_NAME == 1 && ENTRY_READ_PROFILE_NAME == 2 && ENTRY_READ_ARGUMENT == 3,
    "Rust CLI binding layout");

int32_t native_engine_option_category(void *, uint32_t);
zapret_engine_route_result zapret_native_cli_route_effect(native_engine_cli *, zapret_engine_route);
zapret_engine_scan_event zapret_native_cli_scan(int, char **, zapret_engine_scan_cursor *,
    native_engine_cli *, const struct option *, size_t, zapret_log_sink);

typedef struct {
    const struct option *options;
    size_t count;
    char *(*environment)(const char *);
    zapret_log_sink stderr_sink;
    bool (*read_blob)(const char *, size_t, size_t);
} zapret_native_argument_ops;

enum { NATIVE_ARGUMENT_DONE, NATIVE_ARGUMENT_HELP, NATIVE_ARGUMENT_EXIT };
typedef struct {
    uint32_t action;
    int exit_code;
} zapret_native_argument_result;

_Static_assert(sizeof(zapret_native_argument_ops) == 5 * sizeof(void *) &&
    offsetof(zapret_native_argument_ops, read_blob) == 4 * sizeof(void *) &&
    sizeof(zapret_native_argument_result) == 8 && ENTRY_PARSE_DONE == 7 &&
    ENTRY_PARSE_HELP == 8 && ENTRY_LOAD_BLOB == 9, "Rust main argument loop ABI");

zapret_native_argument_result zapret_native_cli_run(int, char **, native_engine_cli *,
    const zapret_native_argument_ops *);
