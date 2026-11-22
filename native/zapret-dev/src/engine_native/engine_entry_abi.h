/* MIT. Plain main-routing and final-phase state; no VM operation runs in Rust. */
#pragma once
#include <getopt.h>
#include "runtime_log_windows.h"

typedef struct {
    struct zapret_list_file *anonymous[4];
    uint64_t payload;
    struct packet_range incoming, outgoing;
    uint32_t index, sub_index;
    bool dry, duplicate, ipv4, ipv6, lan, loopback, empty;
    char save[256];
} zapret_engine_main_options;
void zapret_engine_main_defaults(zapret_engine_main_options *);
_Static_assert(sizeof(zapret_engine_main_options) == 320 + 4 * sizeof(void *) &&
    _Alignof(zapret_engine_main_options) == 8 &&
    offsetof(zapret_engine_main_options, incoming) == 4 * sizeof(void *) + 8 &&
    offsetof(zapret_engine_main_options, save) == 4 * sizeof(void *) + 63,
    "Rust main option storage ABI");

typedef struct{uint32_t action,status;}zapret_engine_route;
typedef int32_t(*zapret_engine_route_callback)(void *,uint32_t);
zapret_engine_route zapret_engine_option_route(void *,bool,zapret_engine_route_callback);
enum {ENTRY_RESIDUAL,ENTRY_HANDLED,ENTRY_EXIT_SUCCESS,ENTRY_EXIT_ERROR,ENTRY_NUMERIC_ERROR,
    ENTRY_CONTROL_ERROR,ENTRY_INVALID,ENTRY_PARSE_DONE,ENTRY_PARSE_HELP,ENTRY_LOAD_BLOB};
enum {ENTRY_READ_OPTION_NAME=1,ENTRY_READ_PROFILE_NAME,ENTRY_READ_ARGUMENT};
typedef struct { int32_t exit_code; bool terminate, handled; } zapret_engine_route_result;
zapret_engine_route_result zapret_engine_route_effect(zapret_engine_route, int32_t, const void *,
    const char *(*)(const void *, uint32_t), zapret_log_sink);
typedef struct {
    const struct option *options;
    size_t count;
    void *context;
    zapret_engine_route_callback category;
    char **argument;
    int *index;
    zapret_log_sink stderr_sink;
    const bool *dry;
} zapret_engine_scan_ops;
typedef struct { size_t next; bool stop_at_operand; } zapret_engine_scan_cursor;
zapret_engine_scan_cursor zapret_engine_scan_begin(char *(*)(const char *));
typedef struct {
    zapret_engine_route route;
    size_t blob_maximum, blob_reserve;
} zapret_engine_scan_event;
zapret_engine_scan_event zapret_engine_scan_arguments(int, char **, zapret_engine_scan_cursor *,
    const zapret_engine_scan_ops *);
_Static_assert(sizeof(zapret_engine_scan_ops) == 8 * sizeof(void *) &&
    sizeof(zapret_engine_scan_event) == 8 + 2 * sizeof(void *) &&
    sizeof(zapret_engine_scan_cursor) == 2 * sizeof(void *) && sizeof(zapret_engine_route_result) == 8 &&
    offsetof(zapret_engine_scan_ops, argument) == 4 * sizeof(void *) &&
    offsetof(zapret_engine_scan_ops, dry) == 7 * sizeof(void *),
    "Rust main argument scan ABI");
typedef struct{uint32_t phase;int32_t result;}zapret_engine_finish;
typedef struct{uint32_t status;int32_t result;}zapret_engine_finish_feedback;
uint32_t zapret_engine_finish_step(zapret_engine_finish *,const zapret_engine_finish_feedback *);
enum{FINISH_PROFILE=1,FINISH_ARGUMENTS,FINISH_VALIDATE,FINISH_CAPTURE,FINISH_LIFECYCLE,FINISH_RUN,
    FINISH_CLEANUP,FINISH_MUTEX,FINISH_STDIO,FINISH_RETURN,FINISH_EXIT_SUCCESS,FINISH_EXIT_ERROR,FINISH_PROFILE_ERROR,FINISH_INVALID};
_Static_assert(sizeof(zapret_engine_route)==8 && sizeof(zapret_engine_finish)==8 && sizeof(zapret_engine_finish_feedback)==8,
    "Rust main-routing/finish ABI");
