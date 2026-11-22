/* MIT. Resource-free Rust actions; throwing VM calls run after each step returns. */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "runtime_log_windows.h"
struct dissect;
typedef struct { uint32_t phase; uint8_t verdict; bool preserve; } zapret_desync_flow;
typedef struct { uint8_t verdict; bool ok, functions; uint32_t gate, kind; } zapret_desync_feedback;
typedef struct { uint32_t phase; uint8_t verdict; } zapret_play_finish_flow;
typedef struct { uint8_t verdict; bool found, tcp, incoming; } zapret_play_finish_feedback;
_Static_assert(sizeof(zapret_desync_flow)==8 && sizeof(zapret_desync_feedback)==12 &&
    sizeof(zapret_play_finish_flow)==8 && sizeof(zapret_play_finish_feedback)==4,
    "Rust final desync/play policy ABI");
uint32_t zapret_desync_step(zapret_desync_flow *, const zapret_desync_feedback *);
void zapret_desync_report(const zapret_desync_flow *, bool, uint32_t, const struct dissect *,
    const size_t *, zapret_log_sink, zapret_log_sink);
uint32_t zapret_play_finish_step(zapret_play_finish_flow *, const zapret_play_finish_feedback *);
