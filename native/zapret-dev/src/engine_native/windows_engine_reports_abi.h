/* MIT. Live engine report callbacks supplied by Rust. */
#pragma once
#include "windows_startup_params_abi.h"

struct zapret_autolist_context;

void native_capture_prepare_report(uint32_t, size_t, const char *);
void native_capture_prepare_status(uint32_t, uint32_t, const char *);
void loop_report(uint32_t, uint32_t, size_t, size_t);
void packet_cache_report(void *, uint32_t, const ip_cache_item *);
void reassembly_report(uint32_t, size_t, size_t, size_t);
void autolist_report(uint32_t, const struct zapret_autolist_context *,
    uint64_t, uint64_t, uint64_t, uint64_t);
