/* MIT. Local bootstrap callbacks linked from Rust. */
#pragma once
#include "windows_startup_params_abi.h"

bool native_boot_pid(void);
bool native_boot_selftest(void);
uint32_t native_boot_error(void);
void native_boot_report(uint32_t event, uint32_t error);
