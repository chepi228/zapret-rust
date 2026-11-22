/* MIT. Command-line termination and profile diagnostics. */
#pragma once
#include <stdint.h>

_Noreturn void exit_clean(int code);
_Noreturn void exithelp_clean(void);
void native_profile_exit(uint32_t status, const char *name);
