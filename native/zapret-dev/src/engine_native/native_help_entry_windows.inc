/* MIT. Bind native output and execute the process exit after Rust returns. */
#include "runtime_log_windows.h"

typedef struct { const char *(*payload)(uint32_t), *(*protocol)(uint32_t); } zapret_help_names;
int zapret_native_help(const zapret_help_names *, zapret_log_sink);
_Static_assert(sizeof(zapret_help_names) == 16 && L7P_LAST == 31 && L7_LAST == 16, "Rust help entry ABI");

#ifndef ZAPRET_HELP_NAMES
#define ZAPRET_HELP_NAMES NULL
#endif
static void exithelp(void)
{
    close_std_and_exit(zapret_native_help(ZAPRET_HELP_NAMES, printf));
}
#undef ZAPRET_HELP_NAMES
