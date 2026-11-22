/* MIT. Keep terminating cleanup on the C side of profile diagnostics. */
#include "profile_flow_windows.h"
#include "runtime_log_windows.h"

bool zapret_profile_report_status(uint32_t, const char *, zapret_log_sink);

static void native_profile_exit(uint32_t status, const char *name)
{
    if (zapret_profile_report_status(status, name, DLOG_ERR)) exit_clean(1);
}
