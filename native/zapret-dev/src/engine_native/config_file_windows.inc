/* MIT. Process exit happens after the Rust frame has returned. */
#include "runtime_log_windows.h"
_Static_assert(MAX_CONFIG_FILE_SIZE == 16384, "Rust config input limit");
bool zapret_native_config_read(const char *, wordexp_t *, const void *, void (*)(DWORD), zapret_log_sink);
void config_from_file(const char *filename)
{
    if (!zapret_native_config_read(filename, &params.wexp, NULL, wf_error, DLOG_ERR))
        exit_clean(1);
}
