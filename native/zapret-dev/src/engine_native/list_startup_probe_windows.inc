/* Observe errno first. The name stays borrowed and is read again for the log. */
#include "list_startup_abi.h"
#include "runtime_log_windows.h"
void zapret_list_startup_report(uint32_t, const struct zapret_list_file *, int (*)(const char *), zapret_log_sink);
static bool list_startup_open(const char *filename) { return file_open_test(filename, O_RDONLY); }
static void list_startup_open_error(uint32_t kind, const struct zapret_list_file *file)
{
    zapret_list_startup_report(kind, file, DLOG_PERROR, DLOG_ERR);
}
static bool test_list_files(void)
{
    return zapret_list_startup_probe(&params.hostlists, &params.ipsets,
        list_startup_open, list_startup_open_error);
}
