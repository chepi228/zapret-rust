/* Bind native list diagnostics to the common Rust loader. */
#include "list_windows.h"
#include "runtime_log_windows.h"

typedef struct {
    int (*load)(const char *, int, zapret_list_insert, void *, zapret_list_info *);
    zapret_log_sink message, error;
    int (*perror)(const char *);
    void (*set_error)(DWORD);
} zapret_list_append_ops;
_Static_assert(sizeof(zapret_list_append_ops) == 40, "Rust list append ABI");
bool zapret_list_append_file(const char *, int, zapret_list_insert, void *, const zapret_list_append_ops *);

static bool append_list_file(void *target, const char *filename, int hosts, zapret_list_insert insert)
{
    static const zapret_list_append_ops ops = {zapret_list_load, DLOG_CONDUP, DLOG_ERR, DLOG_PERROR, wf_error};
    return zapret_list_append_file(filename, hosts, insert, target, &ops);
}
