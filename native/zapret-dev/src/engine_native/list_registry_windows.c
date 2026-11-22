/* MIT. Resolve paths and report filesystem errors through the engine. */
#include "runtime_log_windows.h"

bool zapret_list_stamp_checked(const char *, file_mod_sig *, const char *,
    bool (*)(const char *, file_mod_sig *), int (*)(const char *), zapret_log_sink);
bool zapret_list_read_checked(const char *, const char *, int,
    bool (*)(const char *, int), int (*)(const char *), zapret_log_sink);

struct zapret_list_file *zapret_list_register_path(struct zapret_list_files **files,
    struct zapret_list_collection **collection, const char *filename)
{
    char canonical[PATH_MAX];
    if (filename && !realpath(filename, canonical)) return NULL;
    return zapret_list_register(files, collection, filename ? canonical : NULL);
}

bool zapret_list_read_stamp(const char *filename, file_mod_sig *stamp, const char *kind)
{
    return zapret_list_stamp_checked(filename, stamp, kind, file_mod_signature, DLOG_PERROR, DLOG_ERR);
}

bool zapret_list_probe_read(const char *filename, const char *kind)
{
    return zapret_list_read_checked(filename, kind, O_RDONLY, file_open_test, DLOG_PERROR, DLOG_ERR);
}
