/* C bindings for the Rust probe, selection and registration sequence. */
#include "list_startup_abi.h"

#ifndef ZAPRET_LIST_STARTUP_CALLBACKS
#define ZAPRET_LIST_STARTUP_CALLBACKS
static bool list_startup_size(const char *filename) { return file_size(filename, NULL); }
static void list_startup_size_error(uint32_t kind, const char *filename)
{
    DLOG_ERR(zapret_list_startup_error(kind), filename);
}
static struct zapret_list_file *list_startup_register_slot(struct desync_profile *profile,
    uint32_t slot, const char *filename)
{
    switch (slot) {
    case 0: return zapret_list_register_path(&params.hostlists, &profile->hl_collection, filename);
    case 1: return zapret_list_register_path(&params.hostlists, &profile->hl_collection_exclude, filename);
    case 2: return zapret_list_register_path(&params.ipsets, &profile->ips_collection, filename);
    case 3: return zapret_list_register_path(&params.ipsets, &profile->ips_collection_exclude, filename);
    default: return NULL;
    }
}
#endif

#if ZAPRET_LIST_STARTUP_HOSTS
struct zapret_list_file *RegisterHostlist(struct desync_profile *profile, bool exclude, const char *filename)
{
    return zapret_list_register_checked(profile, exclude, 0, filename,
        list_startup_size, list_startup_size_error, list_startup_register_slot);
}
#else
struct zapret_list_file *RegisterIpset(struct desync_profile *profile, bool exclude, const char *filename)
{
    return zapret_list_register_checked(profile, exclude, 1, filename,
        list_startup_size, list_startup_size_error, list_startup_register_slot);
}
#endif
