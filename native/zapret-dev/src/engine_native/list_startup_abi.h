/* The probe and diagnostic callbacks never enter Lua. */
#pragma once
typedef bool (*list_startup_probe)(const char *);
typedef void (*list_startup_probe_error)(uint32_t, const struct zapret_list_file *);
typedef void (*list_startup_register_error)(uint32_t, const char *);
typedef struct zapret_list_file *(*list_startup_register)(struct desync_profile *, uint32_t, const char *);
bool zapret_list_startup_probe(struct zapret_list_files *const *, struct zapret_list_files *const *,
    list_startup_probe, list_startup_probe_error);
struct zapret_list_file *zapret_list_register_checked(struct desync_profile *, bool, uint32_t,
    const char *, list_startup_probe, list_startup_register_error, list_startup_register);
bool zapret_list_host_nonempty(hostlist_pool **, bool (*)(hostlist_pool **, const char *, size_t, uint32_t));
void zapret_profile_ensure_automatic_hosts(struct desync_profile_list *,
    void (*)(struct zapret_list_file *));
const char *zapret_list_startup_error(uint32_t);
