/* MIT. List traversal, filtering and reporting use the native reload and log sinks. */
#pragma once
#include "runtime_log_windows.h"
typedef struct {
    bool (*reload)(struct zapret_list_file *, bool *);
    void (*automatic)(void);
    zapret_log_sink log;
} zapret_host_policy_ops;
typedef struct {
    bool (*reload)(struct zapret_list_file *);
    zapret_log_sink log;
    size_t (*format_address)(const uint8_t *, size_t, char *, size_t);
} zapret_ip_policy_ops;
_Static_assert(sizeof(zapret_host_policy_ops) == 24 && sizeof(zapret_ip_policy_ops) == 24 &&
    INET6_ADDRSTRLEN == 65 && offsetof(struct zapret_list_file, filename) == 0 &&
    offsetof(struct desync_profile, n) == 0 && offsetof(struct desync_profile, name) == 8,
    "Rust list diagnostics ABI");
void zapret_list_report_profile(const struct desync_profile *, bool, zapret_log_sink);
size_t zapret_lua_ntop(const uint8_t *, size_t, char *, size_t);
bool zapret_hostlists_load_all(const struct zapret_list_files *, const zapret_host_policy_ops *);
bool zapret_ipsets_load_all(const struct zapret_list_files *, const zapret_ip_policy_ops *);
bool zapret_hostlists_reload_pair(const struct zapret_list_collection *, const struct zapret_list_collection *, const zapret_host_policy_ops *);
bool zapret_ipsets_reload_pair(const struct zapret_list_collection *, const struct zapret_list_collection *, const zapret_ip_policy_ops *);
bool zapret_hostlists_check(const struct zapret_list_collection *, const struct zapret_list_collection *, const char *, bool, bool *, bool, const zapret_host_policy_ops *);
bool zapret_ipsets_check(const struct zapret_list_collection *, const struct zapret_list_collection *, const void *, const void *, const void *, const void *, const zapret_ip_policy_ops *);
