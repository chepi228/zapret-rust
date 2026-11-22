/* MIT. Bind the native startup checks and log sinks. */
#include "runtime_log_windows.h"
#include "engine_profile_exports_abi.h"

typedef struct {
    void *profiles, *templates;
    const char *debug_file, *auto_log;
    uint32_t profile_count, template_count;
    const uint32_t *log_target;
    const bool *writable, *server;
} zapret_startup_validation_target;
typedef struct {
    bool (*add_default)(struct desync_profile_list_head *), (*writable)(void),
        (*label)(const char *), (*defaults)(struct desync_profile *);
    void (*debug)(const struct desync_profile *, const char *);
    bool (*checks[4])(void);
    void (*summary)(void), (*report)(uint32_t, uint32_t, const char *),
        (*destroy_templates)(struct desync_profile_list_head *);
} zapret_startup_validation_ops;
typedef struct {
    zapret_log_sink debug, console, error;
    char *(*environment)(const char *);
} zapret_startup_validation_logs;
_Static_assert(sizeof(zapret_startup_validation_target) == 7 * sizeof(void *) + 8 &&
    sizeof(zapret_startup_validation_ops) == 12 * sizeof(void *) &&
    sizeof(zapret_startup_validation_logs) == 4 * sizeof(void *) &&
    offsetof(struct zapret_list_file, filename) == 0 && sizeof(enum log_target) == sizeof(uint32_t) &&
    LOG_TARGET_FILE == 1, "Rust startup validation ABI");
uint32_t zapret_profile_startup_validate(const zapret_startup_validation_target *, const zapret_startup_validation_ops *);
void zapret_profile_startup_report(uint32_t, uint32_t, const char *, const zapret_startup_validation_logs *);
bool zapret_profile_startup_status(uint32_t, zapret_log_sink);
void zapret_profile_startup_summary(void (*)(void), void (*)(void), void (*)(void), zapret_log_sink);
bool native_profile_add_default(struct desync_profile_list_head *);

static void native_startup_validation_summary(void)
{
    zapret_profile_startup_summary(HostlistsDebug, IpsetsDebug, BlobDebug, DLOG);
}

static void native_startup_validation_report(uint32_t event, uint32_t count, const char *path)
{
    static const zapret_startup_validation_logs logs = {DLOG, DLOG_CONDUP, DLOG_ERR, getenv};
    zapret_profile_startup_report(event, count, path, &logs);
}

static const zapret_startup_validation_ops startup_validation_ops = {
    native_profile_add_default, make_writable_dir, ensure_file_access, filter_defaults,
    LuaDesyncDebug,
    {test_list_files, lua_test_init_script_files, LoadAllHostLists, LoadAllIpsets},
    native_startup_validation_summary, native_startup_validation_report, dp_list_destroy,
};

static bool native_startup_validate(unsigned profile_count, unsigned template_count)
{
    const zapret_startup_validation_target target = {
        &params.desync_profiles, &params.desync_templates, params.debug_logfile, params.hostlist_auto_debuglog,
        profile_count, template_count, (const uint32_t *)&params.debug_target, &params.writable_dir_enable, &params.server,
    };
    uint32_t status = zapret_profile_startup_validate(&target, &startup_validation_ops);
    return zapret_profile_startup_status(status, DLOG_ERR);
}
