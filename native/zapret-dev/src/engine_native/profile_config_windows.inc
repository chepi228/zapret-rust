/* MIT. Native collection and allocator operations for Rust profile management. */
#include "engine_profile_exports_abi.h"
#include "runtime_log_windows.h"

typedef struct {
    void *(*allocate)(size_t);
    void (*release)(void *);
    char *(*duplicate)(const char *);
    bool (*copy)(uint32_t, void *, const void *);
    void (*destroy)(uint32_t, void *);
    void (*failures)(void *);
    zapret_log_sink error;
} zapret_profile_config_ops;
_Static_assert(sizeof(zapret_profile_config_ops) == 7 * sizeof(void *) &&
    offsetof(zapret_profile_config_ops, error) == 6 * sizeof(void *),
    "Rust profile callbacks ABI");

static void *profile_config_allocate(size_t size) { return calloc(1, size); }
static bool profile_config_copy(uint32_t kind, void *to, const void *from)
{
    switch (kind) {
    case 0: case 1: case 2: case 3:
        return zapret_list_collection_copy(to, *(struct zapret_list_collection *const *)from);
    case 4: case 5: return port_filters_copy(to, from);
    case 6: return icmp_filters_copy(to, from);
    case 7: return ipp_filters_copy(to, from);
    default: return funclist_copy(to, from);
    }
}
static void profile_config_destroy(uint32_t kind, void *head)
{
    switch (kind) {
    case 0: case 1: case 2: case 3: zapret_list_collection_destroy(head); break;
    case 4: case 5: port_filters_destroy(head); break;
    case 6: icmp_filters_destroy(head); break;
    case 7: ipp_filters_destroy(head); break;
    default: funclist_destroy(head); break;
    }
}
static void profile_config_failures(void *head) { HostFailPoolDestroy(head); }
static const zapret_profile_config_ops profile_config_ops = {
    profile_config_allocate, free, strdup, profile_config_copy, profile_config_destroy,
    profile_config_failures, DLOG_ERR,
};

void zapret_profile_init_dynamic(struct desync_profile *);
void zapret_profile_init(struct desync_profile *);
void zapret_profile_clear(struct desync_profile *, const zapret_profile_config_ops *);
void zapret_profile_entry_destroy(struct desync_profile_list *, const zapret_profile_config_ops *);
void zapret_profile_list_destroy(struct desync_profile_list_head *, const zapret_profile_config_ops *);
struct desync_profile_list *zapret_profile_add(struct desync_profile_list_head *, const zapret_profile_config_ops *);
void zapret_profile_move(struct desync_profile_list_head *, struct desync_profile_list *);
struct desync_profile_list *zapret_profile_search(struct desync_profile_list *, const char *);
bool zapret_profile_has_automatic(const struct desync_profile_list *);
bool zapret_profile_import(struct desync_profile *, const struct desync_profile *, const zapret_profile_config_ops *);

void dp_init_dynamic(struct desync_profile *dp) { zapret_profile_init_dynamic(dp); }
void dp_init(struct desync_profile *dp) { zapret_profile_init(dp); }
void dp_clear(struct desync_profile *dp) { zapret_profile_clear(dp, &profile_config_ops); }
void dp_entry_destroy(struct desync_profile_list *entry) { zapret_profile_entry_destroy(entry, &profile_config_ops); }
void dp_list_destroy(struct desync_profile_list_head *head) { zapret_profile_list_destroy(head, &profile_config_ops); }
struct desync_profile_list *dp_list_add(struct desync_profile_list_head *head)
{ return zapret_profile_add(head, &profile_config_ops); }
void dp_list_move(struct desync_profile_list_head *head, struct desync_profile_list *entry)
{ zapret_profile_move(head, entry); }
struct desync_profile_list *dp_list_search_name(struct desync_profile_list_head *head, const char *name)
{ return zapret_profile_search(LIST_FIRST(head), name); }
bool dp_list_have_autohostlist(struct desync_profile_list_head *head)
{ return zapret_profile_has_automatic(LIST_FIRST(head)); }
bool dp_copy(struct desync_profile *to, const struct desync_profile *from)
{ return zapret_profile_import(to, from, &profile_config_ops); }

uint32_t zapret_profile_next(native_profile_flow *, const char *, const zapret_profile_config_ops *);
uint32_t zapret_profile_finish(native_profile_flow *, const zapret_profile_config_ops *);
uint32_t zapret_profile_label(struct desync_profile *, bool, const char *, const zapret_profile_config_ops *);
uint32_t zapret_profile_import_named(const native_profile_flow *, const char *, const zapret_profile_config_ops *);

uint32_t native_profile_next(native_profile_flow *flow, const char *name)
{ return zapret_profile_next(flow, name, &profile_config_ops); }
uint32_t native_profile_finish(native_profile_flow *flow)
{ return zapret_profile_finish(flow, &profile_config_ops); }
uint32_t native_profile_label(struct desync_profile *profile, bool cookie, const char *name)
{ return zapret_profile_label(profile, cookie, name, &profile_config_ops); }
uint32_t native_profile_import(const native_profile_flow *flow, const char *name)
{ return zapret_profile_import_named(flow, name, &profile_config_ops); }

bool zapret_profile_add_default(struct desync_profile_list_head *, const zapret_profile_config_ops *);
bool native_profile_add_default(struct desync_profile_list_head *head)
{ return zapret_profile_add_default(head, &profile_config_ops); }
