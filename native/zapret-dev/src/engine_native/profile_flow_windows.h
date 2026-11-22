/* MIT. Windows option dispatch shares the engine's current profile and lists. */
#pragma once
typedef struct {
    struct desync_profile_list_head *profiles, *templates;
    struct desync_profile_list *current;
    unsigned count, template_count;
    bool skip, template;
} native_profile_flow;

_Static_assert(sizeof(native_profile_flow) == (sizeof(void *) == 4 ? 24 : 40) &&
    offsetof(native_profile_flow, skip) == 3 * sizeof(void *) + 8,
    "Rust profile flow layout");

uint32_t native_profile_next(native_profile_flow *, const char *);
uint32_t native_profile_finish(native_profile_flow *);
uint32_t native_profile_label(struct desync_profile *, bool, const char *);
uint32_t native_profile_import(const native_profile_flow *, const char *);
