/* MIT. Shutdown Lua on a C frame, then let Rust order the remaining owned cleanup. */
typedef struct{void *context,*conntrack,*profiles,*templates,*hosts,*ips,*cache,*blobs,*scripts,*timers,*ssid,*networks,*parts,**capture;}zapret_lifecycle_state;
typedef void (*zapret_drop_slot)(void *);
typedef struct {
    zapret_drop_slot arguments, conntrack, profiles, registry, cache, blobs, strings, timers, filters, release;
} zapret_lifecycle_drop_ops;
bool zapret_lifecycle_cleanup(const zapret_lifecycle_state *,const zapret_lifecycle_drop_ops *);
_Static_assert(sizeof(zapret_lifecycle_state) == 14 * sizeof(void *) &&
    sizeof(zapret_lifecycle_drop_ops) == 10 * sizeof(void *), "Rust cleanup state ABI");
#define ZAPRET_DROP_BINDING(name, operation) \
    static void native_drop_ ## name(void *slot) { operation(slot); }
ZAPRET_DROP_BINDING(arguments, cleanup_args)
ZAPRET_DROP_BINDING(conntrack, ConntrackPoolDestroy)
ZAPRET_DROP_BINDING(profiles, dp_list_destroy)
ZAPRET_DROP_BINDING(registry, zapret_list_files_destroy)
ZAPRET_DROP_BINDING(cache, ipcacheDestroy)
ZAPRET_DROP_BINDING(blobs, blob_collection_destroy)
ZAPRET_DROP_BINDING(strings, strlist_destroy)
ZAPRET_DROP_BINDING(timers, TimerPoolDestroy)
ZAPRET_DROP_BINDING(filters, cleanup_windivert_portfilters)
#undef ZAPRET_DROP_BINDING

static const zapret_lifecycle_drop_ops native_cleanup_ops = {
    .arguments = native_drop_arguments,
    .conntrack = native_drop_conntrack,
    .profiles = native_drop_profiles,
    .registry = native_drop_registry,
    .cache = native_drop_cache,
    .blobs = native_drop_blobs,
    .strings = native_drop_strings,
    .timers = native_drop_timers,
    .filters = native_drop_filters,
    .release = free,
};
void cleanup_params(struct params_s *params)
{
    lua_shutdown();
    const zapret_lifecycle_state state={params,&params->conntrack,&params->desync_profiles,&params->desync_templates,&params->hostlists,&params->ipsets,&params->ipcache,&params->blobs,&params->lua_init_scripts,&params->timers,&params->ssid_filter,&params->nlm_filter,&params->wf_raw_part,(void **)&params->windivert_filter};
    if(!zapret_lifecycle_cleanup(&state,&native_cleanup_ops))abort();
}
