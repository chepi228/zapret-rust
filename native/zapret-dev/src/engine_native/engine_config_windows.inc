/* MIT. SDK/engine offsets are verified in C; Rust owns default values. */
typedef struct { size_t size; size_t offsets[10]; } zapret_engine_config_layout;
bool zapret_engine_config_init(void *, size_t, const zapret_engine_config_layout *);
typedef struct { void *(*allocate)(size_t); void (*release)(void *); } zapret_engine_config_allocator;
bool zapret_engine_filter_buffers(char ***const, size_t, const zapret_engine_config_allocator *);
bool zapret_engine_filter_clear(char ***const, size_t, const zapret_engine_config_allocator *);
static const zapret_engine_config_allocator native_engine_config_allocator = {malloc, free};
static const zapret_engine_config_layout native_engine_config_layout = {
    sizeof(struct params_s), {
        offsetof(struct params_s, intercept), offsetof(struct params_s, desync_fwmark),
        offsetof(struct params_s, ctrack_t_syn), offsetof(struct params_s, ctrack_t_est),
        offsetof(struct params_s, ctrack_t_fin), offsetof(struct params_s, ctrack_t_udp),
        offsetof(struct params_s, ipcache_lifetime), offsetof(struct params_s, lua_gc),
        offsetof(struct params_s, reasm_payload_disable), offsetof(struct params_s, payload_disable)
    }
};
_Static_assert(DPI_DESYNC_FWMARK_DEFAULT == 0, "Rust Windows default mark");
_Static_assert(CTRACK_T_SYN == 60 && CTRACK_T_EST == 300 && CTRACK_T_FIN == 60 && CTRACK_T_UDP == 60, "Rust conntrack defaults");
_Static_assert(IPCACHE_LIFETIME == 7200 && LUA_GC_INTERVAL == 60 && L7P_NONE == 31, "Rust engine defaults");
#define NATIVE_FILTER_SLOTS(p) { \
    &(p)->wf_pf_tcp_src_in, &(p)->wf_pf_tcp_dst_in, &(p)->wf_pf_udp_src_in, &(p)->wf_pf_udp_dst_in, \
    &(p)->wf_pf_tcp_src_out, &(p)->wf_pf_tcp_dst_out, &(p)->wf_pf_udp_src_out, &(p)->wf_pf_udp_dst_out, \
    &(p)->wf_icf_in, &(p)->wf_icf_out, &(p)->wf_ipf_in, &(p)->wf_ipf_out, &(p)->wf_raw_filter }
void cleanup_windivert_portfilters(struct params_s *params)
{
    char **slots[] = NATIVE_FILTER_SLOTS(params);
    zapret_engine_filter_clear(slots, sizeof(slots) / sizeof(*slots), &native_engine_config_allocator);
    strlist_destroy(&params->wf_raw_part);
}
bool alloc_windivert_portfilters(struct params_s *params)
{
    char **slots[] = NATIVE_FILTER_SLOTS(params);
    return zapret_engine_filter_buffers(slots, sizeof(slots) / sizeof(*slots), &native_engine_config_allocator);
}
void init_params(struct params_s *params)
{
    if (!zapret_engine_config_init(params, sizeof(*params), &native_engine_config_layout)) abort();
}
