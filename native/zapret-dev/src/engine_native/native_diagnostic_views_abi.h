/* MIT. Native sources and output functions borrowed by the Rust presenters. */
#pragma once
#include "runtime_log_windows.h"

typedef struct {
    const bool *debug;
    struct zapret_list_files *const *registry;
    struct desync_profile_list *const *profiles;
    struct desync_profile_list *const *templates;
} zapret_list_debug_sources;

const char *zapret_native_ip_fill(const void *,const void *);
void zapret_native_list_profile_debug(const struct desync_profile *,const char *,bool,zapret_log_sink);
void zapret_native_list_debug(const zapret_list_debug_sources *,bool,zapret_log_sink);
void zapret_native_blob_debug(struct blob_item *const *,zapret_log_sink);
void zapret_native_lua_debug(const struct desync_profile *,const char *,bool,
    const char *(*payload_name)(t_l7payload),zapret_log_sink);

_Static_assert(sizeof(zapret_list_debug_sources)==32&&offsetof(zapret_list_debug_sources,templates)==24,"Rust list diagnostic sources ABI");
_Static_assert(sizeof(struct desync_profile)==184&&offsetof(struct desync_profile,hl_collection)==88&&offsetof(struct desync_profile,hostlist_auto)==104&&offsetof(struct desync_profile,lua_desync)==160&&offsetof(struct desync_profile_list,next.le_next)==184,"Rust diagnostic profile ABI");
_Static_assert(sizeof(struct zapret_list_file)==56&&offsetof(struct zapret_list_file,hostlist)==32&&offsetof(struct zapret_list_file,ipset)==40,"Rust diagnostic file ABI");
_Static_assert(sizeof(struct func_list)==80&&offsetof(struct func_list,args)==56&&offsetof(struct func_list,next.le_next)==64&&sizeof(struct str2_list)==32&&offsetof(struct str2_list,next.le_next)==16&&sizeof(struct blob_item)==56&&offsetof(struct blob_item,next.le_next)==40&&L7P_LAST==31,"Rust diagnostic rule/blob ABI");
