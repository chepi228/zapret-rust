/* MIT. Rust entry points for local CLI profile controls, defaults and lists. */
#pragma once
#include <stddef.h>
#include "params.h"
#include "profile_flow_windows.h"

_Static_assert(offsetof(native_profile_flow, current) == 2 * sizeof(void *) &&
    offsetof(native_profile_flow, template) == 3 * sizeof(void *) + 9 &&
    offsetof(struct desync_profile_list, dp) == 0, "Rust CLI profile storage");
_Static_assert(sizeof(struct packet_range) == 20 && _Alignof(struct packet_range) == 4 &&
    offsetof(struct packet_range, to) == 8 && offsetof(struct packet_range, upper_cutoff) == 16 &&
    offsetof(struct packet_pos, pos) == 4, "Rust CLI range storage");

#define FILTER_LIST_LAYOUT(head, item, links) \
    _Static_assert(sizeof(struct head) == sizeof(void *) && offsetof(struct head, lh_first) == 0 && \
        offsetof(struct item, next.le_next) == (links) && \
        offsetof(struct item, next.le_prev) == (links) + sizeof(void *), \
        "Rust filter list storage")
FILTER_LIST_LAYOUT(port_filters_head, port_filter_item, 8);
FILTER_LIST_LAYOUT(icmp_filters_head, icmp_filter_item, sizeof(void *));
FILTER_LIST_LAYOUT(ipp_filters_head, ipp_filter_item, sizeof(void *));
#undef FILTER_LIST_LAYOUT

int engine_control_option(int index, const char *text, native_profile_flow *flow,
    struct desync_profile_list **entry, struct desync_profile **profile,
    struct zapret_list_file **host, struct zapret_list_file **host_exclude,
    struct zapret_list_file **ip, struct zapret_list_file **ip_exclude,
    uint64_t *payload, struct packet_range *incoming, struct packet_range *outgoing, bool *dry);
bool filter_defaults(struct desync_profile *profile);
bool parse_pf_list(const char *text, struct port_filters_head *head);
bool parse_icf_list(const char *text, struct icmp_filters_head *head);
bool parse_ipp_list(const char *text, struct ipp_filters_head *head);
