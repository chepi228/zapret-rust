/* MIT. Failed filter options release only the entries added by that option. */
bool zapret_parse_port_list(const char *, struct port_filters_head *,
    bool (*)(struct port_filters_head *, const port_filter *));
bool zapret_parse_icmp_list(const char *, struct icmp_filters_head *,
    bool (*)(struct icmp_filters_head *, const icmp_filter *));
bool zapret_parse_ip_list(const char *, struct ipp_filters_head *,
    bool (*)(struct ipp_filters_head *, const ipp_filter *));

// The C pools insert at the head and own their allocation. Roll back to the
// prior head if Rust rejects an item or a pool cannot allocate a new entry.
#define FILTER_LIST_ADAPTER(function, head_type, item_type, parse, add) \
static bool function(const char *opt, struct head_type *head) \
{ \
    struct item_type *previous = LIST_FIRST(head); \
    if (parse(opt, head, add)) return true; \
    struct item_type *entry; \
    while ((entry = LIST_FIRST(head)) != previous) { \
        LIST_REMOVE(entry, next); \
        free(entry); \
    } \
    return false; \
}

FILTER_LIST_ADAPTER(parse_pf_list, port_filters_head, port_filter_item, zapret_parse_port_list, port_filter_add)
FILTER_LIST_ADAPTER(parse_icf_list, icmp_filters_head, icmp_filter_item, zapret_parse_icmp_list, icmp_filter_add)
FILTER_LIST_ADAPTER(parse_ipp_list, ipp_filters_head, ipp_filter_item, zapret_parse_ip_list, ipp_filter_add)
#undef FILTER_LIST_ADAPTER
