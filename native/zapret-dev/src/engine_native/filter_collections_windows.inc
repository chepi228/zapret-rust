/* MIT. Preserve packet-filter list declarations and the shared C allocator. */
bool zapret_filter_collection_add(uint32_t, void *, const void *, const zapret_collection_allocator *);
bool zapret_filter_collection_copy(uint32_t, void *, const void *, const zapret_collection_allocator *);
void zapret_filter_collection_destroy(uint32_t, void *, const zapret_collection_allocator *);
bool zapret_filter_collection_matches(uint32_t, const void *, uint16_t, uint8_t);
bool zapret_filter_collection_deny_empty(uint32_t, void *, const zapret_collection_allocator *);
_Static_assert(sizeof(struct port_filter_item) == 24 && offsetof(struct port_filter_item, next) == 8, "Rust port filter links");
_Static_assert(sizeof(struct icmp_filter_item) == 24 && offsetof(struct icmp_filter_item, next) == 8, "Rust ICMP filter links");
_Static_assert(sizeof(struct ipp_filter_item) == 24 && offsetof(struct ipp_filter_item, next) == 8, "Rust IP filter links");
bool port_filter_add(struct port_filters_head *head, const port_filter *filter)
{ return zapret_filter_collection_add(0, head, filter, &native_collection_allocator); }
bool port_filters_copy(struct port_filters_head *to, const struct port_filters_head *from)
{ return zapret_filter_collection_copy(0, to, from, &native_collection_allocator); }
void port_filters_destroy(struct port_filters_head *head)
{ zapret_filter_collection_destroy(0, head, &native_collection_allocator); }
bool port_filters_match(const struct port_filters_head *head, uint16_t port)
{ return zapret_filter_collection_matches(0, head, port, 0); }
bool port_filters_deny_if_empty(struct port_filters_head *head)
{ return zapret_filter_collection_deny_empty(0, head, &native_collection_allocator); }
bool icmp_filter_add(struct icmp_filters_head *head, const icmp_filter *filter)
{ return zapret_filter_collection_add(1, head, filter, &native_collection_allocator); }
bool icmp_filters_copy(struct icmp_filters_head *to, const struct icmp_filters_head *from)
{ return zapret_filter_collection_copy(1, to, from, &native_collection_allocator); }
void icmp_filters_destroy(struct icmp_filters_head *head)
{ zapret_filter_collection_destroy(1, head, &native_collection_allocator); }
bool icmp_filters_match(const struct icmp_filters_head *head, uint8_t type, uint8_t code)
{ return zapret_filter_collection_matches(1, head, type, code); }
bool icmp_filters_deny_if_empty(struct icmp_filters_head *head)
{ return zapret_filter_collection_deny_empty(1, head, &native_collection_allocator); }
bool ipp_filter_add(struct ipp_filters_head *head, const ipp_filter *filter)
{ return zapret_filter_collection_add(2, head, filter, &native_collection_allocator); }
bool ipp_filters_copy(struct ipp_filters_head *to, const struct ipp_filters_head *from)
{ return zapret_filter_collection_copy(2, to, from, &native_collection_allocator); }
void ipp_filters_destroy(struct ipp_filters_head *head)
{ zapret_filter_collection_destroy(2, head, &native_collection_allocator); }
bool ipp_filters_match(const struct ipp_filters_head *head, uint8_t protocol)
{ return zapret_filter_collection_matches(2, head, protocol, 0); }
bool ipp_filters_deny_if_empty(struct ipp_filters_head *head)
{ return zapret_filter_collection_deny_empty(2, head, &native_collection_allocator); }
