/* MIT. Built against the pinned original cache records and uthash layouts. */
void *reference_fail_create(void) { return calloc(1, sizeof(hostfail_pool *)); }
void *reference_fail_add(void *root, const char *name, int timeout)
{ return HostFailPoolAdd(root, name, timeout); }
void *reference_fail_find(void *root, const char *name)
{ return HostFailPoolFind(*(hostfail_pool **)root, name); }
void reference_fail_read(void *value, cache_fail_view *view)
{
    const hostfail_pool *entry = value;
    view->name = entry->str; view->counter = entry->counter; view->expires = entry->expire;
}
void reference_fail_increment(void *value) { ++((hostfail_pool *)value)->counter; }
void reference_fail_set_counter(void *value, int counter) { ((hostfail_pool *)value)->counter = counter; }
void reference_fail_delete(void *root, void *entry) { HostFailPoolDel(root, entry); }
void reference_fail_purge(void *root, time_t *previous, bool limited)
{
    if (limited) HostFailPoolPurgeRateLimited(root, previous);
    else HostFailPoolPurge(root);
}
void reference_fail_destroy(void *root) { HostFailPoolDestroy(root); }
void reference_fail_dump(void *root) { HostFailPoolDump(*(hostfail_pool **)root); }
void *reference_fail_after(void *root, size_t *cursor)
{
    hostfail_pool *entry = *(hostfail_pool **)root;
    size_t index = 0;
    while (entry && index++ < *cursor) entry = entry->hh.next;
    if (entry) ++*cursor;
    return entry;
}
void *reference_ip_create(void) { return calloc(1, sizeof(ip_cache)); }
ip_cache_item *reference_ip_touch(void *root, const struct in_addr *a4, const struct in6_addr *a6, const char *iface)
{ return ipcacheTouch(root, a4, a6, iface); }
ip_cache_item *reference_ip_find(void *root, const struct in_addr *a4, const struct in6_addr *a6, const char *iface)
{ return ipcacheFind(root, a4, a6, iface); }
void reference_ip_purge(void *root, time_t lifetime) { ipcachePurgeRateLimited(root, lifetime); }
void reference_ip_destroy(void *root) { ipcacheDestroy(root); }
void reference_ip_dump(void *root) { ipcachePrint(root); }
ip_cache_item *reference_ip_after(void *root, bool ipv6, size_t *cursor, unsigned char *address, unsigned char *iface)
{
    size_t index = 0;
    memset(address, 0, 16);
    if (ipv6) {
        ip_cache6 *entry = ((ip_cache *)root)->ipcache6;
        while (entry && index++ < *cursor) entry = entry->hh.next;
        if (!entry) return NULL;
        ++*cursor;
        memcpy(address, &entry->key.addr, 16); memcpy(iface, entry->key.iface, IFNAMSIZ);
        return &entry->data;
    } else {
        ip_cache4 *entry = ((ip_cache *)root)->ipcache4;
        while (entry && index++ < *cursor) entry = entry->hh.next;
        if (!entry) return NULL;
        ++*cursor;
        memcpy(address, &entry->key.addr, 4); memcpy(iface, entry->key.iface, IFNAMSIZ);
        return &entry->data;
    }
}
