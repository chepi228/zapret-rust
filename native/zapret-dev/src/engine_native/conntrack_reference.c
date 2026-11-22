/* MIT. Compiled with the pinned original header, before the native patch. */
void *reference_create(time_t interval, uint32_t syn, uint32_t est, uint32_t fin, uint32_t udp)
{
    t_conntrack *table = calloc(1, sizeof(*table));
    if (!table) abort();
    ConntrackPoolInit(table, interval, syn, est, fin, udp);
    return table;
}
void reference_destroy(void *table) { ConntrackPoolDestroy(table); }
bool reference_feed(void *table, const struct dissect *packet, t_ctrack **track, bool *reverse)
{ return ConntrackPoolFeed(table, packet, track, reverse); }
bool reference_search(void *table, const struct dissect *packet, t_ctrack **track, bool *reverse)
{ return ConntrackPoolDoubleSearch(table, packet, track, reverse); }
bool reference_drop(void *table, const struct dissect *packet) { return ConntrackPoolDrop(table, packet); }
void reference_purge(void *table) { ConntrackPoolPurge(table); }
t_ctrack *reference_after(void *table, size_t *cursor, t_conn *key)
{
    t_conntrack_pool *entry = ((t_conntrack *)table)->pool;
    size_t index = 0;
    while (entry && index++ < *cursor) entry = entry->hh.next;
    if (!entry) return NULL;
    ++*cursor;
    *key = entry->conn;
    return &entry->track;
}
time_t reference_last_purge(void *table) { return ((t_conntrack *)table)->t_last_purge; }
