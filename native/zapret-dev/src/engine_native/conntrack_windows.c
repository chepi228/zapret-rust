/* MIT. Lua references and clocks around the Rust conntrack. */
#include "conntrack_windows.h"

static const char *connstate_s[] = { "SYN", "ESTABLISHED", "FIN" };

void ConntrackClearHostname(t_ctrack *track)
{
    free(track->hostname);
    track->hostname = NULL;
    track->hostname_is_ip = false;
}

static void ConntrackClearTrack(t_ctrack *track)
{
    ConntrackClearHostname(track);
    ReasmClear(&track->reasm_client);
    rawpacket_queue_destroy(&track->delayed);
    luaL_unref(params.L, LUA_REGISTRYINDEX, track->lua_state);
    luaL_unref(params.L, LUA_REGISTRYINDEX, track->lua_instance_cutoff);
}

static void ConntrackFreeElem(t_conntrack_pool *entry)
{
    ConntrackClearTrack(&entry->track);
    free(entry);
}

static void ConntrackInitTrack(t_ctrack *track)
{
    memset(track, 0, sizeof(*track));
    track->lua_state = track->lua_instance_cutoff = LUA_NOREF;
    track->l7proto = L7_UNKNOWN;
    track->reasm_client_payload = L7P_UNKNOWN;
    rawpacket_queue_init(&track->delayed, RAW_PACKET_QUEUE_DELAYED_MAX);
    lua_newtable(params.L);
    track->lua_state = luaL_ref(params.L, LUA_REGISTRYINDEX);
    lua_newtable(params.L);
    track->lua_instance_cutoff = luaL_ref(params.L, LUA_REGISTRYINDEX);
}

void ConntrackPoolDestroy(t_conntrack *table)
{
    uint64_t cursor = 0;
    t_conntrack_pool *entry;
    while ((entry = zapret_conntrack_after(table->pool, &cursor))) {
        zapret_conntrack_remove(&table->pool, &entry->conn);
        ConntrackFreeElem(entry);
    }
}

void ConntrackPoolInit(t_conntrack *table, time_t interval, uint32_t syn, uint32_t established,
    uint32_t fin, uint32_t udp)
{
    table->timeout_syn = syn;
    table->timeout_established = established;
    table->timeout_fin = fin;
    table->timeout_udp = udp;
    table->t_purge_interval = interval;
    table->t_last_purge = boottime();
    table->pool = NULL;
}

bool ConntrackExtractConn(t_conn *key, bool reverse, const struct dissect *packet)
{
    return zapret_conntrack_key(key, (const unsigned char *)packet->ip,
        (const unsigned char *)packet->ip6, (const unsigned char *)packet->tcp,
        (const unsigned char *)packet->udp, reverse) != 0;
}

static t_conntrack_pool *ConntrackNew(t_conntrack *table, const t_conn *key)
{
    t_conntrack_pool *entry = malloc(sizeof(*entry));
    if (!entry) return NULL;
    entry->conn = *key;
    if (!zapret_conntrack_insert(&table->pool, key, entry)) {
        free(entry);
        return NULL;
    }
    ConntrackInitTrack(&entry->track);
    return entry;
}

static void ConntrackFeedPacket(t_ctrack *track, bool reverse, const struct dissect *packet)
{
    zapret_conntrack_packet input = {
        .tcp = (const unsigned char *)packet->tcp,
        .tcp_size = packet->len_l4,
        .payload_size = packet->len_payload,
        .ipv6_flow = packet->ip6 ? ntohl(packet->ip6->ip6_ctlun.ip6_un1.ip6_un1_flow) : 0,
        .ipv6 = packet->ip6 != NULL,
    };
    if (zapret_conntrack_update(&track->pos, &input, reverse, 0)) {
        ConntrackClearTrack(track);
        ConntrackInitTrack(track);
        zapret_conntrack_update(&track->pos, &input, reverse, 1);
    }
    clock_gettime(CLOCK_BOOT_OR_UPTIME, &track->pos.t_last);
    if (!track->t_start.tv_sec) track->t_start = track->pos.t_last;
}

bool ConntrackPoolDoubleSearch(t_conntrack *table, const struct dissect *packet, t_ctrack **track, bool *reverse)
{
    t_conn key;
    int incoming;
    if (!ConntrackExtractConn(&key, false, packet)) return false;
    t_conntrack_pool *entry = zapret_conntrack_find(table->pool, &key, &incoming);
    if (!entry) return false;
    if (track) *track = &entry->track;
    if (reverse) *reverse = incoming != 0;
    return true;
}

bool ConntrackPoolFeed(t_conntrack *table, const struct dissect *packet, t_ctrack **track, bool *reverse)
{
    t_conn key;
    int incoming = 0;
    if (!ConntrackExtractConn(&key, false, packet)) return false;
    t_conntrack_pool *entry = zapret_conntrack_find(table->pool, &key, &incoming);
    if (!entry) {
        int start = zapret_conntrack_start((const unsigned char *)packet->tcp, packet->udp != NULL);
        if (!start) return false;
        incoming = start == 2;
        if (incoming) ConntrackExtractConn(&key, true, packet);
        entry = ConntrackNew(table, &key);
        if (!entry) return false;
    }
    ConntrackFeedPacket(&entry->track, incoming != 0, packet);
    entry->track.pos.ipproto = packet->tcp ? IPPROTO_TCP : packet->udp ? IPPROTO_UDP : IPPROTO_NONE;
    if (track) *track = &entry->track;
    if (reverse) *reverse = incoming != 0;
    return true;
}

bool ConntrackPoolDrop(t_conntrack *table, const struct dissect *packet)
{
    t_conn key;
    if (!ConntrackExtractConn(&key, false, packet)) return false;
    t_conntrack_pool *entry = zapret_conntrack_find(table->pool, &key, NULL);
    if (!entry) return false;
    zapret_conntrack_remove(&table->pool, &entry->conn);
    ConntrackFreeElem(entry);
    return true;
}

void ConntrackPoolPurge(t_conntrack *table)
{
    time_t now = boottime();
    if (!now || now - table->t_last_purge < table->t_purge_interval) return;
    uint64_t cursor = 0;
    t_conntrack_pool *entry;
    while ((entry = zapret_conntrack_after(table->pool, &cursor))) {
        if (zapret_conntrack_expired(table, &entry->track.pos, entry->conn.l4proto,
                entry->track.b_cutoff, now)) {
            zapret_conntrack_remove(&table->pool, &entry->conn);
            ConntrackFreeElem(entry);
        }
    }
    table->t_last_purge = now;
}

