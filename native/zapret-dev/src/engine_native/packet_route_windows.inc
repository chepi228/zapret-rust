/* MIT. Rust selects the route, prepares ICMP/IP profiles and repairs checksums. */
#include "runtime_log_windows.h"

enum zapret_packet_route_kind { ROUTE_INVALID, ROUTE_TCP, ROUTE_UDP, ROUTE_ICMP, ROUTE_IP };
typedef void (*zapret_packet_debug)(bool, const struct dissect *);
typedef struct {
    const struct in_addr *ipv4;
    const struct in6_addr *ipv6;
} zapret_route_address;
typedef struct {
    zapret_route_address destination, source;
    const char *hostname, *ssid;
    uint32_t mark;
    uint8_t protocol, icmp_type, icmp_code;
    bool hostname_is_ip;
} zapret_other_query;
typedef struct {
    struct desync_profile *profile;
    t_ctrack *track;
    zapret_route_address target;
    uint32_t l7, payload;
    bool incoming;
} zapret_other_play;
typedef struct {
    bool (*search)(const struct dissect *, t_ctrack **, bool *);
    bool (*cached_host)(zapret_route_address, char *, bool *);
    struct desync_profile *(*find)(const zapret_other_query *);
    const char *(*ssid)(const char *);
    zapret_log_sink log;
    zapret_packet_debug attached_debug;
} zapret_other_ops;

_Static_assert(sizeof(zapret_other_query) == 56 && offsetof(zapret_other_query, protocol) == 52 &&
    sizeof(zapret_other_play) == 48 && offsetof(zapret_other_play, incoming) == 40 &&
    sizeof(zapret_other_ops) == 48 && sizeof(zapret_route_address) == 16 &&
    offsetof(struct desync_profile, n) == 0 && offsetof(struct desync_profile, name) == 8 &&
    offsetof(struct dissect, icmp) == 64 && offsetof(struct dissect, transport_len) == 80 &&
    offsetof(struct dissect, data_payload) == 88 && offsetof(struct dissect, frag_off) == 106,
    "Rust IP and ICMP route ABI");
_Static_assert(L7P_IPV4 == 4 && L7P_IPV6 == 5 && L7P_ICMP == 6 && VERDICT_NOCSUM == 8 &&
    ICMP_DEST_UNREACH == 3 && ICMP_REDIRECT == 5 && ICMP_TIME_EXCEEDED == 11 &&
    ICMP_PARAMETERPROB == 12 && ICMP6_DST_UNREACH == 1 && ICMP6_PACKET_TOO_BIG == 2 &&
    ICMP6_PARAM_PROB == 4, "Rust IP and ICMP constants");

uint32_t zapret_packet_route(const struct dissect *, bool, zapret_log_sink, zapret_packet_debug);
bool zapret_prepare_other_packet(const struct dissect *, const char *, const char *, uint32_t,
    bool, const zapret_other_ops *, zapret_other_play *);
void zapret_packet_repair_checksum(const struct dissect *, uint8_t, zapret_log_sink);

static bool packet_route_search(const struct dissect *packet, t_ctrack **track, bool *reverse)
{
    return ConntrackPoolDoubleSearch(&params.conntrack, packet, track, reverse);
}
static bool packet_route_hostname(zapret_route_address address, char *hostname, bool *is_ip)
{
    return ipcache_get_hostname(address.ipv4, address.ipv6, hostname, 256, is_ip);
}
static struct desync_profile *packet_route_find(const zapret_other_query *query)
{
    return dp_find(&params.desync_profiles, query->protocol,
        query->destination.ipv4, query->destination.ipv6, query->source.ipv4, query->source.ipv6,
        0, query->icmp_type, query->icmp_code, query->hostname, query->hostname_is_ip,
        L7_UNKNOWN, query->ssid, query->mark, NULL, NULL, NULL);
}
static uint8_t packet_play_other(uint32_t mark, const char *ifin, const char *ifout,
    const struct dissect *packet, uint8_t *modified, size_t *modified_length)
{
    const zapret_other_ops ops = {
        .search = packet_route_search, .cached_host = packet_route_hostname, .find = packet_route_find,
#ifdef HAS_FILTER_SSID
        .ssid = wlan_ssid_search_ifname,
#endif
        .log = DLOG, .attached_debug = params.debug ? packet_debug : NULL,
    };
    zapret_other_play play;
    if (!zapret_prepare_other_packet(packet, ifin, ifout, mark, params.server, &ops, &play))
        return VERDICT_PASS;
    return desync(play.profile, mark, ifin, ifout, play.incoming, play.track, NULL, play.payload, play.l7,
        packet, play.target.ipv4, play.target.ipv6, 0, modified, modified_length, 0, 0, 0, NULL, 0, NULL, 0);
}
static uint8_t dpi_desync_packet_play(
    unsigned int replay_piece, unsigned int replay_count, size_t reasm_offset, uint32_t mark,
    const char *ifin, const char *ifout, const t_ctrack_positions *positions,
    const uint8_t *data, size_t length, uint8_t *modified, size_t *modified_length)
{
    struct dissect packet;
    proto_dissect_l3l4(data, length, &packet, false);
    uint32_t route = zapret_packet_route(&packet, !!replay_count, DLOG, packet_debug);
    if (route == ROUTE_INVALID) return VERDICT_PASS;
    uint8_t verdict;
    switch (route) {
    case ROUTE_TCP:
        verdict = dpi_desync_tcp_packet_play(replay_piece, replay_count, reasm_offset, mark, ifin, ifout,
            positions, &packet, modified, modified_length);
        break;
    case ROUTE_UDP:
        verdict = dpi_desync_udp_packet_play(replay_piece, replay_count, reasm_offset, mark, ifin, ifout,
            positions, &packet, modified, modified_length);
        break;
    default:
        verdict = packet_play_other(mark, ifin, ifout, &packet, modified, modified_length);
        break;
    }
    if (route != ROUTE_IP)
        zapret_packet_repair_checksum(&packet, verdict, params.debug ? DLOG : NULL);
    return verdict;
}
