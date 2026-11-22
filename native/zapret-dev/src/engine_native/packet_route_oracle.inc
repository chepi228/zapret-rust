/* MIT. IP/ICMP routing and the exact wire bytes after each verdict. */
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

static void packet_debug(bool replay, const struct dissect *packet)
{
    DLOG("packet %u protocol=%u len=%zu\n", replay, packet->proto, packet->len_pkt);
}
void extract_endpoints(const struct ip *ipv4, const struct ip6_hdr *ipv6, const struct tcphdr *tcp,
    const struct udphdr *udp, struct sockaddr_storage *src, struct sockaddr_storage *dst)
{
    CHECK((!!ipv4 != !!ipv6) && !tcp && !udp && src && dst);
}
bool ConntrackPoolDoubleSearch(t_conntrack *pool, const struct dissect *packet, t_ctrack **out, bool *from_server)
{
    effect('C');
    CHECK(pool == &params.conntrack && (!!packet->ip != !!packet->ip6));
    if (!(test_flags & 1) || (!packet->tcp && !packet->udp)) return false;
    *out = &track;
    *from_server = (test_flags & 2) != 0;
    return true;
}
static bool ipcache_get_hostname(const struct in_addr *ipv4, const struct in6_addr *ipv6,
    char *name, size_t capacity, bool *is_ip)
{
    CHECK((!!ipv4 != !!ipv6) && capacity == 256);
    const uint8_t *address = ipv4 ? (const uint8_t *)ipv4 : (const uint8_t *)ipv6;
    uint8_t last = address[ipv4 ? 3 : 15];
    CHECK(last == 1 || last == 2);
    effect(last == 1 ? 's' : 'd');
    if ((test_flags & 12) == (last == 1 ? 4 : 8)) {
        strcpy(name, "cache.example");
        *is_ip = (test_flags & 16) != 0;
        return true;
    }
    name[0] = 0;
    return false;
}
#ifdef HAS_FILTER_SSID
const char *wlan_ssid_search_ifname(const char *name)
{
    effect('W');
    return (name && *name && ((test_flags & 8) ? !strcmp(name, "in") : !strcmp(name, "out")))
        ? "test network" : NULL;
}
#endif
static struct desync_profile *dp_find(struct desync_profile_list_head *head, uint8_t protocol,
    const struct in_addr *ipv4, const struct in6_addr *ipv6, const struct in_addr *ipv4_rev,
    const struct in6_addr *ipv6_rev, uint16_t port, uint8_t type, uint8_t code,
    const char *hostname, bool is_ip, t_l7proto l7, const char *ssid, uint32_t mark,
    bool *done, bool *match, bool *excluded)
{
    effect('P');
    CHECK(head == &params.desync_profiles && !port && l7 == L7_UNKNOWN && mark == 2);
    CHECK(!done && !match && !excluded && (!!ipv4 != !!ipv6));
    const uint8_t *dest = ipv4 ? (const uint8_t *)ipv4 : (const uint8_t *)ipv6;
    const uint8_t *src = ipv4_rev ? (const uint8_t *)ipv4_rev : (const uint8_t *)ipv6_rev;
    CHECK(dest[ipv4 ? 3 : 15] == 2 && src[ipv4 ? 3 : 15] == 1);
    if (hostname) strcpy(trace.hostname, hostname);
    DLOG("find proto=%u type=%u code=%u ip=%u ssid=%s\n", protocol, type, code, is_ip, ssid ? ssid : "-");
    return test_flags & 32 ? NULL : &profile;
}
static uint8_t route_desync(struct desync_profile *dp, uint32_t mark, const char *ifin, const char *ifout,
    bool incoming, t_ctrack *ct, const t_ctrack_positions *positions, t_l7payload payload,
    t_l7proto proto, const struct dissect *packet, const struct in_addr *ipv4, const struct in6_addr *ipv6,
    uint16_t port, uint8_t *modified, size_t *mod_len, unsigned int piece, unsigned int count,
    size_t offset, const uint8_t *tcp, size_t tcp_len, const uint8_t *quic, size_t quic_len)
{
    CHECK(dp == &profile && mark == 2 && !positions && !port && !piece && !count && !offset);
    CHECK((!ct || ct == &track) && packet && modified && *mod_len == 8);
    CHECK(!tcp && !tcp_len && !quic && !quic_len && (!!ipv4 != !!ipv6));
    effect('L');
    trace.have_host = !!ct;
    trace.from_peer = incoming;
    trace.payload = payload;
    trace.l7 = proto;
    trace.quic_bytes = digest(ipv4 ? (const uint8_t *)ipv4 : (const uint8_t *)ipv6, ipv4 ? 4 : 16);
    return verdict;
}
static uint8_t route_stream(unsigned int piece, unsigned int count, size_t offset, uint32_t mark,
    const char *ifin, const char *ifout, const t_ctrack_positions *positions, const struct dissect *packet,
    uint8_t *modified, size_t *length)
{
    CHECK(mark == 2 && !positions && !piece && !count && !offset && modified && *length == 8);
    CHECK(!!packet->tcp != !!packet->udp);
    effect(packet->tcp ? 'T' : 'U');
    return verdict;
}

#include "packet_checksum_reference.inc"
#define dpi_desync_tcp_packet_play route_stream
#define dpi_desync_udp_packet_play route_stream
#define desync route_desync
#define dpi_desync_packet_play reference_route
#include "packet_route_reference.inc"
#undef dpi_desync_packet_play
#include "packet_route_windows.inc"
#undef desync
#undef dpi_desync_tcp_packet_play
#undef dpi_desync_udp_packet_play

static size_t make_ip(uint8_t *buffer, bool ipv6, uint8_t protocol, size_t payload)
{
    size_t header = ipv6 ? 40 : 20;
    memset(buffer, 0, header + payload);
    if (ipv6) {
        buffer[0] = 0x60;
        buffer[4] = (uint8_t)(payload >> 8);
        buffer[5] = (uint8_t)payload;
        buffer[6] = protocol;
        buffer[7] = 64;
        buffer[23] = 1;
        buffer[39] = 2;
    } else {
        size_t length = header + payload;
        buffer[0] = 0x45;
        buffer[2] = (uint8_t)(length >> 8);
        buffer[3] = (uint8_t)length;
        buffer[8] = 64;
        buffer[9] = protocol;
        buffer[15] = 1;
        buffer[19] = 2;
    }
    return header;
}
static void run_route(struct trace *out, uint8_t *buffer, size_t length, bool actual)
{
    memset(&trace, 0, sizeof(trace));
    memset(&track, 0, sizeof(track));
    log_at = effect_at = 0;
    params.debug = (test_flags & 128) != 0;
    params.server = (test_flags & 16) != 0;
    track.dp = &profile;
    track.l7proto = L7_HTTP;
    track.dp_search_complete = (test_flags & 32) != 0;
    track.hostname = test_flags & 64 ? "tracked.example" : NULL;
    track.hostname_is_ip = true;
    profile.n = 1;
    verdict = (uint8_t)test_flags;
    const char *ifin = test_flags & 4 ? "in" : NULL;
    const char *ifout = test_flags & 8 ? "out" : "";
    uint8_t modified[8];
    size_t mod_len = sizeof(modified);
    trace.verdict = (actual ? dpi_desync_packet_play : reference_route)(
        0, 0, 0, 2, ifin, ifout, NULL, buffer, length, modified, &mod_len);
    memcpy(out, &trace, sizeof(trace));
}
static void check_routes(void)
{
    static const uint8_t types[] = {0, 1, 2, 3, 4, 5, 8, 11, 12, 128};
    unsigned cases = 0, checksum_changes = 0, deferred_sources = 0;
    for (unsigned family = 0; family < 2; ++family)
    for (test_case = 0; test_case < 14; ++test_case) {
        uint8_t wire[128] = {0}, before[128], after[128];
        bool ipv6 = family != 0;
        size_t length;
        if (test_case == 0) {
            length = 13;
        } else if (test_case <= 3) {
            size_t transport = test_case == 1 ? 21 : 9;
            size_t header = make_ip(wire, ipv6, test_case == 1 ? 6 : test_case == 2 ? 17 : 50, transport);
            uint8_t *segment = wire + header;
            segment[1] = 3;
            segment[3] = 4;
            if (test_case == 1) {
                segment[12] = 0x50;
                segment[13] = TH_ACK;
                segment[16] = 0xff;
            } else if (test_case == 2) {
                segment[5] = 9;
                segment[6] = 0xff;
            }
            segment[transport - 1] = 0xad;
            length = header + transport;
        } else {
            bool inner_v6 = (test_case & 1) != 0;
            size_t inner_len = (inner_v6 ? 40 : 20) + 8;
            if (test_case == 4 || test_case == 5) inner_len = 5;
            size_t header = make_ip(wire, ipv6, ipv6 ? 58 : 1, 8 + inner_len);
            uint8_t *icmp = wire + header;
            icmp[0] = types[test_case - 4];
            icmp[1] = 3;
            icmp[2] = 0xff;
            if (inner_len > 5) {
                // An ICMP quote may stop after the transport header.
                size_t inner = make_ip(icmp + 8, inner_v6, 17, 8);
                icmp[8 + inner + 5] = 32;
                if (inner_v6) icmp[8 + 5] = 32;
                else icmp[8 + 3] = 52;
            }
            length = header + 8 + inner_len;
        }
        for (test_flags = 0; test_flags < 256; ++test_flags) {
            struct trace a, b;
            memcpy(before, wire, length);
            memcpy(after, wire, length);
            // Change an address in the log sink just before checksum repair.
            const bool defer_source = test_flags == 128 &&
                (test_case == 1 || test_case == 2 || test_case == 4);
            const size_t address_byte = ipv6 ? 23 : 15;
            if (defer_source) checksum_log_byte = before + address_byte;
            run_route(&a, before, length, false);
            CHECK(!checksum_log_byte);
            if (defer_source) checksum_log_byte = after + address_byte;
            run_route(&b, after, length, true);
            CHECK(!checksum_log_byte);
            CHECK(!memcmp(&a, &b, sizeof(a)));
            CHECK(!memcmp(before, after, length));
            deferred_sources += defer_source;
            checksum_changes += !!memcmp(wire, after, length);
            ++cases;
        }
    }
    CHECK(checksum_changes);
    printf("PASS packet_route cases=%u checksum_changes=%u deferred_sources=%u\n",
        cases, checksum_changes, deferred_sources);
}
