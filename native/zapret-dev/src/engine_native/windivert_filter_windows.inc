/* MIT. Render the native capture filter into the caller's bounded buffer. */
typedef struct {
    const char *tcp_source_out, *tcp_destination_out, *tcp_source_in, *tcp_destination_in;
    const char *udp_source_in, *udp_destination_out, *icmp_out, *icmp_in, *ip_out, *ip_in, *raw;
    const struct str_list *parts;
    uint32_t index, sub_index, flags;
} zapret_capture_filter;
_Static_assert(offsetof(struct str_list, str) == 0 &&
    offsetof(struct str_list, next.le_next) == sizeof(void *) &&
    offsetof(zapret_capture_filter, parts) == 11 * sizeof(void *) &&
    offsetof(zapret_capture_filter, flags) == 12 * sizeof(void *) + 8 &&
    sizeof(zapret_capture_filter) == (sizeof(void *) == 4 ? 60 : 112), "Rust capture filter ABI");

bool zapret_filter_clauses(const char *, uint32_t, const char *, const char *, char *, size_t);
bool zapret_build_windivert_filter(char *, size_t, const zapret_capture_filter *);

static bool wf_make_pf(const char *opt, const char *l4, const char *port, char *out, size_t size)
{
    return zapret_filter_clauses(opt, 0, l4, port, out, size);
}
static bool wf_make_icf(const char *opt, char *out, size_t size)
{
    return zapret_filter_clauses(opt, 1, NULL, NULL, out, size);
}
static bool wf_make_ipf(const char *opt, char *out, size_t size)
{
    return zapret_filter_clauses(opt, 2, NULL, NULL, out, size);
}
static bool wf_make_filter(
    char *output, size_t size, unsigned int index, unsigned int sub_index, bool ipv4, bool ipv6,
    bool allow_empty_tcp, const char *tcp_source_out, const char *tcp_destination_out,
    const char *tcp_source_in, const char *tcp_destination_in,
    const char *udp_source_in, const char *udp_destination_out,
    const char *icmp_out, const char *icmp_in, const char *ip_out, const char *ip_in,
    const char *raw, const struct str_list_head *parts, bool exclude_lan, bool exclude_loopback)
{
    const zapret_capture_filter filter = {
        .tcp_source_out = tcp_source_out, .tcp_destination_out = tcp_destination_out,
        .tcp_source_in = tcp_source_in, .tcp_destination_in = tcp_destination_in,
        .udp_source_in = udp_source_in, .udp_destination_out = udp_destination_out,
        .icmp_out = icmp_out, .icmp_in = icmp_in, .ip_out = ip_out, .ip_in = ip_in, .raw = raw,
        .parts = LIST_FIRST(parts), .index = index, .sub_index = sub_index,
        .flags = (ipv4 ? 1u : 0u) | (ipv6 ? 2u : 0u) | (allow_empty_tcp ? 4u : 0u) |
            (exclude_lan ? 8u : 0u) | (exclude_loopback ? 16u : 0u),
    };
    return zapret_build_windivert_filter(output, size, &filter);
}
