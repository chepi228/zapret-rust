/* MIT. Compare the complete generated filter and check exact buffer boundaries. */
#define wf_make_l3 reference_wf_make_l3
#include "version_filter_reference.inc"
#undef wf_make_l3
#define wf_make_pf reference_wf_make_pf
#define wf_make_icf reference_wf_make_icf
#define wf_make_ipf reference_wf_make_ipf
#define wf_make_filter reference_wf_make_filter
#include "capture_filter_reference.inc"
#undef wf_make_pf
#undef wf_make_icf
#undef wf_make_ipf
#undef wf_make_filter
#include "windivert_filter_windows.inc"
bool zapret_filter_ip_versions(const char *, bool *, bool *);

static void check_capture_filter(void)
{
    static const char *const forms[] = {"80,443", "5-10,~8080,65535", "*", "0", "", "-",
        "8:0,3,-", "58,17,-", "255:255", "256:0", "80,bad", "~*", "1,,2"};
    char before[4096], after[4096], opt[64];
    unsigned clauses = 0;
    for (unsigned i = 0; i < sizeof(forms) / sizeof(*forms); ++i) {
        input = forms[i];
        for (unsigned kind = 0; kind < 3; ++kind) {
            strcpy(opt, input);
            bool c, r;
            if (kind == 0) {
                c = reference_wf_make_pf(opt, "tcp", "DstPort", before, sizeof(before));
                r = wf_make_pf(input, "tcp", "DstPort", after, sizeof(after));
            } else if (kind == 1) {
                c = reference_wf_make_icf(opt, before, sizeof(before));
                r = wf_make_icf(input, after, sizeof(after));
            } else {
                c = reference_wf_make_ipf(opt, before, sizeof(before));
                r = wf_make_ipf(input, after, sizeof(after));
            }
            CHECK(c == r && (c ? !strcmp(before, after) : !*after));
            ++clauses;
        }
    }
    static const char *const versions[] = {"ipv4", "ipv6", "ipv4,ipv6", "ipv6,ipv4", "ipv4,ipv4",
        "ipv6,bad", "ipv4,", "ipv", ""};
    for (unsigned i = 0; i < sizeof(versions) / sizeof(*versions); ++i) {
        input = versions[i];
        strcpy(opt, input);
        bool c4 = false, c6 = true, r4 = c4, r6 = c6;
        bool ok = reference_wf_make_l3(opt, &c4, &c6);
        CHECK(zapret_filter_ip_versions(input, &r4, &r6) == ok);
        CHECK(ok ? (c4 == r4 && c6 == r6) : (!r4 && r6));
    }
    struct str_list_head parts = LIST_HEAD_INITIALIZER(parts);
    struct str_list p1 = {.str = "ip.Protocol==49"}, p2 = {.str = "udp"};
    LIST_INSERT_HEAD(&parts, &p1, next);
    LIST_INSERT_HEAD(&parts, &p2, next);
    input = "complete expression";
    for (unsigned f = 0; f < 4096; ++f) {
        unsigned index = f & 1 ? 12 : 0;
        bool ipv4 = !!(f & 2), ipv6 = !!(f & 4), empty_tcp = !!(f & 8);
        const char *tcp_src_out = f & 16 ? "tcp.SrcPort==80" : "";
        const char *tcp_dst_out = f & 16 ? "tcp.DstPort==80" : "";
        const char *tcp_src_in = f & 32 ? "tcp.SrcPort==443" : "";
        const char *tcp_dst_in = f & 32 ? "tcp.DstPort==443" : "";
        const char *udp_src = f & 64 ? "udp.SrcPort==53" : "";
        const char *udp_dst = f & 128 ? "udp.DstPort==53" : "";
        const char *icmp = f & 256 ? "icmp or icmpv6" : "";
        const char *ip = f & 256 ? "ip.Protocol==50" : "";
        const char *raw = f & 512 ? "!loopback" : "";
        const struct str_list_head empty = {0};
        const struct str_list_head *selected_parts = f & 128 ? &parts : &empty;
        bool lan = !!(f & 1024), loopback = !!(f & 2048);
#define ARGS index, 2, ipv4, ipv6, empty_tcp, tcp_src_out, tcp_dst_out, tcp_src_in, tcp_dst_in, \
        udp_src, udp_dst, icmp, icmp, ip, ip, raw, selected_parts, lan, loopback
        CHECK(reference_wf_make_filter(before, sizeof(before), ARGS));
        CHECK(wf_make_filter(after, sizeof(after), ARGS) && !strcmp(before, after));
        size_t length = strlen(before);
        memset(after, '#', sizeof(after));
        CHECK(wf_make_filter(after, length + 1, ARGS) && !strcmp(before, after) && after[length + 1] == '#');
        memset(after, '#', sizeof(after));
        CHECK(!wf_make_filter(after, length, ARGS) && !*after && after[length] == '#');
#undef ARGS
    }
    CHECK(!wf_make_pf("80", "tcp", "DstPort", after, 7) && !*after);
    printf("PASS capture_filter expressions=4096 clauses=%u versions=%zu size_boundaries=8193\n",
        clauses, sizeof(versions) / sizeof(*versions));
}
