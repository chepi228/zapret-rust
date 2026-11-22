/* MIT. Startup filter grammar, exact masks and numeric failure behavior. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "filter.h"
#include "protocol.h"
#include "pools.h"
#include "filters_windows.h"
#include "mask_reference.inc"
#undef main

static const char *input;
#define CHECK(condition) do { \
    if (!(condition)) { fprintf(stderr, "FAIL config filter '%s' line %d: %s\n", input, __LINE__, #condition); exit(1); } \
} while (0)
static unsigned options, matches, masks;

static void compare(const char *text)
{
    input = text;
    port_filter c_port, r_port;
    bool c = pf_parse(text, &c_port), r = zapret_pf_parse(text, &r_port);
    CHECK(c == r);
    if (c) {
        CHECK(c_port.from == r_port.from && c_port.to == r_port.to && c_port.neg == r_port.neg);
        uint16_t ports[] = {0, 1, 80, 443, c_port.from, c_port.to, UINT16_MAX};
        for (unsigned i = 0; i < sizeof(ports) / sizeof(*ports); ++i) {
            CHECK(pf_match(ports[i], &c_port) == zapret_pf_match(ports[i], &r_port));
            ++matches;
        }
    }
    icmp_filter c_icmp, r_icmp;
    c = icf_parse(text, &c_icmp);
    r = zapret_icf_parse(text, &r_icmp);
    CHECK(c == r);
    if (c) {
        CHECK(c_icmp.mode == r_icmp.mode && c_icmp.type == r_icmp.type &&
            c_icmp.code == r_icmp.code && c_icmp.code_valid == r_icmp.code_valid);
        for (unsigned i = 0; i <= UINT8_MAX; i += 3) {
            CHECK(icf_match(i, 0, &c_icmp) == zapret_icf_match(i, 0, &r_icmp));
            CHECK(icf_match(c_icmp.type, i, &c_icmp) == zapret_icf_match(r_icmp.type, i, &r_icmp));
            matches += 2;
        }
    }
    ipp_filter c_ip, r_ip;
    c = ipp_parse(text, &c_ip);
    r = zapret_ipp_parse(text, &r_ip);
    CHECK(c == r);
    if (c) {
        CHECK(c_ip.mode == r_ip.mode && c_ip.proto == r_ip.proto);
        for (unsigned i = 0; i <= UINT8_MAX; ++i) {
            CHECK(ipp_match(i, &c_ip) == zapret_ipp_match(i, &r_ip));
            ++matches;
        }
    }
    struct packet_range c_range, r_range;
    c = packet_range_parse(text, &c_range);
    r = zapret_packet_range_parse(text, &r_range);
    CHECK(c == r);
    if (c)
        CHECK(c_range.from.mode == r_range.from.mode && c_range.from.pos == r_range.from.pos &&
            c_range.to.mode == r_range.to.mode && c_range.to.pos == r_range.to.pos &&
            c_range.upper_cutoff == r_range.upper_cutoff);
    options += 4;
}
static void mask(const char *text, bool payload)
{
    input = text;
    char mutable[160];
    CHECK(strlen(text) < sizeof(mutable));
    strcpy(mutable, text);
    uint64_t want, got = UINT64_MAX;
    bool c = (payload ? parse_l7p_list : parse_l7_list)(mutable, &want);
    char copy[160];
    strcpy(copy, text);
    bool r = (payload ? zapret_parse_payload_list : zapret_parse_l7_list)(copy, &got);
    CHECK(c == r && !strcmp(copy, text));
    CHECK(c ? (got == want) : (got == UINT64_MAX));
    ++masks;
}
static void overflow_tests(void)
{
    input = "overflow";
    port_filter port = {.from = 10, .to = 20, .neg = true};
    CHECK(!zapret_pf_parse("4294967297", &port));
    CHECK(!zapret_pf_parse("1-4294967298", &port));
    CHECK(!zapret_pf_parse("-4294967295", &port));
    CHECK(port.from == 10 && port.to == 20 && port.neg);
    icmp_filter icmp = {.mode = FLTMODE_FILTER, .type = 8, .code = 4, .code_valid = true};
    CHECK(!zapret_icf_parse("4294967304:4", &icmp));
    CHECK(!zapret_icf_parse("8:4294967300", &icmp));
    CHECK(icmp.mode == FLTMODE_FILTER && icmp.type == 8 && icmp.code == 4 && icmp.code_valid);
    ipp_filter ip = {.mode = FLTMODE_FILTER, .proto = 6};
    CHECK(!zapret_ipp_parse("4294967302", &ip));
    CHECK(ip.mode == FLTMODE_FILTER && ip.proto == 6);
    struct packet_range range = {{'n', 1}, {'n', 4}, true};
    CHECK(!zapret_packet_range_parse("n4294967297-n2", &range));
    CHECK(!zapret_packet_range_parse("n1<n18446744073709551616", &range));
    CHECK(range.from.mode == 'n' && range.from.pos == 1 && range.to.mode == 'n' &&
        range.to.pos == 4 && range.upper_cutoff);
}

static void match_boundaries(void)
{
    input = "native ABI bounds";
    CHECK(!pf_match(0, NULL) && !zapret_pf_match(0, NULL));
    CHECK(!zapret_pf_match(80, NULL) && !zapret_icf_match(8, 0, NULL) && !zapret_ipp_match(6, NULL));
    CHECK(!zapret_pf_parse("80", NULL) && !zapret_icf_parse("8", NULL) &&
        !zapret_ipp_parse("6", NULL) && !zapret_packet_range_parse("a", NULL));

    SYSTEM_INFO system;
    GetSystemInfo(&system);
    size_t page = system.dwPageSize;
    uint8_t *memory = VirtualAlloc(NULL, page * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    DWORD previous;
    CHECK(memory && VirtualProtect(memory + page, page, PAGE_NOACCESS, &previous));
    uint8_t *end = memory + page;
    CHECK(!pf_match(0, (const port_filter *)end) && !zapret_pf_match(0, (const port_filter *)end));
    CHECK(!zapret_pf_parse(NULL, (port_filter *)end) && !zapret_icf_parse(NULL, (icmp_filter *)end) &&
        !zapret_ipp_parse(NULL, (ipp_filter *)end) && !zapret_packet_range_parse(NULL, (struct packet_range *)end));
    end[-1] = FLTMODE_ANY;
    CHECK(icf_match(8, 0, (const icmp_filter *)(end - 1)) && zapret_icf_match(8, 0, (const icmp_filter *)(end - 1)));
    CHECK(ipp_match(6, (const ipp_filter *)(end - 1)) && zapret_ipp_match(6, (const ipp_filter *)(end - 1)));
    end[-1] = FLTMODE_SKIP;
    CHECK(!icf_match(8, 0, (const icmp_filter *)(end - 1)) && !zapret_icf_match(8, 0, (const icmp_filter *)(end - 1)));
    CHECK(!ipp_match(6, (const ipp_filter *)(end - 1)) && !zapret_ipp_match(6, (const ipp_filter *)(end - 1)));
    end[-2] = FLTMODE_FILTER;
    CHECK(!icf_match(8, 0, (const icmp_filter *)(end - 2)) && !zapret_icf_match(8, 0, (const icmp_filter *)(end - 2)));
    CHECK(VirtualFree(memory, 0, MEM_RELEASE));
}
#include "startup_arguments_oracle.inc"
#include "windivert_filter_oracle.inc"

int main(void)
{
    static const char *const forms[] = {"", "*", "-", "~*", "~0", "0", "-0", "+0", "  80", "80 ",
        "0-0", "65535", "65536", "5-2", "0040-0443", "80- 81", "80 -81", "8:0", "8: 0",
        " 8:0 ", "6:128", "8:", "ah", "a", "a-a", "a<", "x", "n1-x", "n1-d5", "<s7",
        "n8<n12", "n8<n12-a", "-n8", "n8", "s4294967295-", "a<d+5", "r4-b0", "a-a-tail"};
    for (unsigned i = 0; i < sizeof(forms) / sizeof(*forms); ++i) compare(forms[i]);
    for (unsigned a = 0; a < 256; ++a)
    for (unsigned b = 0; b < 256; b += 17) {
        char text[64];
        snprintf(text, sizeof(text), "%u-%u", a * 257, b * 257);
        compare(text);
        snprintf(text, sizeof(text), "%u:%u", a, b);
        compare(text);
        snprintf(text, sizeof(text), "%c%u%c%c%u", "ndspb"[a % 5], a * 257, b & 1 ? '<' : '-',
            "ndspb"[b % 5], b * 257);
        compare(text);
    }
    for (unsigned variant = 0; variant < 2; ++variant) {
        unsigned limit = variant ? L7P_LAST : L7_LAST;
        for (unsigned a = 0; a < limit; ++a)
        for (unsigned b = 0; b < limit; ++b) {
            char text[160];
            snprintf(text, sizeof(text), "%s,%s", variant ? l7payload_str(a) : l7proto_str(a),
                variant ? l7payload_str(b) : l7proto_str(b));
            mask(text, variant);
        }
        mask("", variant);
        mask("all,invalid", variant);
        mask("unknown,,all", variant);
        mask("known, unknown", variant);
        mask("unknown,", variant);
        mask("UNKNOWN", variant);
    }
    overflow_tests();
    match_boundaries();
    printf("PASS filter_config options=%u match_checks=%u masks=%u overflow_checks=8 direct_exports=7 guarded_match=1\n",
        options, matches, masks);
    check_startup_arguments();
    check_capture_filter();
    return 0;
}
