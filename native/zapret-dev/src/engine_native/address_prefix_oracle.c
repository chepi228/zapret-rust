/* MIT. CIDR compatibility and immutable prefix-mask boundaries. */
#include "helpers.h"
#include "filters_windows.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef main
static unsigned text_cases, parse_cases, mask_cases, atomic_failures;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL address prefix text=%u parse=%u mask=%u line=%d: %s\n", text_cases, parse_cases, mask_cases, __LINE__, #condition); exit(1); } \
} while (0)
#define str_cidr4 reference_str_cidr4
#define str_cidr6 reference_str_cidr6
#define parse_cidr4 reference_parse_cidr4
#define parse_cidr6 reference_parse_cidr6
#define print_cidr4 reference_print_cidr4
#define print_cidr6 reference_print_cidr6
#define mask_from_bitcount reference_mask_from_bitcount
#define mask_from_bitcount6 reference_mask_from_bitcount6
#define mask_from_bitcount6_prepare reference_mask_from_bitcount6_prepare
#include "address_prefix_reference.inc"
#undef str_cidr4
#undef str_cidr6
#undef parse_cidr4
#undef parse_cidr6
#undef print_cidr4
#undef print_cidr6
#undef mask_from_bitcount
#undef mask_from_bitcount6
#undef mask_from_bitcount6_prepare
uint32_t zapret_prefix_mask4(uint32_t);
const struct in6_addr *zapret_prefix_mask6(uint32_t);
void zapret_prefix_prepare6(void);

static uint64_t random_state = UINT64_C(0x636964725f6d6173);
static uint64_t next(void) { random_state ^= random_state << 13; random_state ^= random_state >> 7; random_state ^= random_state << 17; return random_state; }
static void compare_parse(bool ipv6, const char *text)
{
    union { struct cidr4 v4; struct cidr6 v6; } expected, actual, before;
    memset(&before, 0x69, sizeof(before));
    memcpy(&expected, &before, sizeof(before));
    memcpy(&actual, &before, sizeof(before));
    char left[128], right[128];
    CHECK(strlen(text) < sizeof(left));
    strcpy(left, text); strcpy(right, text);
    bool c = ipv6 ? reference_parse_cidr6(left, &expected.v6) : reference_parse_cidr4(left, &expected.v4);
    bool r = ipv6 ? zapret_parse_cidr6(right, &actual.v6) : zapret_parse_cidr4(right, &actual.v4);
    CHECK(c == r && !strcmp(left, text) && !strcmp(right, text));
    if (r) {
        CHECK(!memcmp(&expected, &actual, sizeof(actual)));
    } else { CHECK(!memcmp(&actual, &before, sizeof(actual))); ++atomic_failures; }
    ++parse_cases;
}

static void check_public_boundaries(void)
{
    struct cidr4 ipv4 = {0};
    struct cidr6 ipv6 = {0};
    CHECK(!zapret_parse_cidr4(NULL, &ipv4) && !zapret_parse_cidr4("1.2.3.4", NULL));
    CHECK(!zapret_parse_cidr6(NULL, &ipv6) && !zapret_parse_cidr6("::1", NULL));
    char output[] = "canary";
    zapret_str_cidr4(output, sizeof(output), NULL);
    zapret_str_cidr6(output, sizeof(output), NULL);
    CHECK(!strcmp(output, "canary"));

    SYSTEM_INFO system;
    GetSystemInfo(&system);
    void *unreadable = VirtualAlloc(NULL, system.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
    CHECK(unreadable);
    zapret_str_cidr4(output, 0, unreadable);
    zapret_str_cidr6(NULL, 0, unreadable);
    zapret_str_cidr4(NULL, sizeof(output), unreadable);
    zapret_str_cidr6(NULL, sizeof(output), unreadable);
    CHECK(!strcmp(output, "canary") && VirtualFree(unreadable, 0, MEM_RELEASE));
}
int main(void)
{
    WSADATA winsock;
    CHECK(!WSAStartup(MAKEWORD(2, 2), &winsock));
    reference_mask_from_bitcount6_prepare();
    for (unsigned zeros = 0; zeros <= 256; ++zeros) {
        CHECK(reference_mask_from_bitcount(zeros) == zapret_prefix_mask4(zeros)); ++mask_cases;
        if (zeros <= 128) {
            const struct in6_addr *rust = zapret_prefix_mask6(zeros);
            CHECK(rust && !((uintptr_t)rust & 3));
            CHECK(!memcmp(reference_mask_from_bitcount6(zeros), rust, 16)); ++mask_cases;
        } else CHECK(!zapret_prefix_mask6(zeros));
    }
    CHECK(!zapret_prefix_mask6(UINT32_MAX) && !zapret_prefix_mask4(UINT32_MAX));
    zapret_prefix_prepare6();
    for (unsigned ipv6 = 0; ipv6 <= 1; ++ipv6) for (unsigned round = 0; round < 4096; ++round) {
        union { struct cidr4 v4; struct cidr6 v6; } cidr;
        for (unsigned index = 0; index < sizeof(cidr); ++index) ((uint8_t *)&cidr)[index] = (uint8_t)next();
        unsigned prefix = round % 256;
        if (ipv6) cidr.v6.preflen = prefix; else cidr.v4.preflen = prefix;
        for (unsigned capacity = 0; capacity <= 64; ++capacity) {
            char left[96], right[96]; memset(left, 0x69, sizeof(left)); memcpy(right, left, sizeof(left));
            if (ipv6) { reference_str_cidr6(left + 7, capacity, &cidr.v6); zapret_str_cidr6(right + 7, capacity, &cidr.v6); }
            else { reference_str_cidr4(left + 7, capacity, &cidr.v4); zapret_str_cidr4(right + 7, capacity, &cidr.v4); }
            CHECK(!memcmp(left, right, sizeof(left))); ++text_cases;
        }
        char address[INET6_ADDRSTRLEN], text[96];
        CHECK(inet_ntop(ipv6 ? AF_INET6 : AF_INET, &cidr, address, sizeof(address)));
        snprintf(text, sizeof(text), "%s/%s%u%s", address, round % 3 ? "" : " +", round % (ipv6 ? 132 : 36), round % 7 ? "" : "suffix");
        compare_parse(ipv6, text);
        compare_parse(ipv6, address);
    }
    static const char *const invalid[] = {"", "/", "invalid", "::1/129", "[::1]/64", "1.2.3.4/33", "1.2.3.4/", "1.2.3.4/-1", "::1/-1", "1.2.3.4/999999999999999999999999999999999999"};
    for (unsigned index = 0; index < sizeof(invalid) / sizeof(*invalid); ++index) {
        compare_parse(false, invalid[index]); compare_parse(true, invalid[index]);
    }
    char *wrapped[] = {"1.2.3.4/4294967296", "::1/4294967296", "1.2.3.4/-4294967296", "::1/-4294967296"};
    for (unsigned index = 0; index < 4; ++index) {
        union { struct cidr4 v4; struct cidr6 v6; } cidr, before;
        memset(&cidr, 0x69, sizeof(cidr));
        memcpy(&before, &cidr, sizeof(cidr));
        CHECK(!(index % 2 ? zapret_parse_cidr6(wrapped[index], &cidr.v6) :
            zapret_parse_cidr4(wrapped[index], &cidr.v4)));
        CHECK(!memcmp(&cidr, &before, sizeof(cidr)));
    }
    check_public_boundaries();
    WSACleanup();
    printf("PASS address_prefix functions=9 text_cases=%u parse_cases=%u mask_cases=%u atomic_failures=%u rejected_wraps=4 direct_cidr=4 guarded_output=1\n", text_cases, parse_cases, mask_cases, atomic_failures);
    return 0;
}
