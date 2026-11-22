/* MIT. Exact output bytes, host edits and bounded writes against pinned C. */
#include "helpers.h"
#undef main
#include "address_reference.inc"
#include "address_windows.h"

void ntopa46(const struct in_addr *, const struct in6_addr *, char *, size_t);
void ntop46(const struct sockaddr *, char *, size_t);
void ntop46_port(const struct sockaddr *, char *, size_t);
uint16_t saport(const struct sockaddr *);
bool sa_has_addr(const struct sockaddr *);
bool strip_host_to_ip(char *);

static unsigned socket_cases, host_cases;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL engine address socket=%u host=%u line=%d: %s\n", socket_cases, host_cases, __LINE__, #condition); exit(1); } \
} while (0)
static uint64_t random_state = 0x616464726573735fULL;
static uint64_t next(void)
{
    random_state ^= random_state << 13;
    random_state ^= random_state >> 7;
    random_state ^= random_state << 17;
    return random_state;
}
static void compare_host(const char *text)
{
    char left[192], right[192];
    memset(left, 0x69, sizeof(left));
    CHECK(strlen(text) < sizeof(left));
    strcpy(left, text);
    memcpy(right, left, sizeof(left));
    bool expected = reference_strip_host_to_ip(left);
    bool actual = strip_host_to_ip(right);
    CHECK(expected == actual && !memcmp(left, right, sizeof(left)));
    ++host_cases;
}
int main(void)
{
    WSADATA winsock;
    CHECK(!WSAStartup(MAKEWORD(2, 2), &winsock));
    for (unsigned round = 0; round < 4096; ++round) {
        struct sockaddr_storage storage;
        for (unsigned index = 0; index < sizeof(storage); ++index) ((uint8_t *)&storage)[index] = (uint8_t)next();
        static const unsigned short families[] = {AF_INET, AF_INET6, AF_UNSPEC, 777};
        storage.ss_family = families[round % 4];
        struct sockaddr *address = (struct sockaddr *)&storage;
        if (!(round % 17)) memset((uint8_t *)&storage + 4, 0, sizeof(storage) - 4);
        CHECK(reference_saport(address) == saport(address));
        CHECK(reference_sa_has_addr(address) == sa_has_addr(address));
        socket_cases += 2;
        for (size_t capacity = 0; capacity <= 64; ++capacity) {
            char left[96], right[96];
            memset(left, 0x69, sizeof(left));
            memcpy(right, left, sizeof(left));
            reference_ntop46(address, left + 8, capacity);
            ntop46(address, right + 8, capacity);
            CHECK(!memcmp(left, right, sizeof(left)));
            memset(left, 0x69, sizeof(left));
            memcpy(right, left, sizeof(left));
            reference_ntop46_port(address, left + 8, capacity);
            ntop46_port(address, right + 8, capacity);
            CHECK(!memcmp(left, right, sizeof(left)));
            memset(left, 0x69, sizeof(left));
            memcpy(right, left, sizeof(left));
            const struct in_addr *ipv4 = round % 4 < 2 ? &((struct sockaddr_in *)address)->sin_addr : NULL;
            const struct in6_addr *ipv6 = round % 2 ? &((struct sockaddr_in6 *)address)->sin6_addr : NULL;
            reference_ntopa46(ipv4, ipv6, left + 8, capacity);
            ntopa46(ipv4, ipv6, right + 8, capacity);
            CHECK(!memcmp(left, right, sizeof(left)));
            socket_cases += 3;
        }
        char host[160], ip[INET6_ADDRSTRLEN];
        unsigned family = round % 2 ? AF_INET : AF_INET6;
        CHECK(inet_ntop(family, (uint8_t *)&storage + 8, ip, sizeof(ip)));
        snprintf(host, sizeof(host), "%s%s%s%s", round % 3 ? " \t " : "", round % 2 ? "" : "[", ip,
            round % 2 ? ":65535" : "]:65535");
        compare_host(host);
        compare_host(ip);
        size_t length = next() % 120;
        static const char symbols[] = "0123456789abcdefABCDEF:.[]% \t";
        for (size_t index = 0; index < length; ++index) host[index] = symbols[next() % (sizeof(symbols) - 1)];
        host[length] = 0;
        compare_host(host);
    }
    static const char *const text[] = {
        "", " ", "\t", "a", "  a", "[]", "[", "[::1", "[::1]:443", " \t[::ffff:1.2.3.4]:9", "::1", " \t::1",
        "[invalid]suffix", "0.0.0.0:0", "  255.255.255.255:65535", "01.2.3.4:80", "1.2.3.4 ", "1.2.3.4:80:90",
        "[::1]anything", "fe80::1%4", "[fe80::1%4]:5", "[::]:", "127.0.0.1", "\t1.2.3.4", "имя:80"
    };
    for (unsigned index = 0; index < sizeof(text) / sizeof(*text); ++index) compare_host(text[index]);
    ntopa46(NULL, NULL, NULL, 0);
    WSACleanup();
    printf("PASS engine_address functions=6 socket_cases=%u host_cases=%u capacities=65\n", socket_cases, host_cases);
    return 0;
}
