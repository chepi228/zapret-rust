/* MIT. Regression comparisons use the pinned C functions and Rust ABI. */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define HASH_NONFATAL_OOM 1
#define HASH_FUNCTION HASH_BER
#include "uthash.h"
#include "kavl.h"
#include "pools_windows.h"
#define DLOG(...) ((void)0)
#define HOSTLIST_POOL_FLAG_STRICT_MATCH 1
struct kavl_bit_elem {
    unsigned int bitlen;
    uint8_t *data;
    KAVL_HEAD(struct kavl_bit_elem) head;
};
#include "reference.inc"

static uint32_t random_state = 0xd901efa3;
static uint32_t next_word(void)
{
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return random_state;
}
static size_t host_checks, ip_checks, enumeration_checks;

static int compare_prefixes(const struct kavl_bit_elem *reference, const struct zapret_ip_pool *rust, unsigned width)
{
    if (!!reference != !!rust) return 0;
    kavl_itr_t(kavl_bit) iterator;
    kavl_itr_first(kavl_bit, reference, &iterator);
    zapret_prefix_info actual;
    unsigned char previous[16];
    const unsigned char *after = NULL;
    for (const struct kavl_bit_elem *element = kavl_at(&iterator); element; element = kavl_at(&iterator)) {
        if (!zapret_ip_next(rust, after, &actual)) return 0;
        unsigned char expected[16] = {0};
        expand_bits(expected, element->data, element->bitlen, width / 8);
        if (actual.bits != element->bitlen || memcmp(expected, actual.address, sizeof(expected))) return 0;
        memcpy(previous, actual.address, sizeof(previous));
        after = previous;
        ++enumeration_checks;
        if (!kavl_itr_next(kavl_bit, &iterator)) break;
    }
    return !zapret_ip_next(rust, after, &actual);
}

int main(void)
{
    for (unsigned run = 0; run < 250; ++run) {
        struct reference_host_pool *reference = NULL;
        struct hostlist_pool *rust = NULL;
        for (unsigned step = 0; step < 40; ++step) {
            char domain[80], host[100];
            snprintf(domain, sizeof(domain), "%c%u.%u.example", 'a' + step % 20, next_word() % 8, run % 4);
            if (step % 7 == 0) strcpy(domain, step % 2 ? "" : "example");
            uint32_t flags = next_word() & 1;
            if (!reference_HostlistPoolAddStr(&reference, domain, flags) ||
                !zapret_host_add(&rust, (const unsigned char *)domain, strlen(domain), flags)) return 1;
            if (step % 3 == 0) {
                reference_HostlistPoolAddStr(&reference, domain, flags ^ 1);
                zapret_host_add(&rust, (const unsigned char *)domain, strlen(domain), flags ^ 1);
            }
            for (unsigned kind = 0; kind < 5; ++kind) {
                switch (kind) {
                case 0: snprintf(host, sizeof(host), "%s", domain); break;
                case 1: snprintf(host, sizeof(host), "www.%s", domain); break;
                case 2: snprintf(host, sizeof(host), "wwwx%s", domain); break;
                case 3: snprintf(host, sizeof(host), "%s.", domain); break;
                default: snprintf(host, sizeof(host), "%u.EXAMPLE", next_word() % 32); break;
                }
                for (unsigned exact = 0; exact < 2; ++exact) {
                    int expected = reference_SearchHostList(reference, host, exact);
                    int actual = zapret_host_match(rust, host, exact, NULL);
                    if (actual != expected) {
                        printf("FAIL host run %u step %u input '%s' exact %u C %d Rust %d\n",
                            run, step, host, exact, expected, actual);
                        return 1;
                    }
                    ++host_checks;
                }
            }
        }
        reference_HostlistPoolDestroy(&reference);
        zapret_host_destroy(&rust);
        if (rust) return 1;
    }

    for (unsigned width = 32; width <= 128; width += 96) {
        for (unsigned run = 0; run < 100; ++run) {
            struct kavl_bit_elem *reference = NULL;
            struct zapret_ip_pool *rust = NULL;
            for (unsigned step = 0; step < 90; ++step) {
                unsigned char address[16];
                for (unsigned i = 0; i < sizeof(address); ++i) address[i] = next_word();
                if (step % 4) memset(address, 0x20, width == 32 ? 2 : 6);
                uint8_t bits = step == 89 ? 0 : next_word() % (width + 1);
                if (run >= 50 && step < 89)
                    bits = width == 32 ? 16 + next_word() % 17 : 64 + next_word() % 65;
                if (!ipset_kavl_add(&reference, address, bits) || !zapret_ip_add(&rust, address, width, bits)) return 1;
                if (!compare_prefixes(reference, rust, width)) {
                    printf("FAIL enumeration width %u run %u step %u prefix %u\n", width, run, step, bits);
                    return 1;
                }
                for (unsigned probe = 0; probe < 30; ++probe) {
                    if (probe % 3) for (unsigned i = 0; i < width / 8; ++i) address[i] = next_word();
                    uint8_t length = probe % 3 ? width : next_word() % 256;
                    int expected = kavl_bit_get(reference, address, length) != NULL;
                    int actual = zapret_ip_check(rust, address, length);
                    if (actual != expected) {
                        printf("FAIL IP width %u run %u step %u query %u C %d Rust %d\n",
                            width, run, step, length, expected, actual);
                        return 1;
                    }
                    ++ip_checks;
                }
            }
            kavl_bit_destroy(&reference);
            zapret_ip_destroy(&rust);
            if (rust) return 1;
        }
    }
    printf("PASS %zu host decisions, %zu IP decisions, %zu ordered prefix entries against pinned C\n",
        host_checks, ip_checks, enumeration_checks);
    return 0;
}
