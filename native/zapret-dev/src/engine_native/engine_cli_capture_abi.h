/* MIT. Windows CLI storage passed to the Rust capture option binding. */
#pragma once
#include <stddef.h>
#include "engine_config_exports_abi.h"

typedef struct {
    char *save;
    size_t save_capacity;
    bool *ipv4, *ipv6, *lan, *loopback, *empty, *duplicate;
    unsigned *index, *sub_index, *hashes;
} zapret_capture_cli;

_Static_assert(sizeof(zapret_capture_cli) == 11 * sizeof(void *) && sizeof(unsigned) == 4 &&
    offsetof(zapret_capture_cli, save_capacity) == sizeof(void *) &&
    offsetof(zapret_capture_cli, index) == 8 * sizeof(void *) &&
    offsetof(zapret_capture_cli, hashes) == 10 * sizeof(void *), "Rust capture CLI storage");
_Static_assert(WINDIVERT_MAX == 65536 && WINDIVERT_PORTFILTER_MAX == 4096 && WF_COUNT == 16 &&
    WF_TCP_IN == 0 && WF_UDP_IN == 1 && WF_TCP_OUT == 2 && WF_UDP_OUT == 3 &&
    WF_ICMP_IN == 4 && WF_ICMP_OUT == 5 && WF_IPP_IN == 6 && WF_IPP_OUT == 7 &&
    WF_RAWF_PART == 9 && WF_RAWF_FILTER == 10 && GLOBAL_SSID_FILTER == 11 &&
    GLOBAL_SSID_FILTER_NEG == 12 && GLOBAL_NLM_FILTER == 13 && GLOBAL_NLM_FILTER_NEG == 14 && WF_RAWF == 15,
    "Rust capture option hash slots");

int engine_capture_option(int index, const char *text, zapret_capture_cli *state);
