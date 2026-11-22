/* MIT. Preserve the upstream names for engine and Lua call sites. */
#include "filters_windows.h"
bool pf_parse(const char *s, port_filter *out) { return zapret_pf_parse(s, out); }
bool pf_match(uint16_t port, const port_filter *filter) { return zapret_pf_match(port, filter); }
bool icf_parse(const char *s, icmp_filter *out) { return zapret_icf_parse(s, out); }
bool icf_match(uint8_t type, uint8_t code, const icmp_filter *filter) { return zapret_icf_match(type, code, filter); }
bool ipp_parse(const char *s, ipp_filter *out) { return zapret_ipp_parse(s, out); }
bool ipp_match(uint8_t protocol, const ipp_filter *filter) { return zapret_ipp_match(protocol, filter); }
bool packet_range_parse(const char *s, struct packet_range *out) { return zapret_packet_range_parse(s, out); }
