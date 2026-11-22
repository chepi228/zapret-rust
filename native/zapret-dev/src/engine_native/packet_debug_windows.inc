/* MIT. Check the packet fields read by the Rust packet diagnostic entry. */
_Static_assert(sizeof(struct dissect) == 14 * sizeof(void *) &&
    offsetof(struct dissect, ip) == 2 * sizeof(void *) && offsetof(struct dissect, ip6) == 3 * sizeof(void *) &&
    offsetof(struct dissect, proto) == 5 * sizeof(void *) && offsetof(struct dissect, tcp) == 6 * sizeof(void *) &&
    offsetof(struct dissect, udp) == 7 * sizeof(void *) && offsetof(struct dissect, icmp) == 8 * sizeof(void *) &&
    offsetof(struct dissect, data_payload) == 11 * sizeof(void *) &&
    offsetof(struct dissect, len_payload) == 12 * sizeof(void *) &&
    offsetof(struct dissect, frag) == 13 * sizeof(void *) && offsetof(struct dissect, frag_off) == 13 * sizeof(void *) + 2,
    "Rust packet diagnostic source ABI");

void packet_debug(bool replay, const struct dissect *packet);
