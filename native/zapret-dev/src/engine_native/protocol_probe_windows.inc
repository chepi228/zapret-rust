/* MIT. Ordered detector dispatch is implemented by Rust. */
void zapret_protocol_probe(const t_protocol_probe *, int32_t, const uint8_t *, size_t,
    uint32_t *, uint32_t *, uint32_t *, uint64_t, void (*)(uint32_t));

_Static_assert(sizeof(t_protocol_probe) == 24 && offsetof(t_protocol_probe, l7) == 4 &&
    offsetof(t_protocol_probe, check) == 8 && offsetof(t_protocol_probe, l7match) == 16 &&
    sizeof(t_l7proto) == 4 && sizeof(t_l7payload) == 4 && L7_UNKNOWN == 1,
    "Rust protocol probe ABI");

static void protocol_probe_report(uint32_t payload)
{
    DLOG("packet contains %s payload\n", l7payload_str(payload));
}
static void protocol_probe(const t_protocol_probe *probe, int count, const uint8_t *data, size_t length,
    t_ctrack *track, t_l7proto *protocol, t_l7payload *payload)
{
    zapret_protocol_probe(probe, count, data, length,
        track ? (uint32_t *)&track->l7proto : NULL, (uint32_t *)protocol, (uint32_t *)payload,
        params.payload_disable, params.debug ? protocol_probe_report : NULL);
}
