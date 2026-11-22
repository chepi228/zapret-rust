/* MIT. WinDivert bitfield observations remain native; Rust selects packet inputs. */
#include "runtime_log_windows.h"

typedef struct {uint32_t mark; const char *ifin, *ifout;} zapret_capture_packet_plan;
typedef struct {uint32_t index, subindex; bool outbound;} zapret_capture_interface;
typedef struct {
    zapret_capture_interface interface;
    bool ipv6, ip_checksum, tcp_checksum, udp_checksum;
} zapret_capture_observation;
typedef struct {
    bool (*impostor)(const void *);
    void (*interface)(const void *, zapret_capture_interface *);
    zapret_log_sink debug;
} zapret_capture_packet_ops;

_Static_assert(sizeof(zapret_capture_packet_plan) == 3 * sizeof(void *) &&
    offsetof(zapret_capture_packet_plan, ifin) == sizeof(void *) && IFNAMSIZ >= 22 &&
    sizeof(zapret_capture_interface) == 12 && offsetof(zapret_capture_interface, outbound) == 8 &&
    sizeof(zapret_capture_observation) == 16 && offsetof(zapret_capture_observation, ipv6) == 12 &&
    sizeof(zapret_capture_packet_ops) == 3 * sizeof(void *), "Rust native packet interface projection ABI");

bool zapret_prepare_capture_packet(uint32_t, size_t, const zapret_capture_observation *, const void *,
    const zapret_capture_packet_ops *, uint8_t *, size_t, zapret_capture_packet_plan *);

static bool capture_impostor(const void *address)
{
    return ((const WINDIVERT_ADDRESS *)address)->Impostor;
}

static void capture_interface(const void *address, zapret_capture_interface *interface)
{
    const WINDIVERT_ADDRESS *native = address;
    *interface = (zapret_capture_interface){native->Network.IfIdx, native->Network.SubIfIdx, native->Outbound};
}

static uint8_t loop_process(const void *addresses, uint32_t index, uint32_t id,
    const uint8_t *packet, size_t length, uint8_t *modified, size_t *modified_length)
{
    const WINDIVERT_ADDRESS *native = (const WINDIVERT_ADDRESS *)addresses + index;
    const zapret_capture_observation observation = {
        {native->Network.IfIdx, native->Network.SubIfIdx, native->Outbound},
        native->IPv6, native->IPChecksum, native->TCPChecksum, native->UDPChecksum,
    };
    static const zapret_capture_packet_ops ops = {capture_impostor, capture_interface, DLOG};
    char ifname[IFNAMSIZ];
    zapret_capture_packet_plan input;
    if (!zapret_prepare_capture_packet(id, length, &observation, native, &ops,
        (uint8_t *)ifname, sizeof(ifname), &input)) return VERDICT_PASS;
    return processPacketData(&input.mark, input.ifin, input.ifout, packet, length, modified, modified_length);
}
