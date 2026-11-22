/* MIT. Bind driver submission and the existing logical network check. */
#include "engine_loop_windows.h"

static uint32_t receive_poll(void)
{
    /* Preserve the original yield and the rate-limited network observation. */
    usleep(0);
    if (bQuit) return ZAPRET_QUIT;
    if (!logical_net_filter_match_rate_limited()) return ZAPRET_RECONNECT;
    return ZAPRET_BATCH;
}

static uint32_t receive_submit(HANDLE filter, uint8_t *packet, uint32_t capacity, uint32_t *received,
    void *addresses, uint32_t *address_bytes, OVERLAPPED *overlapped)
{
    if (WinDivertRecvEx(filter, packet, capacity, received, 0, addresses, address_bytes, overlapped))
        return ERROR_SUCCESS;
    return GetLastError();
}

uint32_t zapret_capture_receive(void *addresses, uint8_t *packet,
    zapret_capture_batch *batch, uint64_t *deadline)
{
    static const zapret_win_receive_ops ops = {
        &zapret_capture_timers, receive_poll, receive_submit
    };
    uint32_t status = zapret_win_receive(&ops, w_filter, w_receive_event, packet,
        addresses, batch, deadline);
    return zapret_win_receive_report(status, EIO, ESHUTDOWN, DLOG_ERR);
}
