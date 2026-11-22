/* MIT. Bind the engine's existing C and LuaJIT operations to the Rust loop. */
#include "engine_loop_windows.h"

static bool loop_quitting(void)
{
    return bQuit;
}

static bool loop_timers_active(void)
{
    return params.timers != NULL;
}

static bool loop_timers_dirty(void)
{
    return params.timers_dirty;
}

static uint64_t loop_timers_next(void)
{
    return TimerPoolNext(params.timers, &params.timers_dirty);
}

static uint64_t loop_timers_run(uint64_t now)
{
    return TimerPoolRun(&params.timers, &params.timers_dirty, now);
}

const zapret_loop_timers zapret_capture_timers = {
    loop_timers_active, loop_timers_dirty, loop_timers_next, boottime_ms, loop_timers_run
};

static void loop_sleep_ms(uint64_t delay)
{
    struct timespec ts = {
        .tv_sec = (time_t)(delay / 1000U),
        .tv_nsec = delay % 1000U * 1000000U
    };
    nanosleep(&ts, NULL);
}

static void loop_prepare(void)
{
    ReloadCheck();
    lua_do_gc();
}

static void loop_idle_report(bool quitting)
{
    if (quitting)
        DLOG_CONDUP("quit requested\n");
    else
        DLOG("processing timers\n");
}

void NoInterceptLoop(void)
{
    zapret_idle_loop(&zapret_capture_timers, loop_quitting, loop_sleep_ms,
        loop_prepare, loop_idle_report);
}

static bool loop_activate(uint32_t *error)
{
    if (!windivert_init(params.windivert_filter)) {
        *error = w_win32_error;
        return false;
    }
    DLOG_CONDUP(params.intercept ? "windivert initialized. capture is started.\n" : "windivert initialized\n");
    if (!win_sandbox()) {
        *error = w_win32_error;
        DLOG_ERR("Cannot init Windows sandbox\n");
        return false;
    }
    /* Run Lua initialization after entering the Windows sandbox. */
    if (!params.L && !lua_init()) {
        *error = ERROR_INVALID_PARAMETER;
        return false;
    }
    do_fuzz();
    return true;
}

static bool loop_ipv6(const void *addresses, uint32_t index)
{
    return ((const WINDIVERT_ADDRESS *)addresses)[index].IPv6;
}

static uint8_t loop_process(const void *addresses, uint32_t index, uint32_t id,
    const uint8_t *packet, size_t length, uint8_t *modified, size_t *modified_length)
{
    const WINDIVERT_ADDRESS *wa = (const WINDIVERT_ADDRESS *)addresses + index;
    DLOG("\npacket: id=%u len=%zu %s IPv6=%u IPChecksum=%u TCPChecksum=%u UDPChecksum=%u IfIdx=%u.%u\n",
        id, length, wa->Outbound ? "outbound" : "inbound", wa->IPv6, wa->IPChecksum,
        wa->TCPChecksum, wa->UDPChecksum, wa->Network.IfIdx, wa->Network.SubIfIdx);
    if (wa->Impostor) {
        DLOG("windivert: passing impostor packet\n");
        return VERDICT_PASS;
    }
    char ifname[IFNAMSIZ];
    snprintf(ifname, sizeof(ifname), "%u.%u", wa->Network.IfIdx, wa->Network.SubIfIdx);
    uint32_t mark = 0;
    return processPacketData(&mark, wa->Outbound ? "" : ifname, wa->Outbound ? ifname : "",
        packet, length, modified, modified_length);
}

static bool loop_send(const void *addresses, uint32_t index, const uint8_t *packet, size_t length)
{
    return windivert_send(packet, length, (const WINDIVERT_ADDRESS *)addresses + index);
}

static void loop_report(uint32_t event, uint32_t id, size_t length, size_t other)
{
    switch (event) {
    case ZAPRET_NETWORK_WAITING:
        DLOG_CONDUP("logical network is not present. waiting it to appear.\n");
        break;
    case ZAPRET_NETWORK_PRESENT:
        DLOG_CONDUP("logical network now present\n");
        break;
    case ZAPRET_NETWORK_LOST:
        DLOG_CONDUP("\nlogical network disappeared. deinitializing windivert.\n");
        break;
    case ZAPRET_CAPTURE_QUIT:
        DLOG("quit requested\n");
        break;
    case ZAPRET_NO_INTERCEPT_QUIT:
        DLOG("no intercept quit\n");
        break;
    case ZAPRET_RECEIVE_OVERSIZE:
        DLOG("windivert: ignoring too large packet\n");
        break;
    case ZAPRET_INVALID_BATCH:
        DLOG_ERR("windivert: invalid batch (%zu bytes, %zu addresses)\n", length, other);
        break;
    case ZAPRET_INVALID_IPV4:
        DLOG_ERR("invalid ipv4 packet\n");
        break;
    case ZAPRET_INVALID_IPV6:
        DLOG_ERR("invalid ipv6 packet\n");
        break;
    case ZAPRET_PASS:
        DLOG("packet: id=%u reinject unmodified\n", id);
        break;
    case ZAPRET_MODIFY:
        DLOG("packet: id=%u reinject modified len %zu => %zu\n", id, length, other);
        break;
    case ZAPRET_DROP:
        DLOG("packet: id=%u drop\n", id);
        break;
    case ZAPRET_SEND_FAILED:
        DLOG_ERR("windivert: reinject of packet id=%u failed\n", id);
        break;
    case ZAPRET_INVALID_MODIFICATION:
        DLOG_ERR("windivert: packet id=%u invalid modified length %zu\n", id, other);
        break;
    }
}

static const zapret_capture_ops capture_ops = {
    .register_signals = catch_signals,
    .network_ready = logical_net_filter_match,
    .quitting = loop_quitting,
    .sleep_ms = loop_sleep_ms,
    .activate = loop_activate,
    .deactivate = rawsend_cleanup,
    .idle = NoInterceptLoop,
    .prepare = loop_prepare,
    .receive = zapret_capture_receive,
    .ipv6 = loop_ipv6,
    .process = loop_process,
    .send = loop_send,
    .report = loop_report,
};
