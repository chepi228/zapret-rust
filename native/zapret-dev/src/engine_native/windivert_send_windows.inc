/* MIT. Driver submission and diagnostics around the Rust send path. */
#include "runtime_log_windows.h"

_Static_assert(sizeof(WINDIVERT_ADDRESS) == 80 && offsetof(WINDIVERT_ADDRESS, Network) == 16 &&
    offsetof(WINDIVERT_DATA_NETWORK, IfIdx) == 0 && offsetof(WINDIVERT_DATA_NETWORK, SubIfIdx) == 4 &&
    sizeof(((struct sockaddr *)0)->sa_family) == 2 && AF_INET6 == 23, "Rust WinDivert send ABI");

bool zapret_divert_address(uint16_t, const char *, WINDIVERT_ADDRESS *);
bool zapret_divert_send(HANDLE, const uint8_t *, size_t, const WINDIVERT_ADDRESS *,
    uint32_t *, BOOL (*)(HANDLE, const uint8_t *, uint32_t, const WINDIVERT_ADDRESS *));
typedef struct {
    BOOL (*submit)(HANDLE, const uint8_t *, uint32_t, const WINDIVERT_ADDRESS *);
    void (*invalid_interface)(void);
    zapret_log_sink error;
} zapret_rawsend_ops;

bool zapret_divert_rawsend(uint16_t, const char *, const uint8_t *, size_t, HANDLE const *,
    uint32_t *, const zapret_rawsend_ops *);

static BOOL submit_windivert_send(HANDLE handle, const uint8_t *data, uint32_t length,
    const WINDIVERT_ADDRESS *address)
{
    return WinDivertSend(handle, data, length, NULL, address);
}
static void rawsend_invalid_interface(void)
{
    errno = EINVAL;
}

bool windivert_send(const uint8_t *data, size_t length, const WINDIVERT_ADDRESS *address)
{
    return zapret_divert_send(w_filter, data, length, address, &w_win32_error, submit_windivert_send);
}
bool rawsend(const struct sockaddr *destination, uint32_t mark, const char *ifout,
    const void *data, size_t length)
{
    (void)mark;
    static const zapret_rawsend_ops ops = {
        .submit = submit_windivert_send,
        .invalid_interface = rawsend_invalid_interface,
        .error = DLOG_ERR,
    };
    return zapret_divert_rawsend(destination->sa_family, ifout, data, length, &w_filter,
        &w_win32_error, &ops);
}
