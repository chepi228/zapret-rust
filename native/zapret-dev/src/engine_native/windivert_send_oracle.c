/* MIT. WinDivert boundary test with a mock submission function. */
#include <errno.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include "windivert/windivert.h"
#undef main

static unsigned cases, calls, failure, reports;
static bool check_send_report;
static uint32_t w_win32_error;
static HANDLE w_filter = (HANDLE)(uintptr_t)0x1234;
static uint8_t data[37];
static WINDIVERT_ADDRESS submitted;
#define CHECK(condition) do { \
    if (!(condition)) { fprintf(stderr, "FAIL send case %u line %d: %s\n", cases, __LINE__, #condition); exit(1); } \
} while (0)
static BOOL mock_send(HANDLE handle, const void *packet, UINT length, UINT *sent,
    const WINDIVERT_ADDRESS *address)
{
    CHECK(handle == w_filter && packet == data && length == sizeof(data) && !sent && address);
    memcpy(&submitted, address, sizeof(submitted));
    ++calls;
    SetLastError(calls == failure ? UINT32_C(0xa0000025) : ERROR_SUCCESS);
    return calls == failure ? FALSE : TRUE;
}
int DLOG_ERR(const char *format, ...)
{
    const bool image_hash_hint =
        !strcmp(format, "windivert: try to disable secure boot and install OS patches\n");
    CHECK(!strcmp(format, "windivert send error. win32 code %u\n")
        || !strcmp(format, "windivert: error opening filter: %s") || image_hash_hint);
    if (image_hash_hint) CHECK(!check_send_report && w_win32_error == ERROR_INVALID_IMAGE_HASH);
    if (check_send_report) {
        CHECK(!strcmp(format, "windivert send error. win32 code %u\n"));
        va_list args;
        va_start(args, format);
        unsigned code = va_arg(args, unsigned);
        va_end(args);
        CHECK(calls == failure && errno == ERANGE);
        CHECK(code == UINT32_C(0xa0000025) && w_win32_error == code && GetLastError() == code);
    }
    ++reports;
    return 0;
}
#define WinDivertSend mock_send
#define rawsend reference_rawsend
#define rawsend_rep reference_rawsend_rep
#define windivert_send reference_windivert_send
#include "send_reference.inc"
#include "send_repeat_reference.inc"
#undef rawsend
#undef rawsend_rep
#undef windivert_send
#include "windivert_send_windows.inc"
#include "rawsend_repeat_windows.inc"
#undef WinDivertSend

struct outcome {
    WINDIVERT_ADDRESS address;
    unsigned calls, reports, win_error;
    int code;
    bool success;
};
static void result(struct outcome *out, const struct sockaddr *destination, const char *interface,
    int repeats, bool actual)
{
    memset(out, 0, sizeof(*out));
    memset(&submitted, 0, sizeof(submitted));
    calls = reports = 0;
    w_win32_error = 349;
    errno = ERANGE;
    check_send_report = true;
    out->success = (actual ? rawsend_rep : reference_rawsend_rep)(
        repeats, destination, 7, interface, data, sizeof(data));
    check_send_report = false;
    out->code = errno;
    out->calls = calls;
    out->reports = reports;
    out->win_error = w_win32_error;
    out->address = submitted;
}
#include "windivert_handles_oracle.inc"
#include "network_gate_oracle.inc"

int main(void)
{
    static const char *const interfaces[] = {NULL, "", "1.0", "0.0", "394.41", "4294967295.4294967295",
        " 01.+02", "+1. 2", "1.2 suffix", "1..2", "1.  ", "1 .2", ".1", "Ethernet", "1", "0x1.2"};
    struct sockaddr address = {0};
    for (unsigned version = 0; version < 2; ++version) {
        address.sa_family = version ? AF_INET6 : AF_INET;
        for (unsigned i = 0; i < sizeof(interfaces) / sizeof(*interfaces); ++i)
        for (int repeats = -1; repeats <= 6; ++repeats)
        for (failure = 0; failure <= 7; ++failure) {
            struct outcome c, r;
            result(&c, &address, interfaces[i], repeats, false);
            result(&r, &address, interfaces[i], repeats, true);
            CHECK(c.success == r.success && c.calls == r.calls && c.reports == r.reports);
            CHECK(c.code == r.code && c.win_error == r.win_error);
            CHECK(!memcmp(&c.address, &r.address, sizeof(c.address)));
            ++cases;
        }
    }
    calls = 0;
    CHECK(!rawsend(&address, 0, "4294967296.1", data, sizeof(data)) && errno == EINVAL);
    CHECK(!rawsend(&address, 0, "1.4294967296", data, sizeof(data)) && errno == EINVAL);
    CHECK(!rawsend(&address, 0, "-4294967295.1", data, sizeof(data)) && errno == EINVAL);
    CHECK(!windivert_send(data, (size_t)UINT32_MAX + 1, &submitted));
    CHECK(!calls && w_win32_error == ERROR_INVALID_PARAMETER && GetLastError() == ERROR_INVALID_PARAMETER);
    printf("PASS windivert_send cases=%u boundary_cases=4\n", cases);
    check_handles();
    check_network_gate();
    return 0;
}
