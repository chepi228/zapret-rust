/* MIT. Provide the driver functions while Rust owns their startup order. */
#include "runtime_log_windows.h"
typedef struct {
    HANDLE (*open)(const char *);
    void (*close)(HANDLE);
    HANDLE (*event)(void);
} zapret_divert_handle_ops;
uint32_t zapret_divert_activate(HANDLE *, HANDLE *, uint32_t *, const char *, const char *,
    const zapret_divert_handle_ops *);
void zapret_divert_deactivate(HANDLE *, HANDLE *, void (*)(HANDLE));
typedef struct {
    char *(*message)(uint32_t);
    zapret_log_sink log;
    void (*release)(char *);
} zapret_divert_diagnostics;
_Static_assert(sizeof(zapret_divert_handle_ops) == 3 * sizeof(void *) &&
    sizeof(zapret_divert_diagnostics) == 3 * sizeof(void *), "Rust WinDivert handle ABI");
bool zapret_divert_open_report(uint32_t, const uint32_t *, const zapret_divert_diagnostics *);

static HANDLE windivert_open_driver(const char *filter)
{
    return WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
}
static void windivert_close_driver(HANDLE filter) { WinDivertClose(filter); }
static HANDLE windivert_create_receive_event(void) { return CreateEventW(NULL, TRUE, FALSE, NULL); }

static char *windivert_open_message(uint32_t error)
{
    LPSTR message = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, error, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPSTR)&message, 0, NULL);
    return message;
}
static void windivert_open_message_release(char *message) { LocalFree(message); }

void rawsend_cleanup(void)
{
    zapret_divert_deactivate(&w_filter, &w_receive_event, windivert_close_driver);
}
bool windivert_init(const char *filter)
{
    static const zapret_divert_handle_ops ops = {
        windivert_open_driver, windivert_close_driver, windivert_create_receive_event,
    };
    uint32_t status = zapret_divert_activate(&w_filter, &w_receive_event, &w_win32_error, filter,
        ZAPRET_WINDIVERT_MUTEX, &ops);
    static const zapret_divert_diagnostics diagnostics = {
        windivert_open_message, DLOG_ERR, windivert_open_message_release,
    };
    return zapret_divert_open_report(status, &w_win32_error, &diagnostics);
}
