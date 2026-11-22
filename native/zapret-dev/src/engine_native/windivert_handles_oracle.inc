/* MIT. An unnamed mutex and real private receive events with a mock driver. */
static HANDLE w_receive_event;
static unsigned open_calls, close_calls, event_calls, fault;
static HANDLE factory(void) { return (HANDLE)(uintptr_t)0x3456; }
static HANDLE mock_open(const char *filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags)
{
    CHECK(!strcmp(filter, "false") && layer == WINDIVERT_LAYER_NETWORK && !priority && !flags);
    ++open_calls;
    DWORD error = fault == 1 ? ERROR_ACCESS_DENIED :
        fault == 3 ? ERROR_INVALID_IMAGE_HASH : ERROR_SUCCESS;
    SetLastError(error);
    return error ? INVALID_HANDLE_VALUE : factory();
}
static BOOL mock_close(HANDLE handle)
{
    CHECK(handle == factory());
    ++close_calls;
    return TRUE;
}
static HANDLE mock_event(LPSECURITY_ATTRIBUTES security, BOOL manual, BOOL signal, LPCWSTR name)
{
    CHECK(!security && manual && !signal && !name);
    ++event_calls;
    if (fault == 2) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    return CreateEventW(security, manual, signal, name);
}
#define WinDivertOpen mock_open
#define WinDivertClose mock_close
#define CreateEventW mock_event
#define windivert_init reference_windivert_init
#define rawsend_cleanup reference_rawsend_cleanup
#include "handle_reference.inc"
#undef windivert_init
#undef rawsend_cleanup
#define ZAPRET_WINDIVERT_MUTEX NULL
#include "windivert_handles_windows.inc"
#undef ZAPRET_WINDIVERT_MUTEX
#undef WinDivertOpen
#undef WinDivertClose
#undef CreateEventW

struct activation {
    unsigned opens, closes, events, reports, error;
    bool success, valid_pair;
};
static void activate(struct activation *out, bool actual, unsigned prior, unsigned current)
{
    w_filter = w_receive_event = NULL;
    open_calls = close_calls = event_calls = reports = 0;
    bool (*init)(const char *) = actual ? windivert_init : reference_windivert_init;
    void (*cleanup)(void) = actual ? rawsend_cleanup : reference_rawsend_cleanup;
    if (prior) {
        fault = prior - 1;
        CHECK(init("false") == (fault == 0));
    }
    fault = current;
    memset(out, 0, sizeof(*out));
    out->success = init("false");
    out->valid_pair = w_filter == factory() && w_receive_event;
    CHECK(out->success == out->valid_pair);
    if (out->success) {
        CHECK(WaitForSingleObject(w_receive_event, 0) == WAIT_TIMEOUT);
        CHECK(SetEvent(w_receive_event));
        CHECK(WaitForSingleObject(w_receive_event, 0) == WAIT_OBJECT_0);
        CHECK(WaitForSingleObject(w_receive_event, 0) == WAIT_OBJECT_0);
    } else {
        CHECK(!w_filter && !w_receive_event);
    }
    out->error = w_win32_error;
    cleanup();
    cleanup();
    CHECK(!w_filter && !w_receive_event);
    out->opens = open_calls;
    out->closes = close_calls;
    out->events = event_calls;
    out->reports = reports;
}
static void check_handles(void)
{
    unsigned total = 0;
    for (unsigned prior = 0; prior < 5; ++prior)
    for (unsigned current = 0; current < 4; ++current) {
        struct activation c, r;
        activate(&c, false, prior, current);
        activate(&r, true, prior, current);
        CHECK(!memcmp(&c, &r, sizeof(c)));
        ++total;
    }
    printf("PASS windivert_handles cases=%u\n", total);
}
