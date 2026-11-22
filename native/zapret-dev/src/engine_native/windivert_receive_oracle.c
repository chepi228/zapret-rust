/* MIT. Exercise the Rust receive state machine using private overlapped pipes. */
#include "engine_loop_windows.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef enum {
    IMMEDIATE,
    PENDING,
    TIMED,
    LATE_POLL,
    REPLACED_TIMER,
    QUIT_BEFORE_SUBMIT,
    QUIT_PENDING,
    RECONNECT_PENDING,
    DISCONNECT_PENDING,
    OVERSIZE,
    SHUTDOWN,
    INVALID_LENGTH,
    INVALID_ADDRESSES,
    BROKEN_EVENT,
} receive_case;

static receive_case scenario;
static HANDLE writer;
static uint32_t polls, submissions, runs;
static bool timer_active;
static uint64_t clock_ms;
static const uint8_t fixture[] = { 1, 3, 5, 7 };

static void write_fixture(void)
{
    DWORD written = 0;
    assert(WriteFile(writer, fixture, sizeof(fixture), &written, NULL));
    assert(written == sizeof(fixture));
}

static bool active(void) { return timer_active; }
static bool dirty(void) { return scenario == REPLACED_TIMER && runs == 0; }
static uint64_t next(void)
{
    return clock_ms + (scenario == REPLACED_TIMER ? 0 : scenario == LATE_POLL ? 1000 : 10);
}
static uint64_t now(void) { return clock_ms; }
static uint64_t run(uint64_t time)
{
    assert(timer_active && time == clock_ms);
    ++runs;
    timer_active = false;
    write_fixture();
    return 0;
}

static uint32_t poll(void)
{
    ++polls;
    if (scenario == QUIT_BEFORE_SUBMIT) return ZAPRET_QUIT;
    if (submissions == 0) return ZAPRET_BATCH;
    switch (scenario) {
    case PENDING: write_fixture(); break;
    case TIMED: clock_ms += 10; break;
    case LATE_POLL: clock_ms += 2000; break;
    case QUIT_PENDING: return ZAPRET_QUIT;
    case RECONNECT_PENDING: return ZAPRET_RECONNECT;
    case DISCONNECT_PENDING:
        assert(CloseHandle(writer));
        writer = NULL;
        break;
    default: assert(false);
    }
    return ZAPRET_BATCH;
}

static uint32_t submit(HANDLE reader, uint8_t *data, uint32_t capacity,
    uint32_t *received, void *addresses, uint32_t *address_bytes, OVERLAPPED *overlapped)
{
    ++submissions;
    assert(capacity == 128 && *address_bytes == 160);
    if (scenario == OVERSIZE) return ERROR_INSUFFICIENT_BUFFER;
    if (scenario == SHUTDOWN) return ERROR_NO_DATA;
    *address_bytes = scenario == INVALID_ADDRESSES ? 79 : 80;
    memset(addresses, 0xf5, 80);
    if (scenario == INVALID_LENGTH) {
        *received = capacity + 1;
        return 0;
    }
    if (ReadFile(reader, data, capacity, NULL, overlapped)) {
        DWORD length = 0;
        assert(GetOverlappedResult(reader, overlapped, &length, FALSE));
        *received = length;
        assert(scenario == IMMEDIATE || scenario == REPLACED_TIMER || scenario == INVALID_ADDRESSES);
        return 0;
    }
    DWORD error = GetLastError();
    assert(error == ERROR_IO_PENDING);
    return error;
}

static HANDLE open_pipe(void)
{
    static unsigned sequence;
    wchar_t name[96];
    swprintf(name, sizeof(name) / sizeof(*name),
        L"\\\\.\\pipe\\zapret-receive-check-%lu-%llu-%u",
        GetCurrentProcessId(), (unsigned long long)GetTickCount64(), ++sequence);
    HANDLE reader = CreateNamedPipeW(name, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED |
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
        1, 256, 256, 0, NULL);
    assert(reader != INVALID_HANDLE_VALUE);
    writer = CreateFileW(name, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    assert(writer != INVALID_HANDLE_VALUE);
    return reader;
}

static void check_case(receive_case which, uint32_t expected_status, uint32_t expected_error,
    uint32_t expected_polls, uint32_t expected_submissions, uint32_t expected_runs)
{
    scenario = which;
    polls = submissions = runs = 0;
    timer_active = which == TIMED || which == LATE_POLL || which == REPLACED_TIMER;
    clock_ms = 100;
    uint64_t deadline = which == REPLACED_TIMER ? 1234 : 0;
    static const zapret_loop_timers timers = { active, dirty, next, now, run };
    static const zapret_win_receive_ops ops = { &timers, poll, submit };
    HANDLE reader = open_pipe();
    HANDLE event = which == BROKEN_EVENT ? NULL : CreateEventW(NULL, TRUE, TRUE, NULL);
    assert(event || which == BROKEN_EVENT);
    if (which == IMMEDIATE || which == INVALID_ADDRESSES) write_fixture();
    uint8_t data[128] = {0}, addresses[160] = {0};
    zapret_capture_batch batch = { sizeof(data), 2, 0 };
    uint32_t status = zapret_win_receive(&ops, reader, event, data, addresses, &batch, &deadline);
    assert(status == expected_status && batch.error == expected_error);
    assert(polls == expected_polls && submissions == expected_submissions && runs == expected_runs);
    if (expected_status == ZAPRET_BATCH) {
        assert(batch.count == 1 && batch.length == sizeof(fixture));
        assert(!memcmp(data, fixture, sizeof(fixture)));
        assert(addresses[0] == 0xf5 && addresses[79] == 0xf5 && addresses[80] == 0);
    }
    if (which == QUIT_PENDING || which == RECONNECT_PENDING) {
        /* The same pipe, event and buffers can be reused immediately. A read
           left pending by the previous call would consume the fixture first. */
        scenario = IMMEDIATE;
        submissions = 0;
        write_fixture();
        batch = (zapret_capture_batch){ sizeof(data), 2, 0 };
        assert(zapret_win_receive(&ops, reader, event, data, addresses, &batch, &deadline) == ZAPRET_BATCH);
        assert(batch.length == sizeof(fixture) && !memcmp(data, fixture, sizeof(fixture)));
    }
    if (event) assert(CloseHandle(event));
    assert(CloseHandle(reader));
    if (writer) assert(CloseHandle(writer));
}

void check_overlapped_receive(void)
{
    check_case(IMMEDIATE, ZAPRET_BATCH, 0, 1, 1, 0);
    check_case(PENDING, ZAPRET_BATCH, 0, 2, 1, 0);
    check_case(TIMED, ZAPRET_BATCH, 0, 2, 1, 1);
    check_case(LATE_POLL, ZAPRET_BATCH, 0, 2, 1, 1);
    check_case(REPLACED_TIMER, ZAPRET_BATCH, 0, 1, 1, 1);
    check_case(QUIT_BEFORE_SUBMIT, ZAPRET_QUIT, 0, 1, 0, 0);
    check_case(QUIT_PENDING, ZAPRET_QUIT, 0, 2, 1, 0);
    check_case(RECONNECT_PENDING, ZAPRET_RECONNECT, 0, 2, 1, 0);
    check_case(DISCONNECT_PENDING, ZAPRET_RECEIVE_ERROR, ERROR_BROKEN_PIPE, 2, 1, 0);
    check_case(OVERSIZE, ZAPRET_OVERSIZE, ERROR_INSUFFICIENT_BUFFER, 1, 1, 0);
    check_case(SHUTDOWN, ZAPRET_SHUTDOWN, ERROR_NO_DATA, 1, 1, 0);
    check_case(INVALID_LENGTH, ZAPRET_RECEIVE_ERROR, ERROR_INVALID_DATA, 1, 1, 0);
    check_case(INVALID_ADDRESSES, ZAPRET_RECEIVE_ERROR, ERROR_INVALID_DATA, 1, 1, 0);
    check_case(BROKEN_EVENT, ZAPRET_RECEIVE_ERROR, ERROR_INVALID_HANDLE, 1, 0, 0);
    puts("PASS 14 receive cases with private Windows pipes, including delayed timer wakeup and immediate buffer reuse after quit and reconnect");
}
