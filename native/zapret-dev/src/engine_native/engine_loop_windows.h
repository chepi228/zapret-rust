/* MIT. C adapters for the native Rust engine loop. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "runtime_log_windows.h"

#define ZAPRET_CAPTURE_ADDRESS_COUNT 128

enum zapret_receive_status {
    ZAPRET_BATCH,
    ZAPRET_OVERSIZE,
    ZAPRET_RECONNECT,
    ZAPRET_QUIT,
    ZAPRET_RECEIVE_ERROR,
    ZAPRET_SHUTDOWN,
};

enum zapret_capture_event {
    ZAPRET_NETWORK_WAITING,
    ZAPRET_NETWORK_PRESENT,
    ZAPRET_NETWORK_LOST,
    ZAPRET_CAPTURE_QUIT,
    ZAPRET_NO_INTERCEPT_QUIT,
    ZAPRET_RECEIVE_OVERSIZE,
    ZAPRET_INVALID_BATCH,
    ZAPRET_INVALID_IPV4,
    ZAPRET_INVALID_IPV6,
    ZAPRET_PASS,
    ZAPRET_MODIFY,
    ZAPRET_DROP,
    ZAPRET_SEND_FAILED,
    ZAPRET_INVALID_MODIFICATION,
};

typedef struct {
    size_t length;
    uint32_t count;
    uint32_t error;
} zapret_capture_batch;

typedef struct {
    bool (*active)(void);
    bool (*dirty)(void);
    uint64_t (*next)(void);
    uint64_t (*now)(void);
    uint64_t (*run)(uint64_t);
} zapret_loop_timers;

typedef struct {
    const zapret_loop_timers *timers;
    uint32_t (*poll)(void);
    uint32_t (*submit)(HANDLE, uint8_t *, uint32_t, uint32_t *,
        void *, uint32_t *, OVERLAPPED *);
} zapret_win_receive_ops;

typedef struct {
    void (*register_signals)(void);
    bool (*network_ready)(void);
    bool (*quitting)(void);
    void (*sleep_ms)(uint64_t);
    bool (*activate)(uint32_t *);
    void (*deactivate)(void);
    void (*idle)(void);
    void (*prepare)(void);
    uint32_t (*receive)(void *, uint8_t *, zapret_capture_batch *, uint64_t *);
    bool (*ipv6)(const void *, uint32_t);
    uint8_t (*process)(const void *, uint32_t, uint32_t, const uint8_t *,
        size_t, uint8_t *, size_t *);
    bool (*send)(const void *, uint32_t, const uint8_t *, size_t);
    void (*report)(uint32_t, uint32_t, size_t, size_t);
} zapret_capture_ops;

_Static_assert(sizeof(zapret_capture_batch) == sizeof(size_t) + 8 &&
    offsetof(zapret_capture_batch, count) == sizeof(size_t),
    "Rust capture batch ABI");
_Static_assert(sizeof(zapret_loop_timers) == 5 * sizeof(void *) &&
    sizeof(zapret_win_receive_ops) == 3 * sizeof(void *) &&
    sizeof(zapret_capture_ops) == 13 * sizeof(void *), "Rust capture callbacks ABI");

uint32_t zapret_capture_loop(const zapret_capture_ops *, void *, bool);
void zapret_idle_loop(const zapret_loop_timers *, bool (*)(void), void (*)(uint64_t),
    void (*)(void), void (*)(bool));
uint32_t zapret_win_receive(const zapret_win_receive_ops *, HANDLE, HANDLE, uint8_t *,
    void *, zapret_capture_batch *, uint64_t *);
uint32_t zapret_win_receive_report(uint32_t, int, int, zapret_log_sink);

extern const zapret_loop_timers zapret_capture_timers;
uint32_t zapret_capture_receive(void *, uint8_t *, zapret_capture_batch *, uint64_t *);
