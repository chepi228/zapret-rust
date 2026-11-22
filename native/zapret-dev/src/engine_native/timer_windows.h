/* MIT. Rust owns timer records; the LuaJIT adapter owns registry references. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct timer_pool timer_pool;
typedef struct {
    uint64_t id;
    uint64_t period;
    uint32_t fires;
    int32_t name_ref;
    int32_t func_ref;
    int32_t data_ref;
    uint32_t oneshot;
} zapret_timer_info;

_Static_assert(offsetof(zapret_timer_info, name_ref) == 20 &&
    offsetof(zapret_timer_info, oneshot) == 32 && sizeof(zapret_timer_info) == 40,
    "Rust timer descriptor ABI");

/* set returns -1 on failure, 0 on insertion, and 1 with the previous record. */
int zapret_timer_set(timer_pool **, const char *, const zapret_timer_info *, uint64_t, zapret_timer_info *);
int zapret_timer_get(const timer_pool *, const char *, zapret_timer_info *);
int zapret_timer_after(const timer_pool *, uint64_t, zapret_timer_info *);
int zapret_timer_remove(timer_pool **, uint64_t, zapret_timer_info *);
int zapret_timer_due(timer_pool *, uint64_t, uint64_t, zapret_timer_info *);
int zapret_timer_finish(timer_pool **, uint64_t, uint64_t, int, zapret_timer_info *);
uint64_t zapret_timer_next(const timer_pool *);

void TimerPoolDestroy(timer_pool **pool);
uint64_t TimerPoolNext(const timer_pool *pool, bool *dirty);
uint64_t TimerPoolRun(timer_pool **pool, bool *dirty, uint64_t now);
void zapret_timer_unref(const zapret_timer_info *timer);
