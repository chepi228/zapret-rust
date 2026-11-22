/* MIT. Compare non-capturing bindings with a private clock and timer slots. */
#include "windows_engine_idle_abi.h"
#include "nfqws.h"
#include <limits.h>
#include <stdatomic.h>
#include <string.h>
#undef main

struct params_s params;
_Atomic(sig_atomic_t) bQuit;

enum event { DEBUG_LOG, NEXT, CLOCK, SLEEP, COLLECT, RUN, CONSOLE_LOG };
enum scenario {
    EMPTY, EARLY_QUIT, WAIT_FOR_TIMER, QUIT_IN_SLEEP, ALREADY_DUE, REPLACE_IN_LOG,
    REMOVE_IN_NEXT, REPLACE_IN_GC, REMOVE_IN_GC, QUIT_IN_GC, DIRECT_SLEEP
};

struct observation {
    uint64_t first, second;
    unsigned event, dirty;
};

struct sample {
    struct observation events[24];
    uint64_t now;
    unsigned used, pool, dirty, quitting;
};

static struct sample *active;
static enum scenario current;
static int tokens[2];
static uint64_t next_time;

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL idle fixture case=%u line=%d: %s\n", (unsigned)current, __LINE__, #condition); \
    exit(1); \
} } while (0)

static timer_pool *timer_slot(unsigned index)
{
    return (timer_pool *)&tokens[index];
}

static unsigned pool_number(const timer_pool *pool)
{
    if (!pool) return 0;
    CHECK(pool == timer_slot(0) || pool == timer_slot(1));
    return pool == timer_slot(0) ? 1 : 2;
}

static void record(enum event event, uint64_t first, uint64_t second)
{
    CHECK(active && active->used < sizeof(active->events) / sizeof(*active->events));
    active->events[active->used++] = (struct observation){
        .first = first, .second = second, .event = event, .dirty = params.timers_dirty
    };
}

int DLOG(const char *format, ...)
{
    CHECK(!strcmp(format, "processing timers\n"));
    record(DEBUG_LOG, 0, 0);
    if (current == REPLACE_IN_LOG) params.timers = timer_slot(1);
    return 0;
}

int DLOG_CONDUP(const char *format, ...)
{
    CHECK(!strcmp(format, "quit requested\n"));
    record(CONSOLE_LOG, 0, 0);
    return 0;
}

uint64_t boottime_ms(void)
{
    record(CLOCK, active->now, 0);
    return active->now;
}

static uint64_t fixture_next(const timer_pool *pool, bool *dirty)
{
    CHECK(dirty == &params.timers_dirty);
    record(NEXT, pool_number(pool), next_time);
    *dirty = false;
    if (current == REMOVE_IN_NEXT) params.timers = NULL;
    return next_time;
}

uint64_t __wrap_zapret_timer_next_dirty(const timer_pool *pool, bool *dirty)
{
    return fixture_next(pool, dirty);
}

uint64_t TimerPoolRun(timer_pool **pool, bool *dirty, uint64_t now)
{
    CHECK(pool == &params.timers && dirty == &params.timers_dirty);
    record(RUN, pool_number(*pool), now);
    *pool = NULL;
    *dirty = false;
    return 0;
}

void lua_do_gc(void)
{
    record(COLLECT, pool_number(params.timers), 0);
    if (current == REPLACE_IN_GC) {
        params.timers = timer_slot(1);
        params.timers_dirty = true;
    }
    if (current == REMOVE_IN_GC) params.timers = NULL;
    if (current == QUIT_IN_GC) atomic_store(&bQuit, 1);
}

static int observe_sleep(int64_t seconds, long nanoseconds, const void *remaining)
{
    CHECK(seconds >= 0 && nanoseconds >= 0 && nanoseconds < 1000000000L && !remaining);
    record(SLEEP, (uint64_t)seconds, (uint64_t)nanoseconds);
    if (current != DIRECT_SLEEP) {
        active->now += (uint64_t)seconds * 1000 + (uint64_t)nanoseconds / 1000000;
        if (current == QUIT_IN_SLEEP) atomic_store(&bQuit, -1);
    }
    return -1;
}

static int fixture_nanosleep(const struct timespec *requested, struct timespec *remaining)
{
    return observe_sleep(requested->tv_sec, requested->tv_nsec, remaining);
}

int __wrap_nanosleep64(const struct _timespec64 *requested, struct _timespec64 *remaining)
{
    return observe_sleep(requested->tv_sec, requested->tv_nsec, remaining);
}

#undef TimerPoolNext
#define TimerPoolNext fixture_next
#define nanosleep fixture_nanosleep
#define ReloadCheck() ((void)0)
#define loop_quitting reference_quitting
#define loop_sleep_ms reference_sleep
#define loop_prepare reference_prepare
#define zapret_capture_timers reference_timers
#define NoInterceptLoop reference_idle
#include "engine_idle_reference.inc"
#undef NoInterceptLoop
#undef zapret_capture_timers
#undef loop_prepare
#undef loop_sleep_ms
#undef loop_quitting
#undef ReloadCheck
#undef nanosleep
#undef TimerPoolNext

static void begin(struct sample *sample)
{
    active = sample;
    sample->now = 100;
    params.timers = current == EMPTY ? NULL : timer_slot(0);
    params.timers_dirty = true;
    atomic_store(&bQuit, current == EARLY_QUIT ? INT_MIN : 0);
    switch (current) {
    case WAIT_FOR_TIMER: next_time = 170; break;
    case QUIT_IN_SLEEP: next_time = UINT64_MAX; break;
    case ALREADY_DUE: next_time = 99; break;
    default: next_time = 100; break;
    }
}

static void finish(void)
{
    active->pool = pool_number(params.timers);
    active->dirty = params.timers_dirty;
    active->quitting = atomic_load(&bQuit) != 0;
    active = NULL;
}

static void check_idle(void)
{
    for (current = EMPTY; current < DIRECT_SLEEP; ++current) {
        struct sample reference = {0}, rust = {0};
        begin(&reference);
        reference_idle();
        finish();
        begin(&rust);
        NoInterceptLoop();
        finish();
        CHECK(!memcmp(&reference, &rust, sizeof(rust)));
        if (current == EMPTY) CHECK(!rust.used);
        else CHECK(rust.events[0].event == DEBUG_LOG && rust.events[1].event == NEXT);
        if (current == EARLY_QUIT)
            CHECK(rust.used == 3 && rust.events[2].event == CONSOLE_LOG);
        if (current == WAIT_FOR_TIMER) {
            CHECK(rust.used == 10 && rust.events[3].event == SLEEP && rust.events[3].second == 50000000);
            CHECK(rust.events[6].event == SLEEP && rust.events[6].second == 20000000);
            CHECK(rust.events[8].event == COLLECT && rust.events[9].event == RUN &&
                rust.events[9].second == 0 && rust.now == 170);
        }
        if (current == QUIT_IN_SLEEP) {
            CHECK(rust.used == 5 && rust.events[3].event == SLEEP &&
                rust.events[3].second == 50000000 && rust.events[4].event == CONSOLE_LOG);
        }
        if (current == REPLACE_IN_LOG) CHECK(rust.events[1].first == 2);
        if (current == REMOVE_IN_NEXT) CHECK(rust.used == 2 && !rust.pool);
        if (current == REPLACE_IN_GC)
            CHECK(rust.used == 5 && rust.events[4].event == RUN &&
                rust.events[4].first == 2 && rust.events[4].dirty);
        if (current == REMOVE_IN_GC)
            CHECK(rust.used == 5 && rust.events[4].event == RUN && !rust.events[4].first);
        if (current == QUIT_IN_GC)
            CHECK(rust.used == 5 && rust.events[4].event == RUN && rust.quitting);
    }
}

static void check_sleep(void)
{
    current = DIRECT_SLEEP;
    const uint64_t values[] = {0, 1, 49, 50, 999, 1000, 1001, UINT32_MAX, UINT64_MAX / 2, UINT64_MAX};
    for (unsigned i = 0; i < sizeof(values) / sizeof(*values); ++i) {
        struct sample reference = {0}, rust = {0};
        begin(&reference);
        reference_sleep(values[i]);
        finish();
        begin(&rust);
        loop_sleep_ms(values[i]);
        finish();
        CHECK(!memcmp(&reference, &rust, sizeof(rust)) && rust.used == 1);
        CHECK(rust.events[0].first == values[i] / 1000 &&
            rust.events[0].second == values[i] % 1000 * 1000000);
    }
}

static unsigned check_quit_and_timers(void)
{
    const int quit_values[] = {0, 1, -1, INT_MIN, INT_MAX};
    for (unsigned i = 0; i < sizeof(quit_values) / sizeof(*quit_values); ++i) {
        atomic_store(&bQuit, quit_values[i]);
        CHECK(loop_quitting() == (quit_values[i] != 0));
    }

    for (unsigned side = 0; side < 2; ++side) {
        struct sample sample = {0};
        const zapret_loop_timers *timers = side ? &zapret_capture_timers : &reference_timers;
        current = EMPTY;
        begin(&sample);
        CHECK(!timers->active() && timers->dirty());
        params.timers = timer_slot(1);
        CHECK(timers->active() && timers->dirty() && timers->now() == 100);
        CHECK(timers->next() == 100 && !timers->dirty());
        CHECK(!timers->run(UINT64_MAX) && !timers->active() && !timers->dirty());
        CHECK(sample.used == 3 && sample.events[1].first == 2);
        CHECK(sample.events[2].event == RUN && sample.events[2].first == 2 &&
            sample.events[2].second == UINT64_MAX);
        finish();
    }
    return sizeof(quit_values) / sizeof(*quit_values);
}

int main(void)
{
    check_idle();
    check_sleep();
    unsigned quits = check_quit_and_timers();
    printf("PASS windows_engine_idle loops=%u timespec_cases=10 quit_values=%u timer_tables=2 "
        "deferred_pool_reads=1 capped_shutdown_poll=1\n", (unsigned)DIRECT_SLEEP, quits);
    return 0;
}
