/* MIT. Dispatch Lua callbacks after the Rust scheduler releases the pool. */
void zapret_timer_unref(const zapret_timer_info *timer)
{
    luaL_unref(params.L, LUA_REGISTRYINDEX, timer->name_ref);
    luaL_unref(params.L, LUA_REGISTRYINDEX, timer->func_ref);
    luaL_unref(params.L, LUA_REGISTRYINDEX, timer->data_ref);
}

void TimerPoolDestroy(timer_pool **pool)
{
    zapret_timer_info timer;
    while (zapret_timer_after(*pool, 0, &timer)) {
        if (zapret_timer_remove(pool, timer.id, &timer)) zapret_timer_unref(&timer);
    }
}

uint64_t TimerPoolNext(const timer_pool *pool, bool *dirty)
{
    *dirty = false;
    return zapret_timer_next(pool);
}

static bool run_timer(const zapret_timer_info *timer)
{
    lua_rawgeti(params.L, LUA_REGISTRYINDEX, timer->func_ref);
    lua_rawgeti(params.L, LUA_REGISTRYINDEX, timer->name_ref);
    lua_rawgeti(params.L, LUA_REGISTRYINDEX, timer->data_ref);
    DLOG("\ntimer: '%s' period %llu oneshot %u fires=%u\n",
        lua_tostring(params.L, -2), (unsigned long long)timer->period, timer->oneshot, timer->fires);
    if (!lua_pcall(params.L, 2, 0, 0)) return true;
    lua_dlog_error();
    return false;
}

uint64_t TimerPoolRun(timer_pool **pool, bool *dirty, uint64_t now)
{
    if (!now) now = boottime_ms();
    uint64_t after = 0;
    zapret_timer_info timer, removed;
    *dirty = false;
    while (zapret_timer_due(*pool, after, now, &timer)) {
        after = timer.id;
        bool succeeded = run_timer(&timer);
        if (zapret_timer_finish(pool, timer.id, now, succeeded, &removed)) {
            lua_rawgeti(params.L, LUA_REGISTRYINDEX, removed.name_ref);
            DLOG("timer: '%s' deleted because of %s\n",
                lua_tostring(params.L, -1), succeeded ? "oneshot" : "error");
            lua_pop(params.L, 1);
            zapret_timer_unref(&removed);
        }
        if (*dirty) {
            after = 0;
            *dirty = false;
        }
    }
    return zapret_timer_next(*pool);
}
