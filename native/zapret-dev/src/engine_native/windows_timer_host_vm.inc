/* MIT. Execute only the VM actions selected by the Rust timer scheduler. */
#include "windows_timer_vm_abi.h"
#include "lua_timer_report_windows.h"

uint32_t zapret_timer_lifecycle_native_step(zapret_timer_lifecycle_state *, timer_pool **, bool *);

static uint64_t timer_host_dispatch(uint32_t entry, timer_pool **pool, bool *dirty, uint64_t now)
{
    zapret_timer_lifecycle_state state = {.entry = entry, .now = now};
    uint32_t operation;
    while ((operation = zapret_timer_lifecycle_native_step(&state, pool, dirty))) {
        switch (operation) {
        case 1:
            state.now = boottime_ms();
            break;
        case 4:
            lua_rawgeti(params.L, LUA_REGISTRYINDEX, state.info.func_ref);
            lua_rawgeti(params.L, LUA_REGISTRYINDEX, state.info.name_ref);
            lua_rawgeti(params.L, LUA_REGISTRYINDEX, state.info.data_ref);
            DLOG(zapret_lua_timer_report(false, false).format, lua_tostring(params.L, -2),
                (unsigned long long)state.info.period, state.info.oneshot, state.info.fires);
            if (!lua_pcall(params.L, 2, 0, 0)) state.status = true;
            else {
                lua_dlog_error();
                state.status = false;
            }
            break;
        case 6:
            lua_rawgeti(params.L, LUA_REGISTRYINDEX, state.removed.name_ref);
            break;
        case 7: {
            zapret_lua_timer_log report = zapret_lua_timer_report(true, state.succeeded != 0);
            DLOG(report.format, lua_tostring(params.L, -1), report.reason);
            break;
        }
        case 8:
            lua_pop(params.L, 1);
            break;
        case 9:
        case 14: {
            const zapret_timer_info *timer = operation == 9 ? &state.removed : &state.info;
            luaL_unref(params.L, LUA_REGISTRYINDEX, timer->name_ref);
            luaL_unref(params.L, LUA_REGISTRYINDEX, timer->func_ref);
            luaL_unref(params.L, LUA_REGISTRYINDEX, timer->data_ref);
            break;
        }
        default:
            abort();
        }
    }
    return state.output;
}

void TimerPoolDestroy(timer_pool **pool)
{
    timer_host_dispatch(1, pool, NULL, 0);
}

uint64_t TimerPoolRun(timer_pool **pool, bool *dirty, uint64_t now)
{
    return timer_host_dispatch(3, pool, dirty, now);
}
