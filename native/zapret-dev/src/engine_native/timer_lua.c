/* MIT. Lua-facing timer API for the pinned engine. */
static int luacall_timer_set(lua_State *L)
{
    lua_check_argc_range(L, "timer_set", 3, 5);
    LUA_STACK_GUARD_ENTER(L)

    int argc = lua_gettop(L);
    const char *name = luaL_checkstring(L, 1);
    lua_Integer period = luaL_checkinteger(L, 3);
    if (period < 10) return luaL_error(L, "invalid timer period. must be >=10 ms");

    switch (lua_type(L, 2)) {
    case LUA_TSTRING: {
        const char *func = lua_tostring(L, 2);
        lua_getglobal(L, func);
        if (!lua_isfunction(L, -1))
            return luaL_error(L, "timer function '%s' does not exist", func);
        break;
    }
    case LUA_TFUNCTION:
        lua_pushvalue(L, 2);
        break;
    default:
        return luaL_error(L, "invalid timer function type");
    }

    zapret_timer_info timer = {
        .period = (uint64_t)period,
        .oneshot = argc >= 4 && lua_toboolean(L, 4),
        .data_ref = LUA_NOREF,
    };
    timer.func_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_pushstring(L, name);
    timer.name_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    if (argc >= 5) {
        lua_pushvalue(L, 5);
        timer.data_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    }

    zapret_timer_info old;
    int result = zapret_timer_set(&params.timers, name, &timer, boottime_ms(), &old);
    if (result < 0) {
        zapret_timer_unref(&timer);
        return luaL_error(L, "could not create timer");
    }
    if (result) zapret_timer_unref(&old);
    params.timers_dirty = true;
    DLOG("timer: '%s' %s. period %llu oneshot %u\n", name,
        result ? "replaced" : "created", (unsigned long long)timer.period, timer.oneshot);
    LUA_STACK_GUARD_RETURN(L, 0)
}

static int luacall_timer_del(lua_State *L)
{
    lua_check_argc(L, "timer_del", 1);
    LUA_STACK_GUARD_ENTER(L)

    const char *name = luaL_checkstring(L, 1);
    zapret_timer_info timer, removed;
    bool found = zapret_timer_get(params.timers, name, &timer) &&
        zapret_timer_remove(&params.timers, timer.id, &removed);
    if (found) {
        zapret_timer_unref(&removed);
        params.timers_dirty = true;
    }
    DLOG("timer: '%s' %s\n", name, found ? "deleted" : "not found");
    lua_pushboolean(L, found);
    LUA_STACK_GUARD_RETURN(L, 1)
}

static int luacall_timer_info(lua_State *L)
{
    lua_check_argc(L, "timer_info", 1);
    LUA_STACK_GUARD_ENTER(L)

    zapret_timer_info timer;
    if (zapret_timer_get(params.timers, luaL_checkstring(L, 1), &timer)) {
        lua_newtable(L);
        lua_pushliteral(L, "name");
        lua_rawgeti(L, LUA_REGISTRYINDEX, timer.name_ref);
        lua_rawset(L, -3);
        lua_pushliteral(L, "func");
        lua_rawgeti(L, LUA_REGISTRYINDEX, timer.func_ref);
        lua_rawset(L, -3);
        lua_pushf_lint(L, "period", timer.period);
        lua_pushf_bool(L, "oneshot", timer.oneshot != 0);
        lua_pushf_lint(L, "fires", timer.fires);
    } else {
        lua_pushnil(L);
    }
    LUA_STACK_GUARD_RETURN(L, 1)
}

static int luacall_timer_enum(lua_State *L)
{
    lua_check_argc(L, "timer_enum", 0);
    LUA_STACK_GUARD_ENTER(L)

    lua_Integer index = 1;
    uint64_t after = 0;
    zapret_timer_info timer;
    lua_newtable(L);
    while (zapret_timer_after(params.timers, after, &timer)) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, timer.name_ref);
        lua_rawseti(L, -2, index++);
        after = timer.id;
    }
    LUA_STACK_GUARD_RETURN(L, 1)
}
