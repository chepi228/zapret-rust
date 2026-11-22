-- Timer mutation checks run through the real engine with interception disabled.
local failures = 0
local function check(name, value)
    print((value and "ok " or "FAIL ")..name)
    if not value then failures = failures + 1 end
end
local prefix = "timer_fixture_"
local function count()
    local result = {}
    for _, name in ipairs(timer_enum()) do
        if name:sub(1, #prefix) == prefix then result[#result + 1] = name end
    end
    return result
end

check("timer API rejects short periods and missing callback names",
    not pcall(timer_set, prefix.."invalid", function() end, 9) and
    not pcall(timer_set, prefix.."invalid", "__no_such_timer_function__", 10) and
    timer_info(prefix.."invalid") == nil)
local empty = function() end
timer_set(prefix.."a", empty, 10000)
timer_set(prefix.."b", empty, 10000)
timer_set(prefix.."a", empty, 10000, true)
local order = count()
local info = timer_info(prefix.."a")
check("timer replacement moves to the end and resets public info",
    #order == 2 and order[1] == prefix.."b" and order[2] == prefix.."a" and
    info.func == empty and info.period == 10000 and info.oneshot and info.fires == 0)
check("timer deletion reports presence and removes registry entries",
    timer_del(prefix.."a") and not timer_del(prefix.."a") and timer_del(prefix.."b") and #count() == 0)

local weak = setmetatable({}, {__mode="v"})
do
    local payload = {}
    weak[1] = payload
    timer_set(prefix.."gc", empty, 10000, true, payload)
end
collectgarbage("collect")
check("registered timers retain their callback data", weak[1] ~= nil)
assert(timer_del(prefix.."gc"))
collectgarbage("collect")
check("deleted timers release their callback data", weak[1] == nil)

do
    local function fails(fn, text, ...)
        local ok, message = pcall(fn, ...)
        return not ok and tostring(message):find(text, 1, true) ~= nil
    end
    check("timer entry arities retain their exact public names",
        fails(timer_set, "timer_set expect from 3 to 5 arguments, got 0") and
        fails(timer_del, "timer_del expect exactly 1 arguments, got 0") and
        fails(timer_info, "timer_info expect exactly 1 arguments, got 0") and
        fails(timer_enum, "timer_enum expect exactly 0 arguments, got 1", 1))
    check("timer period errors precede callback type validation",
        fails(timer_set, "invalid timer period. must be >=10 ms", prefix.."bad", {}, 9))
    check("timer name errors precede period validation",
        fails(timer_set, "bad argument #1", {}, {}, {}))
    local function callback() end
    local slot = prefix.."entry"
    timer_set(slot, callback, "10.75")
    check("timer periods retain LuaJIT numeric string coercion", timer_info(slot).period == 10)
    assert(timer_del(slot))
    check("numeric timer callbacks remain invalid types",
        fails(timer_set, "invalid timer function type", slot, 123, 10000))
    _G[prefix.."callback"] = callback
    timer_set(slot, prefix.."callback", 10000)
    check("named timer callbacks publish the resolved function identity", timer_info(slot).func == callback)
    assert(timer_del(slot))
    local truthy = true
    for _, value in ipairs({0, "", {}, callback}) do
        timer_set(slot, callback, 10000, value)
        truthy = truthy and timer_info(slot).oneshot
    end
    timer_set(slot, callback, 10000, false)
    truthy = truthy and not timer_info(slot).oneshot
    timer_set(slot, callback, 10000, nil)
    check("timer oneshot retains Lua truthiness for optional values", truthy and not timer_info(slot).oneshot)
    assert(timer_del(slot))
    timer_set(slot.."\0ignored", prefix.."callback\0ignored", 10000)
    local nul = timer_info(slot.."\0suffix")
    check("timer C string names and callback lookups retain NUL termination",
        nul.name == slot and nul.func == callback and timer_del(slot))
    _G[prefix.."callback"] = nil
    timer_set(314159265, callback, 10000)
    check("numeric timer names retain string coercion", timer_info(314159265).name == "314159265" and timer_del("314159265"))
    timer_set(slot, callback, 10000)
    local first = timer_info(slot)
    local keys = {}
    for key in pairs(first) do keys[#keys + 1] = key end
    table.sort(keys)
    check("timer info has the exact five public fields", table.concat(keys, ",") == "fires,func,name,oneshot,period")
    local names = timer_enum()
    for i = 1, #names do names[i] = "modified" end
    first.period, first.func = -1, false
    local second = timer_info(slot)
    local present = false
    for _, name in ipairs(timer_enum()) do present = present or name == slot end
    check("timer info and enumeration snapshots are independent", second.period == 10000 and second.func == callback and present)
    assert(timer_del(slot))
    local retained = setmetatable({}, {__mode="v"})
    do
        local old, replacement = {}, {}
        retained[1], retained[2] = old, replacement
        timer_set(slot, callback, 10000, false, old)
        timer_set(slot, callback, 10000, false, replacement)
    end
    collectgarbage("collect")
    check("timer replacement releases old data and retains the new reference", retained[1] == nil and retained[2] ~= nil)
    assert(timer_del(slot))
    collectgarbage("collect")
    check("timer deletion releases replacement data", retained[2] == nil)
end

local recurring_calls, replaced_calls, removed_calls = 0, 0, 0
local payload = {}
local name = prefix.."recurring"
local function recurring(actual, data)
    recurring_calls = recurring_calls + 1
    local current = timer_info(actual)
    check("recurring callback receives its name data and current fire count",
        actual == name and data == payload and current and current.fires == recurring_calls)
    if recurring_calls == 2 then assert(timer_del(actual)) end
end
timer_set(name, recurring, 15, false, payload)

timer_set(prefix.."replace_self", function(actual)
    assert(timer_del(actual))
    timer_set(actual, function(replacement)
        replaced_calls = replaced_calls + 1
        check("self replacement starts with a fresh fire counter", timer_info(replacement).fires == 1)
    end, 15, true)
    error("expected old callback failure after replacement")
end, 10, true)

timer_set(prefix.."delete_other", function()
    assert(timer_del(prefix.."removed"))
    timer_set(prefix.."inserted", function()
        removed_calls = removed_calls + 1
    end, 15, true)
end, 10, true)
timer_set(prefix.."removed", function()
    error("deleted sibling was dispatched")
end, 100, true)

timer_set(prefix.."error", function()
    error("expected timer callback error")
end, 10, false)

timer_set(prefix.."finish", function()
    check("recurring timers stop after deleting themselves", recurring_calls == 2 and timer_info(name) == nil)
    check("an old callback cannot delete its replacement", replaced_calls == 1)
    check("callback mutations discard deleted siblings and run inserted timers", removed_calls == 1)
    check("a callback error removes its original timer", timer_info(prefix.."error") == nil)
    assert(timer_del(prefix.."finish"))
    check("all completed timer references are removed", #count() == 0)
    io.stdout:flush()
    os.exit(failures == 0 and 0 or 1)
end, 300, true)
