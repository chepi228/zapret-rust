-- Rust owns the bounded LRU index. Lua retains engine host-record tables and
-- connection pins because those objects belong to the engine's Lua state.
local native=assert(zapret_ring_native,'native Rust ring bridge is required')
assert(type(native.host_capacity)=='function','unsupported host cache bridge')
local upstream_host_record=assert(automate_host_record)
local native_host_record=zapret_native_modules and zapret_native_modules.stock_host_record
local native_lookup=zapret_native_modules and zapret_native_modules.host_cache_lookup(native)
local running=coroutine.running
local state={native=native,stock=native_host_record or upstream_host_record,lookup=native_lookup}
local engine=zapret_native_modules and zapret_native_modules.host_cache and zapret_native_modules.host_cache(state)
if zapret_native_modules and zapret_native_modules.circular and type(circular)=='function' then
    local compatible,native_circular=circular,zapret_native_modules.circular
    function circular(...)
        if running() then return compatible(...) end
        return native_circular(...)
    end
end
ring_host_cache={backend='Rust'}
local function resolve(desync)
    local hkf=standard_hostkey
    if desync.arg.hostkey then hkf=_G[desync.arg.hostkey];if type(hkf)~='function' then error("automate: invalid hostkey function '"..desync.arg.hostkey.."'") end end
    local host=hkf(desync)
    if not host then return nil end
    local group=(desync.arg.key and #desync.arg.key>0) and desync.arg.key or desync.func_instance
    return group,host
end
local function detach(cache,id)
    local node=cache.by_id[id]
    if not node then return end
    local bucket=autostate and autostate[node.askey]
    if bucket and bucket[node.hostkey]==node.record then bucket[node.hostkey]=nil;if next(bucket)==nil then autostate[node.askey]=nil end end
    local nodes=cache.nodes[node.askey]
    nodes[node.hostkey]=nil;if next(nodes)==nil then cache.nodes[node.askey]=nil end
    cache.by_id[id]=nil;node.active=false;node.record.ring_cache_evicted=true
end
local function lookup(cache,desync,group,host)
    -- C stack frames cannot resume a yielding Lua metamethod or callback.
    if native_lookup and not running() then return native_lookup(cache,desync,group,host) end
    if not host then return nil end
    local state=desync.track and desync.track.lua_state
    local pin=state and state.ring_host_pin
    if pin and pin.token==cache.token and pin.askey==group and pin.hostkey==host then
        native.host_touch(cache.native,pin.node.id)
        return pin.node.record
    end
    local id,evicted,created=native.host_access(cache.native,group,host)
    if evicted then detach(cache,evicted) end
    local node=cache.by_id[id]
    if created then
        if not autostate then autostate={} end
        local bucket=autostate[group];if not bucket then bucket={};autostate[group]=bucket end
        local record=bucket[host];if not record then record={};bucket[host]=record end
        local nodes=cache.nodes[group];if not nodes then nodes={};cache.nodes[group]=nodes end
        node={id=id,askey=group,hostkey=host,record=record,active=true}
        cache.by_id[id],nodes[host]=node,node
    end
    if state then state.ring_host_pin={token=cache.token,askey=group,hostkey=host,node=node} end
    return node.record
end
function state.get(cache,desync)
    if engine and not running() then return engine.get(cache,desync) end
    local group,host=resolve(desync)
    return lookup(cache,desync,group,host)
end
local function upstream_resolved(group,host)
    if not autostate then autostate={} end
    if not autostate[group] then autostate[group]={} end
    if not autostate[group][host] then autostate[group][host]={} end
    return autostate[group][host]
end
function state.attach(cache)
    return setmetatable(cache,
        {__index=function(cache,key)if key=='count' then return native.host_count(cache.native) end end})
end
function ring_host_cache.new(capacity)
    if engine and not running() then return engine.new(capacity) end
    local numeric=type(capacity)=='number' and capacity-capacity==0 and capacity or nil
    capacity=assert(native.host_capacity(capacity==nil,numeric),'invalid host cache capacity')
    return state.attach({native=native.host_new(capacity),capacity=capacity,nodes={},by_id={},token={},get=state.get})
end
state.cache=ring_host_cache.new()
function automate_host_record(desync)
    if engine and not running() then return engine.record(desync) end
    if state.disabled or desync.arg.hostcache~='bounded' then
        if native_host_record and not running() then return native_host_record(desync) end
        return upstream_host_record(desync)
    end
    local group,host=resolve(desync)
    if not host then return nil end
    local ok,record=pcall(lookup,state.cache,desync,group,host)
    if ok then return record end
    state.disabled,state.cache=true,nil
    DLOG_ERR('host cache: '..tostring(record)..'. using standard host records')
    return upstream_resolved(group,host)
end
