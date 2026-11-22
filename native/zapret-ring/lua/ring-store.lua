-- Both LuaJIT paths share the Rust scheduler and the same rooted store objects.
-- Lua runs the yielding compatibility path and supplies the callback values.
local native=assert(zapret_ring_native,'native Rust ring bridge is required')
assert(native.api_version==1 and native.backend=='Rust','unsupported ring ABI')

local scheduler=native.store_scheduler
local effect=native.store_effect
local stat=native.store_stat
assert(type(scheduler)=='function' and type(effect)=='function' and type(stat)=='function','unsupported ring store bridge')
local timer_context=native.context_new(0)
assert(scheduler(timer_context,'probe')==true and effect('probe')==1,'unsupported ring store bridge')

local invalid_limit,temp_suffix,timer_name,timer_delay,timer_once,log_prefix,retry_suffix=effect('metadata')
local records,bytes,ttl,count,dirty,disabled,serial=effect('schema')
local limit_names={records,bytes,ttl}
local stat_fields={[count]=1,[dirty]=2,[disabled]=3,[serial]=4}
local state={native=native,effect=effect,scheduler=scheduler,timer_context=timer_context,roots={},
    limit_names=limit_names,invalid_limit=invalid_limit,temp_suffix=temp_suffix,timer_name=timer_name,
    timer_delay=timer_delay,timer_once=timer_once,log_prefix=log_prefix,retry_suffix=retry_suffix,
    make_clock=function() return function() return os.time() end end}
local engine=zapret_native_modules and zapret_native_modules.ring_store and zapret_native_modules.ring_store(state)
local running=coroutine.running
ring_store={backend='Rust'}
local function number(value)
    if type(value)=='number' and value-value==0 then return value end
end
local function log(value)
    if type(DLOG_ERR)=='function' then pcall(DLOG_ERR,log_prefix..tostring(value)) end
end
local schedule,dispatch
local methods={}
local function clear()
    scheduler(timer_context,'clear')
    state.roots={}
end
local after_effects={
    legacy_commit=function(store) native.store_commit(store.native,true,clock_getfloattime()) end,
    legacy_discard=function(store) native.store_discard(store.native) end,
    defer=function(store,mono) native.store_commit(store.native,false,mono) end,
    log=function(_,_,err) log(err) end,
    clear=clear,
}
local function after(operation,ok,err,store,mono)
    local first,second=effect('after_plan',operation,ok)
    if first then after_effects[first](store,mono,err) end
    if second then after_effects[second](store,mono,err) end
end
local function write_legacy(store)
    local ok,err=pcall(writefile,store.file,native.store_snapshot(store.native,store.now()))
    after('legacy',ok,err,store)
end
local function update(store,writing,changed)
    local object=store.native
    local write,serial
    if writing then
        write,serial=scheduler(timer_context,'prepare_update',object,not not store.legacy,not not store.file,changed)
    else
        write,serial=scheduler(timer_context,'prepare_update',object)
    end
    if write then write_legacy(store) end
    if not serial then return end
    state.roots[serial]=store
    if scheduler(timer_context,'retain',object) then schedule()
    else state.roots[serial]=nil end
end
function methods:discard()
    if engine and not running() then return engine.discard(self) end
    local serial=scheduler(timer_context,'discard',self.native)
    if serial then state.roots[serial]=nil end
end
function methods:get(key)
    if engine and not running() then return engine.get(self,key) end
    if not effect('key',false,type(key)=='string',0) then return nil end
    local value=native.store_get(self.native,key,self.now(),clock_getfloattime())
    update(self,false)
    return value
end
function methods:put(key,n)
    if engine and not running() then return engine.put(self,key,n) end
    local string=type(key)=='string'
    if not effect('key',true,string,string and #key or 0) then return false end
    local whitespace=not not key:find('%s')
    if not effect('value',whitespace,n==nil,not whitespace and n~=nil and number(n) or nil) then return false end
    local changed=native.store_put(self.native,key,n,self.now(),clock_getfloattime())
    update(self,true,changed)
    return changed
end

local function atomic_write(store,text)
    local ok,detail=false,nil
    local action,message=effect('atomic',nil,ok,false)
    while action do
        if action=='write' then writefile(store.temp,text)
        elseif action=='verify' then ok=readfile(store.temp)==text
        elseif action=='rename' then ok,detail=os.rename(store.temp,store.file)
        else error(message or detail) end
        action,message=effect('atomic',action,not not ok,not not detail)
    end
end
local function publish(store,mono)
    local ok,value,text=false,nil,nil
    local action=effect('publish',nil,ok,false)
    while action do
        if action=='validate' then ok,value=pcall(store.validate)
        elseif action=='snapshot' then text=native.store_snapshot(store.native,store.now())
        elseif action=='discard' then store:discard()
        elseif action=='atomic' then ok,value=pcall(atomic_write,store,text)
        elseif action=='commit' then native.store_commit(store.native,ok,mono)
        elseif action=='remove' then pcall(os.remove,store.temp)
        elseif action=='retry_log' then log(tostring(value)..retry_suffix) end
        action=effect('publish',action,ok,value==true)
    end
end
local function flush(store,mono)
    local ok,err=pcall(publish,store,mono)
    after('flush',ok,err,store,mono)
end
dispatch=function()
    local mono=clock_getfloattime()
    local serial=scheduler(timer_context,'select',mono)
    local retired=scheduler(timer_context,'retired')
    while retired do
        state.roots[retired]=nil
        retired=scheduler(timer_context,'retired')
    end
    if not serial then return end
    local store=state.roots[serial]
    flush(store,mono)
    local removed=scheduler(timer_context,'finish',store.native)
    if removed then state.roots[removed]=nil end
end

local function on_timer()
    if engine and not running() then return engine.timer() end
    scheduler(timer_context,'fired')
    local ok,err=pcall(dispatch)
    after('dispatch',ok,err)
    schedule()
end
state.timer=on_timer
local function arm()
    local error_message=effect('timer_check',type(timer_set)=='function')
    if error_message then error(error_message) end
    return timer_set(timer_name,on_timer,timer_delay,timer_once)
end
schedule=function()
    if not scheduler(timer_context,'wants_timer') then return end
    local now=clock_getfloattime()
    if not scheduler(timer_context,'prepare_timer',now) then
        state.roots={}
        return
    end
    local ok,err=pcall(arm)
    local success=effect('timer_success',ok,err==false)
    local warnings=scheduler(timer_context,'timer_result',now,success)
    if not success then
        state.roots={}
        for _=1,warnings do log(err) end
    end
end
function state.attach(store)
    return setmetatable(store,{__index=function(self,key)
        if methods[key] then return methods[key] end
        local index=stat_fields[key]
        if index then return stat(self.native,index) end
    end})
end
function ring_store.new(options)
    if engine and not running() then return engine.new(options) end
    options=options or {}
    local file=options.file
    local now=options.now or state.make_clock()
    local limits={}
    for index,name in ipairs(limit_names) do
        local value=options[name]
        limits[index]=assert(effect('limit',index,not value,number(value)),invalid_limit)
    end
    local text
    local read,provided_file=effect('construction',file~=nil,not not file)
    if read then
        local ok,value=pcall(readfile,file)
        local string=ok and type(value)=='string'
        local result=effect('initial_file',ok,string,string and #value or 0,limits[2])
        if result=='borrow' then text=value elseif result=='empty' then text='' end
    end
    local store={native=native.store_new(limits[1],limits[2],limits[3],provided_file,text,now(),options.legacy==true),
        file=file,now=now,legacy=options.legacy==true,validate=options.validate or function() return false end}
    if read then store.temp=file..temp_suffix..tostring(type(getpid)=='function' and getpid() or 0) end
    return state.attach(store)
end

