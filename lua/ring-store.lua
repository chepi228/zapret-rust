-- Thin engine timer/filesystem adapter. Bounded hints, TTL/LRU, snapshot format,
-- dirty deadlines and retry policy are owned by the pinned Rust backend.
local native=assert(zapret_ring_native,'native Rust ring bridge is required')
assert(native.api_version==1 and native.backend=='Rust','unsupported ring ABI')
ring_store={backend='Rust'}
local pending,scheduled={},false
local timer_context=native.context_new(0)
local schedule,dispatch
local methods={}
local function log(text) if type(DLOG_ERR)=='function' then pcall(DLOG_ERR,'ring store: '..tostring(text)) end end
local function stats(store) return native.store_stats(store.native) end
local function queue(store)
    if pending[store] then return end
    local _,dirty,disabled=stats(store)
    if dirty and not disabled then pending[store]=true;schedule() end
end
function methods:discard() native.store_discard(self.native);pending[self]=nil end
function methods:get(key)
    if type(key)~='string' then return nil end
    local value=native.store_get(self.native,key,self.now(),clock_getfloattime())
    queue(self)
    return value
end
function methods:put(key,n)
    if type(key)~='string' or #key==0 or #key>255 or key:find('%s') then return false end
    if n~=nil and (type(n)~='number' or n%1~=0 or n<2 or n>128) then return false end
    local changed=native.store_put(self.native,key,n,self.now(),clock_getfloattime())
    if self.legacy and self.file and changed then
        local _,_,disabled=stats(self)
        if not disabled then
            local ok,err=pcall(writefile,self.file,native.store_snapshot(self.native,self.now()))
            if ok then native.store_commit(self.native,true,clock_getfloattime()) else native.store_discard(self.native);log(err) end
        end
        return changed
    end
    queue(self)
    return changed
end
local function publish(store,mono)
    local ok,valid=pcall(store.validate)
    if not ok or valid~=true then store:discard();return end
    local text=native.store_snapshot(store.native,store.now())
    ok,valid=pcall(function()
        writefile(store.temp,text)
        if readfile(store.temp)~=text then error('incomplete temporary snapshot') end
        local moved,err=os.rename(store.temp,store.file)
        if not moved then error(err or 'rename failed') end
    end)
    native.store_commit(store.native,ok,mono)
    if not ok then pcall(os.remove,store.temp);log(tostring(valid)..'; retry in 30s') end
end
dispatch=function()
    local mono=clock_getfloattime()
    local selected,due,selected_serial
    for store in pairs(pending) do
        local ready=native.store_due(store.native,mono)
        if not ready then pending[store]=nil
        else
            local _,_,_,serial=stats(store)
            if ready<=mono and (not selected or ready<due or (ready==due and serial<selected_serial)) then selected,due,selected_serial=store,ready,serial end
        end
    end
    if selected then
        local ok,err=pcall(publish,selected,mono)
        if not ok then native.store_commit(selected.native,false,mono);log(err) end
        local _,dirty,disabled=stats(selected)
        if not dirty or disabled then pending[selected]=nil end
    end
end
schedule=function()
    if scheduled then return end
    local now=clock_getfloattime()
    if not native.timer_gate(timer_context,now,nil) then pending={};return end
    local ok,err=pcall(function()
        if type(timer_set)~='function' then error('timer API unavailable') end
        return timer_set('ring_store_flush_v2',function()
            scheduled=false
            local success,message=pcall(dispatch)
            if not success then log(message);pending={} end
            if next(pending) then schedule() end
        end,1000,true)
    end)
    local success=ok and err~=false
    native.timer_gate(timer_context,now,success)
    if success then scheduled=true
    else
        for store in pairs(pending) do if not store.timer_warned then store.timer_warned=true;log(err) end end
        pending={}
    end
end
local function limit(value,default,minimum,maximum)
    value=value or default
    assert(type(value)=='number' and value%1==0 and value>=minimum and value<=maximum,'invalid ring store limit')
    return value
end
function ring_store.new(options)
    options=options or {}
    local file=options.file
    local now=options.now or function() return os.time() end
    local maxrecords=limit(options.maxrecords,2000,1,2000)
    local maxbytes=limit(options.maxbytes,262144,64,262144)
    local ttl=limit(options.ttl,30*24*60*60,1,30*24*60*60)
    local text
    if file then
        local ok,value=pcall(readfile,file)
        if ok then text=type(value)=='string' and #value<=maxbytes and value or '' end
    end
    local store={native=native.store_new(maxrecords,maxbytes,ttl,file~=nil,text,now(),options.legacy==true),file=file,now=now,legacy=options.legacy==true,
        validate=options.validate or function() return false end}
    if file then store.temp=file..'.tmp-'..tostring(type(getpid)=='function' and getpid() or 0) end
    return setmetatable(store,{__index=function(self,key)
        if methods[key] then return methods[key] end
        if key=='count' or key=='dirty' or key=='disabled' or key=='serial' then
            local count,dirty,disabled,serial=stats(self)
            if key=='count' then return count elseif key=='dirty' then return dirty elseif key=='disabled' then return disabled else return serial end
        end
    end})
end
