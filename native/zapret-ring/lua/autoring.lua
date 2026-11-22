-- Keep the same profile state across native calls and yielding Lua callbacks.
local native=assert(zapret_ring_native,'native Rust ring bridge is required')
assert(native.api_version==1 and native.backend=='Rust','unsupported ring ABI')
local context=native.context_new(os.time())
local state={native=native,context=context,memory={},network_epoch=0}
state.epoch_clock=function() return state.network_epoch end
local running=coroutine.running
local context_engine=zapret_native_modules and zapret_native_modules.ring_context and zapret_native_modules.ring_context(state)
ring_network_key=native.network_key
ring_link_guard=native.link_guard
function ring_state_path(dir,state,key)
    if context_engine and not running() then return context_engine.state_path(dir,state,key) end
    if type(dir)~='string' or type(state)~='string' or type(key)~='string' then return nil end
    return native.state_path(dir,state,key)
end
local function ring_context(desync,force)
    if context_engine and not running() then return context_engine.context(desync,force) end
    if not desync.arg.context then return 'legacy',0 end
    local mono=clock_getfloattime()
    local due,key,revision,epoch=native.context_poll(context,desync.arg.state or '',mono,force==true,false)
    if due then
        local text
        local dir=os.getenv('WRITABLE')
        if dir and desync.arg.context=='network-context.txt' then local ok,value=pcall(readfile,dir..'/network-context.txt');if ok then text=value end end
        native.context_observe(context,text,os.time(),mono,false)
        key,revision,epoch=native.context_read(context,desync.arg.state or '',mono)
    end
    state.network_epoch=epoch
    return key,revision
end
function state.validator(probe,key,revision)
    return function()
        local current,generation=ring_context(probe,true)
        return key~=nil and current==key and generation==revision
    end
end
local function ring_link_context(desync)
    if context_engine and not running() then return context_engine.link_context(desync) end
    if desync.arg.link_guard~='link-guard.txt' then return 0,false end
    local mono=clock_getfloattime()
    local due,_,_,_,revision,paused=native.context_poll(context,desync.arg.state or '',mono,false,true)
    if due then
        local text
        local dir=os.getenv('WRITABLE')
        if dir then local ok,value=pcall(readfile,dir..'/link-guard.txt');if ok then text=value end end
        native.context_observe(context,text,os.time(),mono,true)
        _,_,_,revision,paused=native.context_read(context,desync.arg.state or '',mono)
    end
    return revision,paused
end
local function forged_rst(desync)
    local tcp,track=desync.dis.tcp,desync.track
    if not tcp or not track or desync.outgoing then return false end
    local ttl=(desync.dis.ip and desync.dis.ip.ip_ttl) or (desync.dis.ip6 and desync.dis.ip6.ip6_hlim)
    local sent=track.lua_state.rst_sent
    return native.forged(not desync.outgoing,true,bitand(tcp.th_flags,TH_RST)~=0,ttl,track.incoming_ttl,sent and clock_getfloattime()-sent or nil)
end
local function tls_refused(desync)
    local tcp,track=desync.dis.tcp,desync.track
    if not tcp or not track or desync.outgoing or track.l7proto~='tls' or bitand(tcp.th_flags,TH_FIN)==0 then return false end
    return native.refused(true,true,true,true,pos_get(desync,'s'),track.pos.direct.tcp.uppos or 0,#desync.dis.payload)
end
function rst_guard(ctx,desync) if forged_rst(desync) then DLOG('rst_guard: forged rst dropped');return VERDICT_DROP end end
function rst_mark(ctx,desync) if desync.track and desync.dis.tcp and #desync.dis.payload>0 then desync.track.lua_state.rst_sent=clock_getfloattime() end end
local function ring_got(desync)
    local reverse=desync.track and desync.track.pos.reverse
    if not reverse or not reverse.tcp or not reverse.pcounter or reverse.pcounter<1 then return 0 end
    return native.acked(true,bitand(desync.dis.tcp.th_flags,TH_ACK)~=0,desync.dis.tcp.th_ack,reverse.tcp.seq0)
end
local function ring_mem(desync)
    if context_engine and not running() then return context_engine.memory(desync) end
    local name=desync.arg.key or desync.func_instance
    local key,revision=ring_context(desync)
    local old=state.memory[name]
    if old and old.revision==revision and old.context==key then return old end
    if old then old.store:discard() end
    local dir,profile=os.getenv('WRITABLE'),desync.arg.state
    local file=dir and profile and ((desync.arg.context and ring_state_path(dir,profile,key)) or (not desync.arg.context and native.legacy_state_path(dir,profile))) or nil
    local probe={arg={state=profile,context=desync.arg.context}}
    local store=ring_store.new({file=file,legacy=not desync.arg.context,now=desync.arg.context and state.epoch_clock or nil,
        validate=state.validator(probe,key,revision)})
    local mem={store=store,context=key,revision=revision}
    state.memory[name]=mem
    return mem
end
local function ring_remember(desync,w,mem)
    mem=mem or ring_mem(desync)
    if w.revision~=nil and w.revision~=mem.revision then return end
    if w.strategy==1 then mem.store:put(w.key,nil)
    else mem.store:put(w.key,w.strategy);mem.store:put(w.net,w.strategy) end
end
local function ring_conn(desync,crec)
    local w=crec.ring
    local mem
    if not w then w={};crec.ring=w end
    if not w.strategy and desync.outgoing and #desync.dis.payload>0 then
        local hrec=automate_host_record(desync)
        local key=hrec and standard_hostkey(desync)
        if key then
            local raw=desync.target and (desync.target.ip or desync.target.ip6)
            w.hrec,w.key,w.net=hrec,key,raw and native.subnet(raw) or nil
            mem=ring_mem(desync)
            local hint=not hrec.ring_seen or (desync.arg.context and hrec.ring_revision~=mem.revision)
            if hint then hint=mem.store:get(key) or (w.net and mem.store:get(w.net)) end
            local selected,reset=native.initial(hrec.nstrategy,hrec.ctstrategy,hrec.ring_seen==true,hrec.ring_revision,mem.revision,desync.arg.context~=nil,hint or nil)
            if reset then hrec.failure_counter,hrec.failure_time_last,hrec.ring_ok=0,0,nil;hrec.ring_revision=mem.revision end
            hrec.ring_seen,hrec.nstrategy=true,selected
            w.revision,w.strategy=mem.revision,selected
        end
    end
    return w,mem
end
local function ring_skip(desync,crec)
    if crec.nocheck then return true end
    local w,mem=ring_conn(desync,crec)
    local link_revision,paused=ring_link_context(desync)
    if w.revision~=nil then mem=mem or ring_mem(desync) end
    local current_revision=mem and mem.revision or 0
    local skip,initial_link,tainted=native.skip(false,w.hrec and w.hrec.ring_cache_evicted==true or false,w.link_revision,w.link_tainted==true,
        link_revision,paused,w.revision,current_revision,w.strategy,w.hrec and w.hrec.nstrategy or nil)
    w.link_revision,w.link_tainted=initial_link,tainted
    if skip then crec.nocheck=true end
    return skip,w,mem
end
local function ring_success_impl(desync,crec)
    if forged_rst(desync) then return false end
    local skip,w,mem=ring_skip(desync,crec)
    if skip then return false end
    local standard=standard_success_detector(desync,crec)
    local got=0
    if not standard and desync.dis.tcp and desync.outgoing then got=ring_got(desync) end
    local ok,proved=native.success(not not standard,desync.outgoing==true,desync.dis.tcp~=nil,got,tonumber(desync.arg.got))
    if ok and proved and w.strategy then w.hrec.ring_ok=w.strategy;ring_remember(desync,w,mem) end
    return ok
end
local function ring_failure_impl(desync,crec)
    if forged_rst(desync) or ring_skip(desync,crec) then return false end
    local hrec=crec.ring.hrec
    local unproven=hrec and hrec.ring_ok~=hrec.nstrategy or false
    local retrans=desync.arg.retrans
    if unproven and not retrans then desync.arg.retrans=2 end
    local ok,standard=pcall(standard_failure_detector,desync,crec)
    desync.arg.retrans=retrans
    if not ok then error(standard) end
    local refused=not standard and tls_refused(desync) or false
    local failed,count=native.failure(not not standard,refused,unproven,tonumber(desync.arg.fails))
    if count then hrec.failure_counter=count;hrec.failure_time_last=os.time() end
    return failed
end
local function guarded(impl,standard)
    return function(desync,crec)
        local ok,result=pcall(impl,desync,crec)
        if ok then return result end
        DLOG_ERR('ring: '..tostring(result)..'. using standard detector')
        return standard(desync,crec)
    end
end
if zapret_native_modules and zapret_native_modules.autoring then
    local engine=zapret_native_modules.autoring(native,ring_mem,ring_link_context)
    local function bind(compat,handler)
        return function(...)
            if running() then return compat(...) end
            return handler(...)
        end
    end
    rst_guard=bind(rst_guard,engine.rst_guard)
    rst_mark=bind(rst_mark,engine.rst_mark)
    ring_success_impl=bind(ring_success_impl,engine.success)
    ring_failure_impl=bind(ring_failure_impl,engine.failure)
end
ring_success=guarded(ring_success_impl,standard_success_detector)
ring_failure=guarded(ring_failure_impl,standard_failure_detector)
