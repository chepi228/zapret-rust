
local real_time=os.time
local now,mono=real_time()+10,0
local network,composition=string.rep('A',64),string.rep('C',24)
local state='ring-general-'..composition:lower()..'-abc123.txt'
local file='root/'..state:sub(1,-5)..'-'..network..'.txt'
local files,timers={},{}
local writes,bytes=0,0
os.time=function() return now end
os.getenv=function(name) if name=='WRITABLE' then return 'root' end end
clock_getfloattime=function() return mono end
getpid=function() return 42 end
DLOG=function() end;DLOG_ERR=function() end
readfile=function(path) if not files[path] then error('missing') end;return files[path] end
writefile=function(path,text) writes=writes+1;bytes=bytes+#text;files[path]=text end
os.rename=function(from,to) files[to]=files[from];files[from]=nil;return true end
os.remove=function(path) files[path]=nil;return true end
timer_set=function(name,callback,ms) timers[name]={callback=callback,at=mono+ms/1000} end
standard_success_detector=function() return true end
automate_host_record=function(d) return d.host_record end
standard_hostkey=function(d) return d.testkey end
files['root/network-context.txt']='3 '..now..' '..network..' '..composition..'\n'
local function packet(host,key)
    return {arg={key='bench',state=state,context='network-context.txt'},host_record=host,testkey=key,
        func_instance='bench',outgoing=true,track={lua_state={}},dis={tcp={},payload='hello'},target={}}
end
function run_burst(count)
    for i=1,count do
        local host={nstrategy=1,ctstrategy=3}
        local d=packet(host,'host'..i..'.example')
        assert(ring_success(d,{}))
        host.nstrategy=2
        assert(ring_success(d,{}))
    end
    return writes,bytes
end
function run_flush(count)
    now,mono=now+5,mono+5
    local ready={}
    for name,timer in pairs(timers) do if timer.at<=mono then ready[name]=timer;timers[name]=nil end end
    for name,timer in pairs(ready) do timer.callback(name) end
    local text=files[file] or ''
    local saved=0
    for line in text:gmatch('[^\n]+') do if line:match('^host%d+%.example 2') then saved=saved+1 end end
    assert(saved==count,'saved choices differ: '..saved..' / '..count)
    return writes,bytes,#text
end
function run_steady(count)
    local before=writes
    local host={nstrategy=1,ctstrategy=3}
    local d=packet(host,'host1.example')
    for i=1,count do assert(ring_success(d,{}) and host.nstrategy==2) end
    assert(writes==before,'steady choices unexpectedly write state')
end
