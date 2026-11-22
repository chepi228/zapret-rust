-- Compare installed Rust callbacks with the pinned Lua coroutine paths.
local function packed(...)
    return {n=select("#", ...), ...}
end

local function equivalent(a, b, label)
    assert(type(a)==type(b), label..": types differ")
    if type(a)~="table" then
        assert(a==b, label..": "..tostring(a).." differs from "..tostring(b))
        return
    end
    for key,value in pairs(a) do equivalent(value, b[key], label.."."..tostring(key)) end
    for key in pairs(b) do assert(a[key]~=nil, label..": extra key "..tostring(key)) end
end

local function invoke(lua_path, fn, ...)
    if not lua_path then return packed(fn(...)) end
    local co = coroutine.create(function(...) return fn(...) end)
    local result = packed(coroutine.resume(co, ...))
    assert(result[1], tostring(result[2]))
    assert(coroutine.status(co)=="dead")
    local out = {n=result.n-1}
    for i=2,result.n do out[i-1] = result[i] end
    return out
end

local function compare(label, run)
    local expected = run(true)
    local actual = run(false)
    equivalent(actual, expected, label)
end

local function files()
    local function exercise(lua_path)
        local path = assert(os.getenv("WRITABLE")).."/native-file-helpers.bin"
        local data = "\0\255"..("abc123\r\n"):rep(29)
        local open_empty = invoke(lua_path, writefile, path, "")
        local empty = invoke(lua_path, is_gzip_file, path)
        local written = invoke(lua_path, writefile, path, data)
        local binary = invoke(lua_path, z_readfile, path)
        local plain = invoke(lua_path, is_gzip_file, path)
        local result = {open_empty, empty, written, binary, plain}
        assert(binary.n==1 and binary[1]==data and plain[1]==false and empty.n==1)
        if gzip_init then
            local compressed = invoke(lua_path, gzip_file, path, data, "2", 5, 7, 13)
            local archived = invoke(lua_path, readfile, path)[1]
            local magic = invoke(lua_path, is_gzip_file, path)
            local unpacked = invoke(lua_path, gunzip_file, path, 4, 3)
            local transparent = invoke(lua_path, z_readfile, path, "4")
            assert(magic[1]==true and unpacked[1]==data and transparent[1]==data)
            invoke(lua_path, writefile, path, archived:sub(1,-5))
            local corrupt = invoke(lua_path, gunzip_file, path, 4, 5)
            assert(corrupt.n==1 and corrupt[1]==nil)
            local fallback = invoke(lua_path, z_readfile, path)
            assert(fallback[1]==archived:sub(1,-5))
            result[6], result[7], result[8] = compressed, archived, corrupt
        end
        assert(os.remove(path))
        local missing = invoke(lua_path, pcall, readfile, path)
        assert(missing[1]==false and tostring(missing[2]):find("readfile: ",1,true))
        return result
    end
    compare("file helpers", exercise)

    local io_open = io.open
    local file = {
        read=function() return coroutine.yield("read pending") end,
        close=function() end,
    }
    io.open=function() return file end
    local co = coroutine.create(readfile)
    local ok, pending = coroutine.resume(co, "unused")
    assert(ok and pending=="read pending")
    local resumed, output = coroutine.resume(co, "resumed data")
    assert(resumed and output=="resumed data" and coroutine.status(co)=="dead")
    io.open=io_open
    print("ok Rust file helpers match Lua including compression, result arity and yielding reads")
end

local function strategies()
    local logs, sends, state
    DLOG=function(message) logs[#logs+1]=message end
    direction_cutoff_opposite=function(_,d) state.opposite=d.arg.dir or "out" end
    instance_cutoff_shim=function() state.cutoff=true end
    genhost=function(count) return string.rep("H", count) end
    resolve_pos=function(_,_,marker) return ({["2"]=2,["1"]=1,mid=5,["-1"]=9,near=4,far=10})[marker] end
    resolve_multi_pos=function(_,_,marker) return marker=="bad" and {1} or {1,4,7} end
    resolve_range=function(_,_,_,valid) assert(valid);return state.range end
    tls_mod_shim=function(_,value,mods,source)
        return value..mods..(source or "")
    end
    apply_fooling=function(_,dis) dis.tcp.th_flags=19 end
    rawsend_payload_segmented=function(_,data,seq,opts)
        local result = {data=data, seq=seq, repeats=opts and opts.rawsend.repeats,
            fooling=opts and opts.fooling.tcp_ts_up, mark=opts and opts.rawsend.fwmark}
        sends[#sends+1] = result
        return #sends~=state.fail
    end
    rawsend_dissect_ipfrag=function(dis,options)
        sends[#sends+1] = {data=dis.payload, flags=dis.tcp.th_flags, repeats=options.rawsend.repeats}
        return #sends~=state.fail
    end
    local count = 0
    for _,name in ipairs({"fake","syndata","multisplit","multidisorder","fakedsplit","fakeddisorder","hostfakesplit"}) do
        for variant=1,18 do
            for failure=0,8 do
                compare(name.." "..variant.." "..failure, function(lua_path)
                    b_debug=variant%2==0
                    logs,sends,state = {},{}, {fail=failure, range=variant~=4 and {3,7} or nil}
                    local flags = variant==2 and TH_SYN+TH_ACK or TH_SYN
                    local arg = {pos=variant==4 and "bad" or variant==10 and "1" or "2", repeats="2", fwmark=6,
                        tcp_ts_up=true, seqovl_pattern="payload_pattern", pattern="payload_pattern"}
                    if variant==3 then arg.nodrop=true end
                    if variant==5 then arg.tls_mod="rnd" end
                    if variant==6 then arg.nofake1=true;arg.nofake4=true end
                    if variant==7 and name~="syndata" then arg.optional=true;arg.blob="missing_blob" end
                    if variant==8 then arg.dir="in" end
                    if variant==11 then arg.disorder_after="" end
                    if variant==12 then arg.midhost="mid" end
                    if variant==13 then arg.midhost="far";arg.disorder_after="near" end
                    if variant==14 then arg.midhost="bad";arg.disorder_after="bad" end
                    if variant==15 then arg.seqovl_pattern="missing_pattern";arg.optional=true end
                    if variant==16 then arg.payload="~known" end
                    if name=="fake" and not arg.blob then arg.blob="payload_pattern" end
                    if name=="multidisorder" or name=="fakeddisorder" then
                        arg.seqovl=variant==17 and "far" or variant==18 and "bad" or "2"
                    elseif name=="multisplit" or name=="fakedsplit" then
                        arg.seqovl="3"
                    end
                    local d={func_instance=name, arg=arg, outgoing=variant~=9, l7payload="tls_client_hello",
                        dis={payload="a\0bcdefghi",tcp=variant~=2 and {th_flags=flags} or nil},
                        reasm_data=variant==5 and "reassembled" or nil, payload_pattern="\x3a\0",
                        replay=variant>=16, replay_piece=variant==17 and 2 or 1, replay_piece_last=variant==17,
                        track={lua_state={[name.."_replay_drop"]=variant==17 and true or nil}},
                    }
                    if variant==2 then
                        if name=="syndata" then d.dis.tcp={th_flags=flags} elseif failure%2==0 then d.dis.icmp={} end
                    end
                    local verdict=invoke(lua_path, assert(_G[name]), nil, d)
                    return {logs=logs, sends=sends, state=state, verdict=verdict, track=d.track.lua_state}
                end)
                count = count + 1
            end
        end
    end
    print("ok native strategy bytes, offsets, logs, replay and send failures match Lua in "..count.." cases")
end

local function automation()
    local logs, resets
    local time
    os.time=function() return time end
    DLOG=function(message) logs[#logs+1]=message end
    rawsend_dissect=function(dis, options) resets[#resets+1]={dis,options} end
    b_debug=true
    compare("automation counters", function(lua_path)
        logs={}
        local host,conn={},{}
        time=10
        local outcomes={invoke(lua_path, automate_failure_counter,host,conn,3,60)}
        outcomes[2]=invoke(lua_path, automate_failure_counter,host,conn,3,60)
        time=100
        outcomes[3]=invoke(lua_path, automate_failure_counter,host,{},3,60)
        outcomes[4]=invoke(lua_path, automate_failure_counter,host,nil,3,60)
        outcomes[5]=invoke(lua_path, automate_failure_counter,host,nil,3,60)
        invoke(lua_path, automate_failure_counter_reset,host)
        assert(outcomes[5][1]==true and host.failure_counter==nil)
        return {outcomes,host,conn,logs}
    end)
    for variant=1,15 do
        compare("detector "..variant, function(lua_path)
            logs,resets={},{}
            local t={pcounter=variant==10 and 0 or 5,
                tcp={rseq=variant==2 and 40000 or variant==3 and 6000 or 32, uppos_prev=3, pos=2, winsize=2048}}
            local reverse={pcounter=variant==9 and 3 or 1,tcp={winsize=512},ip6_flow=0x60080000}
            local d={arg={reset=true,retrans=variant==4 and "2" or 3,no_rst=variant==5 or nil,
                no_http_redirect=variant==6 or nil}, outgoing=variant==1 or variant==2 or variant==4 or variant==8 or variant==9,
                track={hostname="one.example.com",lua_state={},pos={direct=t,reverse=reverse}},
                l7payload=variant>=5 and variant<=7 and "http_reply" or "unknown", ifin="test",
                dis={payload=variant==7 and "HTTP/1.1 307 Found\r\nLocation: http://example.net/blocked\r\n\r\n" or "a",
                    tcp=variant<8 and {th_flags=variant==3 and TH_RST or TH_ACK,th_sport=80,th_dport=65000} or nil,
                    udp=variant>=8 and variant<=10 and {} or nil,
                    ip6={ip6_src=string.rep("x",16),ip6_dst=string.rep("y",16)},
                }}
            local c={retrans=variant==4 and 1 or nil}
            time=300
            local failed=invoke(lua_path, standard_failure_detector,d,c)
            local success=invoke(lua_path, standard_success_detector,d,c)
            local host={}
            d.arg.fails=2
            local checked=invoke(lua_path, automate_failure_check,d,host,c)
            return {failed,success,checked,host,c,logs,resets}
        end)
    end
    compare("host keys and conditions", function(lua_path)
        local d={arg={nld="2",pattern="x\0"},track={hostname="a.b.example.com",lua_state={}},
            dis={tcp={options={{kind=TCP_KIND_TS}}},payload="aax\0a"}}
        local record=invoke(lua_path, automate_conn_record,d)
        assert(record[1]==d.track.lua_state.automate)
        local key=invoke(lua_path, standard_hostkey,d)
        assert(key[1]=="example.com")
        return {key,invoke(lua_path, cond_payload_str,d),invoke(lua_path,cond_tcp_has_ts,d),
            invoke(lua_path,cond_true,d),invoke(lua_path,cond_false,d)}
    end)
    print("ok native automation matches counters, logging, host keys and detector decisions")
end

local function autoring()
    local reference_get, reference_new = automate_host_record, ring_store.new
    local reference_success, reference_failure = standard_success_detector, standard_failure_detector
    local reference_clock, reference_log, reference_error_log = clock_getfloattime, DLOG, DLOG_ERR
    local reference_time = os.time
    local diagnostics, writes
    clock_getfloattime=function() return 101 end
    os.time=function() return 105 end
    DLOG=function() end
    automate_host_record=function(d) return d.host end
    ring_store.new=function()
        return {
            get=function(_, key) if key=="192.0.2.0/24" then return 2 end end,
            put=function(_, key, value) writes[#writes+1]={key,value} end,
            discard=function() end,
        }
    end
    for variant=1,8 do
        compare("ring variant "..variant, function(lua_path)
            diagnostics,writes={},{}
            DLOG_ERR=function(message)
                assert(message:find("injected detector error",1,true), message)
                diagnostics[#diagnostics+1]=true
            end
            local d={
                arg={key=(lua_path and "lua-" or "rust-")..variant, fails=4},
                dis={tcp={th_flags=TH_ACK,th_ack=30001}, payload="x", ip={ip_ttl=61}},
                track={hostname="test.example.com",l7proto="tls",lua_state={},incoming_ttl=61,
                    pos={direct={tcp={rseq=1,uppos=2,uppos_prev=0,pos=1}},reverse={pcounter=1,tcp={seq0=1}}}},
                outgoing=true, host={nstrategy=1,ctstrategy=3}, target={ip="\192\0\2\1"},
            }
            local conn={}
            standard_success_detector=function() return variant==1 end
            local observed={}
            standard_failure_detector=function(packet)
                observed[#observed+1]=packet.arg.retrans or false
                if variant==8 and #observed==1 then error("injected detector error") end
                return variant==2
            end
            local mark=invoke(lua_path,rst_mark,nil,d)
            if variant==3 then d.outgoing=false;d.dis.tcp.th_flags=TH_RST;d.dis.ip.ip_ttl=55 end
            if variant==4 then d.dis.tcp.th_ack=28001 end
            if variant==2 or variant==8 then d.dis.tcp.th_ack=1 end
            if variant==5 then conn.nocheck=true end
            if variant==6 then d.host.ring_cache_evicted=true end
            local guard=invoke(lua_path,rst_guard,nil,d)
            local success=invoke(lua_path,ring_success,d,conn)
            if variant==7 then d.outgoing=false;d.dis.tcp.th_flags=TH_FIN end
            local failure=invoke(lua_path,ring_failure,d,conn)
            if variant==8 then
                assert(#diagnostics==1 and observed[1]==2 and observed[2]==nil and d.arg.retrans==nil)
            else
                assert(#diagnostics==0)
            end
            return {mark,guard,success,failure,writes,observed,conn,d.host,d.track.lua_state,d.arg.retrans}
        end)
    end
    automate_host_record,ring_store.new=reference_get,reference_new
    standard_success_detector,standard_failure_detector=reference_success,reference_failure
    clock_getfloattime,DLOG,DLOG_ERR=reference_clock,reference_log,reference_error_log
    os.time=reference_time
    print("ok native autoring matches Lua strategy hints, connection guards and failed-detector recovery")
end

local function packet_library()
    local original_log, original_random = DLOG, brandom
    local original_send = rawsend_dissect
    local original_rng = math.random
    local logs, sends
    DLOG=function(message) logs[#logs+1]=message end
    brandom=function(size) return ("x"):rep(size) end
    math.random=function(low,high) return high and low+5 or 1 end
    native_fixture_fragment=function(dis)
        local fragments={}
        for i=1,3 do
            local entry=deepcopy(dis)
            entry.frag=i
            fragments[i]=entry
        end
        return fragments
    end
    for variant=1,22 do
        compare("header edits "..variant, function(lua_path)
            logs={}
            local packet={
                ip=variant<12 and {ip_ttl=64,ip_id=65535} or nil,
                ip6=variant>=12 and {ip6_hlim=64,ip6_nxt=IPPROTO_TCP,exthdr={}} or nil,
                tcp={th_seq=4294967295,th_flags=TH_SYN,th_ack=1,options={
                    {kind=TCP_KIND_NOOP}, {kind=2,data="\0\xff"},
                    {kind=TCP_KIND_TS,data=bu32(4)..bu32(7)},
                }},
                payload="abcdefghi",
            }
            local opts={tcp_seq="2",tcp_ack="-4",tcp_ts="-5",tcp_flags_set="ACK,PSH",tcp_flags_unset="SYN",
                tcp_nop_del=true,tcp_ts_up=true,ip_id="seq",ip_id_conn=true}
            if variant%3==0 then opts.tcp_md5="" end
            if variant%3==1 then opts.ip_ttl="19";opts.ip6_ttl="19" end
            if variant%3==2 then opts.ip_autottl="-1,1-15";opts.ip6_autottl="-1,1-15" end
            if variant>=12 then
                opts.ip6_hopbyhop=""
                opts.ip6_destopt="000000000001"
                opts.ip6_ah=""
            end
            local desync={dis=packet,arg=opts,func_instance="header-test",
                track={incoming_ttl=variant%5==0 and 17 or 60,lua_state={}}}
            invoke(lua_path,apply_fooling,desync)
            invoke(lua_path,apply_fooling,desync)
            invoke(lua_path,apply_ip_id,desync)
            return {packet,desync.track.lua_state,logs,invoke(lua_path,packet_len,packet),
                invoke(lua_path,l3_extra_len,packet,2.5),invoke(lua_path,find_tcp_option,packet.tcp.options,TCP_KIND_TS)}
        end)
    end
    for variant=1,18 do
        for failure=0,4 do
            compare("segment variant "..variant.." "..failure, function(lua_path)
                logs,sends={},{}
                rawsend_dissect=function(d, raw, reconstruct)
                    sends[#sends+1]={deepcopy(d),deepcopy(raw),deepcopy(reconstruct)}
                    return #sends~=failure, "send detail"
                end
                local arg={tcp_seq="2",ip_id_conn=true,ip_id="seq",fwmark=11,badsum=true}
                if variant%4==0 then arg.ipfrag="native_fixture_fragment" end
                if variant%8==0 then arg.ipfrag_disorder=true end
                if variant%3==0 then arg.dir="in" end
                local d={arg=arg, outgoing=variant%5==0,l7payload="http_req",tcp_mss=variant,
                    track={lua_state={},pos={direct={pcounter=3,tcp={rseq=5,pos=8}},reverse={pcounter=9,tcp={rseq=4}}}},
                    dis={ip={ip_id=65535},tcp={th_seq=4294967295,th_urp=variant%10,th_flags=TH_URG,options={}},payload="old"}}
                local range={from={mode="s",pos=4},to={mode="n",pos=3},upper_cutoff=variant%2==0}
                return {invoke(lua_path,rawsend_payload_segmented,d,"abcdefghij",-1),
                    invoke(lua_path,pos_check_range,d,range),invoke(lua_path,pos_get,d,"n",true),
                    invoke(lua_path,direction_check,d),sends,logs,d}
            end)
        end
    end
    for variant=1,18 do
        compare("fragments "..variant, function(lua_path)
            logs={}
            local dis={payload=("abc"):rep(30),udp={uh_sport=12,uh_dport=53}}
            if variant%2==0 then
                dis.ip={ip_id=variant%3==0 and 65535 or 0,options=variant%5==0 and "123" or nil}
            else
                local extensions={
                    {type=IPPROTO_HOPOPTS,next=IPPROTO_DSTOPTS,data=string.rep("a",6)},
                    {type=IPPROTO_DSTOPTS,next=IPPROTO_ROUTING,data=string.rep("b",6)},
                    {type=IPPROTO_ROUTING,next=IPPROTO_DSTOPTS,data=string.rep("c",6)},
                    {type=IPPROTO_DSTOPTS,next=IPPROTO_UDP,data=string.rep("d",6)},
                }
                dis.ip6={ip6_nxt=IPPROTO_HOPOPTS,exthdr=extensions}
                if variant%3==0 then
                    invoke(lua_path,del_ip6_exthdr,dis.ip6,2)
                    invoke(lua_path,fix_ip6_next,dis.ip6,IPPROTO_UDP)
                end
            end
            local options={ipfrag_pos_udp=variant%7==0 and "256" or variant%3==0 and "24" or nil,
                ipfrag_next=variant%4==1 and "255" or nil}
            return {invoke(lua_path,ipfrag2,dis,options),logs,dis}
        end)
    end
    rawsend_dissect=original_send
    brandom,DLOG=original_random,original_log
    math.random=original_rng
    native_fixture_fragment=nil
    print("ok native packet helpers match Lua header edits, TTL cache, segmentation and fragment order")
end

local function rule_data()
    local shared = {key="value"}
    local linked = setmetatable({shared,shared}, {__index={default=17}})
    linked.self=linked
    local copy=deepcopy(linked)
    assert(copy~=linked and copy[1]~=shared and copy.self==copy and copy[1]==copy[2] and copy.default==17)
    local deep={leaf=true}
    for _=1,1024 do deep={next=deep} end
    local nested=deepcopy(deep)
    for _=1,1024 do nested=nested.next end
    assert(nested.leaf==true)
    local moved=zero_based_pos({1,"4",12})
    assert(moved[1]==0 and moved[2]=="4" and moved[3]==11)
    assert(delete_pos_1({1,1,2,1})[1]==2)
    assert(blob({value="\0blob"},"value")=="\0blob")
    assert(seq_ge(3,4294967294) and seq_lt(4294967294,3) and seq_within(4,4294967292,12))
    print("ok native rule data preserves cyclic copies, binary blobs and sequence wraparound")
end

local function plans()
    local original_log = DLOG
    local original_cancel, original_plan = execution_plan_cancel, execution_plan
    local logs, calls
    DLOG=function(message) logs[#logs+1]=message end
    execution_plan_cancel=function() calls[#calls+1]="cancel" end
    execution_plan=function() return {} end
    native_fixture_plan_one=function(_,d)
        calls[#calls+1]={d.func_instance,d.arg.direct,d.arg.escaped,d.arg.width}
        return VERDICT_MODIFY, VERDICT_DROP
    end
    native_fixture_plan_two=function(_,d)
        calls[#calls+1]=d.func_instance
        return VERDICT_DROP
    end
    native_fixture_plan_predicate=function(d) return d.arg.keep=="yes" end
    for variant=1,16 do
        compare("plan "..variant, function(lua_path)
            logs,calls={},{}
            b_debug=variant%2==0
            local range={from={mode="a",pos=0},to={mode="a",pos=0},upper_cutoff=false}
            local desync={track={lua_state={}},dis={payload="abc"},lua_fixture_blob="data",outgoing=true,
                arg={iff=variant%3==0 and "cond_false" or "cond_true",repeats="2",instances="2",
                    neg=variant%4==0 or nil,clear=variant==6 or nil,stop=variant==7 or nil},
                func="initial",func_instance="initial",l7payload="tls_client_hello",
                plan={
                    {func="native_fixture_plan_one",func_n=1,func_instance="one",range=range,payload_filter="all",
                        arg={cond="native_fixture_plan_predicate",keep="yes",direct="%lua_fixture_blob",
                            width="#lua_fixture_blob",escaped="\\%lua_fixture_blob"}},
                    {func="native_fixture_plan_two",func_n=2,func_instance="two",range=range,payload_filter="known",
                        arg={cond=variant%2==0 and "cond_false" or "cond_true"}},
                    {func="native_fixture_plan_one",func_n=3,func_instance="three",range=range,payload_filter="all",
                        arg={direct="last",escaped="last",width="last"}},
                }}
            if variant==9 then invoke(lua_path,instance_cutoff_shim,nil,{
                track=desync.track,func_instance="two",
            },true) end
            if variant==10 then desync.plan[2].payload_filter="none" end
            if variant==11 then desync.plan[2].range={from={mode="x",pos=0},to=range.to} end
            local rule=({"condition","per_instance_condition","stopif","repeater"})[(variant-1)%4+1]
            local result=invoke(lua_path,_G[rule],nil,desync)
            local replay=invoke(lua_path,replay_execution_plan,desync,1)
            local copy=invoke(lua_path,desync_copy,desync)[1]
            assert(copy.track.lua_state==desync.track.lua_state and copy.plan==desync.plan)
            return {result,replay,calls,logs,desync}
        end)
    end
    compare("condition code", function(lua_path)
        local d={func_instance=lua_path and "condition_lua" or "condition_rust",
            arg={cond_code="return desync.arg.cond_code~=nil"}}
        local result=invoke(lua_path,cond_lua,d)
        assert(result[1]==true and _G.desync==nil)
        return result
    end)
    execution_plan_cancel,execution_plan=original_cancel,original_plan
    DLOG=original_log
    print("ok native rule plans match Lua cutoffs, conditional dispatch, repeats and aggregated verdicts")
end

local function protocol_codecs()
    local comparisons=0
    for _,request in ipairs({
        "GET /a HTTP/1.1\r\nHost: example.org\r\nX-Binary:\t\0abc \r\n\r\nhello",
        "\r\n\n GET HTTP/1.0\nUnstructured\nEmpty:  \n\n",
        "GET\t  /x\t\tHTTP/1.1\r\nEmpty:  \r\n\r\n",
        "CONNECT dst.example:443", "GET ", "", "GET /x\nMissingColons\n\nbody",
        "HTTP/1.0 308 Moved\r\nLocation: https://example.org/a\r\n\r\nz",
        "HTTP/1.1 302\nLocation: /here\n\n", "HTTP/2.0 302\r\n", "HTTP/1.1 200",
    }) do
        compare("HTTP binary message", function(lua_path)
            local req=invoke(lua_path,http_dissect_req,request)
            local reply=invoke(lua_path,http_dissect_reply,request)
            local header=invoke(lua_path,http_dissect_header,request)
            local raw=req[1] and invoke(lua_path,http_reconstruct_req,req[1],true)
            return {req,reply,header,raw}
        end)
    end
    for _,url in ipairs({"  https://user:pass@example.org:443/x?a=b", "/r?q", " #hash",
        "///host", "plain.example", "https://[::1]/", "a+b://foo", "HTTP://example", "host?x",
        " x@domain.test/path", " ", "", "\0https://host/"}) do
        compare("url and domain", function(lua_path)
            return {invoke(lua_path,dissect_url,url), invoke(lua_path,dissect_nld,url,2),
                invoke(lua_path,dissect_nld,"a..b.",1), invoke(lua_path,dissect_nld,"",1)}
        end)
    end
    local function extension(kind,data) return bu16(kind)..bu16(#data)..data end
    local function record(kind,data) return bu8(kind).."\3\3"..bu16(#data)..data end
    local host="example.org"
    local named=bu8(0)..bu16(#host)..host
    local extensions=extension(0,bu16(#named)..named)..
        extension(16,"\0\3\2h3")..extension(43,"\4\3\4\3\3")..
        extension(27,"\2\0\2")..extension(10,"\0\2\0\29")..
        extension(13,"\0\3\8\4\0")..extension(34,"\0\2\4\3")..
        extension(11,"\1\0")..extension(45,"\1\1")..
        extension(51,"\0\6\0\29\0\2ab")..
        extension(65445,"\0\6\0\1\0\2ql")..
        extension(57,"\1\2mv\192\32\0\0\0\0\0\0\1Z")..
        extension(65280,"\0experimental")
    local cb="\3\3"..("c"):rep(32).."\2si\0\2\19\1\1\0"..bu16(#extensions)..extensions
    local hello="\1"..bu24(#cb)..cb
    local sb="\3\3"..("s"):rep(32).."\0\19\1\0\0\0"
    local server="\2"..bu24(#sb)..sb
    local old_random=brandom
    brandom=function(size) return ("R"):rep(size) end
    for _,input in ipairs({
        hello, server, record(22,hello), record(22,server),
        record(22,hello:sub(1,51))..record(22,hello:sub(52,95))..record(22,hello:sub(96)),
        record(22,hello)..record(20,"\1")..record(22,"\255encoded")..record(23,"lo"),
        record(29,"unrecognized"), record(22,"\1\0"), record(22,"\1\0\0\20abc"),
    }) do
        for size=0,#input do
            for _,partial in ipairs({false,true}) do
                local bytes="\0"..input:sub(1,size)
                compare("TLS offset/partial "..size.." "..tostring(partial), function(lua_path)
                    local data=invoke(lua_path,tls_dissect,bytes,2,partial)
                    local original=deepcopy(data)
                    local rebuilt=data[1] and invoke(lua_path,pcall,tls_reconstruct,data[1])
                    if rebuilt and not rebuilt[1] then
                        rebuilt={false}
                    end
                    return {original,rebuilt,data,invoke(lua_path,is_tls_hello,bytes,2,partial),
                        invoke(lua_path,is_tls_record,bytes,2,nil,partial)}
                end)
                comparisons=comparisons+1
            end
        end
    end
    for _,options in ipairs({
        {sni_del=true,sni_first="new.test",sni_snt_new=0},
        {sni_snt=3,sni_last="last.test",sni_snt_new=0}, {sni_del_ext=true}, {},
    }) do
        compare("TLS hello alteration and reconstruction", function(lua_path)
            return invoke(lua_path,tls_client_hello_mod,record(22,hello),options)
        end)
    end
    local bare=cb:sub(1,#cb-#extensions-2).."\0\0"
    compare("TLS clients without SNI", function(lua_path)
        return invoke(lua_path,tls_client_hello_mod,"\1"..bu24(#bare)..bare,{sni_first="new.test"})
    end)
    for _,value in ipairs({0,63,64,16383,16384,1073741823,1073741824,9007199254740991,
        "\192\32\0\0\0\0\0\0", "\255\255\255\255\255\255\255\255"}) do
        compare("QUIC variable integer", function(lua_path)
            local wire=invoke(lua_path,bquic_tvb,value)
            return {wire,invoke(lua_path,quic_tvb,"prefix"..wire[1],7),invoke(lua_path,quic_tvb,wire[1]:sub(1,-2))}
        end)
    end
    brandom=old_random
    print("ok native HTTP and QUIC helpers match Lua and "..comparisons.." TLS comparisons passed")
end

local function stock_utilities()
    local old_log, old_ntop, old_ifaddrs, old_time = DLOG,ntop,get_ifaddrs,os.time
    for variant=1,8 do
        compare("stock utilities "..variant, function(lua_path)
            local messages={}
            DLOG=function(message) messages[#messages+1]=message end
            ntop=function(ip) return "["..ip.."]" end
            os.time=function() return 500 end
            get_ifaddrs=function() return {interface={addr={{addr="local-ip"}}}} end
            ifaddrs,ifaddrs_last=nil,nil
            local with_track={lua_state={},pos={
                dt=2,direct={pcounter=1,pdcounter=3,pbcounter=5,tcp={rseq=6,pos=7}},
                reverse={pcounter=2,pdcounter=4,pbcounter=6,tcp={rseq=9,pos=17}},
            }}
            local dis={ip={ip_src="src",ip_dst="dst",ip_p=6},tcp={th_sport=11,th_dport=22,th_seq=3,th_ack=7},payload="payload"}
            local d={dis=dis,track=with_track,outgoing=variant%2==0,
                arg={pattern="load",payload="fixture",undetected="unmatched",code="return desync.dis.tcp.th_ack"},
                func_instance=lua_path and "inline_lua" or "inline_rust"}
            if variant==2 then d.reasm_data="no match" end
            if variant==3 then d.decrypt_data="decoded";d.replay_piece_count=4;d.replay_piece=1 end
            invoke(lua_path,detect_payload_str,nil,d)
            invoke(lua_path,posdebug,nil,d)
            invoke(lua_path,var_debug,{only={"bytes\0"}})
            local code=invoke(lua_path,luaexec,nil,d)
            assert(_G.desync==nil)
            d.func_instance="timer"
            local timer=invoke(lua_path,desync_timer_name,d)
            invoke(lua_path,dis_reverse,dis)
            invoke(lua_path,fix_ip_proto,dis,17)
            local p=invoke(lua_path,pos_range_str,{from={mode="s",pos=5},to={mode="d",pos=9},upper_cutoff=true})
            local array=invoke(lua_path,barray,{"a","b","c"},function(value) return value.."," end)
            local map=invoke(lua_path,btable,{key="test"},function(value) return value end)
            return {d,code,timer,p,array,map,messages,invoke(lua_path,ip2ifname,"local-ip"),
                invoke(lua_path,ip2ifname,"absent"),invoke(lua_path,ip_proto,dis)}
        end)
    end
    DLOG,ntop,get_ifaddrs,os.time=old_log,old_ntop,old_ifaddrs,old_time
    ifaddrs,ifaddrs_last=nil,nil
    local d={arg={},track={hostname="fixture.test"},func_instance="fixture_stock_host"}
    assert(automate_host_record(d)==autostate.fixture_stock_host["fixture.test"])
    autostate.fixture_stock_host=nil
    print("ok native stock helpers match diagnostics, timers, inline rules and host records")
end

local function additional_rules()
    local old={}
    for _,name in ipairs({"DLOG","timer_set","resolve_range","resolve_pos","resolve_multi_pos",
        "rawsend_dissect_ipfrag","rawsend_dissect_segmented","rawsend_payload_segmented",
        "direction_cutoff_opposite","instance_cutoff_shim","desync_timer_name"}) do
        old[name]=packed(_G[name])
    end
    local messages,effects,fail_at
    DLOG=function(message) messages[#messages+1]=message end
    timer_set=function(...) effects[#effects+1]=packed(...) end
    desync_timer_name=function() return "native-timer-fixture" end
    instance_cutoff_shim=function(_,d,arg) effects[#effects+1]={"cutoff",d.func_instance,arg} end
    direction_cutoff_opposite=function(_,d,arg) effects[#effects+1]={"opposite",d.func_instance,arg} end
    resolve_multi_pos=function(text,_,markers)
        if markers=="host,endhost" then
            local first,last=text:find("example.test",1,true)
            return first and {first,last+1} or {}
        end
        return markers=="bad" and {} or {2,4,6,8}
    end
    resolve_pos=function(_,_,marker) return ({inside=3,outside=20,["2"]=2})[marker] end
    resolve_range=function(_,_,marker) return marker=="bad" and nil or {2,4} end
    local function append(kind,packet,options)
        effects[#effects+1]={kind,deepcopy(packet),deepcopy(options)}
        return #effects~=fail_at
    end
    rawsend_dissect_ipfrag=function(dis,options) return append("ipfrag",dis,options) end
    rawsend_dissect_segmented=function(_,dis) return append("segment",dis) end
    rawsend_payload_segmented=function(_,bytes,offset) return append("payload",bytes,offset) end
    local count=0
    for _,rule in ipairs({"drop","send","pktmod","http_domcase","http_hostcase","http_methodeol","http_unixeol",
        "synack_split","synack","wsize","wssize","tls_client_hello_clone","rst","multidisorder_legacy",
        "tcpseg","oob","udplen","dht_dn"}) do
        for variant=1,16 do
            compare(rule.." optional variant "..variant, function(lua_path)
                messages,effects,fail_at={},{},variant==12 and 2 or nil
                local payload="abcdefghij"
                local l7="tls_client_hello"
                if rule:sub(1,5)=="http_" then
                    l7="http_req"
                    payload=variant==3 and "missing" or
                        ("GET / HTTP/1.1\r\nHost: example.test\r\nUser-Agent: "..(variant==4 and "a" or "browser").."\r\n\r\n")
                elseif rule=="dht_dn" then
                    l7,payload="dht","d1:a1:be"
                elseif rule=="udplen" then
                    l7="dns"
                end
                if variant==16 then payload="" end
                local flags=variant%2==0 and TH_SYN+TH_ACK or TH_SYN
                local tcp={th_flags=flags,th_urp=0,th_win=64,th_seq=4,th_ack=7,options={{kind=TCP_KIND_SCALE,data=bu8(4)}}}
                local is_udp=rule=="dht_dn" or rule=="udplen"
                local dis={tcp=not is_udp and variant~=8 and tcp or nil,udp=is_udp and variant~=8 and {} or nil,
                    payload=payload,icmp=variant==8 and {} or nil,ip={ip_id=variant}}
                local arg={wsize="128",scale="2",blob="clone_dst",fallback="fallback_blob",
                    mode=variant%3==0 and "syn" or variant%3==1 and "synack" or "acksyn",
                    spell="hOsT",pos=variant==6 and "bad" or "2",seqovl=(rule=="multidisorder_legacy" and "inside" or "1"),
                    urp=({[2]="e",[3]="inside",[4]="unknown"})[variant],increment=variant%3==0 and "-2" or "3",
                    pattern="fallback_blob",pattern_offset="1",rstack=variant%2==0,
                    delay=rule=="send" and variant==2 and "50" or nil}
                local d={func_instance="fixture",outgoing=variant~=5,dis=dis,arg=arg,l7payload=l7,
                    replay=variant==9 or variant==10,replay_piece=variant==9 and 2 or 1,replay_piece_last=variant==9,
                    reasm_data=rule=="multidisorder_legacy" and payload..payload or nil,reasm_offset=variant%4,
                    track={lua_state={fixture_syn=variant~=13 and true or nil},pos={
                        direct={tcp={rseq=variant==14 and 0 or variant==9 and 2 or 1}},
                        reverse={tcp={rseq=variant==5 and 2 or 1}},
                    }},fallback_blob="x\0z",clone_dst=rule=="tcpseg" and "abcd" or nil}
                b_debug=variant%2==0
                local result=invoke(lua_path,_G[rule],nil,d)
                if rule=="send" and arg.delay then
                    invoke(lua_path,send_timer_delayed,"fixture",effects[#effects][5])
                end
                return {result,effects,d,messages}
            end)
            count=count+1
        end
    end
    for name,value in pairs(old) do _G[name]=value[1] end
    print("ok extra stock packet rules match Lua in "..count.." cases")
end

assert(zapret_native_modules.automation and zapret_native_modules.strategies and
    zapret_native_modules.autoring and zapret_native_modules.packet_utils)
files()
autoring()
packet_library()
rule_data()
plans()
protocol_codecs()
stock_utilities()
automation()
additional_rules()
strategies()
print("ok native Lua module fixture completed")
io.stdout:flush()
