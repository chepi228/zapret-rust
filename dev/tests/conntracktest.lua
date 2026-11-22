-- Exercises the real conntrack_feed API with packets kept entirely in memory.
local failures = 0
local function check(name, value)
    print((value and "ok " or "FAIL ")..name)
    if not value then failures = failures + 1 end
end
local function bytes(hex)
    return (hex:gsub("..", function(byte) return string.char(tonumber(byte, 16)) end))
end
local context_services = {lua_cutoff, execution_plan_cancel, raw_packet, execution_plan}
local missing_context, bad_type, wrong_count = true, true, true
for _, service in ipairs(context_services) do
    local ok, message = pcall(service, nil)
    missing_context = missing_context and not ok and tostring(message):find("missing ctx", 1, true) ~= nil
    ok, message = pcall(service, {})
    bad_type = bad_type and not ok and tostring(message):find("desync_ctx", 1, true) ~= nil
    ok, message = pcall(service, nil, nil, nil)
    wrong_count = wrong_count and not ok and tostring(message):find("expect", 1, true) ~= nil
end
check("orchestrated instance cutoff accepts a missing context before direction validation",
    pcall(instance_cutoff, nil, {}) and pcall(instance_cutoff, nil, false))
check("context services reject missing contexts through normal Lua errors", missing_context)
check("ordinary Lua tables cannot impersonate engine context userdata", bad_type)
check("context services validate argument counts before reading context state", wrong_count)
local tcp_wire = bytes("450000280001000040060000c0000201c6336402303901bb00000064000000005002200000000000")
local udp6_wire = bytes("6ab12345000b112520010db800000000000000000000000120010db800000000000000000000000214e9270f000b836a750070")

local function fails_with(callback, expected, ...)
    local ok, message = pcall(callback, ...)
    return not ok and tostring(message):find(expected, 1, true) ~= nil
end
local outer_entries = {rawsend, rawsend_dissect, conntrack_feed, reconstruct_dissect, dissect}
local outer_arity = true
for _, callback in ipairs(outer_entries) do
    outer_arity = outer_arity and fails_with(callback, "expect from") and
        fails_with(callback, "expect from", nil, nil, nil, nil)
end
check("outer packet entries validate argument counts before packet data", outer_arity)
check("rawsend validates its string before reading options",
    fails_with(rawsend, "string expected", {}, false))
check("rawsend_dissect validates its table before both option sets",
    fails_with(rawsend_dissect, "table expected", "short", false, false))
check("negative repeats stop both send paths before packet extraction",
    fails_with(rawsend, "rawsend: negative repeats", "short", {repeats=-1}) and
    fails_with(rawsend_dissect, "rawsend: negative repeats", {}, {repeats=-1}, false))
check("invalid send packets are rejected before any driver submission",
    fails_with(rawsend, "bad ip4/ip6 header", "short", {}) and
    fails_with(rawsend_dissect, "invalid dissect data", {}, {}, {}))
check("conntrack rejects unsupported types before reconstruction options",
    fails_with(conntrack_feed, "invalid packet data type", 42, false))
local absent_track, absent_direction = conntrack_feed("short", false)
check("raw conntrack input ignores reconstruction options and returns two nils on failure",
    absent_track == nil and absent_direction == nil and select("#", conntrack_feed("short")) == 2)
check("standalone reconstruction reads options before touching an invalid packet",
    fails_with(reconstruct_dissect, "table expected", "short", false))

local function packet(seq, ack, flags, reverse, payload, port, version)
    local frame = dissect(tcp_wire)
    frame.tcp.th_sport, frame.tcp.th_dport = port or 40000, 443
    frame.tcp.th_seq, frame.tcp.th_ack, frame.tcp.th_flags = seq, ack, flags
    frame.tcp.th_win = 4096
    frame.tcp.options = {{kind=2, data=string.char(5, 180)}, {kind=3, data=string.char(30)}}
    frame.payload = payload or ""
    if version == 6 then
        frame.ip6 = dissect(udp6_wire).ip6
        frame.ip = nil
        frame.ip6.ip6_nxt = 6
    end
    if reverse then
        frame.tcp.th_sport, frame.tcp.th_dport = frame.tcp.th_dport, frame.tcp.th_sport
        if frame.ip then frame.ip.ip_src, frame.ip.ip_dst = frame.ip.ip_dst, frame.ip.ip_src
        else frame.ip6.ip6_src, frame.ip6.ip6_dst = frame.ip6.ip6_dst, frame.ip6.ip6_src end
    end
    return frame
end

local old_states = setmetatable({}, {__mode="v"})
do
    local syn, outgoing = conntrack_feed(packet(100, 0, 2))
    assert(syn)
    local state = syn.lua_state
    state.marker = {}
    old_states[1] = state
    check("TCP SYN creates an outgoing connection with capped scale and MSS",
        outgoing and syn.pos.client.pcounter == 1 and syn.pos.server.pcounter == 0 and
        syn.pos.client.tcp.seq0 == 100 and syn.pos.client.tcp.scale == 14 and syn.pos.client.tcp.mss == 1460)

    local reply, out = conntrack_feed(packet(900, 101, 0x12, true))
    check("SYN ACK finds the same connection in reverse direction",
        reply and not out and reply.lua_state == state and reply.pos.client.tcp.seq0 == 100 and
        reply.pos.server.tcp.seq0 == 900 and reply.pos.server.pcounter == 1 and reply.pos.direct == reply.pos.server)

    local wire = reconstruct_dissect(packet(101, 901, 0x18, false, "a\0bc"))
    local ack = assert(conntrack_feed(wire))
    check("raw packet feed updates payload counters and scaled TCP windows",
        ack.lua_state == state and ack.pos.client.pcounter == 2 and ack.pos.client.pdcounter == 1 and
        ack.pos.client.pbcounter == 4 and ack.pos.client.tcp.pos == 5 and ack.pos.client.tcp.uppos == 5 and
        ack.pos.client.tcp.winsize_calc == 4096 * 16384)
    local retransmit = assert(conntrack_feed(wire))
    check("TCP retransmissions retain state and count transferred bytes",
        retransmit.lua_state == state and retransmit.pos.client.pcounter == 3 and
        retransmit.pos.client.pbcounter == 8 and retransmit.pos.client.tcp.uppos == 5)

    local data = assert(conntrack_feed(packet(901, 105, 0x18, true, "z")))
    check("server data updates server counters and logical client acknowledgements",
        data.pos.server.pcounter == 2 and data.pos.server.pbcounter == 1 and
        data.pos.server.tcp.pos == 2 and data.pos.client.tcp.rseq == 5)
    assert(conntrack_feed(packet(105, 902, 0x11)))
    local reused = assert(conntrack_feed(packet(9000, 0, 2)))
    check("a SYN after FIN resets the tuple and preserves the original counter semantics",
        reused.lua_state ~= state and reused.lua_state.marker == nil and
        reused.pos.client.pcounter == 0 and reused.pos.client.tcp.seq0 == 9000)
end
collectgarbage("collect")
check("tuple reinitialization releases the old Lua connection state", old_states[1] == nil)

local ack, direction = conntrack_feed(packet(4, 5, 0x10, false, "", 40002))
check("an untracked ACK cannot create a connection", ack == nil and direction == nil)
local invalid = conntrack_feed(packet(4, 5, 6, false, "", 40002))
check("SYN with RST retains the original connection creation rule", invalid == nil)
local ecn = conntrack_feed(packet(4, 0, 0xc2, false, "", 40002))
check("ECN and CWR bits keep a SYN eligible for tracking", ecn and ecn.pos.client.tcp.seq0 == 4)

local first_reply, out = conntrack_feed(packet(4242, 1234, 0x12, true, "", 40001))
check("first observed SYN ACK establishes the logical client direction",
    first_reply and not out and first_reply.pos.client.tcp.seq0 == 1233 and
    first_reply.pos.server.tcp.seq0 == 4242)
local client = conntrack_feed(packet(1234, 4243, 0x10, false, "", 40001))
check("client packets after a first SYN ACK reuse that connection",
    client and client.lua_state == first_reply.lua_state and client.pos.client.pcounter == 1)

local v6 = assert(conntrack_feed(packet(7, 0, 2, false, "", 40000, 6)))
check("IPv6 tuples stay distinct and retain the TCP flow label",
    v6.pos.client.tcp.seq0 == 7 and v6.pos.client.ip6_flow == 0x6ab12345)

local function udp(reverse)
    local frame = packet(0, 0, 0, reverse, "u\0p", 40003)
    frame.tcp = nil
    frame.ip.ip_p = 17
    frame.udp = dissect(udp6_wire).udp
    frame.udp.uh_sport, frame.udp.uh_dport = reverse and 443 or 40003, reverse and 40003 or 443
    return frame
end
local nested_track
local outer_packet = packet(700, 0, 2, false, "", 42110)
local deferred_options = setmetatable({}, {__index=function(_, key)
    if key == "keepsum" then nested_track = assert(conntrack_feed(packet(800, 0, 2, false, "", 42111))) end
    return nil
end})
local outer_track, outer_outgoing = conntrack_feed(outer_packet, deferred_options)
check("nested feed during option lookup preserves separate connections and outer direction",
    outer_track and nested_track and outer_outgoing and outer_track.lua_state ~= nested_track.lua_state and
    outer_track.pos.client.tcp.seq0 == 700 and nested_track.pos.client.tcp.seq0 == 800)
local request, req_out = conntrack_feed(udp(false))
local response, res_out = conntrack_feed(udp(true))
check("UDP directions reuse one Lua state with separate byte counters",
    request and response and req_out and not res_out and request.lua_state == response.lua_state and
    response.pos.client.pcounter == 1 and response.pos.server.pcounter == 1 and
    response.pos.client.pbcounter == 3 and response.pos.server.pbcounter == 3 and
    response.pos.client.tcp == nil)

local wrap_syn = assert(conntrack_feed(packet(0xffffffff, 0, 2, false, "", 40004)))
local wrap_reply = assert(conntrack_feed(packet(0x7fffffff, 0, 0x12, true, "", 40004)))
check("connection views retain uint32 sequence wrap at the SYN boundary",
    wrap_syn.pos.client.tcp.seq0 == 0xffffffff and wrap_syn.pos.client.tcp.rseq == 0 and
    wrap_reply.pos.client.tcp.seq == 0 and wrap_reply.pos.client.tcp.rseq == 1 and
    wrap_reply.lua_state == wrap_syn.lua_state)
local wrap_data = assert(conntrack_feed(packet(0, 0x80000000, 0x18, false, "wrap", 40004)))
check("relative TCP data positions stay unsigned across sequence rollover",
    wrap_data.pos.client.tcp.rseq == 1 and wrap_data.pos.client.tcp.pos == 5 and
    wrap_data.pos.client.pcounter == 2 and wrap_data.pos.client.pbcounter == 4)
check("direct and reverse fields alias the direction tables in both directions",
    wrap_data.pos.direct == wrap_data.pos.client and wrap_data.pos.reverse == wrap_data.pos.server and
    wrap_reply.pos.direct == wrap_reply.pos.server and wrap_reply.pos.reverse == wrap_reply.pos.client and
    response.pos.direct == response.pos.server and response.pos.reverse == response.pos.client)
check("connection views preserve independent snapshots and numeric timestamps",
    wrap_syn.pos.client.pcounter == 1 and wrap_syn.pos.client.pbcounter == 0 and
    wrap_reply.pos.client.pcounter == 1 and wrap_data.lua_state == wrap_syn.lua_state and
    type(wrap_data.t_start) == "number" and type(wrap_data.pos.dt) == "number" and wrap_data.pos.dt >= 0)

do
    local function keys(value)
        local result = {}
        for key in pairs(value) do result[#result+1] = key end
        table.sort(result)
        return table.concat(result, ",")
    end
    check("TCP position publication retains the complete outer catalog",
        keys(wrap_data.pos.client) == "pbcounter,pcounter,pdcounter,tcp")
    check("TCP position publication retains all ten numbers and the wrap flag",
        keys(wrap_data.pos.client.tcp) == "mss,pos,rseq,rseq_over_2G,scale,seq,seq0,uppos,uppos_prev,winsize,winsize_calc")
    check("UDP position publication omits TCP and zero IPv6 flow fields",
        keys(response.pos.client) == "pbcounter,pcounter,pdcounter" and response.pos.client.tcp == nil)
    check("IPv6 position publication preserves its conditional flow field",
        keys(v6.pos.client) == "ip6_flow,pbcounter,pcounter,pdcounter,tcp" and v6.pos.client.ip6_flow == 0x6ab12345)
    check("Connection position publication retains its complete alias catalog",
        keys(wrap_data.pos) == "client,direct,dt,reverse,server")
    local marker = {}
    wrap_data.pos.direct.publication_marker = marker
    wrap_data.pos.reverse.publication_marker = marker
    check("Published direct and reverse values share the original direction objects",
        wrap_data.pos.client.publication_marker == marker and wrap_data.pos.server.publication_marker == marker)
    wrap_data.pos.direct.publication_marker, wrap_data.pos.reverse.publication_marker = nil, nil
    wrap_data.lua_state.publication_marker = marker
    check("Published registry state shares identity across independent snapshots",
        wrap_syn.lua_state.publication_marker == marker and wrap_reply.lua_state.publication_marker == marker)
    wrap_data.lua_state.publication_marker = nil
    local counter = wrap_data.pos.client.pcounter
    wrap_data.pos.client.pcounter = -123
    check("Published position tables remain separate between snapshots",
        wrap_syn.pos.client.pcounter == 1 and wrap_reply.pos.client.pcounter == 1 and wrap_data.pos.direct.pcounter == -123)
    wrap_data.pos.client.pcounter = counter
end

if failures ~= 0 then error("conntrack fixture has "..failures.." failed checks") end
print("ok conntrack fixture completed")
