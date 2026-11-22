-- Offline fixture shared by the embedded binding and the real engine.
local native = assert(zapret_ring_native)
local tcp_calls, split_calls = 0, 0

local tcp_fallback, host_split = assert(native.tcp_fallback), assert(native.host_split)
-- The adapter captures a backend when it loads. Exercise it with a test
-- backend forwarding each call to the real Rust API.
native.tcp_fallback = function(...)
	tcp_calls = tcp_calls + 1
	return tcp_fallback(...)
end
native.host_split = function(...)
	split_calls = split_calls + 1
	return host_split(...)
end

assert(FOOLING_ADAPTER)()
native.tcp_fallback, native.host_split = tcp_fallback, host_split

local function check(name, value)
	assert(value, name)
	print("ok "..name)
end

TCP_KIND_TS, TCP_KIND_MD5 = 8, 19
local random_calls = 0
brandom = function(size)
	random_calls = random_calls + 1
	return string.rep("x", size)
end
if not DLOG then DLOG = function() end end
if not find_tcp_option then
	find_tcp_option = function(options, kind)
		for index, option in ipairs(options or {}) do
			if option.kind==kind then return index end
		end
	end
end
ts_or_md5({})
local tcp = {th_seq=42, options={{kind=TCP_KIND_TS}}}
ts_or_md5({tcp=tcp})
check("TCP timestamp and non-TCP packets bypass the fallback", tcp.th_seq==42 and #tcp.options==1 and tcp_calls==0)
tcp = {th_seq=1}
ts_or_md5({tcp=tcp})
check("TCP fallback wraps and appends MD5", tcp.th_seq==4294957297 and #tcp.options==1 and tcp.options[1].kind==TCP_KIND_MD5 and #tcp.options[1].data==16)
local md5 = tcp.options[1]
ts_or_md5({tcp=tcp})
check("TCP fallback retains an existing MD5", tcp.th_seq==4294947297 and #tcp.options==1 and tcp.options[1]==md5 and random_calls==1)

VERDICT_PASS, VERDICT_DROP = 0, 1
local sent, fail_at, set_drop = {}, nil, 0
local packet = {dis={tcp={},payload="abcdefgh"}, arg={host="xxx",tcp_ts_up=true}}
direction_cutoff_opposite = function() end
direction_check = function() return true end
payload_check = function() return true end
replay_first = function() return true end
replay_drop = function() return false end
replay_drop_set = function() set_drop = set_drop + 1 end
genhost = function(length, name) assert(length==#name); return name end
rawsend_opts_base = function() return {} end
rawsend_opts = function() return {} end
reconstruct_opts = function() return {} end
resolve_range = function() return {3,5} end
rawsend_payload_segmented = function(desync, data, offset, options)
	sent[#sent+1] = {data=data,offset=offset,fake=options.fooling==desync.arg}
	return #sent~=fail_at
end
check("split sends the established four parts", hostfakesplit_alt(nil,packet)==VERDICT_DROP and #sent==4 and set_drop==1)
check("split keeps byte offsets and send options", sent[1].data=="ab" and sent[1].offset==0 and not sent[1].fake and
	sent[2].data=="xxx" and sent[2].offset==2 and sent[2].fake and
	sent[3].data=="fgh" and sent[3].offset==5 and not sent[3].fake and
	sent[4].data=="cde" and sent[4].offset==2 and not sent[4].fake)
sent, fail_at = {}, 2
check("split stops on a failed write", hostfakesplit_alt(nil,packet)==VERDICT_PASS and #sent==2 and set_drop==1)
sent, fail_at = {}, nil
packet.dis.payload = "abc"
resolve_range = function() return {1,3} end
check("split keeps empty edge parts", hostfakesplit_alt(nil,packet)==VERDICT_DROP and #sent==4 and sent[1].data=="" and sent[3].data=="" and sent[3].offset==3)
replay_first = function() return false end
replay_drop = function() return true end
sent = {}
check("replay verdict uses the engine state without sending", hostfakesplit_alt(nil,packet)==VERDICT_DROP and #sent==0)
check("fooling adapter uses Rust", tcp_calls==2 and split_calls==3)

local u32add_calls = 0
local engine_u32add = u32add
u32add = function(seq, delta)
	u32add_calls = u32add_calls + 1
	if engine_u32add then return engine_u32add(seq, delta) end
	return (seq+delta)%4294967296
end
native.tcp_fallback, native.host_split = nil, nil
FOOLING_ADAPTER()
native.tcp_fallback, native.host_split = tcp_fallback, host_split
tcp = {th_seq=1}
ts_or_md5({tcp=tcp})
replay_first = function() return true end
replay_drop = function() return false end
check("older bridge retains the same result", u32add_calls==1 and tcp.th_seq==4294957297 and
	hostfakesplit_alt(nil,packet)==VERDICT_DROP and #sent==4 and sent[4].data=="abc")
io.stdout:flush()
os.exit(0)
