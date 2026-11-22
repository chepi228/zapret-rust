-- Resolve protocol markers through the public Lua API with in-memory payloads.
local failures = 0
local function check(name, condition)
    print((condition and "ok " or "FAIL ") .. name)
    if not condition then failures = failures + 1 end
end

local function be16(value)
    return string.char(math.floor(value / 256) % 256, value % 256)
end

local function be24(value)
    return string.char(math.floor(value / 65536) % 256) .. be16(value)
end

local function hello(host, padding, session)
    if padding == nil then padding = 8 end
    session = session or ""
    local sni = be16(#host + 3) .. "\0" .. be16(#host) .. host
    local extensions = "\0\0" .. be16(#sni) .. sni .. be16(21) .. be16(padding) .. string.rep("\0", padding)
    local body = "\3\3" .. string.rep("\0", 32) .. string.char(#session) .. session ..
        be16(2) .. "\19\1" .. "\1\0" .. be16(#extensions) .. extensions
    local handshake = "\1" .. be24(#body) .. body
    return "\22\3\1" .. be16(#handshake) .. handshake
end

local name = "www.example.com"
local http = "GET / HTTP/1.1\r\nHost: " .. name .. "\r\n\r\n"
local http_host = assert(http:find(name, 1, true)) - 1
check("HTTP host and end markers match the original bytes",
    resolve_pos(http, "http_req", "host", true) == http_host and
    resolve_pos(http, "http_req", "endhost", true) == http_host + #name)
check("HTTP second-level markers resolve within the existing hostname",
    resolve_pos(http, "http_req", "sld", true) == http_host + 4 and
    resolve_pos(http, "http_req", "midsld", true) == http_host + 7 and
    resolve_pos(http, "http_req", "endsld", true) == http_host + 11)
check("HTTP method handles the supported leading CRLF",
    resolve_pos("\r\n" .. http, "http_req", "method", true) == 2)
check("HTTP host name matching preserves mixed header case and one space",
    resolve_pos(http:gsub("Host: ", "hOsT:\t"), "http_req", "host", true) == http_host)
check("one-based Lua positions retain their default convention",
    resolve_pos(http, "http_req", "host") == http_host + 1)
check("unknown payloads retain absolute positions",
    resolve_pos(http, "unknown", "0", true) == 0 and
    resolve_pos(http, "unknown", "-1", true) == #http - 1 and
    resolve_pos(http, "unknown", "host", true) == nil)

local tls = hello(name)
local before = tls
check("TLS extension length and SNI markers preserve wire offsets",
    resolve_pos(tls, "tls_client_hello", "extlen", true) == 50 and
    resolve_pos(tls, "tls_client_hello", "sniext", true) == 56)
check("TLS hostname markers point into the advertised SNI",
    resolve_pos(tls, "tls_client_hello", "host", true) == 61 and
    resolve_pos(tls, "tls_client_hello", "endhost", true) == 61 + #name and
    resolve_pos(tls, "tls_client_hello", "midsld", true) == 68)

local all_cuts = true
for length = 0, #tls do
    local position = resolve_pos(tls:sub(1, length), "tls_client_hello", "host", true)
    if length < 61 + #name then
        all_cuts = all_cuts and position == nil
    else
        all_cuts = all_cuts and position == 61
    end
end
check("TLS partial records resolve only after the full SNI extension arrives", all_cuts)

local positions = resolve_multi_pos(tls, "tls_client_hello", "midsld,host,host,1,-1,9999", true)
check("multiple marker positions are sorted and deduplicated",
    #positions == 4 and positions[1] == 1 and positions[2] == 61 and
    positions[3] == 68 and positions[4] == #tls - 1)
check("empty marker lists resolve to an empty result",
    #resolve_multi_pos(tls, "tls_client_hello", "", true) == 0)
local range_one = resolve_range(http, "http_req", "host,endhost")
check("ranges retain inclusive one-based endpoints",
    range_one[1] == http_host + 1 and range_one[2] == http_host + #name + 1)
local range_zero = resolve_range(http, "http_req", "host,endhost", false, true)
check("zero-based ranges preserve the same endpoint bytes",
    range_zero[1] == http_host and range_zero[2] == http_host + #name)
local range_end = resolve_range(http, "http_req", "host,9999")
local range_start = resolve_range(http, "http_req", "9999,-1")
check("non-strict ranges expand one missing endpoint",
    range_end[1] == http_host + 1 and range_end[2] == #http and
    range_start[1] == 1 and range_start[2] == #http)
check("strict ranges reject either missing endpoint",
    resolve_range(http, "http_req", "host,9999", true) == nil and
    resolve_range(http, "http_req", "9999,-1", 0) == nil)
check("empty unresolved and reversed ranges return nil",
    resolve_range("", "unknown", "0,-1") == nil and
    resolve_range(http, "unknown", "9998,9999") == nil and
    resolve_range(http, "unknown", "10,1") == nil)
local function range_error(markers)
    local ok, message = pcall(resolve_range, http, "unknown", markers)
    return not ok and message
end
check("range marker count errors retain their precedence",
    range_error(""):find("require 2 markers", 1, true) and
    range_error("1"):find("require 2 markers", 1, true) and
    range_error("1,2,3"):find("bad marker list", 1, true) and
    range_error("1,,2"):find("bad marker list", 1, true))
local marker_limit = string.rep("1,", 127) .. "1"
local at_limit = resolve_multi_pos(http, "unknown", marker_limit, true)
check("128 markers retain sorting and deduplication limits",
    #at_limit == 1 and at_limit[1] == 1 and
    not pcall(resolve_multi_pos, http, "unknown", marker_limit .. ",1"))
check("position names keep the existing embedded-NUL convention",
    resolve_pos(http, "unknown\0ignored", "1\0ignored", true) == 1 and
    #resolve_multi_pos(http, "unknown", "\0ignored") == 0)
check("invalid marker offsets and payload names are rejected",
    not pcall(resolve_pos, tls, "tls_client_hello", "host+32768") and
    not pcall(resolve_pos, tls, "unrecognized", "1") and
    not pcall(resolve_multi_pos, tls, "tls_client_hello", "host,,1"))
check("empty and truncated blobs retain unresolved positions",
    resolve_pos("", "tls_client_hello", "host", true) == nil and
    resolve_pos(tls:sub(1, 4), "tls_client_hello", "extlen", true) == nil)
check("protocol marker reads preserve the source payload", tls == before)

local short_handshake = tls:sub(1, 6) .. be24(40) .. tls:sub(10)
check("TLS markers reject fields beyond the advertised handshake",
    resolve_pos(short_handshake, "tls_client_hello", "host", true) == nil and
    resolve_pos(short_handshake, "tls_client_hello", "extlen", true) == nil)
local cut_sni = tls:sub(1, 6) .. be24(61 + #name - 10) .. tls:sub(10)
check("TLS SNI cannot span the advertised handshake end",
    resolve_pos(cut_sni, "tls_client_hello", "host", true) == nil)
local extra = hello("other.example.net"):sub(6)
local combined = tls:sub(1, 3) .. be16(#tls - 5 + #extra) .. tls:sub(6) .. extra
check("coalesced TLS handshakes retain the first message hostname",
    resolve_pos(combined, "tls_client_hello", "host", true) == 61 and
    resolve_pos(combined, "tls_client_hello", "endhost", true) == 61 + #name)

local function read16(data, offset)
    local a, b = data:byte(offset, offset + 1)
    return a * 256 + b
end
local shortened = assert(tls_mod(tls, "sni=a.b"))
local enlarged = assert(tls_mod(tls, "sni=longer.hostname.example.net"))
check("TLS SNI replacement updates all enclosing lengths",
    #shortened == #tls - #name + 3 and read16(shortened, 4) == #shortened - 5 and
    #enlarged == #tls - #name + #"longer.hostname.example.net" and
    read16(enlarged, 4) == #enlarged - 5 and shortened:sub(62, 64) == "a.b")
check("TLS option parsing retains explicit validation",
    not pcall(tls_mod, tls, "sni=") and not pcall(tls_mod, tls, "rnd,,dupsid") and
    tls_mod(tls, "none") == tls)
local randomized = assert(tls_mod(tls, "rndsni"))
check("TLS random SNI preserves its length and hostname alphabet",
    #randomized == #tls and randomized:sub(62, 61 + #name):match("^[a-z][a-z0-9]+%.[a-z][a-z][a-z]$"))
local original_sid = string.rep("S", 32)
local sid_fake = hello(name, 8, string.rep("F", 32))
local sid_original = hello(name, 8, original_sid)
local sid_result = assert(tls_mod(sid_fake, "rnd,dupsid", sid_original))
check("TLS session copying runs after randomization",
    sid_result:sub(45, 76) == original_sid and #sid_result == #sid_fake)
local encap = assert(tls_mod(tls, "padencap", sid_original))
check("TLS padding encapsulation changes declared lengths without copying payload",
    #encap == #tls and read16(encap, 4) == #tls - 5 + #sid_original and
    read16(encap, #encap - 9) == 8 + #sid_original)
local maximum = hello("a.b", 65540 - #hello("a.b", 0))
check("TLS SNI growth rejects record length overflow",
    #maximum == 65540 and tls_mod(maximum, "sni=a.longer.example.com") == nil)

if failures ~= 0 then error(tostring(failures) .. " protocol fixture failures") end
print("ok protocol fixture completed")
