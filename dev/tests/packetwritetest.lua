-- Exercise the public reconstruct functions using only in-memory packets.
local failures = 0
local valid_cases, rejected_cases = 0, 0
local wire_records = {}

local function check(name, condition)
    print((condition and "ok " or "FAIL ") .. name)
    if not condition then failures = failures + 1 end
end

local function be16(value)
    return string.char(math.floor(value / 256) % 256, value % 256)
end

local function from16(bytes, position)
    local high, low = bytes:byte(position, position + 1)
    return high * 256 + low
end

local function checksum_valid(bytes)
    local sum = 0
    for position = 1, #bytes, 2 do
        sum = sum + bytes:byte(position) * 256 + (bytes:byte(position + 1) or 0)
        sum = sum % 65536 + math.floor(sum / 65536)
    end
    return sum == 65535
end

local function hex(bytes)
    return (bytes:gsub(".", function(byte) return string.format("%02x", byte:byte()) end))
end

local function wire(name, writer, ...)
    local bytes = writer(...)
    assert(type(bytes) == "string" and #bytes > 0, name)
    wire_records[#wire_records + 1] = "wire " .. name .. " " .. hex(bytes)
    valid_cases = valid_cases + 1
    return bytes
end

local function reject(name, writer, ...)
    local ok = pcall(writer, ...)
    if ok then error(name .. " should be rejected") end
    rejected_cases = rejected_cases + 1
end

local ip4 = {
    ip_src = string.char(192, 0, 2, 1), ip_dst = string.char(198, 51, 100, 1),
    ip_ttl = 64, ip_tos = 0x1b, ip_id = 0x1234, ip_p = 6,
}
local ip6 = {
    ip6_src = string.char(0x20, 1, 0x0d, 0xb8) .. string.rep("\0", 11) .. "\1",
    ip6_dst = string.char(0x20, 1, 0x0d, 0xb8) .. string.rep("\0", 11) .. "\2",
    ip6_hlim = 41,
}
local tcp = {
    th_sport = 20000, th_dport = 443, th_seq = 0xfedcba98, th_ack = 0x12345678,
    th_flags = 0x18, th_win = 8192, th_sum = 0xabcd, th_x2 = 11, th_urp = 9,
}
local udp = {uh_sport = 20000, uh_dport = 443, uh_ulen = 44, uh_sum = 0xabcd}
local icmp = {icmp_type = 8, icmp_code = 0, icmp_data = 0xfedcba98, icmp_cksum = 0xabcd}

for length = 0, 40 do
    ip4.options = string.rep("\1", length)
    local header = wire("ipv4-options-" .. length, reconstruct_iphdr, ip4)
    assert(#header == 20 + math.ceil(length / 4) * 4 and checksum_valid(header))
end
ip4.options = string.rep("\1", 41)
reject("IPv4 options beyond 40 bytes", reconstruct_iphdr, ip4)
ip4.options = "\1\1\0"
check("IPv4 options are padded to a word and covered by the header checksum", true)

for length = 0, 38 do
    tcp.options = {{kind = 3, data = string.rep("X\0", math.floor(length / 2)) .. string.rep("Y", length % 2)}}
    local header = wire("tcp-option-" .. length, reconstruct_tcphdr, tcp)
    assert(#header == 20 + math.ceil((length + 2) / 4) * 4)
    assert(header:byte(13) % 16 == tcp.th_x2 and header:byte(22) == length + 2)
end
tcp.options = {{kind = 3, data = string.rep("x", 39)}}
reject("oversized TCP option", reconstruct_tcphdr, tcp)
tcp.options = {{kind = 1}, {kind = 0, data = 42}, {kind = 3, data = 42}}
local header = wire("tcp-option-defaults", reconstruct_tcphdr, tcp)
check("TCP option lengths and default data preserve the wire layout", header:sub(21) == "\1\0\3\2")
tcp.options = {{kind = 2, data = "\5\180"}, {kind = 1}, {kind = 3, data = "\7"}}

ip6.exthdr = {
    {type = 60, next = 51, data = string.rep("\0", 6)},
    {type = 51, next = 17, data = string.rep("\3", 10)},
}
local linked = wire("ipv6-linked", reconstruct_ip6hdr, ip6, {ip6_last_proto = 6})
check("IPv6 option and authentication headers link to the requested final protocol",
    #linked == 60 and from16(linked, 5) == 20 and linked:byte(7) == 60 and
    linked:byte(41) == 51 and linked:byte(42) == 0 and linked:byte(49) == 6 and linked:byte(50) == 1)
ip6.ip6_nxt, ip6.ip6_plen = 0, 55
local preserved = wire("ipv6-preserved", reconstruct_ip6hdr, ip6, {ip6_preserve_next = true})
check("Explicit IPv6 length and next headers are preserved when requested",
    from16(preserved, 5) == 55 and preserved:byte(7) == 0 and preserved:byte(41) == 51 and preserved:byte(49) == 17)
ip6.exthdr = {{type = 51, data = string.rep("\0", 8)}}
reject("invalid authentication header length", reconstruct_ip6hdr, ip6)
ip6.exthdr = {{type = 60, data = string.rep("\0", 5)}}
reject("short IPv6 extension", reconstruct_ip6hdr, ip6)
ip6.exthdr = {{type = 60, data = string.rep("\0", 478)}}
reject("IPv6 extension exceeds the standalone output buffer", reconstruct_ip6hdr, ip6)
ip6.exthdr, ip6.ip6_plen = nil, nil
ip6.ip6_plen = false
reject("invalid payload-length type", reconstruct_ip6hdr, ip6)
ip6.ip6_plen = nil
check("IPv6 writer rejects invalid extension data and invalid payload length", true)

local function full_ip(version, transport)
    if version == 4 then
        ip4.ip_p = transport
        return {ip = ip4}
    end
    return {ip6 = ip6}
end

wire("udp-standalone", reconstruct_udphdr, udp)
wire("icmp-standalone", reconstruct_icmphdr, icmp)
for _, version in ipairs({4, 6}) do
    for _, transport in ipairs({
        {name = "tcp", number = 6, fields = tcp, checksum_at = 17},
        {name = "udp", number = 17, fields = udp, checksum_at = 7},
        {name = "icmp", number = version == 4 and 1 or 58, fields = icmp, checksum_at = 3},
    }) do
        local frame = full_ip(version, transport.number)
        frame[transport.name] = transport.fields
        for length = 0, 33 do
            frame.payload = string.rep("Z\0", math.floor(length / 2)) .. string.rep("p", length % 2)
            local label = "ipv" .. version .. "-" .. transport.name .. "-" .. length
            local bytes = wire(label, reconstruct_dissect, frame)
            local first = version == 4 and (bytes:byte(1) % 16) * 4 or 40
            local segment = bytes:sub(first + 1)
            local pseudo = ""
            if version == 6 then
                pseudo = ip6.ip6_src .. ip6.ip6_dst .. "\0\0" .. be16(#segment) .. "\0\0\0" .. string.char(transport.number)
            elseif transport.name ~= "icmp" then
                pseudo = ip4.ip_src .. ip4.ip_dst .. "\0" .. string.char(transport.number) .. be16(#segment)
            end
            assert(checksum_valid(pseudo .. segment), label)
            if version == 4 then
                assert(from16(bytes, 3) == #bytes and checksum_valid(bytes:sub(1, first)))
            else
                assert(from16(bytes, 5) == #bytes - 40 and bytes:byte(7) == transport.number)
            end
            if transport.name == "udp" then assert(from16(segment, 5) == #segment) end
        end
        local label = "ipv" .. version .. "-" .. transport.name
        local preserved_sum = wire(label .. "-keepsum", reconstruct_dissect, frame, {keepsum = true, badsum = true})
        local first = version == 4 and (preserved_sum:byte(1) % 16) * 4 or 40
        local offset = first + transport.checksum_at
        assert(from16(preserved_sum, offset) == 0xabcd)
        if transport.name == "udp" then assert(from16(preserved_sum, first + 5) == udp.uh_ulen) end
        local regular = reconstruct_dissect(frame)
        local badsum = reconstruct_dissect(frame, {badsum = true})
        assert(from16(regular, offset) ~= from16(badsum, offset))
        assert(regular:sub(1, offset - 1) == badsum:sub(1, offset - 1) and
            regular:sub(offset + 2) == badsum:sub(offset + 2))
    end
end
check("IPv4 and IPv6 TCP, UDP and ICMP checksums cover empty, odd and even payloads", true)
check("Keeping or changing transport checksums preserves other fields", true)

local checksum_headers_valid, checksum_inputs_unchanged, checksum_lengths_valid = true, true, true
for _, version in ipairs({4, 6}) do
    local raw_ip = version == 4 and reconstruct_iphdr(ip4) or reconstruct_ip6hdr(ip6)
    if version == 4 then raw_ip = raw_ip:sub(1, 2) .. be16(#raw_ip) .. raw_ip:sub(5) end
    for _, transport in ipairs({
        {name = "tcp", proto = 6, fix = csum_tcp_fix, header = reconstruct_tcphdr(tcp)},
        {name = "udp", proto = 17, fix = csum_udp_fix, header = reconstruct_udphdr(udp)},
        {name = "icmp", proto = version == 4 and 1 or 58, fix = csum_icmp_fix, header = reconstruct_icmphdr(icmp)},
    }) do
        for _, length in ipairs({0, 1, 7, 8, 255, 65535}) do
            local body = string.rep("Z", length)
            local original = transport.header .. (length % 2 == 1 and "q" or "")
            local corrected = transport.fix(raw_ip, original, body)
            local segment = corrected .. body
            local pseudo = ""
            if version == 6 or transport.name ~= "icmp" then
                local source = version == 4 and ip4.ip_src or ip6.ip6_src
                local destination = version == 4 and ip4.ip_dst or ip6.ip6_dst
                pseudo = source .. destination .. be16(math.floor(#segment / 65536)) .. be16(#segment % 65536) ..
                    "\0\0\0" .. string.char(transport.proto)
            end
            checksum_headers_valid = checksum_headers_valid and checksum_valid(pseudo .. segment)
            checksum_lengths_valid = checksum_lengths_valid and #corrected == #original
            checksum_inputs_unchanged = checksum_inputs_unchanged and original == transport.header .. (length % 2 == 1 and "q" or "")
        end
    end
end
check("Lua checksum APIs cover IPv4/IPv6, odd headers and the maximum 65535-byte payload", checksum_headers_valid)
check("Lua checksum APIs return only the complete supplied transport header", checksum_lengths_valid)
check("Lua checksum APIs preserve the original immutable header strings", checksum_inputs_unchanged)
local raw_ip = reconstruct_iphdr(ip4)
raw_ip = raw_ip:sub(1, 2) .. be16(#raw_ip) .. raw_ip:sub(5)
local corrected_ip = csum_ip4_fix(raw_ip .. "abc")
check("IPv4 checksum API preserves bytes after the declared header",
    corrected_ip:sub(-3) == "abc" and checksum_valid(corrected_ip:sub(1, #raw_ip)))
local oversized_payload, oversized_error = pcall(csum_udp_fix, raw_ip, reconstruct_udphdr(udp), string.rep("X", 65536))
local bad_ip, bad_ip_error = pcall(csum_tcp_fix, "", false, false)
local bad_header, bad_header_error = pcall(csum_tcp_fix, raw_ip, "", false)
check("Checksum validation preserves IP, transport and payload error ordering",
    not oversized_payload and tostring(oversized_error):find("invalid payload length", 1, true) ~= nil and
    not bad_ip and tostring(bad_ip_error):find("invalid ip header", 1, true) ~= nil and
    not bad_header and tostring(bad_header_error):find("invalid tcp header", 1, true) ~= nil)

local payload = "0123456789abcdefghijklmnopqrstuv"
ip4.ip_len, ip4.ip_off, ip4.ip_p = 32, 1, 253
local frag4 = wire("ipv4-fragment", reconstruct_dissect, {ip = ip4, payload = payload})
check("IPv4 reconstruction selects the declared fragment bytes", #frag4 == 32 and frag4:sub(25) == payload:sub(9, 16))
ip4.ip_len = 23
reject("IPv4 fragment shorter than its header", reconstruct_dissect, {ip = ip4, payload = payload})
ip4.ip_len = 56
reject("IPv4 fragment beyond available bytes", reconstruct_dissect, {ip = ip4, payload = payload})
ip4.ip_len = 32
local raw4 = wire("ipv4-raw-fragment", reconstruct_dissect, {ip = ip4, payload = "raw", frag_off = 8})
check("Raw fragment payload skips reconstruction of transport and fragment lengths",
    #raw4 == 27 and from16(raw4, 3) == 32 and raw4:sub(25) == "raw")
ip4.ip_len, ip4.ip_off = nil, nil

ip6.ip6_nxt, ip6.ip6_plen = 44, 16
ip6.exthdr = {{type = 44, next = 253, data = be16(8) .. "\0\0\0\1"}}
local frag6 = wire("ipv6-fragment", reconstruct_dissect,
    {ip6 = ip6, payload = payload}, {ip6_preserve_next = true})
check("IPv6 reconstruction selects the declared fragment bytes", #frag6 == 56 and frag6:sub(49) == payload:sub(9, 16))
ip6.ip6_plen = 7
reject("IPv6 fragment header beyond declared length", reconstruct_dissect, {ip6 = ip6, payload = payload})
ip6.ip6_plen = 40
reject("IPv6 fragment beyond available bytes", reconstruct_dissect, {ip6 = ip6, payload = payload})
local raw6 = wire("ipv6-raw-fragment", reconstruct_dissect, {ip6 = ip6, payload = "raw", frag_off = 8})
assert(#raw6 == 51 and from16(raw6, 5) == 40 and raw6:sub(49) == "raw")
ip6.exthdr, ip6.ip6_plen = nil, 16
reject("truncated IPv6 fragment header", reconstruct_dissect,
    {ip6 = ip6, payload = string.char(253, 0, 0, 0)}, {ip6_preserve_next = true})

reject("address of wrong width", reconstruct_iphdr, {ip_src = "\0", ip_dst = ip4.ip_dst, ip_ttl = 64, ip_p = 6})
reject("invalid TCP field type", reconstruct_tcphdr, {th_sport = "1234", th_dport = 443})
reject("invalid UDP field type", reconstruct_udphdr, {uh_sport = 1, uh_dport = "443"})
reject("missing ICMP data", reconstruct_icmphdr, {icmp_type = 8, icmp_code = 0})
reject("payload larger than output buffer", reconstruct_dissect, {ip = ip4, payload = string.rep("x", 65536)})
wire("stack-recovery", reconstruct_udphdr, udp)
check("Rejected inputs leave the Lua bindings usable", true)
check(string.format("compared %d wire records and rejected %d invalid inputs", valid_cases, rejected_cases),
    valid_cases == 300 and rejected_cases == 16)

local assembly_ip = {ip_src = ip4.ip_src, ip_dst = ip4.ip_dst, ip_ttl = 64, ip_p = 6}
local assembly_ip6 = {ip6_src = ip6.ip6_src, ip6_dst = ip6.ip6_dst, ip6_hlim = 64}
local assembly_tcp = {th_sport = 1234, th_dport = 443, th_seq = 1, th_ack = 0, th_flags = 2, th_win = 4096}
local function traced(fields)
    local calls = {}
    return setmetatable({}, {__index = function(_, key)
        calls[#calls + 1] = key
        return fields[key]
    end}), calls
end
local frame, calls = traced({ip = assembly_ip, tcp = assembly_tcp, payload = "test"})
local assembled = reconstruct_dissect(frame)
check("Assembly reads IPv4 and transport tables lazily",
    #assembled == 44 and table.concat(calls, ",") == "frag_off,ip,tcp,payload")
frame, calls = traced({ip6 = assembly_ip6, icmp = icmp, payload = "test"})
assembled = reconstruct_dissect(frame)
check("IPv6 protocol inference preserves observable table lookup order",
    #assembled == 52 and assembled:byte(7) == 58 and table.concat(calls, ",") ==
    "frag_off,ip,ip6,tcp,udp,icmp,ip,ip6,tcp,udp,icmp,payload")
frame, calls = traced({ip = assembly_ip, tcp = {}, frag_off = 0, payload = "test"})
assembled = reconstruct_dissect(frame)
check("Raw fragment assembly skips transport lookups and length rewriting",
    #assembled == 24 and from16(assembled, 3) == 0 and assembled:sub(21) == "test" and
    table.concat(calls, ",") == "frag_off,ip,payload")
local broken = setmetatable({ip = assembly_ip, tcp = assembly_tcp}, {__index = function(_, key)
    if key == "payload" then error("assembly payload lookup failed") end
end})
local ok, message = pcall(reconstruct_dissect, broken)
check("A packet metamethod error unwinds through the C VM boundary",
    not ok and tostring(message):find("assembly payload lookup failed", 1, true) ~= nil and
    #reconstruct_dissect({ip = assembly_ip, tcp = assembly_tcp}) == 40)
local numeric = reconstruct_dissect({ip = assembly_ip, payload = 123.5})
local ignored = reconstruct_dissect({ip = assembly_ip, payload = {}})
check("Assembly preserves numeric payload coercion and ignored nonstring payloads",
    numeric:sub(21) == "123.5" and #ignored == 20)
ok = pcall(reconstruct_dissect, {ip = assembly_ip, frag_off = false})
local oversized = pcall(reconstruct_dissect, {ip = assembly_ip, frag_off = 0, payload = string.rep("x", 65535)})
check("Invalid fragment metadata and overflowing payloads leave the bindings usable",
    not ok and not oversized and #reconstruct_dissect({ip = assembly_ip, payload = "ok"}) == 22)

local tcp_prefix = string.rep("\0", 12) .. string.char(0x80, 0) .. string.rep("\0", 6)
local options = dissect_tcphdr(tcp_prefix .. "\0\1\2\2" .. string.rep("\0", 8)).options
check("TCP dissection trims only trailing END padding and keeps empty option data",
    #options == 3 and options[1].kind == 0 and options[1].data == nil and
    options[2].kind == 1 and options[3].kind == 2 and options[3].data == "")
local short_tcp = tcp_prefix:sub(1, 12) .. string.char(0x60) .. tcp_prefix:sub(14)
options = dissect_tcphdr(short_tcp .. "\0\2\1\0").options
local truncated_options = dissect_tcphdr(short_tcp .. "\0\2").options
check("Malformed TCP options preserve prior items without reading past the supplied bytes",
    #options == 1 and options[1].kind == 0 and #truncated_options == 1 and truncated_options[1].kind == 0)
local decoded_udp = dissect_udphdr(string.rep("\255", 8))
local decoded_icmp = dissect_icmphdr(string.rep("\255", 8))
check("UDP and ICMP dissection preserve unsigned field widths",
    decoded_udp.uh_sport == 65535 and decoded_udp.uh_ulen == 65535 and
    decoded_icmp.icmp_data == 4294967295 and decoded_icmp.icmp_cksum == 65535)
local oversized_ihl = dissect_iphdr(string.char(0x4f) .. string.rep("\0", 23))
local small_offset = dissect_tcphdr(string.rep("\0", 20))
check("Header dissection retains scalar fields from malformed declared header sizes",
    oversized_ihl.ip_hl == 15 and oversized_ihl.options == nil and
    small_offset.th_off == 0 and #small_offset.options == 0 and dissect_ip6hdr("short") == nil)
local function extension_packet(first, payload, declared)
    return "\96\0\0\0" .. be16(declared or #payload) .. string.char(first, 64) ..
        string.rep("\0", 32) .. payload
end
local extension_payload = string.char(51, 0) .. string.rep("\0", 6) .. string.char(6, 1) .. string.rep("\0", 10)
local extensions = dissect_ip6hdr(extension_packet(0, extension_payload)).exthdr
local clipped_extensions = dissect_ip6hdr(extension_packet(0, extension_payload, 8)).exthdr
check("IPv6 dissection shares extension lengths and respects the declared payload boundary",
    #extensions == 2 and extensions[1].type == 0 and extensions[1].next == 51 and #extensions[1].data == 6 and
    extensions[2].type == 51 and extensions[2].next == 6 and #extensions[2].data == 10 and #clipped_extensions == 1)
local function fragment_options(offset)
    return dissect_ip6hdr(extension_packet(44,
        string.char(0, 0) .. be16(offset) .. string.rep("\0", 4) .. string.char(6, 0) .. string.rep("\0", 6))).exthdr
end
local nonfirst, first_fragment, atomic_fragment = fragment_options(8), fragment_options(1), fragment_options(0)
check("IPv6 dissection stops after nonfirst fragments and continues after first or atomic fragments",
    #nonfirst == 1 and #first_fragment == 2 and #atomic_fragment == 2 and
    nonfirst[1].type == 44 and nonfirst[1].next == 0)

do
    local decoders = {dissect_tcphdr, dissect_udphdr, dissect_icmphdr, dissect_iphdr, dissect_ip6hdr}
    local writers = {reconstruct_tcphdr, reconstruct_udphdr, reconstruct_icmphdr, reconstruct_iphdr, reconstruct_ip6hdr}
    local minimum = {20, 8, 8, 20, 40}
    local names = {"tcphdr", "udphdr", "icmphdr", "iphdr", "ip6hdr"}
    local arity, strict, truncated, counts, writer_arity, invalid = true, true, true, true, true, true
    for i, decode in ipairs(decoders) do
        local ok, message = pcall(decode, false, false)
        arity = arity and not ok and tostring(message):find("expect exactly 1 arguments, got 2", 1, true) ~= nil
        ok, message = pcall(decode, 1234)
        strict = strict and not ok and tostring(message):find("string expected", 1, true) ~= nil
        local short = string.rep("\0", minimum[i] - 1)
        truncated = truncated and decode(short) == nil
        counts = counts and select("#", decode(short)) == 1 and select("#", decode("")) == 1
        ok, message = pcall(writers[i], false, false, false)
        writer_arity = writer_arity and not ok and tostring(message):find("expect", 1, true) ~= nil
        ok, message = pcall(writers[i], false)
        invalid = invalid and not ok and tostring(message):find("invalid data for " .. names[i], 1, true) ~= nil
    end
    check("Header decode entries check exact arity before reading types", arity)
    check("Header decode entries retain strict binary string inputs", strict)
    check("All truncated header entries publish nil", truncated)
    check("Truncated and empty header entries return exactly one value", counts)
    check("Header encode entries check arity before reading tables or options", writer_arity)
    check("Header encode entries preserve their specific failure diagnostics", invalid)
    local zero4, zero16 = string.rep("\0", 4), string.rep("\0", 16)
    local fields = {
        {th_sport=1, th_dport=2, th_seq=3, th_ack=4, th_flags=5, th_win=6},
        {uh_sport=1, uh_dport=2, uh_ulen=8, uh_sum=0},
        {icmp_type=8, icmp_code=0, icmp_cksum=0x0506, icmp_data=0x01020304},
        {ip_ttl=64, ip_p=17, ip_len=28, ip_src=zero4, ip_dst=zero4},
        {ip6_src=zero16, ip6_dst=zero16},
    }
    local single = true
    for i, write in ipairs(writers) do
        single = single and #write(fields[i]) == minimum[i] and select("#", write(fields[i])) == 1
    end
    check("Header encode entries publish exactly the written bytes and one result", single)
    local udp_bytes, icmp_bytes = writers[2](fields[2]), writers[3](fields[3])
    check("UDP entry preserves an independent exact wire vector", udp_bytes == "\0\1\0\2\0\8\0\0")
    check("ICMP entry preserves an independent exact wire vector", icmp_bytes == "\8\0\5\6\1\2\3\4")
    check("IPv4 entry keeps the exact capacity and valid checksum", #writers[4](fields[4]) == 20 and checksum_valid(writers[4](fields[4])))
    local ok, message = pcall(reconstruct_ip6hdr, false, false)
    check("IPv6 options fail before validating the header table", not ok and tostring(message):find("table expected", 1, true) ~= nil)
    local lookup = {}
    local options = setmetatable({}, {__index=function(_, key)
        lookup[#lookup+1] = key
        assert(dissect_udphdr(udp_bytes).uh_dport == 2)
        if key == "ip6_last_proto" then return 17 end
        return false
    end})
    local ip6_bytes = reconstruct_ip6hdr(fields[5], options)
    check("IPv6 entry preserves option lookup order and nested header calls",
        table.concat(lookup, ",") == "ip6_preserve_next,ip6_last_proto" and #ip6_bytes == 40 and ip6_bytes:byte(7) == 17)
    local packet = writers[4](fields[4]) .. udp_bytes
    local decoded = dissect(packet)
    check("Composite packet projection keeps lengths and protocol", decoded.l4proto == 17 and decoded.l3_len == 20 and decoded.l4_len == 8 and decoded.transport_len == 8)
    check("Composite packet projection keeps present and absent headers", decoded.ip.ip_p == 17 and decoded.udp.uh_sport == 1 and decoded.ip6 == nil and decoded.tcp == nil and decoded.icmp == nil and decoded.frag_off == nil)
    check("Composite packet projection keeps empty payload and immutable input", decoded.payload == "" and packet == writers[4](fields[4]) .. udp_bytes)
end

do
    local function keys(value)
        local result = {}
        for key in pairs(value) do result[#result+1] = key end
        table.sort(result)
        return table.concat(result, ",")
    end
    local z = string.rep("\0", 64)
    check("TCP projection preserves its complete field catalog",
        keys(dissect_tcphdr(z:sub(1, 20))) == "options,th_ack,th_dport,th_flags,th_off,th_seq,th_sport,th_sum,th_urp,th_win,th_x2")
    check("UDP projection preserves its complete field catalog",
        keys(dissect_udphdr(z:sub(1, 8))) == "uh_dport,uh_sport,uh_sum,uh_ulen")
    check("ICMP projection preserves its complete field catalog",
        keys(dissect_icmphdr(z:sub(1, 8))) == "icmp_cksum,icmp_code,icmp_data,icmp_type")
    check("IPv4 projection preserves scalar and binary address fields",
        keys(dissect_iphdr("\69" .. z:sub(1, 19))) == "ip_dst,ip_hl,ip_id,ip_len,ip_off,ip_p,ip_src,ip_sum,ip_tos,ip_ttl,ip_v")
    check("IPv6 projection preserves scalar address and extension fields",
        keys(dissect_ip6hdr("\96" .. z:sub(1, 39))) == "exthdr,ip6_dst,ip6_flow,ip6_hlim,ip6_nxt,ip6_plen,ip6_src")
    local tcp_base = z:sub(1, 12) .. "\96" .. z:sub(1, 7)
    local entries = dissect_tcphdr(tcp_base .. "\0\1\0\0").options
    check("TCP END and NOP items omit optional data fields",
        #entries == 2 and entries[1].kind == 0 and entries[2].kind == 1 and keys(entries[1]) == "kind" and keys(entries[2]) == "kind")
    entries = dissect_tcphdr(tcp_base .. "\2\2\0\0").options
    check("TCP zero-length option data remains an explicit empty string",
        #entries == 1 and entries[1].kind == 2 and entries[1].data == "" and keys(entries[1]) == "data,kind")
    entries = dissect_tcphdr(tcp_base .. "\2\4\5\180").options
    check("TCP option metadata keeps one-based array indices and binary bytes",
        entries[0] == nil and #entries == 1 and entries[1].kind == 2 and entries[1].data == "\5\180" and keys(entries[1]) == "data,kind")
    entries = dissect_tcphdr(tcp_base .. "\1\2\255\0").options
    check("Malformed TCP suffix preserves the earlier valid option",
        #entries == 1 and entries[1].kind == 1 and entries[1].data == nil)
    local ipv6 = "\96\0\0\0\0\8\0\64" .. z:sub(1, 32) .. "\59\0" .. z:sub(1, 6)
    local extensions = dissect_ip6hdr(ipv6).exthdr
    check("IPv6 extension projection keeps exact type next and data keys",
        #extensions == 1 and keys(extensions[1]) == "data,next,type" and extensions[1].type == 0 and extensions[1].next == 59 and extensions[1].data == z:sub(1, 6))
    local stopped = dissect_ip6hdr(ipv6:sub(1, 6) .. "\255" .. ipv6:sub(8)).exthdr
    check("Unsupported IPv6 next protocols keep an empty extension table", type(stopped) == "table" and #stopped == 0)
    local ip = dissect_iphdr("\70" .. z:sub(1, 11) .. "\192\0\2\1\198\51\100\2ABCD")
    check("IPv4 raw options and addresses retain their own byte ranges",
        ip.options == "ABCD" and ip.ip_src == "\192\0\2\1" and ip.ip_dst == "\198\51\100\2")
end

if failures ~= 0 then error("packet writer fixture has " .. failures .. " failed checks") end
print(table.concat(wire_records, "\n"))
print("ok packet writer fixture completed")
