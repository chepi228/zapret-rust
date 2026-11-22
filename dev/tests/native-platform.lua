-- Runs in the real native engine after its Windows sandbox has been applied.
local failures = 0
local function check(name, value)
    print((value and "ok " or "FAIL ")..name)
    if not value then failures = failures + 1 end
end

local function normalized(path)
    return path:gsub("\\", "/"):gsub("/+$", ""):lower()
end

local writable = assert(os.getenv("WRITABLE"))
local long_directory = assert(os.getenv("ZAPRET_NATIVE_LONG_DIR"))
local denied_file = assert(os.getenv("ZAPRET_NATIVE_DENIED_FILE"))
assert(normalized(long_directory):sub(1, #normalized(writable) + 1) == normalized(writable).."/")
assert(normalized(denied_file):sub(1, #normalized(writable) + 1) ~= normalized(writable).."/")

check("native Windows runtime keeps FFI disabled", uname().sysname == "Windows_NT" and not pcall(require, "ffi"))
check("native engine preserves its version after default initialization",
    type(NFQWS2_VER) == "string" and NFQWS2_VER:find("github version", 1, true) ~= nil and
    NFQWS2_VER:find("lua_compat_ver", 1, true) ~= nil)
check("sandbox removes process execution and generic DLL loading",
    os.execute == nil and io.popen == nil and package.loadlib == nil)

local readable, replaced = make_readable("a\127\r\n\0\255")
local eol, next_line = find_next_line("a\r\nb", -3)
check("Rust library helpers preserve binary bytes, carriage returns and result arity",
    type(zapret_native_modules.library_utils) == "function" and
    string2hex("\0\255z") == "00 FF 7A" and has_nonprintable("\r\n\t\127") == nil and
    has_nonprintable("a\0\255") == "\0" and readable == "a\127...." and replaced == 4 and
    eol == 1 and next_line == 4 and select("#", find_next_line("a\n")) == 2 and
    str_or_hex("a\0") == "61 00" and hexdump("ab\0", 2) == "61 62 ... ab ... " and
    pattern("\0ab", -1, 5) == "ab\0ab" and in_list(",a\0,,b", "a\0"))
check("Rust path helpers preserve Windows paths and writable directory resolution",
    append_path("C:/data/", "имя.txt") == "C:/data/имя.txt" and
    append_path("", "имя.txt") == "/имя.txt" and
    writable_file_name("C:/data/имя.txt") == "C:/data/имя.txt" and
    writable_file_name("имя.txt") == append_path(writable, "имя.txt"))

local random_apis = {brandom, brandom_az, brandom_az09, bcryptorandom}
local random_empty, random_lengths, random_negative, random_arity = true, true, true, true
for index, api in ipairs(random_apis) do
    random_empty = random_empty and api(0) == "" and select("#", api(0)) == 1
    random_lengths = random_lengths and #api("17") == 17 and #api(1.75) == 1
    local ok, message = pcall(api, -1)
    local name = index == 4 and "bcryptorandom" or "brandom"
    random_negative = random_negative and not ok and tostring(message):find(name..": invalid arg", 1, true) ~= nil
    ok, message = pcall(api, false, false)
    random_arity = random_arity and not ok and tostring(message):find("expect exactly 1 arguments, got 2", 1, true) ~= nil
end
check("random APIs return exactly one empty string for zero bytes", random_empty)
check("random APIs keep numeric strings and fractional integer coercion", random_lengths)
check("alphabet random APIs retain the shared negative length diagnostic", random_negative)
check("random APIs check arity before the argument type", random_arity)
check("alphabet random backends retain their character sets",
    brandom_az(1024):match("^[a-z]+$") ~= nil and brandom_az09(1024):match("^[a-z0-9]+$") ~= nil)
check("hex entry decodes an independent mixed case binary vector", parse_hex("00fF7a") == "\0\255z")
check("hex entry returns exactly one nil for malformed or odd input",
    parse_hex("00Z0") == nil and parse_hex("0") == nil and select("#", parse_hex("00Z0")) == 1)
check("hex entry keeps embedded NUL termination and even length validation",
    parse_hex("00\0Z") == "\0" and parse_hex("\0x") == "" and parse_hex("00\0") == nil and parse_hex("0\0") == nil)
local hex_ok, hex_error = pcall(parse_hex, 1234)
check("hex entry requires a strict string", not hex_ok and tostring(hex_error):find("string expected", 1, true) ~= nil)
local binary_first, binary_second = "\0\255\85\170", "\255\15\240\0"
check("binary entries match independent XOR OR AND vectors",
    bxor(binary_first, binary_second) == "\255\240\165\170" and
    bor(binary_first, binary_second) == "\255\255\245\170" and
    band(binary_first, binary_second) == "\0\15\80\0" and binary_first == "\0\255\85\170")
local binary_arity, binary_lengths, binary_types = true, true, true
for _, api in ipairs({bxor, bor, band}) do
    binary_arity = binary_arity and api("", "") == "" and select("#", api("", "")) == 1
    local ok, message = pcall(api, "x", "xx")
    binary_lengths = binary_lengths and not ok and tostring(message):find("string lengths must be the same\n", 1, true) ~= nil
    ok, message = pcall(api, "x", 123)
    binary_types = binary_types and not ok and tostring(message):find("string expected", 1, true) ~= nil
end
check("binary entries preserve empty inputs and one result", binary_arity)
check("binary entries retain the exact unequal length diagnostic", binary_lengths)
check("binary entries reject numeric operands before comparing lengths", binary_types)

local numeric_names = {"bitlshift", "bitrshift", "bitand", "bitor", "bitxor",
    "bitnot8", "bitnot16", "bitnot24", "bitnot32", "bitnot48", "bitget", "bitset",
    "swap16", "swap24", "swap32", "swap48", "u8add", "u16add", "u24add", "u32add",
    "u48add", "divint", "u8", "u16", "u24", "u32", "u48", "bu8", "bu16", "bu24", "bu32", "bu48"}
local numeric_arity = true
for _, name in ipairs(numeric_names) do
    local ok, message = pcall(_G[name])
    numeric_arity = numeric_arity and not ok and tostring(message):find(name.." expect ", 1, true) ~= nil
end
check("all 32 numeric entries retain public arity diagnostics", numeric_arity)
check("numeric entry operands retain string and fractional coercion",
    bitlshift("3.75", "2.9") == 12 and u16add("65535", "2.75") == 1)
check("numeric modular addition retains signed limits and maximum operand count",
    u8add(-255, -2) == 255 and u8add(unpack((function() local t = {} for i = 1, 100 do t[i] = 1 end return t end)())) == 100)
local numeric_ok, numeric_error = pcall(u8add, 256, false)
check("numeric entries extract later operands before checking earlier ranges",
    not numeric_ok and tostring(numeric_error):find("#2", 1, true) ~= nil and tostring(numeric_error):find("number expected", 1, true) ~= nil)
numeric_ok, numeric_error = pcall(bitset, 0, 48, 49, false)
check("bitset extracts its value before validating the bit range",
    not numeric_ok and tostring(numeric_error):find("#4", 1, true) ~= nil)
check("binary numeric reads preserve absent nil and coercing offset defaults",
    u16("\18\52\86") == 0x1234 and u16("\18\52\86", nil) == 0x1234 and u16("\18\52\86", "2.75") == 0x3456)
numeric_ok, numeric_error = pcall(u16, 1234, false)
check("binary numeric reads require a strict string before examining the offset",
    not numeric_ok and tostring(numeric_error):find("#1", 1, true) ~= nil and tostring(numeric_error):find("string expected", 1, true) ~= nil)
numeric_ok, numeric_error = pcall(u16, "", false)
check("binary numeric reads validate an explicit offset before buffer bounds",
    not numeric_ok and tostring(numeric_error):find("#2", 1, true) ~= nil and tostring(numeric_error):find("number expected", 1, true) ~= nil)
numeric_ok, numeric_error = pcall(u48, "123456", 2)
check("binary numeric reads retain the exact out of range diagnostic",
    not numeric_ok and tostring(numeric_error):find("out of range", 1, true) ~= nil)
check("binary numeric writes preserve signed narrowing and exact output widths",
    bu8(-255) == "\1" and bu16("4660.9") == "\18\52" and bu48(-1) == string.rep("\255", 6))
numeric_ok, numeric_error = pcall(bu8, 256)
check("binary numeric writes reject values beyond the signed symmetric limit",
    not numeric_ok and tostring(numeric_error):find("out of range", 1, true) ~= nil)
check("numeric division retains truncation and exactly one nil for zero divisors",
    divint(-7, 2) == -3 and divint(7, 0) == nil and select("#", divint(7, 0)) == 1)
numeric_ok, numeric_error = pcall(bitget, 0, 47, 48)
check("numeric bit range failures retain their distinct diagnostic",
    not numeric_ok and tostring(numeric_error):find("bit range invalid", 1, true) ~= nil)
check("binary numeric reads and writes preserve embedded zero bytes",
    bu24(u24("\0\255\0")) == "\0\255\0" and select("#", bu24(0)) == 1)

local sha256_abc = parse_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
local sha224_empty = parse_hex("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
check("hash entry matches an independent SHA256 vector", hash("sha256", "abc") == sha256_abc)
check("hash entry matches an independent empty SHA224 vector", hash("sha224", "") == sha224_empty)
check("hash algorithm names preserve C string termination", hash("sha256\0ignored", "abc") == sha256_abc)
local digest_ok, digest_error = pcall(hash, "sha256", 123)
check("hash data remains a strict binary string", not digest_ok and tostring(digest_error):find("#2", 1, true) ~= nil and tostring(digest_error):find("string expected", 1, true) ~= nil)
digest_ok, digest_error = pcall(hash, 256, false)
check("hash algorithm name coercion and rejection precede data validation", not digest_ok and tostring(digest_error):find("unsupported hash type 256", 1, true) ~= nil)
local digest_arity = true
for _, pair in ipairs({{hash, "hash"}, {hkdf, "hkdf"}, {ntop, "ntop"}, {pton, "pton"}}) do
    local ok, message = pcall(pair[1])
    digest_arity = digest_arity and not ok and tostring(message):find(pair[2].." expect exactly", 1, true) ~= nil
end
check("hash HKDF and IP entries retain exact arity diagnostics", digest_arity)
local hkdf_ikm = string.rep("\11", 22)
check("HKDF entry matches RFC5869 case one", hkdf("sha256", parse_hex("000102030405060708090a0b0c"), hkdf_ikm, parse_hex("f0f1f2f3f4f5f6f7f8f9"), 42) == parse_hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))
check("HKDF nil salt and info preserve RFC5869 case three", hkdf("sha256", nil, hkdf_ikm, nil, 42) == parse_hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"))
check("HKDF retains operand string coercion and fractional length narrowing", hkdf("sha256", 123, 456, 789, "17.75") == hkdf("sha256", "123", "456", "789", 17))
check("HKDF zero and oversized outputs return exactly one nil", hkdf("sha256", nil, nil, nil, 0) == nil and select("#", hkdf("sha256", nil, nil, nil, 0)) == 1 and hkdf("sha256", nil, nil, nil, 8161) == nil and hkdf("sha224", nil, nil, nil, 7141) == nil)
digest_ok, digest_error = pcall(hkdf, "sha256", nil, nil, nil, -1)
check("HKDF retains the negative length diagnostic", not digest_ok and tostring(digest_error):find("hkdf: invalid arg", 1, true) ~= nil)
digest_ok, digest_error = pcall(hkdf, "sha256", false, nil, nil, 0)
check("HKDF validates salt before short circuiting a zero output", not digest_ok and tostring(digest_error):find("#2", 1, true) ~= nil)
local ipv4_bytes, ipv6_bytes = "\127\0\0\1", string.rep("\0", 15).."\1"
check("IP entries retain independent IPv4 and IPv6 binary vectors", pton("127.0.0.1") == ipv4_bytes and pton("::1") == ipv6_bytes and ntop(ipv4_bytes) == "127.0.0.1" and ntop(ipv6_bytes) == "::1")
check("IP text conversion preserves embedded NUL termination", pton("127.0.0.1\0ignored") == ipv4_bytes)
local address_types = true
for _, api in ipairs({ntop, pton}) do
    local ok, message = pcall(api, 123)
    address_types = address_types and not ok and tostring(message):find("string expected", 1, true) ~= nil
end
check("both IP entries require strict string inputs", address_types)
check("invalid IP input returns exactly one nil", pton("1.2.3.256") == nil and pton("not an address") == nil and ntop("abc") == nil and select("#", pton("")) == 1 and select("#", ntop("")) == 1)

local unicode = writable.."/данные-é-中.txt"
local payload = "alpha\r\nbeta\0omega"
local invalid_mode, invalid_error, invalid_errno = io.open(unicode, "invalid")
check("invalid file mode returns a Lua file error",
    invalid_mode == nil and type(invalid_error) == "string" and type(invalid_errno) == "number")
local file = assert(io.open(unicode, "w"))
assert(file:write(payload))
assert(file:close())
local exclusive, exclusive_error, exclusive_errno = io.open(unicode, "wxe")
check("exclusive create preserves an existing Unicode file",
    exclusive == nil and type(exclusive_error) == "string" and type(exclusive_errno) == "number" and readfile(unicode) == payload)
local compatible_mode = assert(io.open(unicode, "rZ"))
local compatible_data = compatible_mode:read("*a")
assert(compatible_mode:close())
check("file modes retain pinned Cygwin extension handling", compatible_data == payload)
file = assert(io.open(unicode, "r"))
check("Unicode io.open preserves default binary bytes", file:read("*a") == payload)
assert(file:seek("set", 0))
check("Unicode file seek and line reads preserve carriage returns", file:read("*l") == "alpha\r")
assert(file:close())
local lines = {}
for line in io.lines(unicode) do lines[#lines + 1] = line end
-- The pinned LuaJIT line reader uses C strings and stops each result at NUL.
check("Unicode io.lines preserves pinned LuaJIT NUL handling", #lines == 2 and lines[1] == "alpha\r" and lines[2] == "beta")

local previous_input = io.input()
local input = io.input(unicode)
local input_data = io.read("*a")
io.input(previous_input)
assert(input:close())
check("Unicode io.input uses the native file wrapper", input_data == payload)

local output_path = writable.."/выход-é-中.txt"
local previous_output = io.output()
local output = io.output(output_path)
assert(io.write(payload))
assert(io.flush())
io.output(previous_output)
assert(output:close())
check("Unicode io.output writes through the native file wrapper", readfile(output_path) == payload)

local info = assert(stat(unicode))
check("native stat returns file identity size and subsecond time",
    info.type == "file" and info.size == #payload and type(info.dev) == "number" and
    type(info.inode) == "number" and info.inode ~= 0 and type(info.mtime) == "number" and
    math.abs(info.mtime - os.time()) < 30)
local directory_info = assert(stat(writable))
check("native stat identifies writable directories", directory_info.type == "dir")

local target = writable.."/замена-é-中.txt"
writefile(target, "previous")
local held_source = assert(io.open(unicode, "rb"))
assert(os.rename(unicode, target))
local held_data = held_source:read("*a")
assert(held_source:close())
check("rename keeps an already open source handle readable", held_data == payload)
local renamed = assert(stat(target))
check("Unicode os.rename replaces a snapshot and keeps its identity",
    readfile(target) == payload and renamed.dev == info.dev and renamed.inode == info.inode)
local moved, move_error, move_errno = os.rename(unicode, target)
check("failed rename returns Lua file errors and preserves the destination",
    moved == nil and type(move_error) == "string" and type(move_errno) == "number" and readfile(target) == payload)

local script = long_directory.."/загрузка-é-中.lua"
writefile(script, "\239\187\191#!/usr/bin/lua\nreturn 6 * 7\n")
check("Unicode loadfile handles BOM and shebang beyond MAX_PATH", #script > 260 and assert(loadfile(script))() == 42)
check("Unicode dofile handles paths beyond MAX_PATH", dofile(script) == 42)
local saved_package_path = package.path
package.path = long_directory.."/?.lua"
local loaded = require("загрузка-é-中")
package.path = saved_package_path
check("Unicode require searches native Lua paths", loaded == 42)
check("native stat supports Unicode paths beyond MAX_PATH", assert(stat(script)).type == "file")
local drive, tail = script:match("^([A-Za-z]):(.*)$")
local legacy_path = drive and "/cygdrive/"..drive:lower()..tail
check("native files accept Cygwin paths retained in local state",
    legacy_path and readfile(legacy_path) == readfile(script))
local invalid_file, _, unicode_errno = io.open(writable.."/invalid-"..string.char(255), "r")
check("invalid UTF-8 paths return a Lua file error",
    invalid_file == nil and type(unicode_errno) == "number")

check("absolute drive and UNC state paths bypass WRITABLE",
    writable_file_name("C:/fixture/state.txt") == "C:/fixture/state.txt" and
    writable_file_name("C:\\fixture\\state.txt") == "C:\\fixture\\state.txt" and
    writable_file_name("\\\\server\\share\\state.txt") == "\\\\server\\share\\state.txt" and
    writable_file_name("//server/share/state.txt") == "//server/share/state.txt")
check("relative state paths keep the writable directory",
    normalized(writable_file_name("state.txt")) == normalized(writable.."/state.txt"))

local seconds, nanoseconds = clock_gettime()
local floating = clock_getfloattime()
check("native clocks retain seconds and nanoseconds",
    type(seconds) == "number" and nanoseconds >= 0 and nanoseconds < 1000000000 and
    math.abs(floating - seconds - nanoseconds / 1000000000) < 2)
local epoch = 1700000000
local utc = assert(gmtime(epoch))
check("native gmtime and timegm round trip UTC", utc.year == 2023 and utc.zone == "UTC" and timegm(utc) == epoch)
local local_time = assert(localtime(epoch))
check("native localtime and timelocal round trip local time", type(local_time.zone) == "string" and timelocal(local_time) == epoch)

local system_apis = {stat, uname, clock_gettime, clock_getfloattime, localtime, gmtime, timelocal, timegm}
local system_counts = {1, 0, 0, 0, 1, 1, 1, 1}
local arity_ok = true
for i, api in ipairs(system_apis) do
    for count = 0, 2 do
        if count ~= system_counts[i] then
            local args = count == 0 and {} or count == 1 and {false} or {false, false}
            local ok, message = pcall(api, unpack(args))
            arity_ok = arity_ok and not ok and tostring(message):find("expect exactly", 1, true) ~= nil
        end
    end
end
check("system APIs check exact arity before reading arguments", arity_ok)
check("native UTC projection preserves zero based month and full calendar year",
    utc.mon == 10 and utc.mday == 14 and utc.hour == 22 and utc.min == 13 and utc.sec == 20 and
    utc.wday == 2 and utc.yday == 317 and utc.isdst == 0 and utc.str == "14.11.2023 22:13:20")
check("native time projections accept numeric string timestamps",
    assert(gmtime(tostring(epoch))).str == utc.str and assert(localtime(tostring(epoch))).str == local_time.str)
local time_fields = {"sec", "min", "hour", "mday", "mon", "year", "isdst"}
local lookup_trace = {}
local indirect_time = setmetatable({}, {__index = function(_, key)
    lookup_trace[#lookup_trace + 1] = key
    if key == "sec" then assert(gmtime(epoch).zone == "UTC") end
    return utc[key]
end})
check("time table extraction preserves lookup order and nested calls",
    timegm(indirect_time) == epoch and table.concat(lookup_trace, ",") == table.concat(time_fields, ","))
local strict_time = {}
for _, key in ipairs(time_fields) do strict_time[key] = utc[key] end
strict_time.year = tostring(utc.year)
local strict_ok, strict_error = pcall(timegm, strict_time)
check("time table extraction rejects numeric strings at the named field",
    not strict_ok and tostring(strict_error):find("invalid tm.year", 1, true) ~= nil)
local missing_trace = {}
local missing_time = setmetatable({}, {__index = function(_, key)
    missing_trace[#missing_trace + 1] = key
    if key ~= "hour" then return utc[key] end
end})
local missing_ok, missing_error = pcall(timegm, missing_time)
check("time table extraction stops at its first invalid field",
    not missing_ok and tostring(missing_error):find("invalid tm.hour", 1, true) ~= nil and
    table.concat(missing_trace, ",") == "sec,min,hour")
local structure_ok, structure_error = pcall(timelocal, false)
check("time conversion rejects non table structures before field lookup",
    not structure_ok and tostring(structure_error):find("invalid tm structure", 1, true) ~= nil)
local normalized_time = {sec = 80, min = 12, hour = 22, mday = 14, mon = 10, year = 2023, isdst = 0}
check("native UTC conversion retains CRT calendar normalization", timegm(normalized_time) == epoch)
local wrapped_time = {}
for _, key in ipairs(time_fields) do wrapped_time[key] = utc[key] end
wrapped_time.year = utc.year + 4294967296
check("time conversion narrows calendar fields to native integers", timegm(wrapped_time) == epoch)
local missing_stat, missing_stat_error, missing_stat_errno = stat(writable.."/missing-system-fixture")
check("stat failures retain nil message and numeric errno",
    missing_stat == nil and type(missing_stat_error) == "string" and type(missing_stat_errno) == "number")
local embedded_stat = assert(stat(target.."\0ignored"))
check("stat preserves native filename termination at embedded NUL", embedded_stat.inode == renamed.inode)
local system_name = assert(uname())
local system_name_fields = 0
for _ in pairs(system_name) do system_name_fields = system_name_fields + 1 end
check("uname publishes exactly five native string fields",
    system_name_fields == 5 and type(system_name.sysname) == "string" and type(system_name.nodename) == "string" and
    type(system_name.release) == "string" and type(system_name.version) == "string" and type(system_name.machine) == "string")

local random = bcryptorandom(64)
check("system cryptographic RNG works after privilege drop", type(random) == "string" and #random == 64 and bcryptorandom(0) == "")
check("system RNG rejects invalid lengths", not pcall(bcryptorandom, -1))

local function crypto_bytes(hex)
    return (hex:gsub("..", function(byte) return string.char(tonumber(byte, 16)) end))
end
local crypto_key, crypto_zero = string.rep("\0", 16), string.rep("\0", 16)
local crypto_block = crypto_bytes("66e94bd4ef8a2c3b884cfa59ca342b2e")
check("AES block entry preserves the independent zero key vector and decryption",
    aes(true, crypto_key, crypto_zero) == crypto_block and aes(false, crypto_key, crypto_block) == crypto_zero)
check("AES entry preserves Lua truthiness for direction",
    aes(0, crypto_key, crypto_zero) == crypto_block and aes(nil, crypto_key, crypto_block) == crypto_zero)
local crypto_ok, crypto_error = pcall(aes, true, crypto_key:sub(2), false)
check("AES key length is validated before input type",
    not crypto_ok and tostring(crypto_error):find("wrong key length 15", 1, true) ~= nil)
crypto_ok, crypto_error = pcall(aes_ctr, crypto_key, crypto_zero:sub(2), false)
check("CTR IV length is validated before input type",
    not crypto_ok and tostring(crypto_error):find("wrong iv length 15", 1, true) ~= nil)
check("CTR entry coerces numeric payloads while retaining strict key and IV strings",
    aes_ctr(crypto_key, crypto_zero, 123) == aes_ctr(crypto_key, crypto_zero, "123") and
    not pcall(aes_ctr, 123, crypto_zero, "x") and not pcall(aes_ctr, crypto_key, 123, "x"))
crypto_ok, crypto_error = pcall(aes_gcm, true, crypto_key, "", false, false)
check("GCM empty IV is rejected before payload and associated data",
    not crypto_ok and tostring(crypto_error):find("zero iv length", 1, true) ~= nil)
local crypto_iv = string.rep("\0", 12)
local crypto_cipher, crypto_tag = aes_gcm(true, crypto_key, crypto_iv, crypto_zero)
check("GCM entry preserves independent ciphertext and authentication tag vectors",
    crypto_cipher == crypto_bytes("0388dace60b6a392f328c2b971b2fe78") and
    crypto_tag == crypto_bytes("ab6e47d42cec13bdf53a67b21257bddf"))
local crypto_plain, crypto_decrypt_tag = aes_gcm(false, crypto_key, crypto_iv, crypto_cipher)
check("GCM decryption retains its computed tag result", crypto_plain == crypto_zero and crypto_decrypt_tag == crypto_tag)
local crypto_nil_cipher, crypto_nil_tag = aes_gcm(true, crypto_key, crypto_iv, crypto_zero, nil)
local crypto_empty_cipher, crypto_empty_tag = aes_gcm(true, crypto_key, crypto_iv, crypto_zero, "")
check("GCM missing nil and empty associated data preserve identical results",
    crypto_nil_cipher == crypto_cipher and crypto_nil_tag == crypto_tag and
    crypto_empty_cipher == crypto_cipher and crypto_empty_tag == crypto_tag)
check("GCM payload and associated data require actual strings",
    not pcall(aes_gcm, true, crypto_key, crypto_iv, 123) and not pcall(aes_gcm, true, crypto_key, crypto_iv, "x", 123))

local interfaces = get_ifaddrs()
local valid_interfaces = type(interfaces) == "table"
if valid_interfaces then
    for name, entry in pairs(interfaces) do
        valid_interfaces = valid_interfaces and type(name) == "string" and type(entry) == "table" and
            type(entry.index) == "number" and type(entry.mtu) == "number" and type(entry.addr) == "table"
    end
end
check("native interface enumeration preserves the Lua table contract", valid_interfaces)
local loopback = string.char(127, 0, 0, 1)
check("Winsock source lookup has an initialized socket lifetime", get_source_ip(loopback) == loopback)

-- Fixed wire vectors use documentation addresses. Parse and reconstruction stay
-- in memory, including the independent checksum bytes in each fixture.
local function wire_bytes(hex)
    return (hex:gsub("..", function(byte) return string.char(tonumber(byte, 16)) end))
end

check("native engine reads a gzip-compressed Lua init file", ZAPRET_GZIP_FIXTURE == 42)
local codec_data = "codec\0fixture\r\n"
local gzip_fixture = wire_bytes("1f8b080000000000020a4bce4f494d6648cbac28292d4ae5e502005e47dead0f000000")
local inflater = assert(gunzip_init())
local first, first_end = gunzip_inflate(inflater, gzip_fixture:sub(1, 7))
local second, second_end = gunzip_inflate(inflater, gzip_fixture:sub(8))
gunzip_end(inflater)
check("native gzip decodes independent bytes in separate chunks",
    first and second and first..second == codec_data and first_end == false and second_end == true)
local corrupt = gzip_fixture:sub(1, -9).."\0"..gzip_fixture:sub(-7)
inflater = assert(gunzip_init())
local decoded, finished = gunzip_inflate(inflater, corrupt)
gunzip_end(inflater)
check("native gzip rejects an invalid stream checksum", decoded == nil and finished == nil)

local function codec_roundtrip(bits, read_bits)
    local encoder = assert(gzip_init(bits, 6, 8))
    local part1 = assert(gzip_deflate(encoder, codec_data:sub(1, 6)))
    local part2 = assert(gzip_deflate(encoder, codec_data:sub(7)))
    local tail, done = gzip_deflate(encoder)
    gzip_end(encoder)
    if not tail or not done then return false end
    local decoder = assert(gunzip_init(read_bits))
    local result, eof = gunzip_inflate(decoder, part1..part2..tail)
    gunzip_end(decoder)
    return result == codec_data and eof == true
end
check("native gzip preserves streaming gzip, zlib and raw deflate modes",
    codec_roundtrip(31, 47) and codec_roundtrip(15, 47) and codec_roundtrip(-15, -15))

local tcp4_wire = wire_bytes(
    "452e002c1234400040063c33c0000201c6336402"..
    "303901bb010203040506070850181234ac4a00006100620a")
local tcp4 = dissect(tcp4_wire)
check("wire IPv4 and TCP minimum headers round trip",
    tcp4.ip and tcp4.tcp and tcp4.ip.ip_v == 4 and tcp4.ip.ip_hl == 5 and tcp4.ip.ip_tos == 0x2e and
    tcp4.ip.ip_id == 0x1234 and tcp4.l3_len == 20 and tcp4.l4_len == 20 and
    tcp4.tcp.th_sport == 12345 and tcp4.tcp.th_dport == 443 and tcp4.tcp.th_seq == 0x01020304 and
    tcp4.tcp.th_off == 5 and tcp4.tcp.th_flags == 0x18 and tcp4.tcp.th_win == 0x1234 and
    tcp4.payload == "a\0b\n" and reconstruct_dissect(tcp4, {keepsum=true}) == tcp4_wire)
check("native IPv4 and TCP checksums match the independent wire bytes",
    csum_ip4_fix(tcp4_wire:sub(1, 10)..string.char(0, 0)..tcp4_wire:sub(13, 20)) == tcp4_wire:sub(1, 20) and
    csum_tcp_fix(tcp4_wire:sub(1, 20), tcp4_wire:sub(21, 36)..string.char(0, 0)..tcp4_wire:sub(39, 40),
        tcp4_wire:sub(41)) == tcp4_wire:sub(21, 40))

local tcp4_options_wire = wire_bytes(
    "46010031beef40006306699dc0000201c633640201010101"..
    "303901bba123b456fffefdfc6912100093730000020405b47a")
local tcp4_options = dissect(tcp4_options_wire)
check("wire IPv4 and TCP options keep their lengths and bitfields",
    tcp4_options.ip and tcp4_options.tcp and tcp4_options.ip.ip_hl == 6 and
    tcp4_options.ip.options == string.char(1, 1, 1, 1) and tcp4_options.l3_len == 24 and tcp4_options.l4_len == 24 and
    tcp4_options.tcp.th_seq == 0xa123b456 and tcp4_options.tcp.th_ack == 0xfffefdfc and
    tcp4_options.tcp.th_x2 == 9 and tcp4_options.tcp.th_off == 6 and tcp4_options.tcp.th_flags == 0x12 and
    tcp4_options.tcp.options and #tcp4_options.tcp.options == 1 and tcp4_options.tcp.options[1].kind == 2 and
    tcp4_options.tcp.options[1].data == string.char(5, 0xb4) and tcp4_options.payload == "z" and
    reconstruct_dissect(tcp4_options, {keepsum=true}) == tcp4_options_wire)

local udp6_wire = wire_bytes(
    "6ab12345000b112520010db8000000000000000000000001"..
    "20010db800000000000000000000000214e9270f000b836a750070")
local udp6 = dissect(udp6_wire)
check("wire IPv6 and UDP headers round trip",
    udp6.ip6 and udp6.udp and udp6.ip6.ip6_flow == 0x6ab12345 and udp6.ip6.ip6_plen == 11 and
    udp6.ip6.ip6_nxt == 17 and udp6.ip6.ip6_hlim == 37 and udp6.l3_len == 40 and udp6.l4_len == 8 and
    udp6.udp.uh_sport == 5353 and udp6.udp.uh_dport == 9999 and udp6.udp.uh_ulen == 11 and
    udp6.payload == "u\0p" and reconstruct_dissect(udp6, {keepsum=true}) == udp6_wire)
check("native UDPv6 checksum includes the pseudo-header and odd payload",
    csum_udp_fix(udp6_wire:sub(1, 40), udp6_wire:sub(41, 46)..string.char(0, 0), udp6_wire:sub(49)) ==
        udp6_wire:sub(41, 48))
local partial_udp = udp6_wire:sub(1, 49)
local strict = dissect(partial_udp)
local partial = dissect(partial_udp, true)
check("native parser retains strict and partial IPv6 header handling",
    strict.ip6 == nil and partial.ip6 and partial.udp and partial.l3_len == 40 and
    partial.l4_len == 8 and partial.payload == "u")

check("sandbox can read the prepared medium integrity file", readfile(denied_file) == "native-platform-medium-sentinel\n")
local denied, denied_error, denied_errno = io.open(denied_file, "wb")
if denied then denied:close() end
check("low integrity denies writing outside the prepared writable directory",
    denied == nil and type(denied_error) == "string" and type(denied_errno) == "number")
check("denied write keeps the medium integrity sentinel", readfile(denied_file) == "native-platform-medium-sentinel\n")

check("Unicode os.remove deletes fixture files", os.remove(target) and os.remove(output_path) and os.remove(script))
check("removed Unicode file has a Lua stat error", stat(target) == nil)

local started = clock_getfloattime()
timer_set("native_platform_clock", function()
    local elapsed = clock_getfloattime() - started
    check("native timer runs in the restricted event loop", elapsed >= 0.05 and elapsed < 5)
    io.stdout:flush()
    os.exit(failures == 0 and 0 or 1)
end, 100, true)
