-- Real native Lua codec calls after the process sandbox is active.
local failures = 0
local function check(name, value)
    print((value and "ok " or "FAIL ")..name)
    if not value then failures = failures + 1 end
end

local function encode(data, bits, hint)
    local stream = assert(gzip_init(bits, 6, 8))
    local pieces = {}
    for offset = 1, #data, 4096 do
        local piece = data:sub(offset, offset + 4095)
        local output = hint == nil and gzip_deflate(stream, piece) or gzip_deflate(stream, piece, hint)
        assert(output ~= nil)
        pieces[#pieces + 1] = output
    end
    local tail, finished
    if hint == nil then tail, finished = gzip_deflate(stream)
    else tail, finished = gzip_deflate(stream, nil, hint) end
    assert(tail ~= nil and finished == true)
    pieces[#pieces + 1] = tail
    gzip_end(stream)
    return table.concat(pieces)
end

local function decode(data, bits, hint)
    local stream = assert(gunzip_init(bits))
    local pieces, finished = {}, false
    for offset = 1, #data, 17 do
        local piece = data:sub(offset, offset + 16)
        local output, done
        if hint == nil then output, done = gunzip_inflate(stream, piece)
        else output, done = gunzip_inflate(stream, piece, hint) end
        assert(output ~= nil)
        pieces[#pieces + 1], finished = output, done
    end
    gunzip_end(stream)
    return table.concat(pieces), finished
end

local payload = ("codec\0данные-é-中\r\n"):rep(8192)
local function one_shot_codec(bits, level, memory)
    local encoder = assert(gzip_init(bits, level, memory))
    local first = assert(gzip_deflate(encoder, "codec options"))
    local tail, done = gzip_deflate(encoder)
    assert(done)
    assert(select("#", gzip_end(encoder)) == 0)
    return first..tail
end
local default_codec = one_shot_codec(nil, nil, nil)
check("codec defaults retain explicit gzip options", default_codec == one_shot_codec(31, 9, 8))
check("codec options accept numeric strings", one_shot_codec("31", "9", "8") == default_codec)
check("codec options narrow to native integers before initialization",
    one_shot_codec(31 + 2^32, 9 + 2^32, 8 + 2^32) == default_codec)
local wide_decoder = assert(gunzip_init(47 + 2^32))
local wide_data, wide_done = gunzip_inflate(wide_decoder, default_codec)
check("inflate options retain native integer narrowing and zero result close",
    wide_data == "codec options" and wide_done == true and select("#", gunzip_end(wide_decoder)) == 0)
local lifecycle_stream = assert(gzip_init())
local lifecycle_ok, lifecycle_error = pcall(gunzip_end, lifecycle_stream)
assert(gzip_deflate(lifecycle_stream, "still valid"))
assert(gzip_deflate(lifecycle_stream))
gzip_end(lifecycle_stream)
local closed_ok, closed_error = pcall(gunzip_end, lifecycle_stream)
check("codec role mismatch preserves state and closed state takes precedence",
    not lifecycle_ok and tostring(lifecycle_error):find("gzip stream role mismatch", 1, true) ~= nil and
    not closed_ok and tostring(closed_error):find("gzip stream is not valid", 1, true) ~= nil)
check("invalid codec options return exactly one nil result",
    select("#", gzip_init(0)) == 1 and gzip_init(0) == nil and
    select("#", gunzip_init(99)) == 1 and gunzip_init(99) == nil)
check("codec argument counts are checked before invalid userdata or options",
    not pcall(gunzip_init, false, false) and not pcall(gzip_init, false, false, false, false) and
    not pcall(gzip_end) and not pcall(gunzip_end, false, false))
for _, mode in ipairs({{31, 47, "gzip"}, {15, 47, "zlib"}, {-15, -15, "raw deflate"}}) do
    local compressed = encode(payload, mode[1], 64)
    local decoded, finished = decode(compressed, mode[2], 64)
    check("native streaming "..mode[3].." retains binary Unicode data", decoded == payload and finished == true)
end

local compressed = encode(payload, 31)
local stream = assert(gunzip_init())
local decoded, finished = gunzip_inflate(stream, compressed, 0)
gunzip_end(stream)
check("zero inflate hint grows from a usable minimum", decoded == payload and finished == true)

stream = assert(gunzip_init())
local rejected, rejected_end = gunzip_inflate(stream, compressed, -1)
decoded, finished = gunzip_inflate(stream, compressed, 0)
gunzip_end(stream)
check("negative inflate hint rejects before consuming the stream", rejected == nil and rejected_end == nil and decoded == payload and finished == true)

stream = assert(gzip_init())
rejected, rejected_end = gzip_deflate(stream, payload, -1)
local first = assert(gzip_deflate(stream, payload, 64))
local tail, done = gzip_deflate(stream)
gzip_end(stream)
decoded, finished = decode(first..assert(tail), 47)
check("negative deflate hint preserves the stream for a valid retry", rejected == nil and rejected_end == nil and done == true and decoded == payload and finished == true)

local corrupt = compressed:sub(1, -9)..string.char((compressed:byte(-8) + 1) % 256)..compressed:sub(-7)
stream = assert(gunzip_init())
rejected, rejected_end = gunzip_inflate(stream, corrupt)
local closed = pcall(gunzip_end, stream)
check("corrupt checksum returns nil and retains explicit stream cleanup", rejected == nil and rejected_end == nil and closed)
check("closed codec stream rejects a second end", not pcall(gunzip_end, stream))

stream = assert(gunzip_init())
check("codec role mismatch fails before changing the stream", not pcall(gzip_deflate, stream, "input"))
decoded, finished = gunzip_inflate(stream, compressed)
gunzip_end(stream)
check("role mismatch leaves the decoder usable", decoded == payload and finished == true)

local stable = true
for _ = 1, 32 do
    stream = assert(gunzip_init())
    rejected, rejected_end = gunzip_inflate(stream, compressed, 2^52)
    decoded, finished = gunzip_inflate(stream, compressed, 64)
    gunzip_end(stream)
    stable = stable and rejected == nil and rejected_end == nil and decoded == payload and finished == true
end
collectgarbage("collect")
collectgarbage("collect")
check("oversized hints remain bounded across retries and collection", stable)

for _, mode in ipairs({{31, 47}, {15, 47}, {-15, -15}}) do
    local empty, eof = decode(encode("", mode[1], 0), mode[2], 0)
    check("empty codec stream finishes in mode "..mode[1], empty == "" and eof == true)
end

io.stdout:flush()
os.exit(failures == 0 and 0 or 1)
