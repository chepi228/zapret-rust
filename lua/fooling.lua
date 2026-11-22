-- zapret: дополнения к стандартным библиотекам zapret2 (zapret-lib.lua, zapret-antidpi.lua).

-- Совместимость с исходным движком и пакетами с предыдущей версией Rust-моста.
local native = zapret_ring_native or {}
-- Штатная библиотека распознаёт пути Windows только через uname Cygwin.
local system = uname and uname()
if native.windows_absolute_path and system and system.sysname=="Windows_NT" then
	is_absolute_path = native.windows_absolute_path
end

-- Re-loading this adapter must preserve hooks installed by Lua callers.
if zapret_native_modules and not zapret_native_modules.bundled_rules_installed then
	local running = coroutine.running
	local function install(entries)
		for name, handler in pairs(entries) do
			local lua_handler = _G[name]
			_G[name] = function(...)
				if running() then return lua_handler(...) end
				return handler(...)
			end
		end
	end
	local function less_equal(a, b) return a <= b end
	install(zapret_native_modules.library_utils())
	if zapret_native_modules.automation then
		install(zapret_native_modules.automation(less_equal))
	end
	if zapret_native_modules.packet_utils then
		install(zapret_native_modules.packet_utils(less_equal))
	end
	if zapret_native_modules.strategies then
		install(zapret_native_modules.strategies(less_equal))
	end
	zapret_native_modules.bundled_rules_installed = true
end
local tcp_fallback = native.tcp_fallback or function(seq, has_md5)
	return u32add(seq, -10000), not has_md5
end
local host_split = native.host_split or function(len, start, finish)
	return 0, start, start, finish, finish, len, start, finish
end

-- Фейки Flowseal портятся устаревшим TCP timestamp (tcp_ts=-600000, у Flowseal fooling=ts): DPI их читает,
-- а сервер выбрасывает. Но timestamp есть, только если его поддерживает сервер. Без него фейк ушёл бы
-- неиспорченным, сервер принял бы его как настоящие данные, и соединение сломалось бы.
-- В таком соединении портим фейк как в стандартных стратегиях bol-van: MD5-опция и сдвиг sequence.
-- Использование: fake:blob=...:tcp_ts=-600000:tcp_ts_up:fool=ts_or_md5
function ts_or_md5(dis, fooling_options)
	local tcp = dis.tcp
	if not tcp or find_tcp_option(tcp.options, TCP_KIND_TS) then return end
	local seq, append_md5 = tcp_fallback(tonumber(tcp.th_seq), find_tcp_option(tcp.options, TCP_KIND_MD5)~=nil)
	if append_md5 then
		if not tcp.options then tcp.options = {} end
		table.insert(tcp.options, {kind=TCP_KIND_MD5, data=brandom(16)})
	end
	tcp.th_seq = seq
	DLOG("ts_or_md5: no tcp timestamp in this connection. fake gets md5 option and seq-10000 instead")
end

-- hostfakesplit с порядком частей altorder=1 из zapret1 (им пользуются ALT3 и ALT13 Flowseal): начало, поддельное имя, конец, настоящее имя.
-- Фильтр, собирающий сегменты подряд, получает целый запрос с чужим именем, а настоящее имя догоняет его вне очереди. В zapret2 такого
-- порядка нет. Это hostfakesplit из zapret-antidpi.lua (bol-van, MIT) с другим порядком отправки; то же сделали z2k и zapret2-next.
-- Использование: hostfakesplit_alt:host=mail.ru:tcp_ts=-600000:tcp_ts_up:fool=ts_or_md5:repeats=5
function hostfakesplit_alt(ctx, desync)
	if not desync.dis.tcp then
		if not desync.dis.icmp then instance_cutoff_shim(ctx, desync) end
		return
	end
	direction_cutoff_opposite(ctx, desync)
	local data = desync.reasm_data or desync.dis.payload
	if #data>0 and direction_check(desync) and payload_check(desync) then
		if replay_first(desync) then
			local pos = resolve_range(data, desync.l7payload, "host,endhost-1", true)
			if pos then
				-- как в hostfakesplit: настоящие части без порчи (кроме tcp_ts_up), порча и повторы - у поддельной, ip_id - у всех
				local orig = {rawsend = rawsend_opts_base(desync), reconstruct = {}, ipfrag = {}, ipid = desync.arg, fooling = {tcp_ts_up = desync.arg.tcp_ts_up}}
				local fake = {rawsend = rawsend_opts(desync), reconstruct = reconstruct_opts(desync), ipfrag = {}, ipid = desync.arg, fooling = desync.arg}
				local ranges = {host_split(#data, pos[1]-1, pos[2])}
				for index = 1, #ranges, 2 do
					local start, finish = ranges[index], ranges[index+1]
					local part, options
					if index==3 then -- вторая часть содержит поддельное имя
						part, options = genhost(finish-start, desync.arg.host), fake
					else
						part, options = string.sub(data, start+1, finish), orig
					end
					if not rawsend_payload_segmented(desync, part, start, options) then return VERDICT_PASS end
				end
				replay_drop_set(desync)
				return VERDICT_DROP
			end
			DLOG("hostfakesplit_alt: host range cannot be resolved")
		else
			DLOG("hostfakesplit_alt: not acting on further replay pieces")
		end
		-- продолжение сборки, которая уже отправлена по частям
		if replay_drop(desync) then return VERDICT_DROP end
	end
end

if zapret_native_modules and zapret_native_modules.fooling then
	local native_ts, native_split = zapret_native_modules.fooling(tcp_fallback, host_split)
	local lua_ts, lua_split = ts_or_md5, hostfakesplit_alt
	local running = coroutine.running
	ts_or_md5 = function(...)
		if running() then return lua_ts(...) end
		return native_ts(...)
	end
	hostfakesplit_alt = function(...)
		if running() then return lua_split(...) end
		return native_split(...)
	end
end
