/* MIT. VM operations happen after Rust has returned the converted address. */
size_t zapret_lua_ntop(const uint8_t *, size_t, char *, size_t);
size_t zapret_lua_pton(const char *, uint8_t *, size_t);

static int luacall_ntop(lua_State *vm)
{
    lua_check_argc(vm, "ntop", 1);
    size_t size;
    const char *bytes = lua_reqlstring(vm, 1, &size);
    char text[INET6_ADDRSTRLEN];
    size_t length = zapret_lua_ntop((const uint8_t *)bytes, size, text, sizeof(text));
    if (length) lua_pushlstring(vm, text, length);
    else lua_pushnil(vm);
    return 1;
}

static int luacall_pton(lua_State *vm)
{
    lua_check_argc(vm, "pton", 1);
    const char *text = lua_reqstring(vm, 1);
    uint8_t address[16];
    size_t length = zapret_lua_pton(text, address, sizeof(address));
    if (length) lua_pushlstring(vm, (const char *)address, length);
    else lua_pushnil(vm);
    return 1;
}
