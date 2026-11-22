/* MIT. Lua argument checks and longjmp-capable operations stay in C. */
size_t zapret_lua_hash(uint32_t, const uint8_t *, size_t, uint8_t *, size_t);
bool zapret_lua_hkdf(uint32_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, size_t);

static unsigned native_lua_hash_bits(lua_State *vm, const char *name)
{
    if (!strcmp(name, "sha256")) return 256;
    if (!strcmp(name, "sha224")) return 224;
    luaL_error(vm, "unsupported hash type %s", name);
    return 0;
}
static int luacall_hash(lua_State *vm)
{
    lua_check_argc(vm, "hash", 2);
    unsigned bits = native_lua_hash_bits(vm, luaL_checkstring(vm, 1));
    size_t length;
    const uint8_t *data = (const uint8_t *)lua_reqlstring(vm, 2, &length);
    uint8_t digest[32];
    size_t size = zapret_lua_hash(bits, data, length, digest, sizeof(digest));
    if (!size) return luaL_error(vm, "hash failure");
    lua_pushlstring(vm, (const char *)digest, size);
    return 1;
}
static int luacall_hkdf(lua_State *vm)
{
    lua_check_argc(vm, "hkdf", 5);
    unsigned bits = native_lua_hash_bits(vm, luaL_checkstring(vm, 1));
    size_t salt_length = 0, key_length = 0, info_length = 0;
    const uint8_t *salt = lua_isnil(vm, 2) ? NULL : (const uint8_t *)luaL_checklstring(vm, 2, &salt_length);
    const uint8_t *key = lua_isnil(vm, 3) ? NULL : (const uint8_t *)luaL_checklstring(vm, 3, &key_length);
    const uint8_t *info = lua_isnil(vm, 4) ? NULL : (const uint8_t *)luaL_checklstring(vm, 4, &info_length);
    lua_Integer length = luaL_checkinteger(vm, 5);
    if (length < 0) return luaL_error(vm, "hkdf: invalid arg");
    if (!length || length > 255 * (bits / 8)) {
        lua_pushnil(vm);
        return 1;
    }
    uint8_t *output = lua_newuserdata(vm, (size_t)length);
    if (zapret_lua_hkdf(bits, salt, salt_length, key, key_length, info, info_length, output, (size_t)length))
        lua_pushlstring(vm, (const char *)output, (size_t)length);
    else lua_pushnil(vm);
    lua_remove(vm, -2);
    return 1;
}
