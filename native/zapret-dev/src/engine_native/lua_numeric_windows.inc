/* MIT. VM argument access and errors stay entirely outside Rust frames. */
uint32_t zapret_lua_number(uint32_t, uint32_t, const int64_t *, size_t, uint64_t *);
bool zapret_lua_read_number(const uint8_t *, size_t, int64_t, uint32_t, uint64_t *);
bool zapret_lua_write_number(int64_t, uint32_t, uint8_t *);

static inline __attribute__((always_inline)) int native_lua_number(lua_State *L, const char *name, uint32_t operation,
    uint32_t width, int minimum, int maximum)
{
    if (minimum == maximum) lua_check_argc(L, name, minimum);
    else lua_check_argc_range(L, name, minimum, maximum);
    int count = lua_gettop(L);
    int64_t values[maximum];
    for (int index = 0; index < count; ++index) values[index] = (int64_t)luaL_checklint(L, index + 1);
    uint64_t value;
    uint32_t status = zapret_lua_number(operation, width, values, (size_t)count, &value);
    if (status == 3) lua_pushnil(L);
    else if (status) return luaL_error(L, status == 2 ? "bit range invalid" : "out of range");
    else lua_pushlint(L, (int64_t)value);
    return 1;
}
#define NATIVE_NUMBER(name, operation, width, minimum, maximum) \
    static int luacall_##name(lua_State *L) { return native_lua_number(L, #name, operation, width, minimum, maximum); }
NATIVE_NUMBER(bitlshift, 0, 48, 2, 2)
NATIVE_NUMBER(bitrshift, 1, 48, 2, 2)
NATIVE_NUMBER(bitand, 2, 48, 2, 100)
NATIVE_NUMBER(bitor, 3, 48, 1, 100)
NATIVE_NUMBER(bitxor, 4, 48, 1, 100)
NATIVE_NUMBER(bitnot8, 5, 8, 1, 1)
NATIVE_NUMBER(bitnot16, 5, 16, 1, 1)
NATIVE_NUMBER(bitnot24, 5, 24, 1, 1)
NATIVE_NUMBER(bitnot32, 5, 32, 1, 1)
NATIVE_NUMBER(bitnot48, 5, 48, 1, 1)
NATIVE_NUMBER(bitget, 6, 48, 3, 3)
NATIVE_NUMBER(bitset, 7, 48, 4, 4)
NATIVE_NUMBER(swap16, 8, 16, 1, 1)
NATIVE_NUMBER(swap24, 8, 24, 1, 1)
NATIVE_NUMBER(swap32, 8, 32, 1, 1)
NATIVE_NUMBER(swap48, 8, 48, 1, 1)
NATIVE_NUMBER(u8add, 9, 8, 1, 100)
NATIVE_NUMBER(u16add, 9, 16, 1, 100)
NATIVE_NUMBER(u24add, 9, 24, 1, 100)
NATIVE_NUMBER(u32add, 9, 32, 1, 100)
NATIVE_NUMBER(u48add, 9, 48, 1, 100)
NATIVE_NUMBER(divint, 10, 48, 2, 2)
#undef NATIVE_NUMBER

static int native_lua_read(lua_State *L, const char *name, uint32_t width)
{
    lua_check_argc_range(L, name, 1, 2);
    size_t length;
    const uint8_t *data = (const uint8_t *)lua_reqlstring(L, 1, &length);
    int64_t offset = lua_gettop(L) == 2 && lua_type(L, 2) != LUA_TNIL ? (int64_t)luaL_checkinteger(L, 2) : 1;
    uint64_t value;
    if (!zapret_lua_read_number(data, length, offset, width, &value)) return luaL_error(L, "out of range");
    lua_pushlint(L, (int64_t)value);
    return 1;
}
static int native_lua_write(lua_State *L, const char *name, uint32_t width)
{
    lua_check_argc(L, name, 1);
    int64_t value = (int64_t)luaL_checklint(L, 1);
    uint8_t bytes[6];
    if (!zapret_lua_write_number(value, width, bytes)) return luaL_error(L, "out of range");
    lua_pushlstring(L, (const char *)bytes, width / 8);
    return 1;
}
#define NATIVE_BINARY(width) \
    static int luacall_u##width(lua_State *L) { return native_lua_read(L, "u" #width, width); } \
    static int luacall_bu##width(lua_State *L) { return native_lua_write(L, "bu" #width, width); }
NATIVE_BINARY(8)
NATIVE_BINARY(16)
NATIVE_BINARY(24)
NATIVE_BINARY(32)
NATIVE_BINARY(48)
#undef NATIVE_BINARY
