/* MIT. Marshal borrowed Rust wire values into Lua tables with C VM boundaries. */
typedef struct {
    const uint8_t *data;
    size_t length, offset;
    uint8_t next, kind;
    bool stopped;
} zapret_lua_packet_cursor;
typedef struct {
    uint32_t values[10];
    const uint8_t *source, *destination;
    zapret_lua_packet_cursor cursor;
    uint8_t count, address_width, table_capacity;
} zapret_lua_packet_header_values;
typedef struct { const uint8_t *data; size_t length; uint8_t kind, next; bool has_data; } zapret_lua_packet_item;
bool zapret_lua_packet_header(uint8_t, const uint8_t *, size_t, zapret_lua_packet_header_values *);
uint32_t zapret_lua_packet_item_next(zapret_lua_packet_cursor *, zapret_lua_packet_item *);
_Static_assert(sizeof(zapret_lua_packet_cursor)==32 && sizeof(zapret_lua_packet_header_values)==96 && sizeof(zapret_lua_packet_item)==24, "Rust Lua packet dissection ABI");

static void native_lua_push_packet_items(lua_State *L, const char *field, zapret_lua_packet_cursor *cursor)
{
    LUA_STACK_GUARD_ENTER(L)
    lua_pushstring(L, field);
    lua_newtable(L);
    lua_Integer index=1;
    zapret_lua_packet_item item;
    uint32_t status;
    while ((status=zapret_lua_packet_item_next(cursor, &item))==1) {
        lua_pushinteger(L, index++);
        lua_createtable(L, 0, cursor->kind==0?2:3);
        lua_pushf_int(L, cursor->kind==0?"kind":"type", item.kind);
        if (cursor->kind==1) lua_pushf_int(L, "next", item.next);
        if (item.has_data) lua_pushf_raw(L, "data", item.data, item.length);
        lua_rawset(L, -3);
    }
    if (status==2) luaL_error(L, "invalid packet iterator state");
    lua_rawset(L, -3);
    LUA_STACK_GUARD_LEAVE(L, 0)
}
void lua_pushf_tcphdr_options(lua_State *L, const struct tcphdr *tcp, size_t length)
{
    zapret_lua_packet_header_values header;
    zapret_lua_packet_cursor empty={0};
    bool present=zapret_lua_packet_header(0, (const uint8_t *)tcp, length, &header);
    native_lua_push_packet_items(L, "options", present?&header.cursor:&empty);
}
void lua_pushf_ip6exthdr(lua_State *L, const struct ip6_hdr *ip6, size_t length)
{
    zapret_lua_packet_header_values header;
    zapret_lua_packet_cursor empty={.kind=1};
    bool present=zapret_lua_packet_header(4, (const uint8_t *)ip6, length, &header);
    native_lua_push_packet_items(L, "exthdr", present?&header.cursor:&empty);
}
static void native_lua_push_packet_header(lua_State *L, uint8_t kind, const uint8_t *data, size_t length)
{
    static const char *fields[][10]={
        {"th_sport","th_dport","th_seq","th_ack","th_x2","th_off","th_flags","th_win","th_sum","th_urp"},
        {"uh_sport","uh_dport","uh_ulen","uh_sum"},
        {"icmp_type","icmp_code","icmp_cksum","icmp_data"},
        {"ip_v","ip_hl","ip_tos","ip_len","ip_id","ip_off","ip_ttl","ip_p","ip_sum"},
        {"ip6_flow","ip6_plen","ip6_nxt","ip6_hlim"},
    };
    LUA_STACK_GUARD_ENTER(L)
    zapret_lua_packet_header_values header;
    if (!zapret_lua_packet_header(kind, data, length, &header)) lua_pushnil(L);
    else {
        lua_createtable(L, 0, header.table_capacity);
        for (uint8_t index=0; index<header.count; ++index) lua_pushf_lint(L, fields[kind][index], header.values[index]);
        if (header.address_width) {
            lua_pushf_raw(L, kind==3?"ip_src":"ip6_src", header.source, header.address_width);
            lua_pushf_raw(L, kind==3?"ip_dst":"ip6_dst", header.destination, header.address_width);
        }
        if (kind==0) native_lua_push_packet_items(L, "options", &header.cursor);
        else if (kind==4) native_lua_push_packet_items(L, "exthdr", &header.cursor);
        else if (kind==3 && header.cursor.data) lua_pushf_raw(L, "options", header.cursor.data, header.cursor.length);
    }
    LUA_STACK_GUARD_LEAVE(L, 1)
}
void lua_push_tcphdr(lua_State *L, const struct tcphdr *tcp, size_t length)
{ native_lua_push_packet_header(L, 0, (const uint8_t *)tcp, length); }
void lua_push_udphdr(lua_State *L, const struct udphdr *udp, size_t length)
{ native_lua_push_packet_header(L, 1, (const uint8_t *)udp, length); }
void lua_push_icmphdr(lua_State *L, const struct icmp46 *icmp, size_t length)
{ native_lua_push_packet_header(L, 2, (const uint8_t *)icmp, length); }
void lua_push_iphdr(lua_State *L, const struct ip *ip, size_t length)
{ native_lua_push_packet_header(L, 3, (const uint8_t *)ip, length); }
void lua_push_ip6hdr(lua_State *L, const struct ip6_hdr *ip6, size_t length)
{ native_lua_push_packet_header(L, 4, (const uint8_t *)ip6, length); }
