/* MIT. Decode Lua tables before passing their fields to the Rust serializers. */
#include "packet_write_windows.h"

static bool read_packet_integer(lua_State *L, int idx, const char *name,
    bool required, lua_Integer *value)
{
    lua_getfield(L, idx, name);
    bool ok = !required || lua_type(L, -1) == LUA_TNUMBER;
    *value = lua_tointeger(L, -1);
    lua_pop(L, 1);
    return ok;
}

static bool read_packet_u32(lua_State *L, int idx, const char *name, uint32_t *value)
{
    lua_getfield(L, idx, name);
    const bool ok = lua_type(L, -1) == LUA_TNUMBER;
    if (ok) *value = (uint32_t)lua_tolint(L, -1);
    lua_pop(L, 1);
    return ok;
}

static bool read_packet_address(lua_State *L, int idx, const char *name,
    uint8_t *out, size_t width)
{
    lua_getfield(L, idx, name);
    size_t length;
    const char *data = lua_type(L, -1) == LUA_TSTRING ? lua_tolstring(L, -1, &length) : NULL;
    bool ok = data && length == width;
    if (ok) memcpy(out, data, width);
    lua_pop(L, 1);
    return ok;
}

bool lua_reconstruct_iphdr(lua_State *L, int idx, struct ip *ip, size_t *len)
{
    if (*len < sizeof(*ip) || lua_type(L, idx) != LUA_TTABLE) return false;
    LUA_STACK_GUARD_ENTER(L)
    idx = lua_absindex(L, idx);
    zapret_ipv4_fields fields;
    lua_Integer value;
    read_packet_integer(L, idx, "ip_tos", false, &value);
    fields.service = (uint8_t)value;
    read_packet_integer(L, idx, "ip_len", false, &value);
    fields.length = (uint16_t)value;
    read_packet_integer(L, idx, "ip_id", false, &value);
    fields.identification = (uint16_t)value;
    read_packet_integer(L, idx, "ip_off", false, &value);
    fields.fragment = (uint16_t)value;
    if (!read_packet_integer(L, idx, "ip_ttl", true, &value)) return false;
    fields.hop_limit = (uint8_t)value;
    if (!read_packet_integer(L, idx, "ip_p", true, &value)) return false;
    fields.protocol = (uint8_t)value;
    if (!read_packet_address(L, idx, "ip_src", fields.source, sizeof(fields.source)) ||
        !read_packet_address(L, idx, "ip_dst", fields.destination, sizeof(fields.destination))) return false;

    lua_getfield(L, idx, "options");
    size_t options_length = 0;
    const char *options = lua_type(L, -1) == LUA_TSTRING ? lua_tolstring(L, -1, &options_length) : NULL;
    size_t written = zapret_write_ipv4((uint8_t *)ip, *len, &fields, (const uint8_t *)options, options_length);
    lua_pop(L, 1);
    LUA_STACK_GUARD_LEAVE(L, 0)
    if (!written) return false;
    *len = written;
    return true;
}

bool lua_reconstruct_ip6hdr(lua_State *L, int idx, struct ip6_hdr *ip, size_t *len,
    uint8_t last_protocol, bool preserve_next)
{
    if (*len < sizeof(*ip) || lua_type(L, idx) != LUA_TTABLE) return false;
    LUA_STACK_GUARD_ENTER(L)
    idx = lua_absindex(L, idx);
    zapret_ipv6_fields fields = {0};
    lua_getfield(L, idx, "ip6_flow");
    fields.flow = lua_type(L, -1) == LUA_TNUMBER ? (uint32_t)lua_tolint(L, -1) : 0x60000000;
    lua_pop(L, 1);
    lua_Integer value;
    read_packet_integer(L, idx, "ip6_nxt", false, &value);
    fields.next = (uint8_t)value;
    read_packet_integer(L, idx, "ip6_hlim", false, &value);
    fields.hop_limit = (uint8_t)value;
    if (!read_packet_address(L, idx, "ip6_src", fields.source, sizeof(fields.source)) ||
        !read_packet_address(L, idx, "ip6_dst", fields.destination, sizeof(fields.destination))) return false;

    lua_getfield(L, idx, "ip6_plen");
    switch (lua_type(L, -1)) {
    case LUA_TNIL:
        break;
    case LUA_TNUMBER:
        fields.payload_length = (uint16_t)luaL_checkinteger(L, -1);
        fields.has_payload_length = 1;
        break;
    default:
        luaL_error(L, "reconstruct_ip6hdr: ip6_plen wrong type");
    }
    lua_pop(L, 1);

    uint8_t *output = (uint8_t *)ip;
    size_t filled = sizeof(*ip);
    size_t next_offset = offsetof(struct ip6_hdr, ip6_ctlun.ip6_un1.ip6_un1_nxt);
    zapret_write_ipv6(output, &fields);
    lua_getfield(L, idx, "exthdr");
    if (lua_type(L, -1) == LUA_TTABLE) {
        const int extensions = lua_gettop(L);
        for (lua_Integer item = 1; ; ++item) {
            lua_rawgeti(L, extensions, item);
            if (lua_isnil(L, -1)) {
                lua_pop(L, 1);
                break;
            }
            const int extension = lua_gettop(L);
            if (lua_type(L, extension) != LUA_TTABLE ||
                !read_packet_integer(L, extension, "type", true, &value)) goto err;
            const uint8_t kind = (uint8_t)value;
            lua_getfield(L, extension, "next");
            const uint8_t next = lua_type(L, -1) == LUA_TNUMBER ? (uint8_t)lua_tointeger(L, -1) : IPPROTO_NONE;
            lua_pop(L, 1);
            lua_getfield(L, extension, "data");
            if (lua_type(L, -1) != LUA_TSTRING) goto err;
            size_t data_length;
            const char *data = lua_tolstring(L, -1, &data_length);
            size_t written = zapret_write_ipv6_extension(output + filled, *len - filled,
                kind, next, (const uint8_t *)data, data_length);
            if (!written) goto err;
            if (!preserve_next) output[next_offset] = kind;
            next_offset = filled;
            filled += written;
            lua_pop(L, 2);
        }
    }
    lua_pop(L, 1);
    zapret_finish_ipv6(output, filled, &fields, next_offset, last_protocol, preserve_next);
    *len = filled;
    LUA_STACK_GUARD_LEAVE(L, 0)
    return true;
err:
    LUA_STACK_GUARD_UNWIND(L)
    return false;
}

bool lua_reconstruct_tcphdr(lua_State *L, int idx, struct tcphdr *tcp, size_t *len)
{
    if (*len < sizeof(*tcp) || lua_type(L, idx) != LUA_TTABLE) return false;
    LUA_STACK_GUARD_ENTER(L)
    idx = lua_absindex(L, idx);
    zapret_tcp_fields fields;
    lua_Integer value;
    if (!read_packet_integer(L, idx, "th_sport", true, &value)) return false;
    fields.source = (uint16_t)value;
    if (!read_packet_integer(L, idx, "th_dport", true, &value)) return false;
    fields.destination = (uint16_t)value;
    if (!read_packet_u32(L, idx, "th_seq", &fields.sequence) ||
        !read_packet_u32(L, idx, "th_ack", &fields.acknowledgement)) return false;
    read_packet_integer(L, idx, "th_x2", false, &value);
    fields.reserved = (uint8_t)value;
    if (!read_packet_integer(L, idx, "th_flags", true, &value)) return false;
    fields.flags = (uint8_t)value;
    if (!read_packet_integer(L, idx, "th_win", true, &value)) return false;
    fields.window = (uint16_t)value;
    read_packet_integer(L, idx, "th_sum", false, &value);
    fields.checksum = (uint16_t)value;
    read_packet_integer(L, idx, "th_urp", false, &value);
    fields.urgent = (uint16_t)value;

    size_t available = *len - sizeof(*tcp);
    if (available > 40) available = 40;
    uint8_t *output = (uint8_t *)tcp + sizeof(*tcp);
    size_t filled = 0;
    lua_getfield(L, idx, "options");
    if (lua_type(L, -1) == LUA_TTABLE) {
        const int options = lua_gettop(L);
        for (lua_Integer item = 1; ; ++item) {
            lua_rawgeti(L, options, item);
            if (lua_isnil(L, -1)) {
                lua_pop(L, 1);
                break;
            }
            const int option = lua_gettop(L);
            if (filled == available || lua_type(L, option) != LUA_TTABLE ||
                !read_packet_integer(L, option, "kind", true, &value)) goto err;
            const uint8_t kind = (uint8_t)value;
            const char *data = NULL;
            size_t data_length = 0;
            if (kind != TCP_KIND_END && kind != TCP_KIND_NOOP) {
                lua_getfield(L, option, "data");
                if (lua_type(L, -1) == LUA_TSTRING) data = lua_tolstring(L, -1, &data_length);
            }
            size_t written = zapret_write_tcp_option(output + filled, available - filled,
                kind, (const uint8_t *)data, data_length);
            if (kind != TCP_KIND_END && kind != TCP_KIND_NOOP) lua_pop(L, 1);
            if (!written) goto err;
            filled += written;
            lua_pop(L, 1);
        }
    }
    lua_pop(L, 1);
    const size_t written = zapret_write_tcp((uint8_t *)tcp, *len, &fields, filled);
    if (!written) return false;
    *len = written;
    LUA_STACK_GUARD_LEAVE(L, 0)
    return true;
err:
    LUA_STACK_GUARD_UNWIND(L)
    return false;
}

bool lua_reconstruct_udphdr(lua_State *L, int idx, struct udphdr *udp)
{
    if (lua_type(L, idx) != LUA_TTABLE) return false;
    LUA_STACK_GUARD_ENTER(L)
    idx = lua_absindex(L, idx);
    zapret_udp_fields fields;
    lua_Integer value;
    if (!read_packet_integer(L, idx, "uh_sport", true, &value)) return false;
    fields.source = (uint16_t)value;
    if (!read_packet_integer(L, idx, "uh_dport", true, &value)) return false;
    fields.destination = (uint16_t)value;
    read_packet_integer(L, idx, "uh_ulen", false, &value);
    fields.length = (uint16_t)value;
    read_packet_integer(L, idx, "uh_sum", false, &value);
    fields.checksum = (uint16_t)value;
    zapret_write_udp((uint8_t *)udp, &fields);
    LUA_STACK_GUARD_LEAVE(L, 0)
    return true;
}

bool lua_reconstruct_icmphdr(lua_State *L, int idx, struct icmp46 *icmp)
{
    if (lua_type(L, idx) != LUA_TTABLE) return false;
    LUA_STACK_GUARD_ENTER(L)
    idx = lua_absindex(L, idx);
    zapret_icmp_fields fields;
    lua_Integer value;
    if (!read_packet_integer(L, idx, "icmp_type", true, &value)) return false;
    fields.kind = (uint8_t)value;
    if (!read_packet_integer(L, idx, "icmp_code", true, &value)) return false;
    fields.code = (uint8_t)value;
    if (!read_packet_u32(L, idx, "icmp_data", &fields.data)) return false;
    read_packet_integer(L, idx, "icmp_cksum", false, &value);
    fields.checksum = (uint16_t)value;
    zapret_write_icmp((uint8_t *)icmp, &fields);
    LUA_STACK_GUARD_LEAVE(L, 0)
    return true;
}

#ifndef ZAPRET_LUA_PACKET_ASSEMBLY_RUST
static bool finish_packet(uint8_t *packet, size_t *length, size_t ip_length,
    uint8_t version, uint8_t transport, bool keepsum, bool badsum)
{
    zapret_packet_finish options = {
        .ip_length = ip_length,
        .version = version,
        .transport = transport,
        .keep_checksum = keepsum,
    };
    if (!keepsum && transport) {
        if (transport == IPPROTO_UDP && *length - ip_length > UINT16_MAX) {
            DLOG_ERR("reconstruct_dissect: invalid payload length\n");
            return false;
        }
        if (badsum) options.checksum_xor = 1 + (random() % 0xFFFF);
    }
    switch (zapret_finish_packet(packet, length, &options)) {
    case 0:
        return true;
    case ZAPRET_FINISH_UDP_LENGTH:
        DLOG_ERR("reconstruct_dissect: invalid payload length\n");
        break;
    case ZAPRET_FINISH_IPV4_FRAGMENT_LENGTH:
        DLOG_ERR("ipv4 frag : invalid ip_len\n");
        break;
    case ZAPRET_FINISH_IPV4_FRAGMENT_BOUNDS:
        DLOG_ERR("ipv4 frag : fragment end is outside of the packet\n");
        break;
    case ZAPRET_FINISH_IPV6_FRAGMENT_LENGTH:
        DLOG_ERR("ipv6 frag : invalid ip6_plen\n");
        break;
    case ZAPRET_FINISH_IPV6_FRAGMENT_BOUNDS:
        DLOG_ERR("ipv6 frag : fragmentable part is outside of the packet\n");
        break;
    default:
        DLOG_ERR("reconstruct_dissect: invalid packet layout\n");
        break;
    }
    return false;
}
#endif
