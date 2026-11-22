/* MIT. VM lookups and errors run in C between resource-free Rust transitions. */
typedef struct {
    uint8_t *buffer;
    size_t capacity, used, network, problem;
    uint8_t *output;
    size_t available;
    uint32_t phase, error;
    uint8_t version, transport, last_protocol;
    bool fragmented, keep_sum, bad_sum, preserve_next, serialize;
} zapret_lua_packet_state;
typedef struct { const uint8_t *data; size_t length; bool present, success; } zapret_lua_packet_observation;
typedef struct { uint32_t next; uint8_t protocol; bool done; } zapret_lua_packet_probe;
bool zapret_lua_packet_begin(uint8_t *, size_t, uint8_t, uint8_t, zapret_lua_packet_state *);
bool zapret_lua_packet_observe(zapret_lua_packet_state *, const zapret_lua_packet_observation *);
bool zapret_lua_packet_probe_protocol(uint8_t);
zapret_lua_packet_probe zapret_lua_packet_protocol_step(uint32_t, bool);
const char *zapret_lua_protocol_label(uint32_t);
const char *zapret_lua_assembly_label(uint32_t);
const char *zapret_lua_assembly_error_format(uint32_t);
_Static_assert(sizeof(zapret_lua_packet_state)==72 && sizeof(zapret_lua_packet_observation)==24 &&
    sizeof(zapret_lua_packet_probe)==8 && IPPROTO_NONE==59, "Rust Lua packet assembly ABI");

uint8_t lua_ip6_l4proto_from_dissect(lua_State *L, int idx)
{
    uint32_t step=0;
    for (;;) {
        lua_getfield(L, idx, zapret_lua_protocol_label(step));
        bool present=lua_type(L, -1)==LUA_TTABLE;
        lua_pop(L, 1);
        zapret_lua_packet_probe probe=zapret_lua_packet_protocol_step(step, present);
        if (probe.done) return probe.protocol;
        step=probe.next;
    }
}
static void native_lua_packet_error(const zapret_lua_packet_state *state)
{
    const char *format = zapret_lua_assembly_error_format(state->error);
    if (!format) return;
    switch (state->error) {
        case 8: DLOG_ERR(format, state->problem); break;
        case 9: DLOG_ERR(format, state->problem, state->available); break;
        default: DLOG_ERR(format); break;
    }
}
bool lua_reconstruct_dissect(lua_State *L, int idx, uint8_t *buffer, size_t *length,
    bool keep, bool bad, uint8_t last_protocol, bool preserve_next)
{
    LUA_STACK_GUARD_ENTER(L)
    idx=lua_absindex(L, idx);
    lua_getfield(L, idx, zapret_lua_assembly_label(0));
    bool fragmented=lua_type(L, -1)!=LUA_TNIL;
    if (fragmented) luaL_checkinteger(L, -1);
    lua_pop(L, 1);
    zapret_lua_packet_state state;
    uint8_t flags=(keep?1:0)|(bad?2:0)|(preserve_next?4:0)|(fragmented?8:0);
    if (!zapret_lua_packet_begin(buffer, *length, flags, last_protocol, &state)) goto err;
    for (;;) {
        zapret_lua_packet_observation observation={0};
        if (state.phase==12) { *length=state.used; LUA_STACK_GUARD_LEAVE(L, 0) return true; }
        if (state.phase==13) { native_lua_packet_error(&state); goto err; }
        if (state.phase==11) {
            lua_getfield(L, idx, zapret_lua_assembly_label(state.phase));
            observation.data=(const uint8_t *)lua_tolstring(L, -1, &observation.length);
            if (!zapret_lua_packet_observe(&state, &observation)) { lua_pop(L, 1); goto err; }
            lua_pop(L, 1);
            continue;
        }
        const char *field = zapret_lua_assembly_label(state.phase);
        if (!field || !state.phase) goto err;
        lua_getfield(L, idx, field);
        observation.present=lua_type(L, -1)==LUA_TTABLE;
        size_t written=state.available;
        if (observation.present && state.serialize) {
            switch (state.phase) {
                case 2: observation.success=lua_reconstruct_iphdr(L, -1, (struct ip *)state.output, &written); break;
                case 4: observation.success=lua_reconstruct_ip6hdr(L, -1, (struct ip6_hdr *)state.output, &written,
                    zapret_lua_packet_probe_protocol(state.last_protocol)?lua_ip6_l4proto_from_dissect(L, idx):state.last_protocol, state.preserve_next); break;
                case 6: observation.success=lua_reconstruct_tcphdr(L, -1, (struct tcphdr *)state.output, &written); break;
                case 8: written=sizeof(struct udphdr); observation.success=lua_reconstruct_udphdr(L, -1, (struct udphdr *)state.output); break;
                case 10: written=sizeof(struct icmp46); observation.success=lua_reconstruct_icmphdr(L, -1, (struct icmp46 *)state.output); break;
                default: goto err;
            }
        }
        observation.length=written;
        lua_pop(L, 1);
        if (!zapret_lua_packet_observe(&state, &observation)) goto err;
    }
err:
    LUA_STACK_GUARD_UNWIND(L)
    return false;
}
