/* MIT. Borrowed packet invocation metadata; the caller owns the VM and buffers. */
#pragma once
typedef struct {
    const struct desync_profile *profile;const struct dissect *packet;
    const t_ctrack_position *current,*opposite;const char *interface_in,*interface_out;
    const uint8_t *target4,*target6,*reassembly,*decryption;
    size_t reassembly_length,decryption_length,reassembly_offset;
    uint32_t mark,piece,pieces,payload,protocol;uint16_t port;bool incoming;
}zapret_lua_packet_argument_input;
typedef struct {const char *name;const uint8_t *data;size_t length;int64_t number;uint32_t kind;}zapret_lua_packet_argument;
uint32_t zapret_lua_packet_argument_next(uint32_t *,const zapret_lua_packet_argument_input *,zapret_lua_packet_argument *);
_Static_assert(sizeof(zapret_lua_packet_argument_input)==128 && sizeof(zapret_lua_packet_argument)==40 &&
    offsetof(zapret_lua_packet_argument_input,mark)==104 && offsetof(zapret_lua_packet_argument_input,incoming)==126 &&
    offsetof(zapret_lua_packet_argument,kind)==32 && offsetof(struct desync_profile,name)==8 &&
    offsetof(struct desync_profile,cookie)==16 && offsetof(t_ctrack_position,mss)==50 &&
    offsetof(struct dissect,tcp)==48,"Rust Lua packet argument ABI");
