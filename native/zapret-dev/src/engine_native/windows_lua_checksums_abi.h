/* MIT. LuaJIT registration uses the Rust checksum entries. */
#pragma once

int luacall_csum_ip4_fix(lua_State *);
int luacall_csum_tcp_fix(lua_State *);
int luacall_csum_udp_fix(lua_State *);
int luacall_csum_icmp_fix(lua_State *);
int luacall_tls_mod(lua_State *);
