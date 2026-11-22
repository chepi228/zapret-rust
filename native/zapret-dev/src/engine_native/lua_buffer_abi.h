/* MIT. Rust buffer policy shared by the VM comparison fixtures. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {const uint8_t *data;size_t length;}zapret_lua_buffer_span;
typedef struct {zapret_lua_buffer_span first,second;uint8_t *output;size_t length;uint32_t mode,phase;}zapret_lua_buffer_state;
typedef struct {const uint8_t *data;size_t length;const char *name;uint32_t kind;int32_t index;uint32_t argc,error;}zapret_lua_buffer_action;
typedef struct {zapret_lua_buffer_span span;int64_t integer;}zapret_lua_buffer_value;
typedef struct {bool (*run)(uint32_t,const uint8_t *,size_t,const uint8_t *,size_t,uint8_t *,size_t *);}zapret_lua_buffer_ops;
bool zapret_lua_buffer_begin(uint32_t,zapret_lua_buffer_state *,zapret_lua_buffer_action *);
bool zapret_lua_buffer_step(zapret_lua_buffer_state *,const zapret_lua_buffer_value *,zapret_lua_buffer_action *,const zapret_lua_buffer_ops *);

_Static_assert(sizeof(zapret_lua_buffer_state) == 6 * sizeof(void *) + 8 &&
    offsetof(zapret_lua_buffer_state, mode) == 6 * sizeof(void *) &&
    sizeof(zapret_lua_buffer_action) == 3 * sizeof(void *) + 16 &&
    sizeof(zapret_lua_buffer_value) == 2 * sizeof(void *) + 8 &&
    sizeof(zapret_lua_buffer_ops) == sizeof(void *), "Rust Lua buffer ABI");
