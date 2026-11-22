/* MIT. Windows file services used by the Rust Lua file entries. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <lua.h>
#include <lauxlib.h>
#include "gzip.h"

typedef struct {
    FILE *(*open)(const char *, const char *);
    int (*close)(FILE *);
    bool (*probe)(FILE *);
    void *(*allocate)(size_t);
    void (*release)(void *);
    int (*read)(FILE *, char **, size_t *, size_t);
} zapret_lua_file_ops;

typedef struct {
    zapret_lua_file_ops io;
    int (*load_file)(lua_State *, const char *);
    int (*load_buffer)(lua_State *, const char *, size_t, const char *);
} zapret_lua_file_vm_ops;

_Static_assert(PATH_MAX == 4096 && LUA_ERRFILE == 6 && LUA_MULTRET == -1 &&
    sizeof(zapret_lua_file_ops) == 6 * sizeof(void *) &&
    sizeof(zapret_lua_file_vm_ops) == 8 * sizeof(void *) &&
    offsetof(zapret_lua_file_vm_ops, load_file) == 6 * sizeof(void *) &&
    offsetof(zapret_lua_file_vm_ops, load_buffer) == 7 * sizeof(void *), "Rust Lua file VM ABI");

const zapret_lua_file_vm_ops zapret_lua_file_vm_native_ops = {
    {fopen, fclose, is_gzip, malloc, free, z_readfile}, luaL_loadfile, luaL_loadbuffer
};

bool lua_file_open_test(const char *filename, bool *gzip, char *resolved);
int luaL_doZfile(lua_State *lua, const char *filename);
