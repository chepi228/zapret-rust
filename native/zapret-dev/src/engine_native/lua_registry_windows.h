/* MIT. Borrowed Rust catalog. The C caller owns every VM operation. */
#pragma once
typedef struct {
    const char *version;
    uint32_t mark;
    bool debug,daemon,server,cache_hostname,ctrack_disable;
} zapret_lua_registry_values;
typedef struct {const char *title;uint32_t before_log,after_log;}zapret_lua_registry_section;
typedef struct {const char *name,*text;uint32_t value;}zapret_lua_registry_value;
typedef struct {const char *name;uint32_t slot;}zapret_lua_registry_binding;
typedef struct {const char *name,*first,*second;uint32_t action;}zapret_lua_registry_mt;
uint32_t zapret_lua_registry_constant(uint32_t,size_t,const zapret_lua_registry_values *,zapret_lua_registry_value *);
uint32_t zapret_lua_registry_group(uint32_t,zapret_lua_registry_section *);
const char *zapret_lua_registry_entry_format(void);
uint32_t zapret_lua_registry_function(size_t,size_t,zapret_lua_registry_binding *);
uint32_t zapret_lua_registry_metatable(size_t,zapret_lua_registry_mt *);
_Static_assert(sizeof(zapret_lua_registry_values) == (sizeof(void *) == 4 ? 16 : 24) &&
    sizeof(zapret_lua_registry_section) == sizeof(void *) + 8 &&
    offsetof(zapret_lua_registry_values, debug) == sizeof(void *) + 4 &&
    offsetof(zapret_lua_registry_values, ctrack_disable) == sizeof(void *) + 8 &&
    sizeof(zapret_lua_registry_value) == 3 * sizeof(void *) &&
    sizeof(zapret_lua_registry_binding) == 2 * sizeof(void *) &&
    sizeof(zapret_lua_registry_mt) == 4 * sizeof(void *) &&
    offsetof(zapret_lua_registry_value, value) == 2 * sizeof(void *) &&
    offsetof(zapret_lua_registry_mt, action) == 3 * sizeof(void *),
    "Rust Lua registration ABI");
#ifndef ZAPRET_LUA_REGISTRY_VM
static void native_lua_registry_metatable(lua_State *L,size_t index,lua_CFunction finalizer)
{
    zapret_lua_registry_mt mt;
    if(zapret_lua_registry_metatable(index,&mt)!=1 || !mt.name || (mt.first && !finalizer)){
        luaL_error(L,"invalid Lua metatable catalog");return;
    }
    luaL_newmetatable(L,mt.name);
    if(mt.first){lua_pushcfunction(L,finalizer);lua_setfield(L,-2,mt.first);}
    if(mt.second){lua_pushcfunction(L,finalizer);lua_setfield(L,-2,mt.second);}
    lua_pop(L,1);
}
#endif
