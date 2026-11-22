/* MIT. Detachment waits for a pending hook installation before Lua is freed. */
#pragma once
enum {
    LUA_VM_SHUTDOWN, LUA_VM_INIT_ERROR, LUA_VM_LOADED, LUA_VM_JIT,
    LUA_VM_JIT_STATUS, LUA_VM_JIT_ARGUMENT, LUA_VM_JIT_END, LUA_VM_GC,
    LUA_VM_INTERRUPT,
};
const char *zapret_lua_vm_text(unsigned int);
const char *zapret_lua_vm_jit_status(bool);
void zapret_lua_vm_publish(void *, void (*)(void *));
bool zapret_lua_vm_detach(void *);
void zapret_lua_vm_request_quit(void);
static void native_lua_install_interrupt(void *);
