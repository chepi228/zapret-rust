/* MIT. Lua errors are raised by the VM after the Rust callback has returned. */
static void lua_interrupt_hook(lua_State *vm, lua_Debug *event)
{
    (void)event;
    lua_sethook(vm, NULL, 0, 0);
    luaL_error(vm, zapret_lua_vm_text(LUA_VM_INTERRUPT));
}
static void native_lua_install_interrupt(void *vm)
{
    lua_sethook((lua_State *)vm, lua_interrupt_hook,
        LUA_MASKCALL | LUA_MASKRET | LUA_MASKCOUNT | LUA_MASKLINE, 1);
}
void lua_req_quit(void)
{
    zapret_lua_vm_request_quit();
}
