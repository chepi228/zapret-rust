/* MIT. Rust chooses the next phase; C performs every VM operation. */
static bool native_lua_init_steps(void)
{
    LUA_STACK_GUARD_ENTER(params.L)
    uint32_t state=0;bool previous_ok=true;
    for(;;)switch(zapret_lua_startup_step(&state,previous_ok)){
        case 1:lua_sec_harden();break;
        case 2:lua_init_blobs();break;
        case 3:lua_init_const();break;
        case 4:lua_init_functions();break;
        case 5:lua_init_mt();break;
        case 6:zapret_lua_vm_publish(params.L,native_lua_install_interrupt);break;
        case 7:previous_ok=lua_init_scripts();break;
        case 8:previous_ok=lua_desync_functions_exist();break;
        case 9:
            LUA_STACK_GUARD_LEAVE(params.L,0)
            DLOG(zapret_lua_startup_text(LUA_STARTUP_DONE));return true;
        default:
            LUA_STACK_GUARD_LEAVE(params.L,0)
            lua_shutdown();return false;
    }
}
bool lua_init(void)
{
    DLOG(zapret_lua_startup_text(LUA_STARTUP_INIT));
    if(!lua_basic_init())return false;
    return native_lua_init_steps();
}
