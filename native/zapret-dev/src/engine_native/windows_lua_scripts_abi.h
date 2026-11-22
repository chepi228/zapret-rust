/* MIT. Pinned script-list fields and the Win64 LuaJIT script entry points. */
#pragma once

_Static_assert(LUA_GLOBALSINDEX == -10002 && LUA_MULTRET == -1 &&
    LUA_TFUNCTION == 6 && sizeof(struct str_list) == 24 &&
    offsetof(struct str_list, next.le_next) == 8 &&
    offsetof(struct desync_profile_list, dp) == 0 &&
    offsetof(struct desync_profile_list, next.le_next) == 184 &&
    offsetof(struct desync_profile, lua_desync) == 160 &&
    offsetof(struct func_list, next.le_next) == 64, "Rust Lua script ABI");

_Static_assert(sizeof(struct params_s) == 16896 &&
    offsetof(struct params_s, debug) == 4252 &&
    offsetof(struct params_s, desync_profiles.lh_first) == 4272 &&
    offsetof(struct params_s, lua_init_scripts.lh_first) == 12744 &&
    offsetof(struct params_s, L) == 16888 && sizeof(bQuit) == 4 &&
    _Alignof(_Atomic(sig_atomic_t)) == 4, "Rust Lua script sources");

bool lua_test_init_script_files(void);
bool lua_init_scripts(void);
bool lua_desync_functions_exist(void);
