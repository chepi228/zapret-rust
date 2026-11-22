/* Read params.L afresh for each operation of the global error reporter. */
#include "lua_aux_abi.h"

static void lua_report_error(lua_State *L, bool global, bool fatal)
{
    const char *message = NULL;
    bool string_like = false;
    uint32_t action = 0;
    while ((action = zapret_lua_error_report_next(action, string_like, fatal))) {
        switch (action) {
        case 1: string_like = lua_isstring(global ? params.L : L, -1); break;
        case 2: message = lua_tostring(global ? params.L : L, -1); break;
        case 3: DLOG_ERR(zapret_lua_error_report_format(action), message); break;
        case 4: lua_pop(global ? params.L : L, 1); break;
        case 5: DLOG_ERR(zapret_lua_error_report_format(action)); break;
        case 6: exit(100); return;
        }
    }
}

static void lua_perror(lua_State *L) { lua_report_error(L, false, false); }
static int lua_panic(lua_State *L) { lua_report_error(L, false, true); return 0; }
void lua_dlog_error(void) { lua_report_error(NULL, true, false); }
