#include "engine_prefix_abi.h"

static bool loop_activate(uint32_t *error)
{
    static const zapret_engine_activate_ops ops = {windivert_init, win_sandbox, DLOG_CONDUP, DLOG_ERR};
    if (!zapret_engine_activate_native(params.windivert_filter, &params.intercept, &w_win32_error, error, &ops))
        return false;

    uint32_t phase = 0;
    bool succeeded = false;
    while ((phase = zapret_engine_activate_next(phase, succeeded))) {
        switch (phase) {
        case 1: succeeded = params.L != NULL; break;
        case 2: succeeded = lua_init(); break;
        case 3: *error = ERROR_INVALID_PARAMETER; return false;
        case 4: do_fuzz(); break;
        case 5: return true;
        }
    }
    return false;
}
