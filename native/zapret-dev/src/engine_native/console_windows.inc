/* MIT. Emit the selected signal message and then notify Lua. */
#include "console_shutdown_windows.h"

static void native_console_quit(int event)
{
    zapret_shutdown_message message;
    if (!zapret_console_claim_shutdown(&bQuit, event, &message)) return;
    size_t written = write(1, message.text, message.length);
    (void)written;
    lua_req_quit();
}
static uintptr_t native_console_signal(int event, zapret_console_signal handler)
{
    return (uintptr_t)signal(event, handler);
}
static void catch_signals(void)
{
    static const zapret_engine_console_ops ops = {SetConsoleCtrlHandler, native_console_signal};
    zapret_engine_console_register(native_console_quit, &ops, DLOG_ERR);
}
