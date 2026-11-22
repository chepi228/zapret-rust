/* MIT. Private handlers and VM ownership; no real console signal is sent. */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <windows.h>
#include <signal.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include "lua_lifetime_windows.h"
#include "lua_lifetime_windows.inc"
#include "console_shutdown_windows.h"

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL engine console line=%d: %s\n", __LINE__, #condition); ExitProcess(1); } \
} while (0)
static PHANDLER_ROUTINE console_handler;
static zapret_console_signal interrupt_handler, terminate_handler;
static unsigned mode, console_registrations, signal_registrations, registration_errors;
static _Atomic unsigned quit_calls, installed, closed;
static HANDLE watchdog_done, hook_entered, hook_release, detach_done;
static bool block_install, reenter;
static int token;

static BOOL WINAPI set_console(PHANDLER_ROUTINE handler, BOOL add)
{
    CHECK(add == TRUE);
    console_handler = handler;
    ++console_registrations;
    return mode != 1;
}
static uintptr_t set_signal(int event, zapret_console_signal handler)
{
    CHECK(event == SIGINT || event == SIGTERM);
    if (event == SIGINT) interrupt_handler = handler;
    else terminate_handler = handler;
    ++signal_registrations;
    return mode == 2 ? UINTPTR_MAX : 0;
}
static int registration_error(const char *format, ...)
{
    CHECK(!strcmp(format, "could not register every console shutdown handler\n"));
    CHECK(mode != 0);
    ++registration_errors;
    return 0;
}
static void quit(int event)
{
    CHECK(event == SIGINT || event == SIGTERM);
    atomic_fetch_add(&quit_calls, 1);
    lua_req_quit();
}
static DWORD WINAPI watchdog(void *unused)
{
    (void)unused;
    CHECK(WaitForSingleObject(watchdog_done, 5000) == WAIT_OBJECT_0);
    return 0;
}
static DWORD WINAPI console_request(void *unused)
{
    (void)unused;
    Sleep(20);
    CHECK(console_handler(CTRL_C_EVENT));
    return 0;
}
static DWORD WINAPI request(void *unused)
{
    (void)unused;
    zapret_lua_vm_request_quit();
    return 0;
}
static void guarded_install(void *vm)
{
    CHECK(vm == &token && !atomic_load(&closed));
    atomic_fetch_add(&installed, 1);
    if (reenter) zapret_lua_vm_request_quit();
    if (block_install) {
        CHECK(SetEvent(hook_entered));
        CHECK(WaitForSingleObject(hook_release, 3000) == WAIT_OBJECT_0);
    }
    CHECK(!atomic_load(&closed));
}
static DWORD WINAPI publish(void *unused)
{
    (void)unused;
    zapret_lua_vm_publish(&token, guarded_install);
    return 0;
}
static DWORD WINAPI detach(void *unused)
{
    (void)unused;
    CHECK(zapret_lua_vm_detach(&token));
    atomic_store(&closed, 1);
    CHECK(SetEvent(detach_done));
    return 0;
}
static void join(HANDLE thread)
{
    CHECK(thread && WaitForSingleObject(thread, 3000) == WAIT_OBJECT_0);
    CHECK(CloseHandle(thread));
}
int main(void)
{
    const zapret_engine_console_ops ops = {set_console, set_signal};
    CHECK(zapret_engine_console_register(quit, &ops, registration_error));
    _Atomic(sig_atomic_t) claimed = 0;
    for (unsigned index = 0; index < 2; ++index) {
        zapret_shutdown_message message;
        const char *expected = index ? "TERM received !\n" : "INT received !\n";
        CHECK(zapret_console_claim_shutdown(&claimed, index ? SIGTERM : SIGINT, &message));
        CHECK(message.length == strlen(expected) && !strcmp(message.text, expected));
        CHECK(atomic_load(&claimed) == 1);
        CHECK(!zapret_console_claim_shutdown(&claimed, SIGINT, NULL));
        atomic_store(&claimed, 0);
    }
    CHECK(console_handler && interrupt_handler && terminate_handler);
    lua_State *vm = luaL_newstate();
    CHECK(vm);
    luaL_openlibs(vm);
    zapret_lua_vm_publish(vm, native_lua_install_interrupt);
    CHECK(!luaL_dostring(vm, "return 6*7"));
    CHECK(lua_tointeger(vm, -1) == 42);
    lua_pop(vm, 1);
    watchdog_done = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(watchdog_done);
    HANDLE guard = CreateThread(NULL, 0, watchdog, NULL, 0, NULL);
    HANDLE stopper = CreateThread(NULL, 0, console_request, NULL, 0, NULL);
    CHECK(guard && stopper);
    CHECK(luaL_dostring(vm, "jit.off(); local n=0; while true do n=n+1 end"));
    CHECK(strstr(lua_tostring(vm, -1), "INTERRUPT"));
    CHECK(SetEvent(watchdog_done));
    join(stopper);
    join(guard);
    CHECK(CloseHandle(watchdog_done));
    CHECK(zapret_lua_vm_detach(vm));
    lua_close(vm);

    const DWORD events[] = {CTRL_C_EVENT, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT, 3, 4, 7, UINT32_MAX};
    for (unsigned index = 0; index < sizeof(events) / sizeof(*events); ++index)
        CHECK(console_handler(events[index]) == (index < 5));
    interrupt_handler(SIGINT);
    terminate_handler(SIGTERM);
    HANDLE threads[16];
    for (unsigned index = 0; index < 16; ++index) {
        threads[index] = CreateThread(NULL, 0, console_request, NULL, 0, NULL);
        CHECK(threads[index]);
    }
    for (unsigned index = 0; index < 16; ++index) join(threads[index]);
    CHECK(atomic_load(&quit_calls) == 24);
    for (mode = 1; mode <= 2; ++mode) CHECK(!zapret_engine_console_register(quit, &ops, registration_error));
    CHECK(console_registrations == 3 && signal_registrations == 6 && registration_errors == 2);

    hook_entered = CreateEventW(NULL, TRUE, FALSE, NULL);
    hook_release = CreateEventW(NULL, TRUE, FALSE, NULL);
    detach_done = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(hook_entered && hook_release && detach_done);
    block_install = true;
    HANDLE publisher = CreateThread(NULL, 0, publish, NULL, 0, NULL);
    CHECK(publisher && WaitForSingleObject(hook_entered, 3000) == WAIT_OBJECT_0);
    for (unsigned index = 0; index < 16; ++index) {
        threads[index] = CreateThread(NULL, 0, request, NULL, 0, NULL);
        CHECK(threads[index]);
    }
    for (unsigned index = 0; index < 16; ++index) join(threads[index]);
    HANDLE closer = CreateThread(NULL, 0, detach, NULL, 0, NULL);
    CHECK(closer && WaitForSingleObject(detach_done, 50) == WAIT_TIMEOUT);
    CHECK(SetEvent(hook_release));
    join(publisher);
    join(closer);
    CHECK(atomic_load(&closed) == 1 && atomic_load(&installed) == 1);
    CHECK(CloseHandle(hook_entered) && CloseHandle(hook_release) && CloseHandle(detach_done));
    block_install = false;
    reenter = true;
    for (unsigned round = 0; round < 64; ++round) {
        atomic_store(&closed, 0);
        zapret_lua_vm_publish(&token, guarded_install);
        CHECK(!zapret_lua_vm_detach(&mode));
        zapret_lua_vm_request_quit();
        CHECK(zapret_lua_vm_detach(&token));
        atomic_store(&closed, 1);
        zapret_lua_vm_request_quit();
    }
    CHECK(atomic_load(&installed) == 65);
    printf("PASS engine_console events=9 signals=2 registration_failures=2 threaded_events=16 one_shot_messages=2\n");
    printf("PASS lua_lifetime real_interrupts=1 guarded_closes=1 late_requests=64 deferred_publications=65 reentrant_requests=64\n");
    return 0;
}
