/* MIT. Non-network timer dispatch fixture with C-owned VM/longjmp observations. */
#pragma once
#include "timer_windows.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
typedef struct{void *L;} timer_lifecycle_fixture_params;
extern timer_lifecycle_fixture_params timer_lifecycle_params;
void timer_fixture_registry(void *,int,int);
const char *timer_fixture_string(void *,int);
int timer_fixture_call(void *,int,int,int);
void timer_fixture_pop(void *,int);
void timer_fixture_unref(void *,int,int);
void timer_fixture_log(const char *,...);
void timer_fixture_error(void);
uint64_t timer_fixture_now(void);
int timer_fixture_after(const timer_pool *,uint64_t,zapret_timer_info *);
int timer_fixture_remove(timer_pool **,uint64_t,zapret_timer_info *);
int timer_fixture_due(timer_pool *,uint64_t,uint64_t,zapret_timer_info *);
int timer_fixture_finish(timer_pool **,uint64_t,uint64_t,int,zapret_timer_info *);
uint64_t timer_fixture_next(const timer_pool *);
#ifndef TIMER_LIFECYCLE_ORACLE
#define params timer_lifecycle_params
#define LUA_REGISTRYINDEX (-10000)
#define lua_rawgeti timer_fixture_registry
#define lua_tostring timer_fixture_string
#define lua_pcall timer_fixture_call
#define lua_pop timer_fixture_pop
#define luaL_unref timer_fixture_unref
#define lua_dlog_error timer_fixture_error
#define DLOG timer_fixture_log
#define boottime_ms timer_fixture_now
#define zapret_timer_after timer_fixture_after
#define zapret_timer_remove timer_fixture_remove
#define zapret_timer_due timer_fixture_due
#define zapret_timer_finish timer_fixture_finish
#define zapret_timer_next timer_fixture_next
#endif
