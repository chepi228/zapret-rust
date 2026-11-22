/* MIT. Rust's local Lua option entries use the engine's owned list records. */
#pragma once
#include <stddef.h>
#include "pools.h"

_Static_assert(sizeof(struct str2_list) == 4 * sizeof(void *) && offsetof(struct str2_list, str1) == 0 &&
    offsetof(struct str2_list, str2) == sizeof(void *) &&
    offsetof(struct str2_list, next) == 2 * sizeof(void *),
    "Rust Lua argument list record");
_Static_assert(sizeof(struct func_list) == (sizeof(void *) == 4 ? 72 : 80) &&
    _Alignof(struct func_list) == 8 && offsetof(struct func_list, args) == 56 &&
    offsetof(struct func_list, next) == 56 + sizeof(void *) &&
    sizeof(struct func_list_head) == sizeof(void *) && offsetof(struct func_list_head, lh_first) == 0 &&
    sizeof(struct str2_list_head) == sizeof(void *) &&
    offsetof(struct str2_list_head, lh_first) == 0, "Rust Lua command lists");

bool lua_call_param_add(char *text, struct str2_list_head *args);
struct func_list *parse_lua_call(char *text, struct func_list_head *head);
