/* Rust entry points used by the pinned Cygwin engine. */
#ifndef ZAPRET_CYGWIN_ENGINE_ABI_H
#define ZAPRET_CYGWIN_ENGINE_ABI_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct lua_State;
void *zapret_cygwin_alloc_filter(size_t capacity);
bool zapret_cygwin_openlibs(struct lua_State **slot);
int zapret_cygwin_selftest(bool intercept);
bool zapret_cygwin_tls_resize_fits(size_t size, size_t capacity, uint16_t record, ptrdiff_t delta);
#endif
