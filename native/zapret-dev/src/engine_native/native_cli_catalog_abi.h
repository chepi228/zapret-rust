/* MIT. Rust owns option names/arity/kinds; C supplies native storage. */
#pragma once
#include <getopt.h>
size_t zapret_native_cli_count(void);
const struct option *zapret_native_cli_options(void);
const char *zapret_native_cli_option_name(int32_t);
int32_t zapret_native_cli_kind(int32_t,uint32_t);
bool zapret_native_cli_skip_numeric(int32_t);
size_t zapret_native_cli_capacity(int32_t);
