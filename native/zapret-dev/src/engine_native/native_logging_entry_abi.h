/* MIT. C owns va_list, FILE, errno and native operations; Rust selects phases. */
#pragma once
#include "runtime_log_windows.h"
typedef struct { uint32_t phase; int32_t result; } zapret_log_entry;
uint32_t zapret_log_entry_step(zapret_log_entry *,bool,int32_t);
uint32_t zapret_log_append_step(zapret_log_entry *,bool,int32_t);
bool zapret_log_console_error(int32_t);
int zapret_log_perror(const char *,const char *,zapret_log_sink);
bool zapret_log_path_enabled(const char *);
bool zapret_log_timestamp(const int32_t *,uint8_t *,size_t);
void zapret_system_syslog(int32_t,const char *);
_Static_assert(sizeof(zapret_log_entry)==8,"Rust logging entry ABI");
