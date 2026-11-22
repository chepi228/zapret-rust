/* Native variadic log sink passed to Rust reporters. */
#pragma once
typedef int (*zapret_log_sink)(const char *, ...);
