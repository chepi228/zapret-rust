/* MIT. Rust cursor ABI for the Windows option table. */
#include "runtime_log_windows.h"

typedef struct {
    char *argument;
    const char *diagnostic;
    size_t diagnostic_length;
    int index;
} zapret_cli_option;
_Static_assert(sizeof(struct option) == 32 && offsetof(struct option, has_arg) == 8 &&
    offsetof(struct option, flag) == 16 && offsetof(struct option, val) == 24 &&
    sizeof(zapret_cli_option) == 32, "Rust option table ABI");
_Static_assert(no_argument == 0 && required_argument == 1 && optional_argument == 2,
    "Rust option argument modes");

uint32_t zapret_cli_read(int, char **, const struct option *, size_t, size_t *, bool, zapret_cli_option *);
typedef struct {
    char **argument;
    int *index;
    zapret_log_sink stderr_sink; /* NULL uses UCRT stderr. */
} zapret_cli_output;
int zapret_cli_next(int, char **, const struct option *, size_t, size_t *, bool, const zapret_cli_output *);

