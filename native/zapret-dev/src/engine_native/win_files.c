/* MIT. The native file facade is implemented in zapret-wincompat. */
#ifndef WIN_FILES_IMPLEMENTATION
#define WIN_FILES_IMPLEMENTATION
#endif
#include "win_files.h"

_Static_assert(sizeof(wf_file_info) == 48 && offsetof(wf_file_info, modified) == 32 &&
    offsetof(struct timespec, tv_nsec) == 8 && sizeof(((struct timespec *)0)->tv_nsec) == 4,
    "Rust file info ABI");
