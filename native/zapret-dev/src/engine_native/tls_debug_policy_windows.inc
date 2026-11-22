/* MIT. Check the live debug setting read by the Rust diagnostic entries. */
#include <stddef.h>

_Static_assert(sizeof(struct params_s) == 16896 && _Alignof(struct params_s) == 8 &&
    offsetof(struct params_s, debug) == 4252 && sizeof(params.debug) == 1,
    "Rust diagnostic debug setting ABI");

void TLSDebugHandshake(const uint8_t *data, size_t length);
void TLSDebug(const uint8_t *data, size_t length);
