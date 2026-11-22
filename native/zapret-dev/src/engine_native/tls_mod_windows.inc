/* MIT. Keep upstream's public ABI and logger; all edits are owned by Rust. */
#include "runtime_log_windows.h"
extern bool zapret_tls_mod(const struct fake_tls_mod *, const uint8_t *, size_t,
    uint8_t *, size_t *, size_t, void (*)(const char *));
void zapret_tls_report_applied(const struct fake_tls_mod *, bool, zapret_log_sink);

static void tls_mod_report(const char *message)
{
    DLOG_ERR("%s", message);
}

bool TLSMod(const struct fake_tls_mod *options, const uint8_t *payload,
    size_t payload_length, uint8_t *fake, size_t *length, size_t capacity)
{
    bool applied = zapret_tls_mod(options, payload, payload_length, fake, length, capacity,
        tls_mod_report);
    zapret_tls_report_applied(options, applied, DLOG);
    return applied;
}
