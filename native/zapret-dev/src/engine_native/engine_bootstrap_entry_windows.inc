/* MIT. Retain the existing native network and capture callbacks. */
#include "windows_engine_bootstrap_abi.h"

bool native_boot_network(void)
{
    return win_dark_init(&params.ssid_filter, params.ssid_filter_neg,
        &params.nlm_filter, params.nlm_filter_neg);
}

int native_boot_capture(void)
{
    WINDIVERT_ADDRESS addresses[ZAPRET_CAPTURE_ADDRESS_COUNT];
    return zapret_capture_loop(&capture_ops, addresses, params.intercept);
}
