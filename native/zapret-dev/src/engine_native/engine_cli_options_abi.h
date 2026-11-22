/* Layout for startup and scalar CLI bindings in the Rust engine entry. */
#pragma once

#include "windows_startup_params_abi.h"
#include "engine_profile_exports_abi.h"

_Static_assert(PATH_MAX == 4096 &&
    LOG_TARGET_CONSOLE == 0 && LOG_TARGET_FILE == 1 && LOG_TARGET_SYSLOG == 2 &&
    LOG_PID == 1 && LOG_USER == 8, "Rust CLI record ABI");

#define CLI_PROFILE_FIELD(field, win32, win64, bytes) \
    _Static_assert(offsetof(struct desync_profile, field) == (sizeof(void *) == 4 ? (win32) : (win64)) && \
        sizeof(((struct desync_profile *)0)->field) == (bytes), "Rust CLI field " #field)

CLI_PROFILE_FIELD(hostlist_auto_fail_threshold, 60, 112, 4);
CLI_PROFILE_FIELD(hostlist_auto_fail_time, 64, 116, 4);
CLI_PROFILE_FIELD(hostlist_auto_retrans_threshold, 68, 120, 4);
CLI_PROFILE_FIELD(hostlist_auto_udp_in, 72, 124, 4);
CLI_PROFILE_FIELD(hostlist_auto_udp_out, 76, 128, 4);
CLI_PROFILE_FIELD(hostlist_auto_retrans_maxseq, 80, 132, 4);
CLI_PROFILE_FIELD(hostlist_auto_incoming_maxseq, 84, 136, 4);
CLI_PROFILE_FIELD(hostlist_auto_retrans_reset, 88, 140, 1);
CLI_PROFILE_FIELD(b_hostlist_auto_fail_threshold, 108, 168, 1);
CLI_PROFILE_FIELD(b_hostlist_auto_fail_time, 109, 169, 1);
CLI_PROFILE_FIELD(b_hostlist_auto_retrans_threshold, 110, 170, 1);
CLI_PROFILE_FIELD(b_hostlist_auto_retrans_maxseq, 111, 171, 1);
CLI_PROFILE_FIELD(b_hostlist_auto_incoming_maxseq, 112, 172, 1);
CLI_PROFILE_FIELD(b_hostlist_auto_retrans_reset, 113, 173, 1);
CLI_PROFILE_FIELD(b_hostlist_auto_udp_out, 114, 174, 1);
CLI_PROFILE_FIELD(b_hostlist_auto_udp_in, 115, 175, 1);
#undef CLI_PROFILE_FIELD

_Static_assert(IDX_DEBUG == 0 && IDX_CHDIR == 7 && IDX_PIDFILE == 8 &&
    IDX_WRITABLE == 16 && IDX_LUA_INIT == 18 && IDX_HOSTLIST_AUTO_DEBUG == 33,
    "Rust startup CLI indices");
_Static_assert(IDX_INTERCEPT == 2 && IDX_FUZZ == 3 && IDX_DAEMON == 6 &&
    IDX_CTRACK_TIMEOUTS == 9 && IDX_CTRACK_DISABLE == 10 && IDX_SERVER == 12 &&
    IDX_IPCACHE_LIFETIME == 13 && IDX_IPCACHE_HOSTNAME == 14 && IDX_LUA_GC == 19 &&
    IDX_HOSTLIST_AUTO_FAIL_THRESHOLD == 25 && IDX_HOSTLIST_AUTO_FAIL_TIME == 26 &&
    IDX_HOSTLIST_AUTO_RETRANS_THRESHOLD == 27 && IDX_HOSTLIST_AUTO_RETRANS_MAXSEQ == 28 &&
    IDX_HOSTLIST_AUTO_RETRANS_RESET == 29 && IDX_HOSTLIST_AUTO_INCOMING_MAXSEQ == 30 &&
    IDX_HOSTLIST_AUTO_UDP_IN == 31 && IDX_HOSTLIST_AUTO_UDP_OUT == 32 &&
    IDX_SSID_FILTER_NEG == 73 && IDX_NLM_FILTER_NEG == 75, "Rust numeric CLI indices");

int engine_startup_option(int, const char *);
int engine_numeric_option(int, const char *, struct desync_profile *);
