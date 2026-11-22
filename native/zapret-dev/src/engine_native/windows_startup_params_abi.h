/* MIT. ABI checks for the params_s slots borrowed by Rust startup objects. */
#pragma once
#include "params.h"
#include <stddef.h>

#define ZAPRET_STARTUP_ABI(win32, win64) (sizeof(void *) == 8 ? (win64) : (win32))
#define ZAPRET_STARTUP_FIELD(field, win32, win64, width) \
    _Static_assert(offsetof(struct params_s, field) == ZAPRET_STARTUP_ABI(win32, win64) && \
        sizeof(params.field) == (width), "Rust startup params_s." #field)

_Static_assert(sizeof(struct params_s) == ZAPRET_STARTUP_ABI(16760, 16896) &&
    _Alignof(struct params_s) == 8, "Rust startup params_s ABI");
ZAPRET_STARTUP_FIELD(verstr, 12, 24, 128);
ZAPRET_STARTUP_FIELD(debug_target, 140, 152, 4);
ZAPRET_STARTUP_FIELD(debug_logfile, 144, 156, 4096);
ZAPRET_STARTUP_FIELD(debug, 4240, 4252, 1);
ZAPRET_STARTUP_FIELD(daemon, 4241, 4253, 1);
ZAPRET_STARTUP_FIELD(intercept, 4242, 4254, 1);
ZAPRET_STARTUP_FIELD(fuzz, 4244, 4256, 4);
ZAPRET_STARTUP_FIELD(desync_fwmark, 4252, 4264, 4);
ZAPRET_STARTUP_FIELD(desync_profiles, 4256, 4272, sizeof(void *));
ZAPRET_STARTUP_FIELD(desync_templates, 4260, 4280, sizeof(void *));
ZAPRET_STARTUP_FIELD(windivert_filter, 4280, 4320, sizeof(void *));
ZAPRET_STARTUP_FIELD(ssid_filter, 4264, 4288, sizeof(void *));
ZAPRET_STARTUP_FIELD(nlm_filter, 4268, 4296, sizeof(void *));
ZAPRET_STARTUP_FIELD(ssid_filter_neg, 4272, 4304, 1);
ZAPRET_STARTUP_FIELD(nlm_filter_neg, 4273, 4305, 1);
ZAPRET_STARTUP_FIELD(wf_raw_part, 4276, 4312, sizeof(void *));
ZAPRET_STARTUP_FIELD(wf_pf_tcp_src_in, 4284, 4328, sizeof(void *));
ZAPRET_STARTUP_FIELD(pidfile, 4336, 4432, 4096);
ZAPRET_STARTUP_FIELD(hostlist_auto_debuglog, 8432, 8528, 4096);
ZAPRET_STARTUP_FIELD(hostlists, 12528, 12624, sizeof(void *));
ZAPRET_STARTUP_FIELD(ipsets, 12532, 12632, sizeof(void *));
ZAPRET_STARTUP_FIELD(blobs, 12536, 12640, sizeof(void *));
ZAPRET_STARTUP_FIELD(ctrack_t_syn, 12540, 12648, 4);
ZAPRET_STARTUP_FIELD(ctrack_t_est, 12544, 12652, 4);
ZAPRET_STARTUP_FIELD(ctrack_t_fin, 12548, 12656, 4);
ZAPRET_STARTUP_FIELD(ctrack_t_udp, 12552, 12660, 4);
ZAPRET_STARTUP_FIELD(conntrack, 12560, 12664, 40);
_Static_assert(_Alignof(t_conntrack) == 8, "Rust startup conntrack alignment");
ZAPRET_STARTUP_FIELD(ctrack_disable, 12600, 12704, 1);
ZAPRET_STARTUP_FIELD(server, 12601, 12705, 1);
ZAPRET_STARTUP_FIELD(cache_hostname, 12602, 12706, 1);
ZAPRET_STARTUP_FIELD(ipcache_lifetime, 12604, 12708, 4);
ZAPRET_STARTUP_FIELD(ipcache, 12608, 12712, 2 * sizeof(void *));
ZAPRET_STARTUP_FIELD(reasm_payload_disable, 12616, 12728, 8);
ZAPRET_STARTUP_FIELD(payload_disable, 12624, 12736, 8);
ZAPRET_STARTUP_FIELD(lua_init_scripts, 12632, 12744, sizeof(void *));
ZAPRET_STARTUP_FIELD(writable_dir_enable, 12636, 12752, 1);
ZAPRET_STARTUP_FIELD(writable_dir, 12637, 12753, 4096);
ZAPRET_STARTUP_FIELD(timers, 16736, 16856, sizeof(void *));
ZAPRET_STARTUP_FIELD(timers_dirty, 16740, 16864, 1);
ZAPRET_STARTUP_FIELD(lua_gc, 16744, 16872, 8);
ZAPRET_STARTUP_FIELD(L, 16756, 16888, sizeof(void *));

#undef ZAPRET_STARTUP_FIELD
#undef ZAPRET_STARTUP_ABI
