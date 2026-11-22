//! Windows CLI catalog and semantic schema, separate from native field addresses.
use crate::cli::NumericOption;
use std::ffi::{c_char, c_void};
#[repr(C)]
pub struct OptionSpec {
    pub name: *const c_char,
    pub argument: i32,
    pub flag: *mut i32,
    pub value: i32,
}
unsafe impl Sync for OptionSpec {}
static OPTIONS: [OptionSpec; 79] = [
    OptionSpec {
        name: c"debug".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_DEBUG=0
    OptionSpec {
        name: c"dry-run".as_ptr(),
        argument: 0,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_DRY_RUN=1
    OptionSpec {
        name: c"intercept".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_INTERCEPT=2
    OptionSpec {
        name: c"fuzz".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_FUZZ=3
    OptionSpec {
        name: c"version".as_ptr(),
        argument: 0,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_VERSION=4
    OptionSpec {
        name: c"comment".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_COMMENT=5
    OptionSpec {
        name: c"daemon".as_ptr(),
        argument: 0,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_DAEMON=6
    OptionSpec {
        name: c"chdir".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_CHDIR=7
    OptionSpec {
        name: c"pidfile".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_PIDFILE=8
    OptionSpec {
        name: c"ctrack-timeouts".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_CTRACK_TIMEOUTS=9
    OptionSpec {
        name: c"ctrack-disable".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_CTRACK_DISABLE=10
    OptionSpec {
        name: c"payload-disable".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_PAYLOAD_DISABLE=11
    OptionSpec {
        name: c"server".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_SERVER=12
    OptionSpec {
        name: c"ipcache-lifetime".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_IPCACHE_LIFETIME=13
    OptionSpec {
        name: c"ipcache-hostname".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_IPCACHE_HOSTNAME=14
    OptionSpec {
        name: c"reasm-disable".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_REASM_DISABLE=15
    OptionSpec {
        name: c"writable".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WRITABLE=16
    OptionSpec {
        name: c"blob".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_BLOB=17
    OptionSpec {
        name: c"lua-init".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_LUA_INIT=18
    OptionSpec {
        name: c"lua-gc".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_LUA_GC=19
    OptionSpec {
        name: c"hostlist".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_HOSTLIST=20
    OptionSpec {
        name: c"hostlist-domains".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_HOSTLIST_DOMAINS=21
    OptionSpec {
        name: c"hostlist-exclude".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_HOSTLIST_EXCLUDE=22
    OptionSpec {
        name: c"hostlist-exclude-domains".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_HOSTLIST_EXCLUDE_DOMAINS=23
    OptionSpec {
        name: c"hostlist-auto".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_HOSTLIST_AUTO=24
    OptionSpec {
        name: c"hostlist-auto-fail-threshold".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_HOSTLIST_AUTO_FAIL_THRESHOLD=25
    OptionSpec {
        name: c"hostlist-auto-fail-time".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_HOSTLIST_AUTO_FAIL_TIME=26
    OptionSpec {
        name: c"hostlist-auto-retrans-threshold".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_HOSTLIST_AUTO_RETRANS_THRESHOLD=27
    OptionSpec {
        name: c"hostlist-auto-retrans-maxseq".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_HOSTLIST_AUTO_RETRANS_MAXSEQ=28
    OptionSpec {
        name: c"hostlist-auto-retrans-reset".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_HOSTLIST_AUTO_RETRANS_RESET=29
    OptionSpec {
        name: c"hostlist-auto-incoming-maxseq".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_HOSTLIST_AUTO_INCOMING_MAXSEQ=30
    OptionSpec {
        name: c"hostlist-auto-udp-in".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_HOSTLIST_AUTO_UDP_IN=31
    OptionSpec {
        name: c"hostlist-auto-udp-out".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_HOSTLIST_AUTO_UDP_OUT=32
    OptionSpec {
        name: c"hostlist-auto-debug".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_HOSTLIST_AUTO_DEBUG=33
    OptionSpec {
        name: c"new".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_NEW=34
    OptionSpec {
        name: c"skip".as_ptr(),
        argument: 0,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_SKIP=35
    OptionSpec {
        name: c"name".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_NAME=36
    OptionSpec {
        name: c"template".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_TEMPLATE=37
    OptionSpec {
        name: c"import".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_IMPORT=38
    OptionSpec {
        name: c"cookie".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_COOKIE=39
    OptionSpec {
        name: c"filter-l3".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_FILTER_L3=40
    OptionSpec {
        name: c"filter-tcp".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_FILTER_TCP=41
    OptionSpec {
        name: c"filter-udp".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_FILTER_UDP=42
    OptionSpec {
        name: c"filter-icmp".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_FILTER_ICMP=43
    OptionSpec {
        name: c"filter-ipp".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_FILTER_IPP=44
    OptionSpec {
        name: c"filter-l7".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_FILTER_L7=45
    OptionSpec {
        name: c"ipset".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_IPSET=46
    OptionSpec {
        name: c"ipset-ip".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_IPSET_IP=47
    OptionSpec {
        name: c"ipset-exclude".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_IPSET_EXCLUDE=48
    OptionSpec {
        name: c"ipset-exclude-ip".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_IPSET_EXCLUDE_IP=49
    OptionSpec {
        name: c"payload".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_PAYLOAD=50
    OptionSpec {
        name: c"in-range".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_IN_RANGE=51
    OptionSpec {
        name: c"out-range".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_OUT_RANGE=52
    OptionSpec {
        name: c"lua-desync".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_LUA_DESYNC=53
    OptionSpec {
        name: c"wf-iface".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_IFACE=54
    OptionSpec {
        name: c"wf-l3".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_L3=55
    OptionSpec {
        name: c"wf-tcp-in".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_TCP_IN=56
    OptionSpec {
        name: c"wf-tcp-out".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_TCP_OUT=57
    OptionSpec {
        name: c"wf-udp-in".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_UDP_IN=58
    OptionSpec {
        name: c"wf-udp-out".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_UDP_OUT=59
    OptionSpec {
        name: c"wf-tcp-empty".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_TCP_EMPTY=60
    OptionSpec {
        name: c"wf-icmp-in".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_ICMP_IN=61
    OptionSpec {
        name: c"wf-icmp-out".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_ICMP_OUT=62
    OptionSpec {
        name: c"wf-ipp-in".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_IPP_IN=63
    OptionSpec {
        name: c"wf-ipp-out".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_IPP_OUT=64
    OptionSpec {
        name: c"wf-raw".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_RAW=65
    OptionSpec {
        name: c"wf-raw-part".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_RAW_PART=66
    OptionSpec {
        name: c"wf-raw-filter".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_RAW_FILTER=67
    OptionSpec {
        name: c"wf-filter-lan".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_FILTER_LAN=68
    OptionSpec {
        name: c"wf-filter-loopback".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_FILTER_LOOPBACK=69
    OptionSpec {
        name: c"wf-dup-check".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_DUP_CHECK=70
    OptionSpec {
        name: c"wf-save".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_WF_SAVE=71
    OptionSpec {
        name: c"ssid-filter".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_SSID_FILTER=72
    OptionSpec {
        name: c"ssid-filter-neg".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_SSID_FILTER_NEG=73
    OptionSpec {
        name: c"nlm-filter".as_ptr(),
        argument: 1,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_NLM_FILTER=74
    OptionSpec {
        name: c"nlm-filter-neg".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_NLM_FILTER_NEG=75
    OptionSpec {
        name: c"nlm-list".as_ptr(),
        argument: 2,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_NLM_LIST=76
    OptionSpec {
        name: c"builtin-rules".as_ptr(),
        argument: 0,
        flag: std::ptr::null_mut(),
        value: 0,
    }, // IDX_BUILTIN_RULES=77
    OptionSpec {
        name: std::ptr::null(),
        argument: 0,
        flag: std::ptr::null_mut(),
        value: 0,
    },
];
#[unsafe(no_mangle)]
pub extern "C" fn zapret_native_cli_count() -> usize {
    OPTIONS.len() - 1
}
#[unsafe(no_mangle)]
pub extern "C" fn zapret_native_cli_options() -> *const OptionSpec {
    OPTIONS.as_ptr()
}
#[unsafe(no_mangle)]
pub extern "C" fn zapret_native_cli_option_name(index: i32) -> *const c_char {
    OPTIONS
        .get(index as usize)
        .map_or(std::ptr::null(), |entry| entry.name)
}
#[unsafe(no_mangle)]
pub extern "C" fn zapret_native_cli_kind(index: i32, category: u32) -> i32 {
    match (index, category) {
        (0, 1) => 0,
        (1, 5) => 6,
        (4, 5) => 7,
        (5, 5) => 8,
        (7, 1) => 1,
        (8, 1) => 2,
        (11, 3) => 6,
        (15, 3) => 7,
        (16, 1) => 3,
        (18, 1) => 4,
        (20, 2) => 0,
        (21, 2) => 1,
        (22, 2) => 2,
        (23, 2) => 3,
        (24, 2) => 4,
        (33, 1) => 5,
        (34, 5) => 0,
        (35, 5) => 1,
        (36, 5) => 3,
        (37, 5) => 2,
        (38, 5) => 5,
        (39, 5) => 4,
        (40, 3) => 0,
        (41, 3) => 1,
        (42, 3) => 2,
        (43, 3) => 3,
        (44, 3) => 4,
        (45, 3) => 5,
        (46, 2) => 5,
        (47, 2) => 6,
        (48, 2) => 7,
        (49, 2) => 8,
        (50, 3) => 8,
        (51, 3) => 10,
        (52, 3) => 9,
        (53, 3) => 11,
        (54, 4) => 0,
        (55, 4) => 1,
        (56, 4) => 2,
        (57, 4) => 3,
        (58, 4) => 4,
        (59, 4) => 5,
        (60, 4) => 13,
        (61, 4) => 6,
        (62, 4) => 7,
        (63, 4) => 8,
        (64, 4) => 9,
        (65, 4) => 10,
        (66, 4) => 11,
        (67, 4) => 12,
        (68, 4) => 14,
        (69, 4) => 15,
        (70, 4) => 17,
        (71, 4) => 16,
        (72, 4) => 18,
        (77, 1) => 4,
        (73, 4) => 19,
        (74, 4) => 20,
        (75, 4) => 21,
        (76, 4) => 22,
        _ => -1,
    }
}
fn numeric_metadata(index: i32, option: &mut NumericOption) -> u32 {
    if index == 9 {
        return 2;
    }
    let (kind, lower, upper, scale, flags) = match index {
        2 => (0, -2147483648i64, 2147483647i64, 1, 1),
        3 => (3, -2147483648i64, 2147483647i64, 1, 9),
        6 => (0, -2147483648i64, 2147483647i64, 1, 5),
        10 => (0, -2147483648i64, 2147483647i64, 1, 1),
        12 => (0, -2147483648i64, 2147483647i64, 1, 1),
        13 => (2, 0i64, 4294967295i64, 1, 1),
        14 => (0, -2147483648i64, 2147483647i64, 1, 1),
        19 => (4, 0i64, 2147483647i64, 1000, 1),
        25 => (1, 1i64, 20i64, 1, 1),
        26 => (1, 1i64, 2147483647i64, 1, 1),
        27 => (1, 2i64, 10i64, 1, 1),
        28 => (3, -2147483648i64, 4294967295i64, 1, 1),
        29 => (0, -2147483648i64, 2147483647i64, 1, 1),
        30 => (3, -2147483648i64, 4294967295i64, 1, 1),
        31 => (1, -2147483648i64, 2147483647i64, 1, 1),
        32 => (1, -2147483648i64, 2147483647i64, 1, 1),
        73 => (0, -2147483648i64, 2147483647i64, 1, 1),
        75 => (0, -2147483648i64, 2147483647i64, 1, 1),
        _ => return 0,
    };
    option.kind = kind;
    option.lower = lower;
    option.upper = upper;
    option.scale = scale;
    flags
}

#[repr(C)]
struct NumericTarget {
    value: *mut c_void,
    explicit: *mut bool,
    intercept: *mut bool,
    timeouts: [*mut u32; 4],
}

#[repr(C)]
struct NumericOps {
    number: unsafe extern "C" fn(*const c_char, &NumericOption) -> bool,
    timeouts: unsafe extern "C" fn(*const c_char, *mut u32, *mut u32, *mut u32, *mut u32) -> bool,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_cli_apply_numeric(
    index: i32,
    text: *const c_char,
    target: &NumericTarget,
    ops: &NumericOps,
) -> i32 {
    let mut option = NumericOption {
        target: target.value,
        explicit: target.explicit,
        ..NumericOption::default()
    };
    let operation = numeric_metadata(index, &mut option);
    let parsed = match operation {
        0 => return 0,
        2 => {
            let [syn, established, fin, udp] = target.timeouts;
            unsafe { (ops.timeouts)(text, syn, established, fin, udp) }
        }
        _ => {
            if operation & 8 != 0 {
                option.disable = target.intercept;
            }
            let text = if operation & 4 != 0 {
                std::ptr::null()
            } else {
                text
            };
            unsafe { (ops.number)(text, &option) }
        }
    };
    if parsed { 1 } else { -1 }
}

#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(size_of::<NumericTarget>() == 56);
    assert!(size_of::<NumericOps>() == 16);
};
#[unsafe(no_mangle)]
pub extern "C" fn zapret_native_cli_skip_numeric(index: i32) -> bool {
    matches!(index, 73 | 75)
}
#[unsafe(no_mangle)]
pub extern "C" fn zapret_native_cli_capacity(index: i32) -> usize {
    if matches!(index, 65..=67) {
        65536
    } else {
        4096
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_has_all_windows_options_and_c_terminator() {
        assert_eq!(zapret_native_cli_count(), 78);
        assert!(!zapret_native_cli_options().is_null());
    }
    #[test]
    fn category_exception_and_option_kinds_are_semantic_metadata() {
        assert_eq!(zapret_native_cli_kind(0, 1), 0);
        assert_eq!(zapret_native_cli_kind(76, 4), 22);
        assert!(zapret_native_cli_skip_numeric(73));
        assert!(zapret_native_cli_skip_numeric(75));
        assert!(!zapret_native_cli_skip_numeric(74));
        assert_eq!(zapret_native_cli_capacity(65), 65536);
    }
    #[test]
    fn numeric_schema_supplies_bounds_scale_and_side_effect_flags() {
        let mut n = NumericOption {
            target: std::ptr::null_mut(),
            explicit: std::ptr::null_mut(),
            lower: 0,
            upper: 0,
            scale: 0,
            kind: 0,
            disable: std::ptr::null_mut(),
        };
        assert_eq!(numeric_metadata(25, &mut n), 1);
        assert_eq!((n.lower, n.upper, n.scale, n.kind), (1, 20, 1, 1));
        assert_eq!(numeric_metadata(19, &mut n), 1);
        assert_eq!((n.lower, n.scale, n.kind), (0, 1000, 4));
        assert_eq!(numeric_metadata(3, &mut n), 9);
        assert_eq!(numeric_metadata(6, &mut n), 5);
    }
}
