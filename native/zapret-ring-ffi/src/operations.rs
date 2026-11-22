//! Canonical public operation order shared by the backend and native VM policy.
pub const STORE_SCHEDULER: u32 = 34;
pub const STORE_EFFECT: u32 = STORE_SCHEDULER + 1;
pub const STORE_STAT: u32 = STORE_EFFECT + 1;
pub const HOST_CAPACITY: u32 = STORE_STAT + 1;

pub const OPERATIONS: &[&str] = &[
    "store_new",
    "store_get",
    "store_put",
    "store_snapshot",
    "store_due",
    "store_commit",
    "store_discard",
    "store_stats",
    "context_new",
    "context_due",
    "context_observe",
    "context_read",
    "network_key",
    "link_guard",
    "state_path",
    "subnet",
    "acked",
    "forged",
    "refused",
    "success",
    "failure",
    "initial",
    "skip",
    "timer_gate",
    "host_new",
    "host_access",
    "host_touch",
    "host_count",
    "legacy_state_path",
    "context_poll",
    "tcp_fallback",
    "host_split",
    "windows_absolute_path",
    "store_scheduler",
    "store_effect",
    "store_stat",
    "host_capacity",
];

const _: () = assert!(OPERATIONS.len() == HOST_CAPACITY as usize);
