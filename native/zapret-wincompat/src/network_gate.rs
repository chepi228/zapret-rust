//! Compose the Windows network constraints and cache the observed decision.
#[repr(C)]
struct Snapshot {
    second: u64,
    error: u32,
    checked: bool,
    allowed: bool,
}

type Query = unsafe extern "C" fn() -> u32;

#[repr(C)]
struct Queries {
    wlan: Query,
    network: Query,
}

#[cfg(windows)]
#[unsafe(no_mangle)]
extern "C" fn zapret_network_observation(is_hresult: bool, matched: bool, status: u32) -> u32 {
    let failed = if is_hresult {
        (status as i32) < 0
    } else {
        status != 0
    };
    if failed { 2 } else { u32::from(matched) }
}

fn accepts(observation: u32, negated: bool) -> bool {
    match observation {
        0 => negated,
        1 => !negated,
        // Errors are distinct from an absent SSID/network.
        _ => false,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_network_gate(
    snapshot: &mut Snapshot,
    ticks: u64,
    refresh: bool,
    wlan_negated: bool,
    network_negated: bool,
    error: *mut u32,
    queries: &Queries,
) -> bool {
    let second = ticks / 1000;
    if refresh || !snapshot.checked || snapshot.second != second {
        let allowed = accepts(unsafe { (queries.wlan)() }, wlan_negated)
            && accepts(unsafe { (queries.network)() }, network_negated);
        *snapshot = Snapshot {
            second,
            error: unsafe { error.read() },
            checked: true,
            allowed,
        };
    } else {
        unsafe { error.write(snapshot.error) };
    }
    snapshot.allowed
}
