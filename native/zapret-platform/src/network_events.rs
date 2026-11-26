use std::{
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicU64, Ordering},
};
use windows_sys::Win32::{
    Foundation::HANDLE, NetworkManagement::IpHelper::*, Networking::WinSock::AF_UNSPEC,
};

// A notification can outlive the selecting thread. Callbacks touch only static storage.
static GENERATION: AtomicU64 = AtomicU64::new(0);
unsafe extern "system" fn interface(
    _: *const c_void,
    _: *const MIB_IPINTERFACE_ROW,
    _: MIB_NOTIFICATION_TYPE,
) {
    GENERATION.fetch_add(1, Ordering::Relaxed);
}
unsafe extern "system" fn route(
    _: *const c_void,
    _: *const MIB_IPFORWARD_ROW2,
    _: MIB_NOTIFICATION_TYPE,
) {
    GENERATION.fetch_add(1, Ordering::Relaxed);
}
unsafe extern "system" fn address(
    _: *const c_void,
    _: *const MIB_UNICASTIPADDRESS_ROW,
    _: MIB_NOTIFICATION_TYPE,
) {
    GENERATION.fetch_add(1, Ordering::Relaxed);
}

pub struct NetworkEvents {
    handles: [HANDLE; 3],
}

impl NetworkEvents {
    pub fn subscribe() -> Option<Self> {
        let mut watcher = Self {
            handles: [ptr::null_mut(); 3],
        };
        let h = &mut watcher.handles;
        let ok = unsafe {
            NotifyIpInterfaceChange(AF_UNSPEC, Some(interface), ptr::null(), false, &mut h[0]) == 0
                && NotifyRouteChange2(AF_UNSPEC, Some(route), ptr::null(), false, &mut h[1]) == 0
                && NotifyUnicastIpAddressChange(
                    AF_UNSPEC,
                    Some(address),
                    ptr::null(),
                    false,
                    &mut h[2],
                ) == 0
        };
        ok.then_some(watcher)
    }

    pub fn generation(&self) -> u64 {
        GENERATION.load(Ordering::Relaxed)
    }
}

impl Drop for NetworkEvents {
    fn drop(&mut self) {
        for &handle in &self.handles {
            if !handle.is_null() {
                unsafe {
                    CancelMibChangeNotify2(handle);
                }
            }
        }
    }
}
