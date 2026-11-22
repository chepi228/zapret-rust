//! Windows network observation with scoped COM and WLAN resources.
mod diagnostics;

use crate::allocate::try_allocate;
use std::{
    ffi::{CStr, c_char, c_void},
    mem::{size_of, transmute},
    ptr,
};
use windows_sys::{
    Win32::{
        Foundation::{
            E_POINTER, ERROR_INVALID_DATA, ERROR_NOT_ENOUGH_MEMORY, ERROR_PROC_NOT_FOUND,
            FreeLibrary, GetLastError, HANDLE, HMODULE, SysFreeString,
        },
        Globalization::{CP_UTF8, WideCharToMultiByte},
        NetworkManagement::WiFi::{
            WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO_LIST, wlan_interface_state_connected,
            wlan_intf_opcode_current_connection,
        },
        System::{
            Com::{CLSCTX_ALL, CoCreateInstance, CoInitialize, CoUninitialize},
            LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
        },
    },
    core::{BSTR, GUID},
};

#[repr(C)]
struct StringNode {
    text: *const c_char,
    next: *const StringNode,
}

unsafe fn empty(head: *const *const StringNode) -> bool {
    head.is_null() || unsafe { head.read() }.is_null()
}

unsafe fn any(mut node: *const StringNode, mut predicate: impl FnMut(&[u8]) -> bool) -> bool {
    while !node.is_null() {
        let text = unsafe { CStr::from_ptr((*node).text) }.to_bytes();
        if predicate(text) {
            return true;
        }
        node = unsafe { (*node).next };
    }
    false
}

// The IDispatch prefix and these Network List Manager slots are the same
// representation used by the controller's read-only profiles implementation.
#[repr(C)]
struct Unknown {
    query: usize,
    add_ref: usize,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}
#[repr(C)]
struct Dispatch {
    base: Unknown,
    methods: [usize; 4],
}
#[repr(C)]
struct Manager {
    base: Dispatch,
    networks: unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> i32,
}
#[repr(C)]
struct Enumerator {
    base: Dispatch,
    new_enum: usize,
    next: unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void, *mut u32) -> i32,
}
#[repr(C)]
struct Network {
    base: Dispatch,
    name: unsafe extern "system" fn(*mut c_void, *mut BSTR) -> i32,
    descriptions: [usize; 3],
    id: unsafe extern "system" fn(*mut c_void, *mut GUID) -> i32,
}

struct ComObject(*mut c_void);
impl ComObject {
    fn new(raw: *mut c_void) -> Result<Self, u32> {
        if raw.is_null() {
            Err(E_POINTER as u32)
        } else {
            Ok(Self(raw))
        }
    }
}

unsafe fn vtable<T>(object: *mut c_void) -> *const T {
    unsafe { object.cast::<*const T>().read() }
}
impl Drop for ComObject {
    fn drop(&mut self) {
        unsafe { ((*vtable::<Unknown>(self.0)).release)(self.0) };
    }
}
struct ComString(BSTR);
impl Drop for ComString {
    fn drop(&mut self) {
        unsafe { SysFreeString(self.0) };
    }
}

fn hresult(code: i32) -> Result<(), u32> {
    if code < 0 { Err(code as u32) } else { Ok(()) }
}
fn win32_hresult(code: u32) -> u32 {
    if code as i32 <= 0 {
        code
    } else {
        0x8007_0000 | (code & 0xffff)
    }
}

fn parse_guid(bytes: &[u8]) -> Option<GUID> {
    if bytes.len() != 36 || [8, 13, 18, 23].iter().any(|&at| bytes[at] != b'-') {
        return None;
    }
    let parse = |start: usize, end: usize| {
        bytes[start..end].iter().try_fold(0u32, |value, byte| {
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a') + 10,
                b'A'..=b'F' => u32::from(byte - b'A') + 10,
                _ => return None,
            };
            Some(value * 16 + digit)
        })
    };
    let mut guid = GUID {
        data1: parse(0, 8)?,
        data2: parse(9, 13)? as u16,
        data3: parse(14, 18)? as u16,
        data4: [0; 8],
    };
    for (target, start) in guid.data4.iter_mut().zip([19, 21, 24, 26, 28, 30, 32, 34]) {
        *target = parse(start, start + 2)? as u8;
    }
    Some(guid)
}
fn same_guid(left: &GUID, right: &GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

unsafe fn network_matches(
    manager: *mut c_void,
    head: *const *const StringNode,
) -> Result<bool, u32> {
    if unsafe { empty(head) } {
        return Ok(true);
    }
    if manager.is_null() {
        return Err(E_POINTER as u32);
    }
    // The environment owns manager. This local view never releases it.
    let table = unsafe { vtable::<Manager>(manager) };
    let mut raw = ptr::null_mut();
    hresult(unsafe { ((*table).networks)(manager, 1, &mut raw) })?;
    let enumerator = ComObject::new(raw)?;
    loop {
        let mut raw = ptr::null_mut();
        let mut fetched = 0;
        let code = unsafe {
            ((*vtable::<Enumerator>(enumerator.0)).next)(enumerator.0, 1, &mut raw, &mut fetched)
        };
        hresult(code)?;
        if code != 0 || fetched == 0 {
            return Ok(false);
        }
        let network = ComObject::new(raw)?;
        let table = unsafe { vtable::<Network>(network.0) };
        let mut id = GUID::default();
        hresult(unsafe { ((*table).id)(network.0, &mut id) })?;
        let mut name = ptr::null();
        hresult(unsafe { ((*table).name)(network.0, &mut name) })?;
        let name = ComString(name);
        let mut utf8 = [0u8; 128];
        let length = unsafe {
            WideCharToMultiByte(
                CP_UTF8,
                0,
                name.0,
                -1,
                utf8.as_mut_ptr(),
                utf8.len() as i32,
                ptr::null(),
                ptr::null_mut(),
            )
        };
        if length == 0 {
            return Err(win32_hresult(unsafe { GetLastError() }));
        }
        let name = &utf8[..length as usize - 1];
        if unsafe {
            any(head.read(), |option| {
                option == name || parse_guid(option).is_some_and(|option| same_guid(&id, &option))
            })
        } {
            return Ok(true);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_nlm_match(
    manager: *mut c_void,
    head: *const *const StringNode,
    error: *mut u32,
) -> bool {
    match unsafe { network_matches(manager, head) } {
        Ok(matched) => {
            unsafe { error.write(0) };
            matched
        }
        Err(code) => {
            unsafe { error.write(code) };
            false
        }
    }
}

type WlanOpen = unsafe extern "system" fn(u32, *const c_void, *mut u32, *mut HANDLE) -> u32;
type WlanClose = unsafe extern "system" fn(HANDLE, *const c_void) -> u32;
type WlanEnumerate =
    unsafe extern "system" fn(HANDLE, *const c_void, *mut *mut WLAN_INTERFACE_INFO_LIST) -> u32;
type WlanQuery = unsafe extern "system" fn(
    HANDLE,
    *const GUID,
    i32,
    *const c_void,
    *mut u32,
    *mut *mut c_void,
    *mut i32,
) -> u32;
type WlanFree = unsafe extern "system" fn(*const c_void);

#[repr(C)]
struct WlanOps {
    open: WlanOpen,
    close: WlanClose,
    enumerate: WlanEnumerate,
    query: WlanQuery,
    free: WlanFree,
}
struct WlanClient<'a>(HANDLE, &'a WlanOps);
impl Drop for WlanClient<'_> {
    fn drop(&mut self) {
        unsafe { (self.1.close)(self.0, ptr::null()) };
    }
}
struct WlanBuffer<'a>(*mut c_void, &'a WlanOps);
impl Drop for WlanBuffer<'_> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { (self.1.free)(self.0) };
        }
    }
}
fn status(code: u32) -> Result<(), u32> {
    if code == 0 { Ok(()) } else { Err(code) }
}

unsafe fn wlan_matches(ops: &WlanOps, head: *const *const StringNode) -> Result<bool, u32> {
    if unsafe { empty(head) } {
        return Ok(true);
    }
    let mut handle = ptr::null_mut();
    let mut version = 0;
    status(unsafe { (ops.open)(2, ptr::null(), &mut version, &mut handle) })?;
    let handle = WlanClient(handle, ops);
    let mut list = ptr::null_mut();
    status(unsafe { (ops.enumerate)(handle.0, ptr::null(), &mut list) })?;
    let buffer = WlanBuffer(list.cast(), ops);
    if list.is_null() {
        return Err(ERROR_INVALID_DATA);
    }
    let count = unsafe { (*list).dwNumberOfItems } as usize;
    let entries = unsafe {
        ptr::addr_of!((*list).InterfaceInfo)
            .cast::<windows_sys::Win32::NetworkManagement::WiFi::WLAN_INTERFACE_INFO>()
    };
    for index in 0..count {
        let entry = unsafe { &*entries.add(index) };
        if entry.isState != wlan_interface_state_connected {
            continue;
        }
        let mut size = 0;
        let mut connection = ptr::null_mut();
        status(unsafe {
            (ops.query)(
                handle.0,
                &entry.InterfaceGuid,
                wlan_intf_opcode_current_connection,
                ptr::null(),
                &mut size,
                &mut connection,
                ptr::null_mut(),
            )
        })?;
        let connection = WlanBuffer(connection, ops);
        if connection.0.is_null() || (size as usize) < size_of::<WLAN_CONNECTION_ATTRIBUTES>() {
            return Err(ERROR_INVALID_DATA);
        }
        let ssid = unsafe {
            &(*connection.0.cast::<WLAN_CONNECTION_ATTRIBUTES>())
                .wlanAssociationAttributes
                .dot11Ssid
        };
        let Some(bytes) = ssid.ucSSID.get(..ssid.uSSIDLength as usize) else {
            return Err(ERROR_INVALID_DATA);
        };
        if unsafe { any(head.read(), |name| name == bytes) } {
            return Ok(true);
        }
    }
    drop(buffer);
    Ok(false)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_wlan_match(
    ops: &WlanOps,
    head: *const *const StringNode,
    error: *mut u32,
) -> bool {
    match unsafe { wlan_matches(ops, head) } {
        Ok(matched) => {
            unsafe { error.write(0) };
            matched
        }
        Err(code) => {
            unsafe { error.write(code) };
            false
        }
    }
}

struct WlanModule {
    module: HMODULE,
    ops: WlanOps,
}
impl Drop for WlanModule {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.module) };
    }
}
impl WlanModule {
    unsafe fn load() -> Result<Self, u32> {
        let module = unsafe {
            LoadLibraryExW(
                windows_sys::core::w!("wlanapi.dll"),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(unsafe { GetLastError() });
        }
        let result = unsafe {
            (|| {
                let open = GetProcAddress(module, c"WlanOpenHandle".as_ptr().cast())?;
                let close = GetProcAddress(module, c"WlanCloseHandle".as_ptr().cast())?;
                let enumerate = GetProcAddress(module, c"WlanEnumInterfaces".as_ptr().cast())?;
                let query = GetProcAddress(module, c"WlanQueryInterface".as_ptr().cast())?;
                let free = GetProcAddress(module, c"WlanFreeMemory".as_ptr().cast())?;
                Some(WlanOps {
                    open: transmute::<unsafe extern "system" fn() -> isize, WlanOpen>(open),
                    close: transmute::<unsafe extern "system" fn() -> isize, WlanClose>(close),
                    enumerate: transmute::<unsafe extern "system" fn() -> isize, WlanEnumerate>(
                        enumerate,
                    ),
                    query: transmute::<unsafe extern "system" fn() -> isize, WlanQuery>(query),
                    free: transmute::<unsafe extern "system" fn() -> isize, WlanFree>(free),
                })
            })()
        };
        if let Some(ops) = result {
            Ok(Self { module, ops })
        } else {
            unsafe { FreeLibrary(module) };
            Err(ERROR_PROC_NOT_FOUND)
        }
    }
}

struct Environment {
    manager: Option<ComObject>,
    apartment: bool,
    wlan: Option<WlanModule>,
}
impl Drop for Environment {
    fn drop(&mut self) {
        drop(self.manager.take());
        if self.apartment {
            unsafe { CoUninitialize() };
        }
    }
}
impl Environment {
    unsafe fn create(wlan: bool, network: bool) -> Result<Self, u32> {
        let mut result = Self {
            manager: None,
            apartment: false,
            wlan: None,
        };
        if network {
            hresult(unsafe { CoInitialize(ptr::null()) })?;
            result.apartment = true;
            let clsid = GUID {
                data1: 0xdcb00c01,
                data2: 0x570f,
                data3: 0x4a9b,
                data4: [0x8d, 0x69, 0x19, 0x9f, 0xdb, 0xa5, 0x72, 0x3b],
            };
            let iid = GUID {
                data1: 0xdcb00000,
                ..clsid
            };
            let mut raw = ptr::null_mut();
            hresult(unsafe {
                CoCreateInstance(&clsid, ptr::null_mut(), CLSCTX_ALL, &iid, &mut raw)
            })?;
            result.manager = Some(ComObject::new(raw)?);
        }
        if wlan {
            result.wlan = Some(unsafe { WlanModule::load() }?);
        }
        Ok(result)
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_network_environment_destroy(slot: *mut *mut Environment) {
    let environment = unsafe { slot.replace(ptr::null_mut()) };
    if !environment.is_null() {
        drop(unsafe { Box::from_raw(environment) });
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_network_environment_init(
    slot: *mut *mut Environment,
    wlan: bool,
    network: bool,
    error: *mut u32,
) -> bool {
    unsafe { zapret_network_environment_destroy(slot) };
    match unsafe { Environment::create(wlan, network) } {
        Ok(environment) => {
            if let Some(environment) = try_allocate(environment) {
                unsafe {
                    slot.write(environment.as_ptr());
                    error.write(0)
                };
                true
            } else {
                unsafe { error.write(ERROR_NOT_ENOUGH_MEMORY) };
                false
            }
        }
        Err(code) => {
            unsafe { error.write(code) };
            false
        }
    }
}

type FilterHead = *const *const StringNode;

#[repr(C)]
struct FilterBinding {
    environment: *mut *mut Environment,
    wlan: *mut FilterHead,
    network: *mut FilterHead,
    wlan_negated: *mut bool,
    network_negated: *mut bool,
    error: *mut u32,
    reset: unsafe extern "C" fn(),
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_network_unbind(binding: &FilterBinding) {
    unsafe {
        zapret_network_environment_destroy(binding.environment);
        binding.network.write(ptr::null());
        binding.wlan.write(ptr::null());
        binding.network_negated.write(false);
        binding.wlan_negated.write(false);
        (binding.reset)();
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_network_bind(
    binding: &FilterBinding,
    wlan: FilterHead,
    wlan_negated: bool,
    network: FilterHead,
    network_negated: bool,
) -> bool {
    unsafe { zapret_network_unbind(binding) };
    let have_wlan = !unsafe { empty(wlan) };
    let have_network = !unsafe { empty(network) };
    if !unsafe {
        zapret_network_environment_init(binding.environment, have_wlan, have_network, binding.error)
    } {
        return false;
    }
    unsafe {
        binding
            .wlan
            .write(if have_wlan { wlan } else { ptr::null() });
        binding
            .network
            .write(if have_network { network } else { ptr::null() });
        binding.wlan_negated.write(wlan_negated);
        binding.network_negated.write(network_negated);
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_network_bind_present(binding: &FilterBinding) -> bool {
    !unsafe { empty(binding.wlan.read()) } || !unsafe { empty(binding.network.read()) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_network_environment_wlan(
    environment: *const Environment,
    head: *const *const StringNode,
    error: *mut u32,
) -> bool {
    if unsafe { empty(head) } {
        unsafe { error.write(0) };
        return true;
    }
    if let Some(ops) =
        unsafe { environment.as_ref() }.and_then(|environment| environment.wlan.as_ref())
    {
        unsafe { zapret_wlan_match(&ops.ops, head, error) }
    } else {
        unsafe { error.write(E_POINTER as u32) };
        false
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_network_environment_nlm(
    environment: *const Environment,
    head: *const *const StringNode,
    error: *mut u32,
) -> bool {
    let manager = unsafe { environment.as_ref() }
        .and_then(|environment| environment.manager.as_ref())
        .map_or(ptr::null_mut(), |manager| manager.0);
    unsafe { zapret_nlm_match(manager, head, error) }
}

#[cfg(test)]
mod binding_tests {
    use super::*;
    use std::cell::Cell;

    thread_local! { static RESETS: Cell<u32> = const { Cell::new(0) }; }

    unsafe extern "C" fn reset() {
        RESETS.with(|count| count.set(count.get() + 1));
    }

    #[test]
    fn empty_filters_preserve_negation_until_teardown_without_opening_windows_observers() {
        let mut environment = ptr::null_mut();
        let head = ptr::null();
        let mut wlan = &head as FilterHead;
        let mut network = &head as FilterHead;
        let (mut wlan_negated, mut network_negated, mut error) = (false, true, 123);
        let binding = FilterBinding {
            environment: &mut environment,
            wlan: &mut wlan,
            network: &mut network,
            wlan_negated: &mut wlan_negated,
            network_negated: &mut network_negated,
            error: &mut error,
            reset,
        };
        RESETS.with(|count| count.set(0));
        assert!(unsafe { zapret_network_bind(&binding, &head, true, ptr::null(), true) });
        assert!(wlan.is_null() && network.is_null() && wlan_negated && network_negated);
        assert_eq!(error, 0);
        assert!(!environment.is_null());
        assert!(!unsafe { zapret_network_bind_present(&binding) });
        unsafe { zapret_network_unbind(&binding) };
        assert!(environment.is_null() && !wlan_negated && !network_negated);
        assert_eq!(RESETS.with(Cell::get), 2);
    }
}
