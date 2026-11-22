use anyhow::{Result, ensure};
use std::{ffi::c_void, ptr::null};
use windows_sys::{
    Win32::{
        Foundation::{RPC_E_CHANGED_MODE, SysAllocStringLen, SysFreeString, SysStringLen},
        System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize},
    },
    core::{BSTR, PCWSTR},
};

#[repr(C)]
pub(crate) struct Unknown {
    query_interface: usize,
    add_ref: usize,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}

#[repr(C)]
pub(crate) struct Dispatch {
    base: Unknown,
    methods: [usize; 4],
}

pub(crate) struct Object(pub(crate) *mut c_void);

impl Object {
    pub(crate) fn new(raw: *mut c_void) -> Result<Self> {
        ensure!(!raw.is_null(), "COM returned no interface");
        Ok(Self(raw))
    }

    // The caller supplies the vtable type for the interface obtained from COM.
    pub(crate) unsafe fn table<T>(&self) -> &T {
        unsafe { &**self.0.cast::<*const T>() }
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        unsafe { (self.table::<Unknown>().release)(self.0) };
    }
}

pub(crate) struct Apartment(bool);

impl Apartment {
    pub(crate) fn enter(operation: &str) -> Result<Self> {
        let hr = unsafe { CoInitializeEx(null(), COINIT_MULTITHREADED as u32) };
        if hr == RPC_E_CHANGED_MODE {
            return Ok(Self(false));
        }
        check(hr, operation)?;
        Ok(Self(true))
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.0 {
            unsafe { CoUninitialize() };
        }
    }
}

pub(crate) struct StringValue(pub(crate) BSTR);

impl StringValue {
    pub(crate) fn allocate(text: &str) -> Result<Self> {
        let text: Vec<_> = text.encode_utf16().collect();
        let length = u32::try_from(text.len())?;
        let string = unsafe { SysAllocStringLen(text.as_ptr(), length) };
        ensure!(!string.is_null(), "COM string allocation failed");
        Ok(Self(string))
    }

    pub(crate) fn read(&self, limit: usize) -> Result<String> {
        // self owns the BSTR returned by the API.
        unsafe { read_bstr(self.0, limit) }
    }
}

impl Drop for StringValue {
    fn drop(&mut self) {
        unsafe { SysFreeString(self.0) };
    }
}

/// The pointer must be a live BSTR or null.
pub(crate) unsafe fn read_bstr(text: PCWSTR, limit: usize) -> Result<String> {
    let length = unsafe { SysStringLen(text) } as usize;
    ensure!(length <= limit, "COM string exceeds size budget");
    if text.is_null() {
        Ok(String::new())
    } else {
        Ok(String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(text, length)
        }))
    }
}

pub(crate) fn check(hr: i32, operation: &str) -> Result<()> {
    ensure!(hr >= 0, "{operation}: HRESULT 0x{:08X}", hr as u32);
    Ok(())
}
