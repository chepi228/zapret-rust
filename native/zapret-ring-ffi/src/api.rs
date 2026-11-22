//! Raw ABI shared by the ring DLL and the native engine.

use super::request::Request;
use core::{ffi::c_void, ptr};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Return {
    pub kind: u32,
    pub number: f64,
    pub offset: usize,
    pub length: usize,
}

#[repr(C)]
pub struct Response {
    pub count: u32,
    pub values: [Return; 8],
    pub object: *mut c_void,
}

impl Default for Response {
    fn default() -> Self {
        Self {
            count: 0,
            values: [Return::default(); 8],
            object: ptr::null_mut(),
        }
    }
}

type Invoke =
    unsafe extern "C" fn(u32, *mut c_void, *const Request, *mut Response, *mut u8, usize) -> i32;
type DropObject = unsafe extern "C" fn(*mut c_void);

#[repr(C)]
pub struct Api {
    pub size: usize,
    pub version: u32,
    pub invoke: Invoke,
    pub drop_object: DropObject,
}
