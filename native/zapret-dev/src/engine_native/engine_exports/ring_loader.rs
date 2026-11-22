//! Pinned ring DLL ownership for the LuaJIT entries.
use core::ffi::{c_char, c_int, c_void};

#[repr(C)]
struct Loader {
    api: *const c_void,
    pin: *mut c_void,
    module: *mut c_void,
}

const _: () = assert!(size_of::<Loader>() == 3 * size_of::<*const c_void>());
const PIN: &str = concat!(env!("ZAPRET_RING_DLL_SHA256"), "\0");
static mut LOADER: Loader = Loader {
    api: core::ptr::null(),
    pin: usize::MAX as *mut c_void,
    module: core::ptr::null_mut(),
};

unsafe extern "system" {
    fn GetLastError() -> u32;
}

unsafe extern "C" {
    fn zapret_ring_load(loader: *mut Loader, hash: *const c_char) -> bool;
    fn zapret_ring_loader_error_text() -> *const c_char;
}

#[cfg(not(feature = "cygwin-host"))]
unsafe extern "C" {
    fn __acrt_iob_func(descriptor: core::ffi::c_uint) -> *mut c_void;
    fn __mingw_fprintf(stream: *mut c_void, format: *const c_char, ...) -> c_int;
}

#[cfg(feature = "cygwin-host")]
unsafe extern "C" {
    fn dprintf(descriptor: c_int, format: *const c_char, ...) -> c_int;
}

#[unsafe(no_mangle)]
extern "C" fn zapret_ring_vm_load() -> bool {
    unsafe {
        if zapret_ring_load(&raw mut LOADER, PIN.as_ptr().cast()) {
            return true;
        }
        let error = GetLastError();
        #[cfg(not(feature = "cygwin-host"))]
        __mingw_fprintf(__acrt_iob_func(2), zapret_ring_loader_error_text(), error);
        #[cfg(feature = "cygwin-host")]
        dprintf(2, zapret_ring_loader_error_text(), u64::from(error));
        false
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_ring_vm_backend() -> *const c_void {
    unsafe { LOADER.api }
}
