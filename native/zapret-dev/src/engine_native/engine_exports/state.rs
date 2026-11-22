//! Storage for the live Windows engine records shared with the native ABI.
use super::startup_params::PARAMS as LAYOUT;
use core::sync::atomic::AtomicI32;

pub(super) const PARAMS_SIZE: usize = LAYOUT.size;

#[repr(C, align(8))]
struct Params([u8; PARAMS_SIZE]);

#[unsafe(export_name = "params")]
static mut PARAMS: Params = Params([0; PARAMS_SIZE]);

#[unsafe(export_name = "bQuit")]
pub(crate) static QUIT: AtomicI32 = AtomicI32::new(0);

#[unsafe(export_name = "w_win32_error")]
pub(super) static mut WIN32_ERROR: u32 = 0;

pub(super) fn params_address() -> *mut u8 {
    (&raw mut PARAMS).cast()
}
