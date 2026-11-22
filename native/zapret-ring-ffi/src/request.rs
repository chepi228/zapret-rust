//! Win64 request layout shared by the ring DLL and the native Lua bridge.
pub const ARGUMENT_SLOTS: usize = 16;
pub const STORE_HANDLE_SLOT: usize = 2;
// A marked pointer is an opaque live handle, never a string.
pub const STORE_HANDLE_PRESENT: u64 = 1 << (ARGUMENT_SLOTS + STORE_HANDLE_SLOT);

#[repr(C)]
pub struct Request {
    pub numbers: [f64; ARGUMENT_SLOTS],
    pub present: u64,
    pub strings: [*const u8; ARGUMENT_SLOTS],
    pub lengths: [usize; ARGUMENT_SLOTS],
    pub text_present: u64,
}
