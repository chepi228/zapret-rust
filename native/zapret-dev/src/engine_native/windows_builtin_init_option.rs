use core::ffi::CStr;

// A lone colon is not a valid Lua chunk. Keep built-in registration in the
// ordered initialization list alongside regular --lua-init arguments.
pub(super) const BUILTIN_SCRIPT: &CStr = c":";
