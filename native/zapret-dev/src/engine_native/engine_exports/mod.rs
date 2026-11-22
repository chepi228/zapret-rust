mod bootstrap_local;
mod cleanup;
mod cli_options;
mod config;
mod conntrack;
mod console;
mod helpers;
mod list_options;
mod lists;
mod lua_arguments;
mod params;
mod platform;
mod pools;
mod profile_filters;
mod profile_layout;
mod profile_options;
mod profiles;
mod protocol;
mod ring_loader;
mod startup;
#[path = "../windows_startup_params.rs"]
mod startup_params;
mod state;

pub(crate) use state::QUIT;

use core::ffi::{c_char, c_int};

type Log = unsafe extern "C" fn(*const c_char, ...) -> c_int;

unsafe extern "C" {
    fn DLOG(format: *const c_char, ...) -> c_int;
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
}
