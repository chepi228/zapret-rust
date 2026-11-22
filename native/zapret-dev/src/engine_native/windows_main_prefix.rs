//! Run local main startup work between operations owned by the C frame.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    ptr,
};

mod windows_main_prefix_types;
mod windows_startup_params;
use windows_main_prefix_types::{HASH_COUNT, PrefixCursor, PrefixSlots, ProfileFlow};
use windows_startup_params::PARAMS as LAYOUT;

const CONFIG_WORD_COUNT: usize = 0;
const CONFIG_WORDS: usize = size_of::<usize>();

type Arguments = *mut *mut c_char;
type Log = unsafe extern "C" fn(*const c_char, ...) -> c_int;

#[repr(C, align(8))]
struct Params([u8; LAYOUT.size]);

#[repr(u32)]
enum HostAction {
    Stop = 0,
    Service = 1,
    Params = 4,
    Banner = 5,
    Help = 6,
    Blobs = 13,
    Profile = 14,
    Exit = 19,
    Ready = 20,
}

unsafe extern "C" {
    #[link_name = "params"]
    static mut PARAMS: Params;

    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
    fn zapret_engine_prefix_next(
        phase: u32,
        available: bool,
        argc: c_int,
        first: u8,
        error: Log,
    ) -> u32;
    fn WinSetIcon();
    fn _time64(output: *mut i64) -> i64;
    fn zapret_srandom(seed: u32);
    fn set_env_exedir(name: *const c_char) -> bool;
    fn zapret_crt_set_console_io_buffering();
    fn zapret_prefix_prepare6();
    fn prepare_low_appdata() -> bool;
    fn zapret_config_from_file(filename: *const c_char) -> bool;
    fn zapret_engine_capture_capacity() -> usize;
    fn calloc(count: usize, size: usize) -> *mut c_void;
    fn alloc_windivert_portfilters(params: *mut u8) -> bool;
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_main_prefix_step(
    cursor: &mut PrefixCursor,
    slots: &PrefixSlots,
) -> HostAction {
    let params = (&raw mut PARAMS).cast::<u8>();
    // The profile callback can replace the current entry before returning.
    if cursor.phase == HostAction::Profile as u32 {
        unsafe {
            let current = (*slots.profiles).current;
            slots.entry.write(current);
            // engine_main_prefix_abi.h checks that dp starts the entry record.
            slots.profile.write(current);
        }
    }

    loop {
        unsafe {
            cursor.phase = zapret_engine_prefix_next(
                cursor.phase,
                cursor.available,
                slots.argc.read(),
                cursor.first,
                DLOG_ERR,
            );
            match cursor.phase {
                1 => return HostAction::Service,
                3 => WinSetIcon(),
                4 => return HostAction::Params,
                5 => return HostAction::Banner,
                6 => return HostAction::Help,
                7 => zapret_srandom(_time64(ptr::null_mut()) as u32),
                8 => {
                    set_env_exedir(slots.argv.read().read());
                }
                9 => zapret_crt_set_console_io_buffering(),
                10 => zapret_prefix_prepare6(),
                11 => slots.hashes.write_bytes(0, HASH_COUNT),
                12 => {
                    prepare_low_appdata();
                }
                13 => return HostAction::Blobs,
                14 => {
                    slots.profiles.write(ProfileFlow {
                        profiles: params.add(LAYOUT.profile_head).cast(),
                        templates: params.add(LAYOUT.template_head).cast(),
                        current: ptr::null_mut(),
                        count: 0,
                        template_count: 0,
                        skip: false,
                        template: false,
                    });
                    return HostAction::Profile;
                }
                15 => cursor.first = slots.argv.read().add(1).read().cast::<u8>().read(),
                16 => {
                    let filename = slots.argv.read().add(1).read().add(1);
                    if !zapret_config_from_file(filename) {
                        return HostAction::Exit;
                    }
                    slots
                        .argv
                        .write(params.add(CONFIG_WORDS).cast::<Arguments>().read());
                    slots
                        .argc
                        .write(params.add(CONFIG_WORD_COUNT).cast::<usize>().read() as c_int);
                }
                17 => {
                    let filter = calloc(1, zapret_engine_capture_capacity());
                    params
                        .add(LAYOUT.capture_filter)
                        .cast::<*mut c_void>()
                        .write(filter);
                    cursor.available = !filter.is_null();
                }
                18 => cursor.available = alloc_windivert_portfilters(params),
                19 => return HostAction::Exit,
                20 => return HostAction::Ready,
                _ => return HostAction::Stop,
            }
        }
    }
}
