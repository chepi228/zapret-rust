//! Execute the main startup and termination actions on the native engine thread.
use super::windows_startup_params::PARAMS as LAYOUT;
use super::*;

const PREFIX_STOP: u32 = 0;
const PREFIX_SERVICE: u32 = 1;
const PREFIX_PARAMS: u32 = 4;
const PREFIX_BANNER: u32 = 5;
const PREFIX_HELP: u32 = 6;
const PREFIX_BLOBS: u32 = 13;
const PREFIX_PROFILE: u32 = 14;
const PREFIX_EXIT: u32 = 19;

const FINISH_CAPTURE: u32 = MAIN_FINISH_BASE + 4;
const FINISH_RUN: u32 = MAIN_FINISH_BASE + 6;
const FINISH_CLEANUP: u32 = MAIN_FINISH_BASE + 7;
const FINISH_RETURN: u32 = MAIN_FINISH_BASE + 10;
const FINISH_EXIT_SUCCESS: u32 = MAIN_FINISH_BASE + 11;
const FINISH_EXIT_ERROR: u32 = MAIN_FINISH_BASE + 12;
const FINISH_PROFILE_ERROR: u32 = MAIN_FINISH_BASE + 13;

#[repr(C)]
struct Banner {
    version: *const c_char,
    revision: *const c_char,
    lua_compat: u32,
    pinned: bool,
}

#[repr(C)]
struct CaptureResult {
    status: u32,
    error: u32,
}

const _: () = {
    let pointer = size_of::<*const c_void>();
    assert!(size_of::<Banner>() == 2 * pointer + 8);
    assert!(offset_of!(Banner, lua_compat) == 2 * pointer);
    assert!(size_of::<CaptureResult>() == 8);
};

unsafe extern "C" {
    #[link_name = "params"]
    static mut PARAMS: u8;
    static zapret_engine_banner: Banner;
    static fake_tls_clienthello_default: [u8; 680];
    static fake_http_request_default: *const c_char;

    fn zapret_native_cli_count() -> usize;
    fn wf_getenv(name: *const c_char) -> *mut c_char;
    fn zapret_native_cli_read_blob(argument: *const c_char, maximum: usize, reserve: usize)
    -> bool;
    fn zapret_native_main_prefix_step(cursor: *mut PrefixCursor, slots: *const PrefixSlots) -> u32;
    fn native_profile_finish(flow: *mut ProfileFlow) -> u32;
    fn cleanup_args(params: *mut c_void);
    fn native_startup_validate(profiles: u32, templates: u32) -> bool;
    fn zapret_native_lifecycle_prepare(params: *mut c_void, dry: bool) -> u32;
    fn zapret_native_lifecycle_release_mutex(slot: *mut *mut c_void);
    fn zapret_crt_close_std();
    fn init_params(params: *mut c_void);
    fn zapret_native_main_version(
        pinned: bool,
        version: *const c_char,
        revision: *const c_char,
        lua_compat: u32,
    );
    fn exithelp() -> !;
    fn native_profile_next(flow: *mut ProfileFlow, name: *const c_char) -> u32;
    fn native_publish_const_blob(
        head: *mut c_void,
        name: *const c_char,
        bytes: *const c_void,
        length: usize,
        reserve: usize,
    ) -> *mut c_void;
    fn zapret_engine_default_blobs(
        head: *mut c_void,
        tls: *const u8,
        tls_length: usize,
        http: *const *const c_char,
        publish: unsafe extern "C" fn(
            *mut c_void,
            *const c_char,
            *const c_void,
            usize,
            usize,
        ) -> *mut c_void,
    ) -> bool;
    fn zapret_native_capture_prepare(
        capture: *const CaptureCli,
        dry: bool,
        mutex: *mut *mut c_void,
    ) -> CaptureResult;
}

unsafe extern "C-unwind" {
    fn service_run(argc: c_int, argv: *mut *mut c_char) -> bool;
    fn native_profile_exit(status: u32, name: *const c_char);
    fn exit_clean(code: c_int) -> !;
    fn exithelp_clean() -> !;
    fn win_main() -> c_int;
    fn cleanup_params(params: *mut c_void);
}

unsafe fn apply_default_blobs(params: *mut u8) {
    let head = unsafe { params.add(LAYOUT.blobs) }.cast();
    if !unsafe {
        zapret_engine_default_blobs(
            head,
            fake_tls_clienthello_default.as_ptr(),
            fake_tls_clienthello_default.len(),
            &raw const fake_http_request_default,
            native_publish_const_blob,
        )
    } {
        unsafe { exit_clean(1) };
    }
}

const OPS: MainOps = MainOps {
    option_count: zapret_native_cli_count,
    environment: wf_getenv,
    read_blob: zapret_native_cli_read_blob,
    prefix: zapret_native_main_prefix_step,
    finish: FinishOps {
        profile: native_profile_finish,
        arguments: cleanup_args,
        validate: native_startup_validate,
        prepare: zapret_native_lifecycle_prepare,
        release: zapret_native_lifecycle_release_mutex,
        close_stdio: zapret_crt_close_std,
    },
};

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_engine_main(argc: c_int, argv: *mut *mut c_char) -> c_int {
    let mut state = MaybeUninit::<MainState>::uninit();
    let params = &raw mut PARAMS;
    unsafe {
        zapret_native_main_begin(state.as_mut_ptr(), argc, argv);
        let mut state = state.assume_init();
        loop {
            match zapret_native_main_advance(&mut state, params.cast(), &OPS) {
                PREFIX_STOP => return 0,
                PREFIX_SERVICE => state.prefix.available = service_run(state.argc, state.argv),
                PREFIX_PARAMS => init_params(params.cast()),
                PREFIX_BANNER => {
                    let banner = &zapret_engine_banner;
                    zapret_native_main_version(
                        banner.pinned,
                        banner.version,
                        banner.revision,
                        banner.lua_compat,
                    );
                }
                PREFIX_HELP => exithelp(),
                PREFIX_BLOBS => apply_default_blobs(params),
                PREFIX_PROFILE => {
                    let status = native_profile_next(state.profiles.as_mut_ptr(), ptr::null());
                    native_profile_exit(status, ptr::null());
                }
                MAIN_ARGUMENT_HELP => exithelp_clean(),
                MAIN_ARGUMENT_EXIT => exit_clean(state.exit_code),
                FINISH_PROFILE_ERROR => {
                    let profile = state.profile.assume_init();
                    native_profile_exit(state.finish.feedback.status, (*profile).name);
                }
                FINISH_CAPTURE => {
                    let result = zapret_native_capture_prepare(
                        state.capture.as_ptr(),
                        state.options.assume_init_ref().dry,
                        &mut state.finish.mutex,
                    );
                    state.finish.feedback.status = result.status;
                }
                FINISH_RUN => state.finish.feedback.result = win_main(),
                FINISH_CLEANUP => cleanup_params(params.cast()),
                FINISH_RETURN => return state.finish.flow.result,
                FINISH_EXIT_SUCCESS => exit_clean(0),
                PREFIX_EXIT | FINISH_EXIT_ERROR => exit_clean(1),
                _ => {
                    DLOG_ERR(c"invalid main finish state\n".as_ptr());
                    exit_clean(1);
                }
            }
        }
    }
}
