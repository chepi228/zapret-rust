//! Bind main's options and native operations to the shared Rust entry policy.
#![no_std]

use core::{
    ffi::{c_char, c_int, c_void},
    mem::{MaybeUninit, offset_of},
    ptr,
};

#[cfg(zapret_engine_production)]
mod windows_main_host;
mod windows_main_prefix_types;
#[cfg(zapret_engine_production)]
mod windows_startup_params;
use windows_main_prefix_types::{HASH_COUNT, PrefixCursor, PrefixSlots, ProfileFlow};

type Log = unsafe extern "C" fn(*const c_char, ...) -> c_int;
type ListSlot = *mut *mut c_void;
type Environment = unsafe extern "C" fn(*const c_char) -> *mut c_char;
type BlobRead = unsafe extern "C" fn(*const c_char, usize, usize) -> bool;

#[repr(C)]
struct OptionSpec {
    name: *const c_char,
    has_arg: c_int,
    flag: *mut c_int,
    value: c_int,
}

#[repr(C)]
struct Profile {
    number: u32,
    name: *const c_char,
}

#[repr(C)]
struct Cli {
    index: c_int,
    text: *mut c_char,
    flow: *mut ProfileFlow,
    entry: *mut *mut c_void,
    profile: *mut *mut Profile,
    anonymous: [ListSlot; 4],
    payload: *mut u64,
    incoming: *mut c_void,
    outgoing: *mut c_void,
    dry: *mut bool,
    capture: *mut c_void,
}

#[repr(C, align(4))]
struct OptionRange([MaybeUninit<u8>; 20]);

#[repr(C)]
struct MainOptions {
    anonymous: [*mut c_void; 4],
    payload: u64,
    incoming: OptionRange,
    outgoing: OptionRange,
    index: u32,
    sub_index: u32,
    dry: bool,
    duplicate: bool,
    ipv4: bool,
    ipv6: bool,
    lan: bool,
    loopback: bool,
    empty: bool,
    save: [c_char; 256],
}

#[repr(C)]
struct CaptureCli {
    save: *mut c_char,
    save_capacity: usize,
    ipv4: *mut bool,
    ipv6: *mut bool,
    lan: *mut bool,
    loopback: *mut bool,
    empty: *mut bool,
    duplicate: *mut bool,
    index: *mut u32,
    sub_index: *mut u32,
    hashes: *mut u32,
}

#[repr(C)]
struct Bindings {
    numeric: unsafe extern "C" fn(c_int, *const c_char, *mut Profile) -> c_int,
    startup: unsafe extern "C" fn(c_int, *const c_char) -> c_int,
    lists: unsafe extern "C" fn(
        c_int,
        *const c_char,
        *mut Profile,
        bool,
        ListSlot,
        ListSlot,
        ListSlot,
        ListSlot,
    ) -> c_int,
    profile: unsafe extern "C" fn(
        c_int,
        *const c_char,
        *mut Profile,
        *mut u64,
        *mut c_void,
        *mut c_void,
    ) -> c_int,
    capture: unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> c_int,
    control: unsafe extern "C" fn(
        c_int,
        *const c_char,
        *mut ProfileFlow,
        *mut *mut c_void,
        *mut *mut Profile,
        ListSlot,
        ListSlot,
        ListSlot,
        ListSlot,
        *mut u64,
        *mut c_void,
        *mut c_void,
        *mut bool,
    ) -> c_int,
    options: unsafe extern "C" fn() -> *const OptionSpec,
}

#[repr(C)]
struct ScanOps {
    options: *const OptionSpec,
    count: usize,
    context: *mut c_void,
    category: unsafe extern "C" fn(*mut c_void, u32) -> c_int,
    argument: *mut *mut c_char,
    index: *mut c_int,
    stderr_sink: Option<Log>,
    dry: *const bool,
}

#[repr(C)]
struct ScanCursor {
    next: usize,
    stop_at_operand: bool,
}

#[repr(C)]
struct Route {
    action: u32,
    status: u32,
}

#[repr(C)]
struct ScanEvent {
    route: Route,
    blob_maximum: usize,
    blob_reserve: usize,
}

#[repr(C)]
struct RouteEffect {
    exit_code: c_int,
    terminate: bool,
    handled: bool,
}

#[repr(C)]
struct ArgumentOps {
    options: *const OptionSpec,
    count: usize,
    environment: Environment,
    stderr_sink: Option<Log>,
    read_blob: BlobRead,
}

#[repr(u32)]
enum ArgumentAction {
    Done,
    Help,
    Exit,
}

#[repr(C)]
struct ArgumentResult {
    action: ArgumentAction,
    exit_code: c_int,
}

const ENTRY_PARSE_DONE: u32 = 7;
const ENTRY_PARSE_HELP: u32 = 8;
const ENTRY_LOAD_BLOB: u32 = 9;

#[repr(C)]
struct Finish {
    phase: u32,
    result: c_int,
}

#[repr(C)]
struct FinishFeedback {
    status: u32,
    result: c_int,
}

#[repr(C)]
struct FinishState {
    flow: Finish,
    feedback: FinishFeedback,
    mutex: *mut c_void,
}

#[repr(C)]
struct FinishOps {
    profile: unsafe extern "C" fn(*mut ProfileFlow) -> u32,
    arguments: unsafe extern "C" fn(*mut c_void),
    validate: unsafe extern "C" fn(u32, u32) -> bool,
    prepare: unsafe extern "C" fn(*mut c_void, bool) -> u32,
    release: unsafe extern "C" fn(*mut *mut c_void),
    close_stdio: unsafe extern "C" fn(),
}

#[repr(C)]
struct MainState {
    options: MaybeUninit<MainOptions>,
    hashes: [MaybeUninit<u32>; HASH_COUNT],
    profiles: MaybeUninit<ProfileFlow>,
    entry: MaybeUninit<*mut c_void>,
    profile: MaybeUninit<*mut Profile>,
    capture: MaybeUninit<CaptureCli>,
    prefix: PrefixCursor,
    finish: FinishState,
    argv: *mut *mut c_char,
    argc: c_int,
    exit_code: c_int,
    parsed: bool,
}

#[repr(C)]
struct MainOps {
    option_count: unsafe extern "C" fn() -> usize,
    environment: Environment,
    read_blob: BlobRead,
    prefix: unsafe extern "C" fn(*mut PrefixCursor, *const PrefixSlots) -> u32,
    finish: FinishOps,
}

const PREFIX_READY: u32 = 20;
const MAIN_ARGUMENT_HELP: u32 = 21;
const MAIN_ARGUMENT_EXIT: u32 = 22;
const MAIN_FINISH_BASE: u32 = 32;

const FINISH_PROFILE: u32 = 1;
const FINISH_ARGUMENTS: u32 = 2;
const FINISH_VALIDATE: u32 = 3;
const FINISH_LIFECYCLE: u32 = 5;
const FINISH_MUTEX: u32 = 8;
const FINISH_STDIO: u32 = 9;

const _: () = {
    let pointer = size_of::<*const c_void>();
    assert!(size_of::<OptionSpec>() == 4 * pointer);
    assert!(offset_of!(OptionSpec, name) == 0 && offset_of!(OptionSpec, has_arg) == pointer);
    assert!(
        offset_of!(OptionSpec, flag) == 2 * pointer && offset_of!(OptionSpec, value) == 3 * pointer
    );
    assert!(offset_of!(Profile, name) == pointer);
    assert!(offset_of!(ProfileFlow, skip) == 3 * pointer + 8);
    assert!(size_of::<Cli>() == 14 * pointer);
    assert!(offset_of!(Cli, anonymous) == 5 * pointer);
    assert!(offset_of!(Cli, capture) == 13 * pointer);
    assert!(size_of::<MainOptions>() == 320 + 4 * pointer);
    assert!(align_of::<MainOptions>() == 8);
    assert!(offset_of!(MainOptions, incoming) == 4 * pointer + 8);
    assert!(offset_of!(MainOptions, save) == 4 * pointer + 63);
    assert!(size_of::<CaptureCli>() == 11 * pointer);
    assert!(offset_of!(CaptureCli, hashes) == 10 * pointer);
    assert!(size_of::<FinishState>() == 16 + pointer && size_of::<FinishOps>() == 6 * pointer);
    assert!(offset_of!(FinishState, feedback) == 8 && offset_of!(FinishState, mutex) == 16);
    let (state_size, prefix, argc) = if pointer == 4 {
        (520, 476, 508)
    } else {
        (616, 560, 600)
    };
    assert!(size_of::<MainState>() == state_size && align_of::<MainState>() == 8);
    assert!(offset_of!(MainState, prefix) == prefix && offset_of!(MainState, finish) == prefix + 8);
    assert!(offset_of!(MainState, argc) == argc);
    assert!(size_of::<MainOps>() == 10 * pointer && offset_of!(MainOps, finish) == 4 * pointer);
    assert!(size_of::<ArgumentOps>() == 5 * pointer && size_of::<ArgumentResult>() == 8);
    assert!(offset_of!(ArgumentOps, read_blob) == 4 * pointer);
    assert!(size_of::<Bindings>() == 7 * pointer && align_of::<Bindings>() == pointer);
    assert!(offset_of!(Bindings, numeric) == 0);
    assert!(offset_of!(Bindings, startup) == pointer);
    assert!(offset_of!(Bindings, lists) == 2 * pointer);
    assert!(offset_of!(Bindings, profile) == 3 * pointer);
    assert!(offset_of!(Bindings, capture) == 4 * pointer);
    assert!(offset_of!(Bindings, control) == 5 * pointer);
    assert!(offset_of!(Bindings, options) == 6 * pointer);
    assert!(size_of::<ScanOps>() == 8 * pointer);
    assert!(
        offset_of!(ScanOps, argument) == 4 * pointer && offset_of!(ScanOps, dry) == 7 * pointer
    );
    assert!(size_of::<ScanCursor>() == 2 * pointer && size_of::<ScanEvent>() == 8 + 2 * pointer);
    assert!(size_of::<RouteEffect>() == 8);
};

#[cfg(zapret_engine_production)]
unsafe extern "C" {
    fn engine_numeric_option(index: c_int, text: *const c_char, profile: *mut Profile) -> c_int;
    fn engine_startup_option(index: c_int, text: *const c_char) -> c_int;
    fn engine_list_option(
        index: c_int,
        text: *const c_char,
        profile: *mut Profile,
        skip: bool,
        host: ListSlot,
        host_exclude: ListSlot,
        ip: ListSlot,
        ip_exclude: ListSlot,
    ) -> c_int;
    fn engine_profile_filter(
        index: c_int,
        text: *const c_char,
        profile: *mut Profile,
        payload: *mut u64,
        incoming: *mut c_void,
        outgoing: *mut c_void,
    ) -> c_int;
    fn engine_capture_option(index: c_int, text: *const c_char, capture: *mut c_void) -> c_int;
    fn engine_control_option(
        index: c_int,
        text: *const c_char,
        flow: *mut ProfileFlow,
        entry: *mut *mut c_void,
        profile: *mut *mut Profile,
        host: ListSlot,
        host_exclude: ListSlot,
        ip: ListSlot,
        ip_exclude: ListSlot,
        payload: *mut u64,
        incoming: *mut c_void,
        outgoing: *mut c_void,
        dry: *mut bool,
    ) -> c_int;
    fn zapret_native_cli_options() -> *const OptionSpec;
}

#[cfg(zapret_engine_production)]
#[unsafe(export_name = "zapret_native_cli_bindings")]
#[unsafe(link_section = ".rdata$zapret_native_cli_bindings")]
static CLI_BINDINGS: Bindings = Bindings {
    numeric: engine_numeric_option,
    startup: engine_startup_option,
    lists: engine_list_option,
    profile: engine_profile_filter,
    capture: engine_capture_option,
    control: engine_control_option,
    options: zapret_native_cli_options,
};

unsafe extern "C" {
    #[cfg(not(zapret_engine_production))]
    #[link_name = "zapret_native_cli_bindings"]
    static CLI_BINDINGS: Bindings;
    fn DLOG_ERR(format: *const c_char, ...) -> c_int;
    fn zapret_engine_scan_begin(environment: Environment) -> ScanCursor;
    fn zapret_engine_scan_arguments(
        argc: c_int,
        argv: *mut *mut c_char,
        cursor: *mut ScanCursor,
        ops: *const ScanOps,
    ) -> ScanEvent;
    fn zapret_engine_route_effect(
        route: Route,
        index: c_int,
        context: *const c_void,
        observe: unsafe extern "C" fn(*const c_void, u32) -> *const c_char,
        error: Log,
    ) -> RouteEffect;
    fn zapret_engine_finish_step(flow: *mut Finish, feedback: *const FinishFeedback) -> u32;
    fn zapret_engine_main_defaults(options: *mut MainOptions);
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_main_bind(
    options: *mut MainOptions,
    hashes: *mut u32,
    flow: *mut ProfileFlow,
    entry: *mut *mut c_void,
    profile: *mut *mut Profile,
    capture: *mut CaptureCli,
    cli: *mut Cli,
) {
    unsafe {
        capture.write(CaptureCli {
            save: (&raw mut (*options).save).cast(),
            save_capacity: 256,
            ipv4: &raw mut (*options).ipv4,
            ipv6: &raw mut (*options).ipv6,
            lan: &raw mut (*options).lan,
            loopback: &raw mut (*options).loopback,
            empty: &raw mut (*options).empty,
            duplicate: &raw mut (*options).duplicate,
            index: &raw mut (*options).index,
            sub_index: &raw mut (*options).sub_index,
            hashes,
        });
        let slots = (&raw mut (*options).anonymous).cast::<*mut c_void>();
        cli.write(Cli {
            index: 0,
            text: ptr::null_mut(),
            flow,
            entry,
            profile,
            anonymous: [slots, slots.add(1), slots.add(2), slots.add(3)],
            payload: &raw mut (*options).payload,
            incoming: (&raw mut (*options).incoming).cast(),
            outgoing: (&raw mut (*options).outgoing).cast(),
            dry: &raw mut (*options).dry,
            capture: capture.cast(),
        });
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_finish_advance(
    state: *mut FinishState,
    params: *mut c_void,
    profiles: *mut ProfileFlow,
    dry: *const bool,
    argc: *mut c_int,
    argv: *mut *mut *mut c_char,
    ops: *const FinishOps,
) -> u32 {
    unsafe {
        loop {
            let action =
                zapret_engine_finish_step(&raw mut (*state).flow, &raw const (*state).feedback);
            match action {
                FINISH_PROFILE => {
                    (*state).feedback.status = ((*ops).profile)(profiles);
                }
                FINISH_ARGUMENTS => {
                    ((*ops).arguments)(params);
                    argv.write(ptr::null_mut());
                    argc.write(0);
                }
                FINISH_VALIDATE => {
                    let valid = ((*ops).validate)((*profiles).count, (*profiles).template_count);
                    (*state).feedback.status = u32::from(!valid);
                }
                FINISH_LIFECYCLE => {
                    (*state).feedback.status = ((*ops).prepare)(params, dry.read());
                }
                FINISH_MUTEX => ((*ops).release)(&raw mut (*state).mutex),
                FINISH_STDIO => ((*ops).close_stdio)(),
                // Lua, native capture, and process exits run on the caller's frame.
                _ => return action,
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_main_begin(
    state: *mut MainState,
    argc: c_int,
    argv: *mut *mut c_char,
) {
    unsafe {
        state.write(MainState {
            options: MaybeUninit::uninit(),
            hashes: [MaybeUninit::uninit(); HASH_COUNT],
            profiles: MaybeUninit::uninit(),
            entry: MaybeUninit::uninit(),
            profile: MaybeUninit::uninit(),
            capture: MaybeUninit::uninit(),
            prefix: PrefixCursor {
                phase: 0,
                available: false,
                first: 0,
            },
            finish: FinishState {
                flow: Finish {
                    phase: 0,
                    result: 0,
                },
                feedback: FinishFeedback {
                    status: 0,
                    result: 0,
                },
                mutex: ptr::null_mut(),
            },
            argv,
            argc,
            exit_code: 0,
            parsed: false,
        });
        zapret_engine_main_defaults((&raw mut (*state).options).cast());
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_main_advance(
    state: *mut MainState,
    params: *mut c_void,
    ops: *const MainOps,
) -> u32 {
    unsafe {
        let options = (&raw mut (*state).options).cast::<MainOptions>();
        let slots = PrefixSlots {
            argc: &raw mut (*state).argc,
            argv: &raw mut (*state).argv,
            hashes: (&raw mut (*state).hashes).cast(),
            profiles: (&raw mut (*state).profiles).cast(),
            entry: (&raw mut (*state).entry).cast(),
            profile: (&raw mut (*state).profile).cast(),
        };
        if !(*state).parsed {
            let action = ((*ops).prefix)(&raw mut (*state).prefix, &slots);
            if action != PREFIX_READY {
                return action;
            }

            let mut cli = MaybeUninit::<Cli>::uninit();
            zapret_native_main_bind(
                options,
                slots.hashes,
                slots.profiles,
                slots.entry,
                slots.profile.cast(),
                (&raw mut (*state).capture).cast(),
                cli.as_mut_ptr(),
            );
            let arguments = ArgumentOps {
                options: (CLI_BINDINGS.options)(),
                count: ((*ops).option_count)(),
                environment: (*ops).environment,
                stderr_sink: None,
                read_blob: (*ops).read_blob,
            };
            let result =
                zapret_native_cli_run((*state).argc, (*state).argv, cli.as_mut_ptr(), &arguments);
            (*state).parsed = true;
            match result.action {
                ArgumentAction::Done => {}
                ArgumentAction::Help => return MAIN_ARGUMENT_HELP,
                ArgumentAction::Exit => {
                    (*state).exit_code = result.exit_code;
                    return MAIN_ARGUMENT_EXIT;
                }
            }
        }
        MAIN_FINISH_BASE
            + zapret_native_finish_advance(
                &raw mut (*state).finish,
                params,
                slots.profiles,
                &raw const (*options).dry,
                slots.argc,
                slots.argv,
                &raw const (*ops).finish,
            )
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn native_engine_option_category(context: *mut c_void, category: u32) -> c_int {
    if category >= 6 {
        return 0;
    }
    let cli = context.cast::<Cli>();
    unsafe {
        // Each category can replace the active profile, so read the live slots
        // for this call and retain no references across the callback.
        let bindings = &CLI_BINDINGS;
        let index = (*cli).index;
        let text = (*cli).text;
        match category {
            0 => (bindings.numeric)(index, text, *(*cli).profile),
            1 => (bindings.startup)(index, text),
            2 => {
                let [hosts, exclude_hosts, ips, exclude_ips] = (*cli).anonymous;
                (bindings.lists)(
                    index,
                    text,
                    *(*cli).profile,
                    (*(*cli).flow).skip,
                    hosts,
                    exclude_hosts,
                    ips,
                    exclude_ips,
                )
            }
            3 => (bindings.profile)(
                index,
                text,
                *(*cli).profile,
                (*cli).payload,
                (*cli).incoming,
                (*cli).outgoing,
            ),
            4 => (bindings.capture)(index, text, (*cli).capture),
            5 => {
                let [hosts, exclude_hosts, ips, exclude_ips] = (*cli).anonymous;
                (bindings.control)(
                    index,
                    text,
                    (*cli).flow,
                    (*cli).entry,
                    (*cli).profile,
                    hosts,
                    exclude_hosts,
                    ips,
                    exclude_ips,
                    (*cli).payload,
                    (*cli).incoming,
                    (*cli).outgoing,
                    (*cli).dry,
                )
            }
            _ => 0,
        }
    }
}

unsafe extern "C" fn option_text(context: *const c_void, field: u32) -> *const c_char {
    let cli = context.cast::<Cli>();
    unsafe {
        match field {
            1 => (*((CLI_BINDINGS.options)()).offset((*cli).index as isize)).name,
            2 => (**(*cli).profile).name,
            3 => (*cli).text,
            _ => ptr::null(),
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_cli_route_effect(cli: *mut Cli, route: Route) -> RouteEffect {
    unsafe { zapret_engine_route_effect(route, (*cli).index, cli.cast(), option_text, DLOG_ERR) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_cli_scan(
    argc: c_int,
    argv: *mut *mut c_char,
    cursor: *mut ScanCursor,
    cli: *mut Cli,
    options: *const OptionSpec,
    count: usize,
    stderr_sink: Option<Log>,
) -> ScanEvent {
    let ops = ScanOps {
        options,
        count,
        context: cli.cast(),
        category: native_engine_option_category,
        argument: unsafe { &raw mut (*cli).text },
        index: unsafe { &raw mut (*cli).index },
        stderr_sink,
        dry: unsafe { (*cli).dry },
    };
    unsafe { zapret_engine_scan_arguments(argc, argv, cursor, &ops) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_native_cli_run(
    argc: c_int,
    argv: *mut *mut c_char,
    cli: *mut Cli,
    ops: *const ArgumentOps,
) -> ArgumentResult {
    unsafe {
        let mut cursor = zapret_engine_scan_begin((*ops).environment);
        loop {
            let event = zapret_native_cli_scan(
                argc,
                argv,
                &mut cursor,
                cli,
                (*ops).options,
                (*ops).count,
                (*ops).stderr_sink,
            );
            let (action, exit_code) = match event.route.action {
                ENTRY_PARSE_DONE => (ArgumentAction::Done, 0),
                ENTRY_PARSE_HELP => (ArgumentAction::Help, 0),
                ENTRY_LOAD_BLOB => {
                    if ((*ops).read_blob)((*cli).text, event.blob_maximum, event.blob_reserve) {
                        continue;
                    }
                    (ArgumentAction::Exit, 1)
                }
                _ => {
                    let outcome = zapret_native_cli_route_effect(cli, event.route);
                    let action = if outcome.terminate {
                        ArgumentAction::Exit
                    } else {
                        ArgumentAction::Done
                    };
                    (action, outcome.exit_code)
                }
            };
            return ArgumentResult { action, exit_code };
        }
    }
}
