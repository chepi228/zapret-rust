//! Resource-free execution context policy between C-owned Lua operations.
use crate::{packet::Packet, play_prolog::connection, profile_config::profile_number};
use std::{
    ffi::{c_char, c_void},
    ptr,
};

#[repr(C)]
pub(super) struct Context {
    pub(super) number: u32,
    function: *const c_char,
    instance: *const c_char,
    pub(super) profile: *const c_void,
    packet: *const c_void,
    pub(super) track: *mut c_void,
    pub(super) incoming: u8,
    cancelled: u8,
    valid: u8,
}

#[repr(C)]
struct Scope {
    instance: *const c_char,
    profile: u32,
    registry: i32,
    incoming: bool,
    outgoing: bool,
    tracked: bool,
}

#[repr(C)]
struct Span {
    data: *const u8,
    length: usize,
}

pub(super) fn aligned<T>(value: *const T) -> bool {
    !value.is_null() && value.is_aligned()
}

fn direction(value: u32) -> Option<(bool, bool)> {
    match value {
        0 => Some((true, true)),
        1 => Some((true, false)),
        2 => Some((false, true)),
        _ => None,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_context_init(context: *mut Context) -> bool {
    if !aligned(context) {
        return false;
    }
    // This is fresh C userdata; zeroing also preserves the original padding.
    unsafe { context.write_bytes(0, 1) };
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_context_valid(context: *const Context, length: usize) -> bool {
    length == size_of::<Context>() && aligned(context) && unsafe { (*context).valid != 0 }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_context_prepare(
    context: *mut Context,
    profile: *const c_void,
    track: *mut c_void,
    packet: *const c_void,
    incoming: bool,
) -> bool {
    if !aligned(context) {
        return false;
    }
    unsafe {
        (*context).profile = profile;
        (*context).track = track;
        (*context).packet = packet;
        (*context).cancelled = 0;
        (*context).incoming = u8::from(incoming);
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_context_active(context: *mut Context, active: bool) -> bool {
    if !aligned(context) {
        return false;
    }
    unsafe { (*context).valid = u8::from(active) };
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_context_rule(
    context: *mut Context,
    function: *const c_char,
    number: u32,
    output: *mut c_char,
    capacity: usize,
) -> bool {
    if !aligned(context) || capacity > isize::MAX as usize || output.is_null() && capacity != 0 {
        return false;
    }
    let profile = unsafe { (*context).profile };
    if !aligned(profile.cast::<u64>()) {
        return false;
    }
    let profile_number = unsafe { profile_number(profile) };
    unsafe {
        (*context).function = function;
        (*context).number = number;
        crate::lua_instance::zapret_desync_instance(
            function,
            profile_number,
            number,
            output,
            capacity,
        );
        (*context).instance = output;
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_context_scope(
    context: *const Context,
    selection: u32,
    instance: bool,
    output: *mut Scope,
) -> bool {
    let Some((incoming, outgoing)) = direction(selection) else {
        return false;
    };
    if !aligned(context) || !aligned(output) {
        return false;
    }
    let track = unsafe { (*context).track };
    if !track.is_null() && !aligned(track.cast::<u64>()) {
        return false;
    }
    let mut scope = Scope {
        instance: unsafe { (*context).instance },
        profile: 0,
        registry: 0,
        incoming,
        outgoing,
        tracked: !track.is_null(),
    };
    if instance && scope.tracked {
        let profile = unsafe { (*context).profile };
        if !aligned(profile.cast::<u64>()) || scope.instance.is_null() {
            return false;
        }
        scope.profile = unsafe { profile_number(profile) };
        scope.registry = unsafe { (*connection(track)).instance_cutoff };
    }
    unsafe { output.write(scope) };
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_context_cutoff(context: *const Context, selection: u32) -> bool {
    let Some((incoming, outgoing)) = direction(selection) else {
        return false;
    };
    if !aligned(context) {
        return false;
    }
    let track = unsafe { (*context).track };
    if track.is_null() {
        return true;
    }
    if !aligned(track.cast::<u64>()) {
        return false;
    }
    let track = unsafe { connection(track) };
    // These flags only transition to true, including repeated/narrower calls.
    unsafe {
        if incoming {
            ptr::addr_of_mut!((*track).lua_in_cutoff).write(true);
        }
        if outgoing {
            ptr::addr_of_mut!((*track).lua_out_cutoff).write(true);
        }
    }
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_context_cancel(context: *mut Context) -> bool {
    if !aligned(context) {
        return false;
    }
    unsafe { (*context).cancelled = 1 };
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_context_cancelled(context: *const Context) -> bool {
    aligned(context) && unsafe { (*context).cancelled != 0 }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_context_packet(context: *const Context, output: *mut Span) -> bool {
    if !aligned(context) || !aligned(output) {
        return false;
    }
    let packet = unsafe { (*context).packet.cast::<Packet>() };
    if !aligned(packet) {
        return false;
    }
    let (data, length) = unsafe { ((*packet).data, (*packet).length) };
    if length > isize::MAX as usize || data.is_null() && length != 0 {
        return false;
    }
    unsafe { output.write(Span { data, length }) };
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{mem::MaybeUninit, ptr};

    #[test]
    fn a_context_without_tracking_retains_the_selected_cutoff_direction() {
        let context = unsafe { MaybeUninit::<Context>::zeroed().assume_init() };
        let mut output = MaybeUninit::uninit();
        for (direction, incoming, outgoing) in [(0, true, true), (1, true, false), (2, false, true)]
        {
            assert!(unsafe {
                zapret_lua_context_scope(&context, direction, true, output.as_mut_ptr())
            });
            let scope = unsafe { output.assume_init_read() };
            assert_eq!((scope.incoming, scope.outgoing), (incoming, outgoing));
            assert!(!scope.tracked);
            assert_eq!(scope.instance, ptr::null());
        }
    }

    #[test]
    fn connection_cutoff_is_monotonic_and_keeps_the_instance_registry_scope() {
        let mut track = [0u64; 32];
        let profile = [u64::from(u32::MAX); 23];
        // Offsets in the pinned C t_ctrack, on Win64 and Win32 respectively.
        let (registry, incoming, outgoing) = if cfg!(target_pointer_width = "64") {
            (224, 197, 198)
        } else {
            (216, 193, 194)
        };
        unsafe {
            track
                .as_mut_ptr()
                .cast::<u8>()
                .add(registry)
                .cast::<i32>()
                .write(-7)
        };
        let context = Context {
            track: track.as_mut_ptr().cast(),
            profile: profile.as_ptr().cast(),
            instance: c"f_1_2".as_ptr(),
            ..unsafe { MaybeUninit::zeroed().assume_init() }
        };
        let mut scope = MaybeUninit::uninit();
        assert!(unsafe { zapret_lua_context_scope(&context, 2, true, scope.as_mut_ptr()) });
        let scope = unsafe { scope.assume_init() };
        assert_eq!((scope.profile, scope.registry), (u32::MAX, -7));
        assert!(scope.tracked && scope.outgoing && !scope.incoming);
        for selection in [2, 1, 2] {
            assert!(unsafe { zapret_lua_context_cutoff(&context, selection) });
        }
        assert_eq!(unsafe { *track.as_ptr().cast::<u8>().add(incoming) }, 1);
        assert_eq!(unsafe { *track.as_ptr().cast::<u8>().add(outgoing) }, 1);
    }

    #[test]
    fn packet_preparation_resets_cancellation_and_preserves_rule_and_active_state() {
        let mut context = unsafe { MaybeUninit::<Context>::zeroed().assume_init() };
        context.number = 42;
        context.function = c"rule".as_ptr();
        context.instance = c"rule_1_42".as_ptr();
        assert!(unsafe { zapret_lua_context_active(&mut context, true) });
        assert!(unsafe { zapret_lua_context_cancel(&mut context) });
        assert!(unsafe { zapret_lua_context_cancelled(&context) });
        assert!(unsafe {
            zapret_lua_context_prepare(
                &mut context,
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                true,
            )
        });
        assert_eq!(context.number, 42);
        assert_eq!(context.function, c"rule".as_ptr());
        assert_eq!(context.instance, c"rule_1_42".as_ptr());
        assert_eq!(context.incoming, 1);
        assert!(!unsafe { zapret_lua_context_cancelled(&context) });
        assert!(unsafe { zapret_lua_context_valid(&context, size_of::<Context>()) });
        assert!(!unsafe { zapret_lua_context_valid(&context, 0) });
    }

    #[test]
    fn a_bad_direction_does_not_publish_metadata_or_change_cutoffs() {
        let context = unsafe { MaybeUninit::<Context>::zeroed().assume_init() };
        let mut output = MaybeUninit::<Scope>::uninit();
        unsafe {
            output
                .as_mut_ptr()
                .cast::<u8>()
                .write_bytes(0xa5, size_of::<Scope>())
        };
        assert!(!unsafe { zapret_lua_context_scope(&context, 3, true, output.as_mut_ptr()) });
        assert!(!unsafe { zapret_lua_context_cutoff(&context, u32::MAX) });
        let bytes =
            unsafe { std::slice::from_raw_parts(output.as_ptr().cast::<u8>(), size_of::<Scope>()) };
        assert!(bytes.iter().all(|&byte| byte == 0xa5));
    }
}
