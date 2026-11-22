//! Borrowed packet invocation fields selected between C-owned Lua VM calls.
use crate::{
    conntrack::Position,
    lua_context::aligned,
    packet::Packet,
    profile_config::{profile_cookie, profile_name, profile_number},
};
use std::{
    ffi::{CStr, c_char, c_void},
    ptr,
};

#[repr(C)]
struct Input {
    profile: *const c_void,
    packet: *const Packet,
    current: *const Position,
    opposite: *const Position,
    interface_in: *const c_char,
    interface_out: *const c_char,
    target4: *const u8,
    target6: *const u8,
    reassembly: *const u8,
    decryption: *const u8,
    reassembly_length: usize,
    decryption_length: usize,
    reassembly_offset: usize,
    mark: u32,
    piece: u32,
    pieces: u32,
    payload: u32,
    protocol: u32,
    port: u16,
    incoming: bool,
}

#[repr(C)]
struct Field {
    name: *const c_char,
    data: *const u8,
    length: usize,
    number: i64,
    kind: u32,
}

#[repr(u32)]
enum Kind {
    Integer = 1,
    Boolean,
    String,
    Bytes,
    Raw,
    Target,
    EnterTarget,
    Pop,
    Payload,
    Protocol,
    Global,
}

impl Field {
    fn new(name: &CStr, kind: Kind) -> Self {
        Self {
            name: name.as_ptr(),
            data: ptr::null(),
            length: 0,
            number: 0,
            kind: kind as u32,
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_packet_argument_next(
    index: *mut u32,
    input: *const Input,
    output: *mut Field,
) -> u32 {
    if !aligned(index) || !aligned(input) || !aligned(output) {
        return 2;
    }
    // C owns the input and all borrowed objects until the surrounding call ends.
    let input = unsafe { &*input };
    loop {
        let current = unsafe { index.read() };
        if current >= 23 {
            return if current == 23 { 0 } else { 2 };
        }
        if current <= 2 && !aligned(input.profile.cast::<u64>()) {
            return 2;
        }
        let mut field = match current {
            0 => {
                let mut field = Field::new(c"profile_n", Kind::Integer);
                field.number = unsafe { profile_number(input.profile) } as i64;
                field
            }
            1 | 2 => {
                let mut field = Field::new(
                    if current == 1 {
                        c"profile_name"
                    } else {
                        c"cookie"
                    },
                    Kind::String,
                );
                field.data = if current == 1 {
                    unsafe { profile_name(input.profile) }
                } else {
                    unsafe { profile_cookie(input.profile) }
                }
                .cast();
                field
            }
            3 => {
                let mut field = Field::new(c"outgoing", Kind::Boolean);
                field.number = i64::from(!input.incoming);
                field
            }
            4 | 5 => {
                let mut field =
                    Field::new(if current == 4 { c"ifin" } else { c"ifout" }, Kind::String);
                let text = if current == 4 {
                    input.interface_in
                } else {
                    input.interface_out
                };
                if !text.is_null() && unsafe { text.read() } != 0 {
                    field.data = text.cast();
                }
                field
            }
            6 => {
                let mut field = Field::new(c"fwmark", Kind::Integer);
                field.number = input.mark as i64;
                field
            }
            7 => Field::new(c"target", Kind::Target),
            8 => Field::new(c"target", Kind::EnterTarget),
            9 => {
                let mut field = Field::new(c"port", Kind::Integer);
                field.number = input.port as i64;
                field
            }
            10 | 11 => {
                let mut field = Field::new(if current == 10 { c"ip" } else { c"ip6" }, Kind::Bytes);
                field.data = if current == 10 {
                    input.target4
                } else {
                    input.target6
                };
                field.length = if current == 10 { 4 } else { 16 };
                field
            }
            12 => Field::new(c"", Kind::Pop),
            13 => {
                let mut field = Field::new(c"replay", Kind::Boolean);
                field.number = i64::from(input.pieces != 0);
                field
            }
            14 => {
                let mut field = Field::new(c"replay_piece", Kind::Integer);
                field.number = input.piece.wrapping_add(1) as i64;
                field
            }
            15 => {
                let mut field = Field::new(c"replay_piece_count", Kind::Integer);
                field.number = input.pieces as i64;
                field
            }
            16 => {
                let mut field = Field::new(c"replay_piece_last", Kind::Boolean);
                field.number = i64::from(input.piece.wrapping_add(1) >= input.pieces);
                field
            }
            17 => {
                let mut field = Field::new(c"l7payload", Kind::Payload);
                field.number = input.payload as i64;
                field
            }
            18 => {
                let mut field = Field::new(c"l7proto", Kind::Protocol);
                field.number = input.protocol as i64;
                field
            }
            19 => {
                let mut field = Field::new(c"reasm_offset", Kind::Integer);
                field.number = input.reassembly_offset as i64;
                field
            }
            20 | 21 => {
                let mut field = Field::new(
                    if current == 20 {
                        c"reasm_data"
                    } else {
                        c"decrypt_data"
                    },
                    Kind::Raw,
                );
                field.data = if current == 20 {
                    input.reassembly
                } else {
                    input.decryption
                };
                field.length = if current == 20 {
                    input.reassembly_length
                } else {
                    input.decryption_length
                };
                field
            }
            22 => {
                if !aligned(input.packet) {
                    return 2;
                }
                if unsafe { (*input.packet).tcp.is_null() } {
                    unsafe { index.write(23) };
                    return 0;
                }
                let mut mss = 0;
                if !input.current.is_null() {
                    if !aligned(input.current) {
                        return 2;
                    }
                    let current = unsafe { (*input.current).mss };
                    if current != 0 && !input.opposite.is_null() {
                        if !aligned(input.opposite) {
                            return 2;
                        }
                        let opposite = unsafe { (*input.opposite).mss };
                        if opposite != 0 {
                            mss = current.min(opposite);
                        }
                    }
                }
                let mut field = Field::new(
                    c"tcp_mss",
                    if mss == 0 {
                        Kind::Global
                    } else {
                        Kind::Integer
                    },
                );
                if mss == 0 {
                    field.data = c"DEFAULT_MSS".as_ptr().cast();
                } else {
                    field.number = mss as i64;
                }
                field
            }
            _ => return 2,
        };
        // Advance only this metadata cursor. C performs the selected VM operation
        // before the next call reads another mutable profile/position field.
        unsafe { index.write(current + 1) };
        if (current == 1 || current == 2 || current == 10 || current == 11) && field.data.is_null()
            || current == 9 && input.port == 0
            || (14..=16).contains(&current) && input.pieces == 0
        {
            continue;
        }
        if current == 12 {
            field.name = ptr::null();
        }
        unsafe { output.write(field) };
        return 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::UnsafeCell, ffi::CStr, mem::MaybeUninit};
    #[test]
    fn replay_piece_numbers_retain_unsigned_wrap_and_offsets_retain_signed_conversion() {
        let input = Input {
            piece: u32::MAX,
            pieces: 1,
            reassembly_offset: usize::MAX,
            ..unsafe { MaybeUninit::zeroed().assume_init() }
        };
        let mut index = 14;
        let mut output = MaybeUninit::<Field>::uninit();
        assert_eq!(
            unsafe { zapret_lua_packet_argument_next(&mut index, &input, output.as_mut_ptr()) },
            1
        );
        let entry = unsafe { output.assume_init_ref() };
        assert_eq!(unsafe { CStr::from_ptr(entry.name) }, c"replay_piece");
        assert_eq!(entry.number, 0);
        index = 16;
        assert_eq!(
            unsafe { zapret_lua_packet_argument_next(&mut index, &input, output.as_mut_ptr()) },
            1
        );
        assert_eq!(unsafe { output.assume_init_ref() }.number, 0);
        index = 19;
        assert_eq!(
            unsafe { zapret_lua_packet_argument_next(&mut index, &input, output.as_mut_ptr()) },
            1
        );
        assert_eq!(
            unsafe { output.assume_init_ref() }.number,
            usize::MAX as i64
        );
    }

    #[test]
    fn raw_spans_keep_null_empty_and_binary_inputs_distinct() {
        let data = [0, 255, 0, 1];
        let mut input = unsafe { MaybeUninit::<Input>::zeroed().assume_init() };
        input.reassembly_length = usize::MAX;
        input.decryption = data.as_ptr();
        input.decryption_length = data.len();
        let mut output = MaybeUninit::<Field>::uninit();
        let mut index = 20;
        assert_eq!(
            unsafe { zapret_lua_packet_argument_next(&mut index, &input, output.as_mut_ptr()) },
            1
        );
        let entry = unsafe { output.assume_init_ref() };
        assert!(entry.data.is_null());
        assert_eq!(entry.length, usize::MAX);
        assert_eq!(
            unsafe { zapret_lua_packet_argument_next(&mut index, &input, output.as_mut_ptr()) },
            1
        );
        let entry = unsafe { output.assume_init_ref() };
        assert_eq!(entry.data, data.as_ptr());
        assert_eq!(entry.length, 4);
    }

    #[test]
    fn mss_is_read_after_previous_vm_work_and_falls_back_lazily() {
        let mut packet = unsafe { MaybeUninit::<Packet>::zeroed().assume_init() };
        packet.tcp = ptr::dangling();
        let first = UnsafeCell::new(Position::default());
        let second = UnsafeCell::new(Position::default());
        unsafe {
            (*first.get()).mss = 1400;
            (*second.get()).mss = 1200;
        }
        let input = Input {
            packet: &packet,
            current: first.get(),
            opposite: second.get(),
            ..unsafe { MaybeUninit::zeroed().assume_init() }
        };
        unsafe {
            (*first.get()).mss = 700;
            (*second.get()).mss = 900;
        }
        let mut index = 22;
        let mut output = MaybeUninit::<Field>::uninit();
        assert_eq!(
            unsafe { zapret_lua_packet_argument_next(&mut index, &input, output.as_mut_ptr()) },
            1
        );
        assert_eq!(unsafe { output.assume_init_ref() }.number, 700);
        unsafe {
            (*first.get()).mss = 0;
        }
        index = 22;
        assert_eq!(
            unsafe { zapret_lua_packet_argument_next(&mut index, &input, output.as_mut_ptr()) },
            1
        );
        let entry = unsafe { output.assume_init_ref() };
        assert_eq!(entry.kind, Kind::Global as u32);
        assert_eq!(unsafe { CStr::from_ptr(entry.data.cast()) }, c"DEFAULT_MSS");
        assert_eq!(
            unsafe { zapret_lua_packet_argument_next(&mut index, &input, output.as_mut_ptr()) },
            0
        );
    }

    #[test]
    fn absent_target_and_replay_fields_are_skipped_without_losing_the_target_pop() {
        let input = unsafe { MaybeUninit::<Input>::zeroed().assume_init() };
        let mut index = 9;
        let mut output = MaybeUninit::<Field>::uninit();
        assert_eq!(
            unsafe { zapret_lua_packet_argument_next(&mut index, &input, output.as_mut_ptr()) },
            1
        );
        assert_eq!(unsafe { output.assume_init_ref() }.kind, Kind::Pop as u32);
        assert_eq!(
            unsafe { zapret_lua_packet_argument_next(&mut index, &input, output.as_mut_ptr()) },
            1
        );
        assert_eq!(unsafe { output.assume_init_ref() }.number, 0);
        assert_eq!(
            unsafe { zapret_lua_packet_argument_next(&mut index, &input, output.as_mut_ptr()) },
            1
        );
        assert_eq!(
            unsafe { CStr::from_ptr(output.assume_init_ref().name) },
            c"l7payload"
        );
    }
}
