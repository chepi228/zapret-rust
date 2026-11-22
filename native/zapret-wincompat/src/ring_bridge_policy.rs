//! Metadata and resource-free entry/registration stages for the pinned ring ABI.
#[path = "ring_bridge_policy/abi.rs"]
mod abi;

use abi::{Feedback, Flow, Registration, RegistrationView};
use core::{
    ffi::{c_char, c_void},
    ptr,
};
#[path = "../../zapret-ring-ffi/src/operations.rs"]
mod operations;
#[path = "../../zapret-ring-ffi/src/request.rs"]
mod request;
use request::{ARGUMENT_SLOTS, Request, STORE_HANDLE_PRESENT, STORE_HANDLE_SLOT};

#[unsafe(no_mangle)]
extern "C" fn zapret_ring_request_number(input: &mut Request, index: i32, value: f64) {
    let index = index as usize;
    if let Some(number) = input.numbers.get_mut(index) {
        *number = value;
        input.present |= 1 << index;
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_ring_request_text(
    input: &mut Request,
    index: i32,
    text: *const u8,
    length: usize,
) {
    let index = index as usize;
    if let Some(string) = input.strings.get_mut(index) {
        *string = text;
        input.lengths[index] = length;
        input.text_present |= 1 << index;
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ring_release_object(
    slot: *mut *mut c_void,
    release: unsafe extern "C" fn(*mut c_void) -> bool,
) {
    if slot.is_null() {
        return;
    }
    let object = unsafe { slot.read() };
    if !object.is_null() && unsafe { release(object) } {
        unsafe { slot.write(ptr::null_mut()) };
    }
}

#[unsafe(no_mangle)]
extern "C" fn zapret_ring_request_store(input: &mut Request, object: *mut c_void) {
    input.strings[STORE_HANDLE_SLOT] = object.cast();
    input.text_present |= STORE_HANDLE_PRESENT;
}

#[unsafe(no_mangle)]
extern "C" fn zapret_ring_loader_error_text() -> *const c_char {
    c"Rust ring module failed its pinned hash/ABI/load checks (Windows error %lu)\n".as_ptr()
}

#[unsafe(no_mangle)]
extern "C" fn zapret_ring_entry_error(action: u32) -> *const c_char {
    match action {
        14 => c"ring native: operation %u rejected input (%d)",
        16 => c"ring native: object unavailable",
        18 => c"ring native: invalid result size",
        25 => c"ring native: invalid result type",
        28 => c"ring native: too many arguments",
        29 => c"ring native: released object",
        30 => c"ring native: nonfinite argument",
        31 => c"ring native: unsupported argument",
        33 => c"ring native: invalid string size",
        _ => c"ring native: invalid bridge state",
    }
    .as_ptr()
}

struct Metadata {
    object: u32,
    constructor: u32,
    capacity: usize,
}
fn metadata(operation: u32) -> Metadata {
    Metadata {
        object: match operation {
            2..=8 | operations::STORE_STAT => 1,
            10..=12 | 24 | 30 | operations::STORE_SCHEDULER => 2,
            26..=28 => 3,
            _ => 0,
        },
        constructor: match operation {
            1 => 1,
            9 => 2,
            25 => 3,
            _ => 0,
        },
        capacity: match operation {
            4 => 262144,
            15 | 29 => 32768,
            _ => 512,
        },
    }
}
fn buffer(flow: &Flow) -> u32 {
    if flow.capacity > 512 { 11 } else { 12 }
}
fn operand(flow: &Flow) -> u32 {
    if flow.index < flow.arguments {
        5
    } else if flow.constructor_class != 0 {
        10
    } else {
        buffer(flow)
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ring_entry_step(flow: &mut Flow, value: &Feedback) -> u32 {
    let next = match flow.phase {
        0 => 1,
        1 => {
            flow.operation = value.operation;
            2
        }
        2 => {
            flow.arguments = value.arguments;
            if value.arguments > ARGUMENT_SLOTS as i32 {
                28
            } else {
                3
            }
        }
        3 => {
            let plan = metadata(flow.operation);
            flow.object_class = plan.object;
            flow.constructor_class = plan.constructor;
            flow.capacity = plan.capacity;
            if flow.object_class != 0 {
                4
            } else {
                operand(flow)
            }
        }
        4 => {
            if value.available {
                operand(flow)
            } else {
                29
            }
        }
        5 => match value.kind {
            1 => 6,
            3 => 7,
            4 => 8,
            0 => {
                flow.index += 1;
                operand(flow)
            }
            7 if flow.operation == operations::STORE_SCHEDULER
                && flow.index as usize == STORE_HANDLE_SLOT =>
            {
                34
            }
            _ if flow.index == 0 && flow.object_class != 0 => {
                flow.index += 1;
                operand(flow)
            }
            _ => 31,
        },
        6 | 8 | 9 => {
            flow.index += 1;
            operand(flow)
        }
        34 => {
            if value.available {
                flow.index += 1;
                operand(flow)
            } else {
                29
            }
        }
        7 => {
            if value.number.is_finite() {
                9
            } else {
                30
            }
        }
        10 => buffer(flow),
        11 | 12 => 13,
        13 => {
            if value.backend != 0 {
                14
            } else if flow.constructor_class != 0 {
                15
            } else {
                17
            }
        }
        15 => {
            if value.available {
                flow.return_count = 1;
                27
            } else {
                16
            }
        }
        17 => {
            if value.results > 8 {
                18
            } else {
                19
            }
        }
        19 => {
            if flow.output_index < value.results {
                if flow.output_index < 8 { 20 } else { 18 }
            } else {
                flow.return_count = value.results as i32;
                27
            }
        }
        20 => match value.kind {
            0 => 21,
            1 => 22,
            2 => 23,
            3 => 24,
            _ => 25,
        },
        21 | 22 | 23 | 26 => {
            flow.output_index += 1;
            19
        }
        24 => {
            if value.offset > flow.capacity || value.length > flow.capacity - value.offset {
                33
            } else {
                26
            }
        }
        27 => 27,
        _ => 32,
    };
    flow.phase = next;
    next
}
#[unsafe(no_mangle)]
extern "C" fn zapret_ring_class_name(class: u32) -> *const c_char {
    match class {
        1 => c"zapret-ring.store.v1".as_ptr(),
        2 => c"zapret-ring.context.v1".as_ptr(),
        3 => c"zapret-ring.hosts.v1".as_ptr(),
        _ => ptr::null(),
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ring_registration_step(
    flow: &mut Registration,
    view: &mut RegistrationView,
) -> u32 {
    let next = match flow.phase {
        0 => 1,
        1 => 2,
        2 => 3,
        3 => 4,
        4 => 5,
        5 => 6,
        6 => {
            flow.object += 1;
            if flow.object < 3 { 1 } else { 7 }
        }
        7 => 8,
        8 => 9,
        9 => 10,
        10 => {
            flow.operation += 1;
            if (flow.operation as usize) < operations::OPERATIONS.len() {
                8
            } else {
                11
            }
        }
        11 => 12,
        12 => 13,
        13 => 14,
        14 => 15,
        15 | 16 => 16,
        _ => 17,
    };
    let name = match next {
        1 => match flow.object {
            0 => "zapret-ring.store.v1",
            1 => "zapret-ring.context.v1",
            2 => "zapret-ring.hosts.v1",
            _ => return 17,
        },
        3 => "__gc",
        4 => "protected native ring object",
        5 => "__metatable",
        8 => {
            view.integer = i64::from(flow.operation) + 1;
            ""
        }
        10 => match operations::OPERATIONS.get(flow.operation as usize) {
            Some(name) => name,
            None => return 17,
        },
        11 => {
            view.integer = 1;
            ""
        }
        12 => "api_version",
        13 => "Rust",
        14 => "backend",
        15 => "zapret_ring_native",
        _ => "",
    };
    if name.len() >= view.name.len() {
        return 17;
    }
    view.name[..name.len()].copy_from_slice(name.as_bytes());
    view.name[name.len()] = 0;
    view.name_length = name.len();
    flow.phase = next;
    next
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn constructors_and_large_outputs_use_their_existing_object_and_capacity_contract() {
        for (op, object, constructor, capacity) in [
            (1, 0, 1, 512),
            (4, 1, 0, 262144),
            (9, 0, 2, 512),
            (15, 0, 0, 32768),
            (25, 0, 3, 512),
            (29, 0, 0, 32768),
            (30, 2, 0, 512),
        ] {
            let plan = metadata(op);
            assert_eq!(
                (plan.object, plan.constructor, plan.capacity),
                (object, constructor, capacity)
            );
        }
    }
    #[test]
    fn arity_error_precedes_initialization_and_all_object_checks() {
        let mut flow = Flow::default();
        let value = Feedback {
            arguments: 17,
            ..Feedback::default()
        };
        for want in [1, 2, 28] {
            assert_eq!(unsafe { zapret_ring_entry_step(&mut flow, &value) }, want)
        }
    }
    #[test]
    fn string_results_check_bounds_before_publication_and_observe_the_late_count() {
        let mut flow = Flow {
            phase: 20,
            operation: 15,
            capacity: 32768,
            ..Flow::default()
        };
        let mut value = Feedback {
            kind: 3,
            offset: 32767,
            length: 1,
            results: 2,
            ..Feedback::default()
        };
        assert_eq!(unsafe { zapret_ring_entry_step(&mut flow, &value) }, 24);
        assert_eq!(unsafe { zapret_ring_entry_step(&mut flow, &value) }, 26);
        assert_eq!(unsafe { zapret_ring_entry_step(&mut flow, &value) }, 19);
        value.results = 1;
        assert_eq!(unsafe { zapret_ring_entry_step(&mut flow, &value) }, 27);
        assert_eq!(flow.return_count, 1);
        flow.phase = 24;
        value.offset = 32768;
        assert_eq!(unsafe { zapret_ring_entry_step(&mut flow, &value) }, 33);
    }
    #[test]
    fn registration_publishes_all_operations_in_the_v1_order() {
        let mut flow = Registration::default();
        let mut view = RegistrationView {
            integer: 0,
            name: [0; 64],
            name_length: 0,
        };
        let mut names = Vec::new();
        loop {
            let action = unsafe { zapret_ring_registration_step(&mut flow, &mut view) };
            assert_eq!(
                std::ffi::CStr::from_bytes_until_nul(&view.name)
                    .unwrap()
                    .to_bytes()
                    .len(),
                view.name_length
            );
            if action == 10 {
                names.push(
                    std::ffi::CStr::from_bytes_until_nul(&view.name)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                )
            }
            if action == 16 {
                break;
            }
        }
        assert_eq!(names.len(), operations::OPERATIONS.len());
        assert_eq!(names.first().unwrap(), "store_new");
        assert_eq!(names[32], "windows_absolute_path");
        assert_eq!(names[33], "store_scheduler");
        assert_eq!(names[operations::STORE_EFFECT as usize - 1], "store_effect");
        assert_eq!(names[operations::STORE_STAT as usize - 1], "store_stat");
        assert_eq!(
            names[operations::HOST_CAPACITY as usize - 1],
            "host_capacity"
        );
    }
}
