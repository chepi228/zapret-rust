//! Operand and registration records shared with the LuaJIT entry object.

#[repr(C)]
#[derive(Default)]
pub(crate) struct Flow {
    pub(crate) phase: u32,
    pub(crate) operation: u32,
    pub(crate) arguments: i32,
    pub(crate) index: i32,
    pub(crate) output_index: u32,
    pub(crate) object_class: u32,
    pub(crate) constructor_class: u32,
    pub(crate) return_count: i32,
    pub(crate) capacity: usize,
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct Feedback {
    pub(crate) operation: u32,
    pub(crate) arguments: i32,
    pub(crate) kind: i32,
    pub(crate) backend: i32,
    pub(crate) number: f64,
    pub(crate) offset: usize,
    pub(crate) length: usize,
    pub(crate) results: u32,
    pub(crate) available: bool,
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct Registration {
    pub(crate) phase: u32,
    pub(crate) object: u32,
    pub(crate) operation: u32,
}

#[repr(C)]
pub(crate) struct RegistrationView {
    pub(crate) integer: i64,
    pub(crate) name: [u8; 64],
    pub(crate) name_length: usize,
}
