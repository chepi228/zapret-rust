use core::{ffi::c_char, slice};

pub(crate) unsafe fn bytes<'a>(data: *const u8, length: usize) -> &'a [u8] {
    if length == 0 {
        &[]
    } else {
        // The C caller supplies length readable bytes for this call.
        unsafe { slice::from_raw_parts(data, length) }
    }
}

pub(crate) fn be16(data: &[u8], offset: usize) -> Option<usize> {
    let field: [u8; 2] = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(usize::from(u16::from_be_bytes(field)))
}

pub(crate) fn be24(data: &[u8], offset: usize) -> Option<usize> {
    let field = data.get(offset..offset.checked_add(3)?)?;
    Some((usize::from(field[0]) << 16) | (usize::from(field[1]) << 8) | usize::from(field[2]))
}

pub(crate) unsafe fn copy_lower(value: &[u8], output: *mut c_char, capacity: usize) {
    if !output.is_null() && capacity != 0 {
        let length = value.len().min(capacity - 1);
        let buffer = unsafe { slice::from_raw_parts_mut(output.cast::<u8>(), length + 1) };
        for (target, source) in buffer.iter_mut().zip(value) {
            *target = source.to_ascii_lowercase();
        }
        buffer[length] = 0;
    }
}

pub(crate) fn length_with_delta(value: usize, delta: isize, maximum: usize) -> Option<usize> {
    value
        .checked_add_signed(delta)
        .filter(|&value| value <= maximum)
}
