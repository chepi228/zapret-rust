//! Numeric work for Lua adapters. No function here calls the VM or allocates.
mod entry;
use std::{ptr, slice};

fn mask(width: u32) -> Option<u64> {
    matches!(width, 8 | 16 | 24 | 32 | 48).then(|| (1u64 << width) - 1)
}

fn fits(value: i64, mask: u64) -> bool {
    (-(mask as i64)..=mask as i64).contains(&value)
}

// Status: 0 value, 1 value out of range, 2 bit range invalid, 3 nil.
fn calculate(operation: u32, width: u32, args: &[i64]) -> Result<u64, u32> {
    let limit = mask(width).ok_or(1u32)?;
    let expected = match operation {
        0 | 1 | 10 => 2..=2,
        2 => 2..=100,
        3 | 4 | 9 => 1..=100,
        5 | 8 => 1..=1,
        6 => 3..=3,
        7 => 4..=4,
        _ => return Err(1),
    };
    if !expected.contains(&args.len()) {
        return Err(1);
    }
    if operation == 10 {
        return args[0].checked_div(args[1]).map(|v| v as u64).ok_or(3);
    }
    if matches!(operation, 2..=5 | 8 | 9) {
        if args.iter().any(|&v| !fits(v, limit)) {
            return Err(1);
        }
    } else if !fits(args[0], limit) || (operation == 7 && !fits(args[3], limit)) {
        return Err(1);
    }
    let value = args[0] as u64;
    Ok(match operation {
        0 | 1 => {
            let shift = u32::try_from(args[1])
                .ok()
                .filter(|&v| v <= 48)
                .ok_or(1u32)?;
            if operation == 0 {
                ((value & limit) << shift) & limit
            } else {
                (value & limit) >> shift
            }
        }
        2 => args.iter().fold(limit, |v, &next| v & next as u64),
        3 => args.iter().fold(0, |v, &next| v | (next as u64 & limit)),
        4 => args.iter().fold(0, |v, &next| v ^ (next as u64 & limit)),
        5 => !value & limit,
        6 | 7 => {
            let from = u32::try_from(args[1]).map_err(|_| 2u32)?;
            let to = u32::try_from(args[2]).map_err(|_| 2u32)?;
            if from > to || to > 47 {
                return Err(2);
            }
            let bits = (1u64 << (to - from + 1)) - 1;
            if operation == 6 {
                (value >> from) & bits
            } else {
                (value & !(bits << from)) | ((args[3] as u64 & bits) << from)
            }
        }
        8 => value.swap_bytes() >> (64 - width),
        9 => {
            args.iter()
                .fold(0u64, |v, &next| v.wrapping_add(next as u64))
                & limit
        }
        _ => unreachable!(),
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_number(
    operation: u32,
    width: u32,
    args: *const i64,
    count: usize,
    output: *mut u64,
) -> u32 {
    if count == 0 || count > 100 {
        return 1;
    }
    match calculate(operation, width, unsafe {
        slice::from_raw_parts(args, count)
    }) {
        Ok(value) => {
            unsafe { output.write(value) };
            0
        }
        Err(status) => status,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_read_number(
    data: *const u8,
    length: usize,
    offset: i64,
    width: u32,
    output: *mut u64,
) -> bool {
    if mask(width).is_none() {
        return false;
    }
    let Some(start) = offset.checked_sub(1).and_then(|v| usize::try_from(v).ok()) else {
        return false;
    };
    let bytes = (width / 8) as usize;
    if start > length || bytes > length - start {
        return false;
    }
    let bytes = unsafe { slice::from_raw_parts(data.add(start), bytes) };
    let value = bytes
        .iter()
        .fold(0u64, |v, &byte| (v << 8) | u64::from(byte));
    unsafe { output.write(value) };
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_lua_write_number(value: i64, width: u32, output: *mut u8) -> bool {
    let Some(limit) = mask(width) else {
        return false;
    };
    if !fits(value, limit) {
        return false;
    }
    let bytes = (value as u64).to_be_bytes();
    let length = (width / 8) as usize;
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr().add(8 - length), output, length) };
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_requests_leave_outputs_unchanged() {
        let mut value = 29u64;
        let data = [1u8; 6];
        for offset in [i64::MIN, -1, 0, 2, i64::MAX] {
            assert!(!unsafe { zapret_lua_read_number(data.as_ptr(), 6, offset, 48, &mut value) });
            assert_eq!(value, 29);
        }
        let mut bytes = [37u8; 6];
        assert!(!unsafe { zapret_lua_write_number(256, 8, bytes.as_mut_ptr()) });
        assert_eq!(bytes, [37; 6]);
        assert_eq!(calculate(10, 48, &[i64::MIN, -1]), Err(3));
        assert_eq!(calculate(10, 48, &[1, 0]), Err(3));
        assert_eq!(calculate(7, 48, &[0, 0, 48, 0]), Err(2));
    }
}
