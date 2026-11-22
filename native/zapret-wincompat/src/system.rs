use std::{
    ffi::c_void,
    slice,
    sync::atomic::{AtomicU64, Ordering},
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};

#[repr(C)]
struct BootTime {
    seconds: i64,
    nanoseconds: i32,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_boot_time(
    status: i32,
    time: *const BootTime,
    milliseconds: bool,
) -> u64 {
    // On failure the native clock may leave its output uninitialized.
    if status != 0 {
        return 0;
    }
    let seconds = unsafe { (*time).seconds as u64 };
    if milliseconds {
        seconds
            .wrapping_mul(1000)
            .wrapping_add(unsafe { (*time).nanoseconds / 1_000_000 } as u64)
    } else {
        seconds
    }
}

static RANDOM_STATE: AtomicU64 = AtomicU64::new(1);

#[unsafe(no_mangle)]
pub extern "C" fn zapret_srandom(seed: u32) {
    RANDOM_STATE.store(u64::from(seed).max(1), Ordering::Relaxed);
}

/// POSIX random's 31-bit result range for non-cryptographic engine choices.
#[unsafe(no_mangle)]
pub extern "C" fn zapret_random() -> i32 {
    // fetch_update is available at the workspace's minimum Rust version.
    #[allow(deprecated)]
    let previous = RANDOM_STATE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(
                value
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1),
            )
        })
        .unwrap_or_else(|value| value);
    let next = previous
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1);
    ((next >> 33) & 0x7fff_ffff) as i32
}

/// # Safety
/// `buffer` must be writable for `length` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zapret_getrandom(buffer: *mut u8, length: usize, flags: u32) -> isize {
    if (length != 0 && buffer.is_null()) || length > u32::MAX as usize || flags & !3 != 0 {
        return -1;
    }
    if length == 0 {
        return 0;
    }
    // BCrypt's system-preferred generator is available to the restricted token.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buffer,
            length as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 { -1 } else { length as isize }
}

/// # Safety
/// The two input pointers must cover their declared lengths. A null pointer is
/// accepted only for an empty input.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zapret_memmem(
    haystack: *const u8,
    haystack_length: usize,
    needle: *const u8,
    needle_length: usize,
) -> *mut c_void {
    if needle_length == 0 {
        return haystack.cast_mut().cast();
    }
    if haystack.is_null()
        || needle.is_null()
        || haystack_length > isize::MAX as usize
        || needle_length > haystack_length
    {
        return std::ptr::null_mut();
    }
    let haystack_bytes = unsafe { slice::from_raw_parts(haystack, haystack_length) };
    let needle_bytes = unsafe { slice::from_raw_parts(needle, needle_length) };
    haystack_bytes
        .windows(needle_length)
        .position(|bytes| bytes == needle_bytes)
        .map_or(std::ptr::null_mut(), |index| unsafe {
            haystack.add(index).cast_mut().cast()
        })
}

#[cfg(test)]
mod boot_time_tests {
    use super::*;

    #[test]
    fn clock_failure_skips_the_output_and_milliseconds_preserve_unsigned_arithmetic() {
        unsafe {
            assert_eq!(zapret_boot_time(-1, std::ptr::null(), true), 0);
            assert_eq!(zapret_boot_time(-1, std::ptr::null(), false), 0);
            let time = BootTime {
                seconds: 9,
                nanoseconds: 999_999_999,
            };
            assert_eq!(zapret_boot_time(0, &time, false), 9);
            assert_eq!(zapret_boot_time(0, &time, true), 9999);
            let time = BootTime {
                seconds: -1,
                nanoseconds: -1_000_000,
            };
            assert_eq!(zapret_boot_time(0, &time, true), u64::MAX - 1000);
        }
    }
}
