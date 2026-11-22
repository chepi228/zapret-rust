//! Domain storage and suffix matching for the pinned native engine.

use crate::logging::LogSink;
use std::{
    collections::HashMap,
    ffi::{CStr, c_char},
    ptr, slice,
};

#[derive(Default)]
pub(super) struct HostPool(HashMap<Vec<u8>, u32>);

impl HostPool {
    fn add(&mut self, name: &[u8], flags: u32) -> bool {
        // Upstream keeps the flags from the first occurrence of a domain.
        if self.0.contains_key(name) {
            return true;
        }
        let mut key = Vec::new();
        if key.try_reserve_exact(name.len()).is_err() || self.0.try_reserve(1).is_err() {
            return false;
        }
        key.extend_from_slice(name);
        self.0.insert(key, flags);
        true
    }

    fn matches(&self, mut host: &[u8], exact: bool, mut trace: impl FnMut(&[u8], i32)) -> bool {
        let mut full = true;
        loop {
            let status = match self.0.get(host) {
                Some(&flags) if !full && flags & 1 != 0 => 1,
                Some(_) => 0,
                None => -1,
            };
            trace(host, status);
            if status == 0 {
                return true;
            }
            if exact {
                return false;
            }
            let Some(dot) = host.iter().position(|&byte| byte == b'.') else {
                return false;
            };
            host = &host[dot + 1..];
            full = false;
        }
    }
}

// Private C ABI. The engine confines each pool to its event-loop thread.
// Calls copy input keys, finish all borrows, and retain no C string pointers.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_host_add(
    slot: *mut *mut HostPool,
    data: *const u8,
    length: usize,
    flags: u32,
) -> i32 {
    let name = if length == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(data, length) }
    };
    let slot = unsafe { &mut *slot };
    if slot.is_null() {
        let mut pool = Box::new(HostPool::default());
        if !pool.add(name, flags) {
            return 0;
        }
        *slot = Box::into_raw(pool);
        1
    } else {
        i32::from(unsafe { &mut **slot }.add(name, flags))
    }
}

pub(super) enum PublishError {
    Allocation,
    Write,
}

/// Keep the public pool consistent when its corresponding file append fails.
pub(super) unsafe fn add_persisted(
    slot: *mut *mut HostPool,
    name: &CStr,
    append: impl FnOnce() -> bool,
) -> Result<(), PublishError> {
    let key = name.to_bytes();
    let existed = unsafe { slot.read().as_ref() }.is_some_and(|pool| pool.0.contains_key(key));
    if unsafe { zapret_host_add(slot, key.as_ptr(), key.len(), 0) } == 0 {
        return Err(PublishError::Allocation);
    }
    // No borrow of the pool survives the file callback.
    if append() {
        return Ok(());
    }
    if !existed {
        let pool = unsafe { &mut *slot.read() };
        pool.0.remove(key);
        if pool.0.is_empty() {
            unsafe { zapret_host_destroy(slot) };
        }
    }
    Err(PublishError::Write)
}

unsafe fn match_host(
    pool: *const HostPool,
    host: *const c_char,
    exact: bool,
    mut trace: impl FnMut(*const c_char, i32),
) -> bool {
    let Some(pool) = (unsafe { pool.as_ref() }) else {
        return false;
    };
    let bytes = unsafe { CStr::from_ptr(host) }.to_bytes();
    pool.matches(bytes, exact, |suffix, status| {
        trace(suffix.as_ptr().cast(), status);
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_host_match(
    pool: *const HostPool,
    host: *const c_char,
    exact: i32,
    trace: Option<unsafe extern "C" fn(*const c_char, *const c_char, i32)>,
) -> i32 {
    // The legacy comparison callback borrows the suffix and leaves the pool alone.
    i32::from(unsafe {
        match_host(pool, host, exact != 0, |suffix, status| {
            if let Some(trace) = trace {
                trace(suffix, host, status);
            }
        })
    })
}

pub(super) unsafe fn host_match_logged(
    pool: *const HostPool,
    host: *const c_char,
    exact: bool,
    log: Option<LogSink>,
) -> bool {
    unsafe {
        match_host(pool, host, exact, |suffix, status| {
            if let Some(log) = log {
                log(c"hostlist check for %s : ".as_ptr(), suffix);
                match status {
                    0 => log(c"positive\n".as_ptr()),
                    1 => log(
                        c"negative : strict_mismatch : %s != %s\n".as_ptr(),
                        suffix,
                        host,
                    ),
                    _ => log(c"negative\n".as_ptr()),
                };
            }
        })
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_host_has(pool: *const HostPool, host: *const c_char) -> i32 {
    let Some(pool) = (unsafe { pool.as_ref() }) else {
        return 0;
    };
    i32::from(
        pool.0
            .contains_key(unsafe { CStr::from_ptr(host) }.to_bytes()),
    )
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_host_destroy(slot: *mut *mut HostPool) {
    let pool = unsafe { ptr::replace(slot, ptr::null_mut()) };
    if !pool.is_null() {
        drop(unsafe { Box::from_raw(pool) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_publication_restores_an_absent_pool_and_allows_retry() {
        let mut pool = ptr::null_mut();
        let slot = ptr::from_mut(&mut pool);
        let name = c"example.test";
        unsafe {
            let result = add_persisted(slot, name, || {
                assert_eq!(zapret_host_has(*slot, name.as_ptr()), 1);
                false
            });
            assert!(matches!(result, Err(PublishError::Write)));
            assert!(pool.is_null());
            assert!(add_persisted(slot, name, || true).is_ok());
            assert_eq!(zapret_host_has(pool, name.as_ptr()), 1);
            zapret_host_destroy(slot);
        }
    }

    #[test]
    fn failed_publication_preserves_existing_entries_and_duplicate_flags() {
        let mut pool = Box::into_raw(Box::new(HostPool::default()));
        let slot = ptr::from_mut(&mut pool);
        let strict = c"strict.example";
        unsafe {
            assert!((*pool).add(strict.to_bytes(), 1));
            assert!(matches!(
                add_persisted(slot, c"new.example", || false),
                Err(PublishError::Write)
            ));
            assert_eq!(zapret_host_has(pool, c"new.example".as_ptr()), 0);
            assert!(matches!(
                add_persisted(slot, strict, || false),
                Err(PublishError::Write)
            ));
            assert!((*pool).matches(strict.to_bytes(), false, |_, _| {}));
            assert!(!(*pool).matches(b"www.strict.example", false, |_, _| {}));
            zapret_host_destroy(slot);
        }
    }

    #[test]
    fn strict_duplicate_flags_keep_the_first_entry() {
        let mut pool = HostPool::default();
        assert!(pool.add(b"example.test", 1));
        assert!(pool.add(b"example.test", 0));
        assert!(pool.matches(b"example.test", false, |_, _| {}));
        assert!(!pool.matches(b"www.example.test", false, |_, _| {}));
        let mut pool = HostPool::default();
        assert!(pool.add(b"example.test", 0));
        assert!(pool.add(b"example.test", 1));
        assert!(pool.matches(b"www.example.test", false, |_, _| {}));
        assert!(!pool.matches(b"www.example.test", true, |_, _| {}));
    }

    #[test]
    fn matching_preserves_labels_case_and_trailing_dots() {
        let mut pool = HostPool::default();
        pool.add(b"example.test", 0);
        assert!(!pool.matches(b"otherexample.test", false, |_, _| {}));
        assert!(!pool.matches(b"EXAMPLE.TEST", false, |_, _| {}));
        assert!(!pool.matches(b"example.test.", false, |_, _| {}));
        assert!(pool.matches(b".example.test", false, |_, _| {}));
        pool.add(b"", 0);
        assert!(pool.matches(b"", true, |_, _| {}));
        assert!(pool.matches(b"example.test.", false, |_, _| {}));
    }
}
