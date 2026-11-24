//! Cache ownership and observation ordering around the existing Rust indexes.
use std::ptr;
type Native = unsafe extern "C" fn(u32, usize, usize, usize, usize, usize) -> usize;
unsafe fn failure_purge(slot: usize, native: Native) {
    unsafe {
        let now = native(1, 0, 0, 0, 0, 0);
        let mut cursor = 0u64;
        loop {
            let item = native(
                14,
                (slot as *const usize).read(),
                ptr::addr_of_mut!(cursor) as usize,
                now,
                0,
                0,
            );
            if item == 0 {
                break;
            }
            native(4, slot, item, 0, 0, 0);
        }
    }
}
unsafe fn ip_family(slot: usize, purge: Option<(usize, usize)>, native: Native) {
    unsafe {
        let mut cursor = 0u64;
        loop {
            let pool = (slot as *const usize).read();
            let position = ptr::addr_of_mut!(cursor) as usize;
            let item = match purge {
                Some((life, now)) => native(15, pool, position, life, now, 0),
                None => native(5, pool, position, 0, 0, 0),
            };
            if item == 0 {
                break;
            }
            let hostname = native(8, item, 0, 0, 0, 0);
            native(9, hostname, 0, 0, 0, 0);
            native(7, slot, item, 0, 0, 0);
        }
    }
}
unsafe fn lifecycle(
    entry: u32,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    native: Native,
) -> usize {
    unsafe {
        match entry {
            1 => {
                failure_purge(a, native);
                0
            }
            2 => {
                let now = native(1, 0, 0, 0, 0, 0);
                let previous = b as *mut i64;
                if native(13, previous.read() as usize, now, 0, 0, 0) != 0 {
                    failure_purge(a, native);
                    previous.write(now as i64);
                }
                0
            }
            3 => {
                ip_family(a, None, native);
                ip_family(b, None, native);
                0
            }
            4 | 5 => {
                let (slot, address, length) = if c != 0 {
                    (a, c, 4)
                } else if d != 0 {
                    (b, d, 16)
                } else {
                    return 0;
                };
                let mut item = native(10, (slot as *const usize).read(), address, length, e, 0);
                if entry == 5 {
                    if item == 0 {
                        let now = native(1, 0, 0, 0, 0, 0);
                        item = native(11, slot, address, length, e, now);
                    }
                    if item != 0 {
                        let now = native(1, 0, 0, 0, 0, 0);
                        native(12, item, now, 0, 0, 0);
                    }
                }
                item
            }
            6 => {
                let now = native(1, 0, 0, 0, 0, 0);
                let previous = d as *mut i64;
                if native(13, previous.read() as usize, now, 0, 0, 0) != 0 {
                    if c != 0 {
                        let family_now = native(1, 0, 0, 0, 0, 0);
                        ip_family(a, Some((c, family_now)), native);
                        let family_now = native(1, 0, 0, 0, 0, 0);
                        ip_family(b, Some((c, family_now)), native);
                    }
                    previous.write(now as i64);
                }
                0
            }
            _ => 0,
        }
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_cache_lifecycle(
    entry: u32,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    native: Native,
) -> usize {
    unsafe { lifecycle(entry, a, b, c, d, e, native) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    #[derive(Default)]
    struct Fixture {
        trace: Vec<(u32, usize, usize, usize)>,
        time: usize,
        found: usize,
        added: usize,
    }
    thread_local! {static FIX:RefCell<Fixture>=RefCell::new(Fixture::default());}
    fn reset(found: usize, added: usize) {
        FIX.with(|f| {
            *f.borrow_mut() = Fixture {
                time: 100,
                found,
                added,
                ..Fixture::default()
            }
        });
    }
    unsafe extern "C" fn native(
        op: u32,
        a: usize,
        b: usize,
        c: usize,
        _d: usize,
        _e: usize,
    ) -> usize {
        FIX.with(|f| {
            let mut f = f.borrow_mut();
            f.trace.push((op, a, b, c));
            match op {
                1 => {
                    let t = f.time;
                    f.time += 1;
                    t
                }
                5 | 14 | 15 => {
                    let cursor = b as *mut u64;
                    unsafe {
                        let n = cursor.read();
                        cursor.write(n + 1);
                        if n == 0 && a != 0 { 40 } else { 0 }
                    }
                }
                4 | 7 => {
                    unsafe { (a as *mut usize).write(0) };
                    0
                }
                8 => 77,
                9 | 12 => 0,
                10 => {
                    assert!(c == 4 || c == 16);
                    f.found
                }
                11 => f.added,
                13 => usize::from(a != b),
                _ => panic!("op {op}"),
            }
        })
    }
    #[test]
    fn touch_prefers_ipv4_and_observes_add_and_touch_times_separately() {
        reset(0, 41);
        let mut p4 = 11usize;
        let mut p6 = 12usize;
        assert_eq!(
            unsafe {
                lifecycle(
                    5,
                    ptr::addr_of_mut!(p4) as usize,
                    ptr::addr_of_mut!(p6) as usize,
                    21,
                    22,
                    0,
                    native,
                )
            },
            41
        );
        FIX.with(|f| {
            let f = f.borrow();
            assert_eq!(
                f.trace.iter().map(|v| v.0).collect::<Vec<_>>(),
                [10, 1, 11, 1, 12]
            );
            assert_eq!(f.trace[0].1, 11);
            assert_eq!(f.trace[0].2, 21);
            assert_eq!(f.trace[4].2, 101);
        });
    }
    #[test]
    fn cache_hit_has_only_the_deferred_touch_clock() {
        reset(42, 0);
        let mut p4 = 11usize;
        let mut p6 = 12usize;
        assert_eq!(
            unsafe {
                lifecycle(
                    5,
                    ptr::addr_of_mut!(p4) as usize,
                    ptr::addr_of_mut!(p6) as usize,
                    0,
                    22,
                    0,
                    native,
                )
            },
            42
        );
        FIX.with(|f| {
            let f = f.borrow();
            assert_eq!(f.trace.iter().map(|v| v.0).collect::<Vec<_>>(), [10, 1, 12]);
            assert_eq!(f.trace[0].1, 12);
            assert_eq!(f.trace[2].2, 100);
        });
    }
    #[test]
    fn allocation_failure_does_not_touch_or_read_a_second_clock() {
        reset(0, 0);
        let mut p = 11usize;
        assert_eq!(
            unsafe { lifecycle(5, ptr::addr_of_mut!(p) as usize, 0, 21, 0, 0, native) },
            0
        );
        FIX.with(|f| {
            assert_eq!(
                f.borrow().trace.iter().map(|v| v.0).collect::<Vec<_>>(),
                [10, 1, 11]
            )
        });
    }
    #[test]
    fn null_address_inputs_do_not_observe_any_native_state() {
        reset(0, 0);
        assert_eq!(unsafe { lifecycle(5, 0, 0, 0, 0, 0, native) }, 0);
        FIX.with(|f| assert!(f.borrow().trace.is_empty()));
    }
    #[test]
    fn failure_rate_limit_keeps_outer_time_and_reads_inner_time_late() {
        reset(0, 0);
        let mut pool = 1usize;
        let mut prev = 99i64;
        unsafe {
            lifecycle(
                2,
                ptr::addr_of_mut!(pool) as usize,
                ptr::addr_of_mut!(prev) as usize,
                0,
                0,
                0,
                native,
            )
        };
        assert_eq!(prev, 100);
        assert_eq!(pool, 0);
        FIX.with(|f| {
            let f = f.borrow();
            assert_eq!(
                f.trace.iter().map(|v| v.0).collect::<Vec<_>>(),
                [1, 13, 1, 14, 4, 14]
            );
            assert_eq!(f.trace[3].3, 101);
        });
    }
    #[test]
    fn disabled_ip_expiry_advances_previous_without_family_observations() {
        reset(0, 0);
        let mut prev = 99i64;
        unsafe { lifecycle(6, 0, 0, 0, ptr::addr_of_mut!(prev) as usize, 0, native) };
        assert_eq!(prev, 100);
        FIX.with(|f| {
            assert_eq!(
                f.borrow().trace.iter().map(|v| v.0).collect::<Vec<_>>(),
                [1, 13]
            )
        });
    }
    #[test]
    fn destroy_releases_hostname_before_record_and_preserves_family_order() {
        reset(0, 0);
        let mut a = 1usize;
        let mut b = 2usize;
        unsafe {
            lifecycle(
                3,
                ptr::addr_of_mut!(a) as usize,
                ptr::addr_of_mut!(b) as usize,
                0,
                0,
                0,
                native,
            )
        };
        assert_eq!((a, b), (0, 0));
        FIX.with(|f| {
            assert_eq!(
                f.borrow().trace.iter().map(|v| v.0).collect::<Vec<_>>(),
                [5, 8, 9, 7, 5, 5, 8, 9, 7, 5]
            )
        });
    }
}
