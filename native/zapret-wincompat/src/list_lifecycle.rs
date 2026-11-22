//! Native list insertion/rollback and path preflight around existing Rust cores.
use std::ptr;
type Native = unsafe extern "C" fn(u32, usize, usize, usize, usize, usize) -> usize;
#[repr(C)]
struct Links {
    next: usize,
    previous: *mut usize,
}
unsafe fn lifecycle(
    kind: u32,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    _e: usize,
    native: Native,
) -> usize {
    unsafe {
        match kind {
            1 => {
                let head = b as *mut usize;
                let previous = head.read();
                if native(a as u32 + 1, c, b, 0, 0, 0) != 0 {
                    return 1;
                }
                loop {
                    let entry = head.read();
                    if entry == previous {
                        break;
                    }
                    let links = (entry as *mut u8).add(d) as *mut Links;
                    let next = (*links).next;
                    let prev = (*links).previous;
                    if next != 0 {
                        (*((next as *mut u8).add(d) as *mut Links)).previous = prev;
                    }
                    prev.write(next);
                    native(4, entry, 0, 0, 0, 0);
                }
                0
            }
            2 => {
                if native(5, a, b, c, d, 0) != 0 {
                    1
                } else {
                    native(6, a, 0, 0, 0, 0);
                    (-1isize) as usize
                }
            }
            3 => {
                let mut text = [0u8; 128];
                let length = c.min(127);
                if length != 0 {
                    ptr::copy_nonoverlapping(b as *const u8, text.as_mut_ptr(), length);
                }
                let text = text.as_mut_ptr() as usize;
                let added = if native(7, a, text, 0, 0, 0) != 0 {
                    native(8, a, 0, 0, 0, 0)
                } else if native(9, a, text, 0, 0, 0) != 0 {
                    native(10, a, 0, 0, 0, 0)
                } else {
                    native(
                        11,
                        a,
                        text,
                        c"bad ip or subnet : %s\n".as_ptr() as usize,
                        0,
                        0,
                    );
                    return 0;
                };
                if added != 0 {
                    1
                } else {
                    native(12, a, 0, 0, 0, 0);
                    (-1isize) as usize
                }
            }
            4 => {
                let mut canonical = [0u8; 4096];
                let path = if c == 0 {
                    0
                } else {
                    if native(13, c, canonical.as_mut_ptr() as usize, 0, 0, 0) == 0 {
                        return 0;
                    }
                    canonical.as_ptr() as usize
                };
                native(14, a, b, path, 0, 0)
            }
            _ => 0,
        }
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_lifecycle(
    kind: u32,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    native: Native,
) -> usize {
    unsafe { lifecycle(kind, a, b, c, d, e, native) }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::RefCell,
        ffi::{CStr, c_char},
    };
    #[derive(Default)]
    struct F {
        ops: Vec<u32>,
        responses: [usize; 17],
        text: Vec<u8>,
        freed: Vec<usize>,
        nodes: [usize; 2],
    }
    thread_local! {static FIX:RefCell<F>=RefCell::new(F::default());}
    unsafe extern "C" fn native(
        op: u32,
        a: usize,
        b: usize,
        _c: usize,
        _d: usize,
        _e: usize,
    ) -> usize {
        FIX.with(|f| {
            let mut f = f.borrow_mut();
            f.ops.push(op);
            unsafe {
                match op {
                    1..=3 => {
                        for node in f.nodes {
                            if node == 0 {
                                continue;
                            }
                            let head = b as *mut usize;
                            let p = (node as *mut u8).add(8) as *mut Links;
                            (*p).next = head.read();
                            (*p).previous = head;
                            if (*p).next != 0 {
                                (*(((*p).next as *mut u8).add(8) as *mut Links)).previous =
                                    ptr::addr_of_mut!((*p).next);
                            }
                            head.write(node);
                        }
                    }
                    4 => f.freed.push(a),
                    7 | 9 | 11 => f.text = CStr::from_ptr(b as *const c_char).to_bytes().to_vec(),
                    13 => {
                        if f.responses[13] != 0 {
                            ptr::copy_nonoverlapping(c"/x".as_ptr().cast::<u8>(), b as *mut u8, 3);
                        }
                    }
                    14 => {
                        f.text = if _c == 0 {
                            Vec::new()
                        } else {
                            CStr::from_ptr(_c as *const c_char).to_bytes().to_vec()
                        };
                    }
                    _ => {}
                }
            }
            f.responses[op as usize]
        })
    }
    fn reset() {
        FIX.with(|f| *f.borrow_mut() = F::default());
    }
    #[repr(C)]
    struct Node {
        value: u64,
        links: Links,
    }
    #[test]
    fn failed_parse_restores_prior_head_and_backlink_and_releases_only_new_nodes() {
        reset();
        let mut old = Node {
            value: 1,
            links: Links {
                next: 0,
                previous: ptr::null_mut(),
            },
        };
        let mut a = Node {
            value: 2,
            links: Links {
                next: 0,
                previous: ptr::null_mut(),
            },
        };
        let mut b = Node {
            value: 3,
            links: Links {
                next: 0,
                previous: ptr::null_mut(),
            },
        };
        let mut head = ptr::addr_of_mut!(old) as usize;
        old.links.previous = ptr::addr_of_mut!(head);
        FIX.with(|f| {
            f.borrow_mut().nodes = [ptr::addr_of_mut!(a) as usize, ptr::addr_of_mut!(b) as usize]
        });
        assert_eq!(
            unsafe {
                lifecycle(
                    1,
                    0,
                    ptr::addr_of_mut!(head) as usize,
                    c"1,bad".as_ptr() as usize,
                    8,
                    0,
                    native,
                )
            },
            0
        );
        assert_eq!(head, ptr::addr_of_mut!(old) as usize);
        assert_eq!(old.links.previous, ptr::addr_of_mut!(head));
        FIX.with(|f| {
            assert_eq!(
                f.borrow().freed,
                [ptr::addr_of_mut!(b) as usize, ptr::addr_of_mut!(a) as usize]
            )
        });
    }
    #[test]
    fn host_allocation_failure_destroys_destination_pool() {
        reset();
        assert_eq!(
            unsafe { lifecycle(2, 1, c"host".as_ptr() as usize, 4, 9, 0, native) } as isize,
            -1
        );
        FIX.with(|f| assert_eq!(f.borrow().ops, [5, 6]));
    }
    #[test]
    fn ip_truncation_and_v6_fallback_keep_failure_teardown_order() {
        reset();
        FIX.with(|f| f.borrow_mut().responses[9] = 1);
        let bytes = [b'x'; 200];
        assert_eq!(
            unsafe { lifecycle(3, 1, bytes.as_ptr() as usize, 200, 0, 0, native) } as isize,
            -1
        );
        FIX.with(|f| {
            let f = f.borrow();
            assert_eq!(f.text.len(), 127);
            assert_eq!(f.ops, [7, 9, 10, 12]);
        });
    }
    #[test]
    fn first_valid_ipv4_branch_does_not_probe_ipv6() {
        reset();
        FIX.with(|f| {
            let mut f = f.borrow_mut();
            f.responses[7] = 1;
            f.responses[8] = 1;
        });
        assert_eq!(
            unsafe { lifecycle(3, 1, c"ip".as_ptr() as usize, 2, 0, 0, native) },
            1
        );
        FIX.with(|f| assert_eq!(f.borrow().ops, [7, 8]));
    }
    #[test]
    fn inline_registration_skips_path_resolution() {
        reset();
        FIX.with(|f| f.borrow_mut().responses[14] = 42);
        assert_eq!(unsafe { lifecycle(4, 1, 2, 0, 0, 0, native) }, 42);
        FIX.with(|f| {
            let f = f.borrow();
            assert_eq!(f.ops, [14]);
            assert!(f.text.is_empty());
        });
    }
    #[test]
    fn resolved_path_is_borrowed_until_registry_copies_it() {
        reset();
        FIX.with(|f| {
            let mut f = f.borrow_mut();
            f.responses[13] = 1;
            f.responses[14] = 42;
        });
        assert_eq!(
            unsafe { lifecycle(4, 1, 2, c"path".as_ptr() as usize, 0, 0, native) },
            42
        );
        FIX.with(|f| {
            let f = f.borrow();
            assert_eq!(f.ops, [13, 14]);
            assert_eq!(f.text, b"/x");
        });
    }
    #[test]
    fn resolution_failure_never_registers_partial_path() {
        reset();
        assert_eq!(
            unsafe { lifecycle(4, 1, 2, c"path".as_ptr() as usize, 0, 0, native) },
            0
        );
        FIX.with(|f| assert_eq!(f.borrow().ops, [13]));
    }
}
