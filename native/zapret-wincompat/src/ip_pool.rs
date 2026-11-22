//! IPv4 and IPv6 prefix sets with the pinned engine's overlap semantics.

use std::{
    collections::BTreeMap,
    ops::Bound::{Excluded, Unbounded},
    ptr, slice,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Prefix {
    end: u128,
    bits: u8,
}

pub(super) struct IpPool {
    width: u8,
    prefixes: BTreeMap<u128, Prefix>,
}

impl IpPool {
    fn new(width: u8) -> Self {
        Self {
            width,
            prefixes: BTreeMap::new(),
        }
    }

    fn range(&self, address: u128, prefix: u8) -> (u128, u128) {
        let host_bits = self.width - prefix.min(self.width);
        let host_mask = u128::MAX
            .checked_shr(u32::from(128 - host_bits))
            .unwrap_or(0);
        (address & !host_mask, address | host_mask)
    }

    fn add(&mut self, address: u128, bits: u8) -> bool {
        if bits > self.width {
            return false;
        }
        let (start, end) = self.range(address, bits);
        if self
            .prefixes
            .range(..=start)
            .next_back()
            .is_some_and(|(_, prefix)| prefix.end >= end)
        {
            return true;
        }
        // A broader prefix replaces all narrower prefixes within its range.
        while let Some((&key, _)) = self.prefixes.range(start..=end).next() {
            self.prefixes.remove(&key);
        }
        self.prefixes.insert(start, Prefix { end, bits });
        true
    }

    fn overlaps(&self, address: u128, bits: u8) -> bool {
        let (start, end) = self.range(address, bits);
        self.prefixes
            .range(..=end)
            .next_back()
            .is_some_and(|(_, prefix)| prefix.end >= start)
    }

    fn next(&self, after: Option<u128>) -> Option<(u128, Prefix)> {
        let entry = match after {
            Some(key) => self.prefixes.range((Excluded(key), Unbounded)).next(),
            None => self.prefixes.first_key_value(),
        };
        entry.map(|(&start, &prefix)| (start, prefix))
    }
}

#[repr(C)]
struct PrefixInfo {
    address: [u8; 16],
    bits: u8,
}

/// # Safety
/// The pointer covers ceil(min(bits, width)/8) bytes in network order.
/// A zero prefix accepts a null pointer, as the C implementation does.
unsafe fn address(data: *const u8, width: u8, bits: u8) -> u128 {
    let mut bytes = [0; 16];
    let offset = 16 - usize::from(width / 8);
    let count = usize::from(bits.min(width).div_ceil(8));
    if count != 0 {
        bytes[offset..offset + count]
            .copy_from_slice(unsafe { slice::from_raw_parts(data, count) });
    }
    u128::from_be_bytes(bytes)
}

// Private C ABI. C owns the slot. IPv4 addresses cover four bytes and IPv6
// addresses cover sixteen bytes. Each call releases its pool borrow on return.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ip_add(
    slot: *mut *mut IpPool,
    data: *const u8,
    width: u8,
    bits: u8,
) -> i32 {
    if !matches!(width, 32 | 128) || bits > width {
        return 0;
    }
    let value = unsafe { address(data, width, bits) };
    let slot = unsafe { &mut *slot };
    if slot.is_null() {
        let mut pool = Box::new(IpPool::new(width));
        pool.add(value, bits);
        *slot = Box::into_raw(pool);
        1
    } else {
        let pool = unsafe { &mut **slot };
        i32::from(pool.width == width && pool.add(value, bits))
    }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_ip_check(
    pool: *const IpPool,
    data: *const u8,
    bits: u8,
) -> i32 {
    let Some(pool) = (unsafe { pool.as_ref() }) else {
        return 0;
    };
    i32::from(pool.overlaps(unsafe { address(data, pool.width, bits) }, bits))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ip_next(
    pool: *const IpPool,
    after: *const u8,
    out: *mut PrefixInfo,
) -> i32 {
    let Some(pool) = (unsafe { pool.as_ref() }) else {
        return 0;
    };
    let after = if after.is_null() {
        None
    } else {
        Some(unsafe { address(after, pool.width, pool.width) })
    };
    let Some((start, prefix)) = pool.next(after) else {
        return 0;
    };
    let mut info = PrefixInfo {
        address: [0; 16],
        bits: prefix.bits,
    };
    let length = usize::from(pool.width / 8);
    info.address[..length].copy_from_slice(&start.to_be_bytes()[16 - length..]);
    unsafe { out.write(info) };
    1
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_ip_destroy(slot: *mut *mut IpPool) {
    let pool = unsafe { ptr::replace(slot, ptr::null_mut()) };
    if !pool.is_null() {
        drop(unsafe { Box::from_raw(pool) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broader_prefix_replaces_all_children_in_both_insertion_orders() {
        let mut pool = IpPool::new(32);
        assert!(pool.add(0xc0000201, 32));
        assert!(pool.add(0xc0000202, 32));
        assert!(pool.add(0xc0000203, 24));
        assert_eq!(pool.prefixes.len(), 1);
        assert!(pool.add(0xc0000280, 25));
        assert_eq!(pool.prefixes.len(), 1);
        assert!(pool.overlaps(0xc00002ff, 32));
        assert!(!pool.overlaps(0xc0000300, 32));
        assert!(pool.overlaps(0xc0000000, 16));
    }

    #[test]
    fn ipv6_edges_and_zero_prefix_keep_the_full_address_width() {
        let mut pool = IpPool::new(128);
        let first = 0x20010db8000000000000000000000001;
        let last = 0x20010db8ffffffffffffffffffffffff;
        assert!(pool.add(first, 32));
        assert!(pool.overlaps(last, 128));
        assert!(!pool.overlaps(0x20010db9000000000000000000000000, 128));
        assert!(pool.add(u128::MAX, 128));
        assert!(pool.overlaps(u128::MAX, 255));
        assert!(!pool.overlaps(u128::MAX - 1, 128));
        assert!(pool.add(0, 0));
        assert_eq!(pool.prefixes.len(), 1);
        assert_eq!(
            pool.next(None),
            Some((
                0,
                Prefix {
                    end: u128::MAX,
                    bits: 0
                }
            ))
        );
    }

    #[test]
    fn adjacent_networks_preserve_separate_debug_entries() {
        let mut pool = IpPool::new(32);
        pool.add(0xc0000280, 25);
        pool.add(0xc0000200, 25);
        assert_eq!(
            pool.next(None),
            Some((
                0xc0000200,
                Prefix {
                    end: 0xc000027f,
                    bits: 25
                }
            ))
        );
        assert_eq!(
            pool.next(Some(0xc0000200)),
            Some((
                0xc0000280,
                Prefix {
                    end: 0xc00002ff,
                    bits: 25
                }
            ))
        );
    }

    #[test]
    fn zero_prefix_needs_no_address_and_repeated_destroy_is_safe() {
        let mut pool = ptr::null_mut();
        unsafe {
            assert_eq!(zapret_ip_check(pool, ptr::null(), 0), 0);
            assert_eq!(zapret_ip_add(&mut pool, ptr::null(), 32, 0), 1);
            assert_eq!(zapret_ip_check(pool, ptr::null(), 0), 1);
            zapret_ip_destroy(&mut pool);
            assert!(pool.is_null());
            zapret_ip_destroy(&mut pool);
        }
    }
}
