//! In-order reassembly and ownership of the native connection's buffer.
#![allow(non_snake_case)]
use std::{
    alloc::{Layout, alloc, dealloc},
    mem::{offset_of, size_of},
    ptr,
};

pub(super) mod session;

#[repr(C)]
struct Reassembly {
    packet: *mut u8,
    sequence: u32,
    size: usize,
    present: usize,
}

impl Reassembly {
    fn initialize(&mut self, size: usize, sequence: u32) -> bool {
        if size == 0 || !self.packet.is_null() {
            return false;
        }
        let Ok(layout) = Layout::array::<u8>(size) else {
            return false;
        };
        let packet = unsafe { alloc(layout) };
        if packet.is_null() {
            return false;
        }
        *self = Self {
            packet,
            sequence,
            size,
            present: 0,
        };
        true
    }

    fn clear(&mut self) {
        if !self.packet.is_null() {
            // Only initialize creates a live descriptor, with a nonzero u8 layout.
            let layout = unsafe { Layout::from_size_align_unchecked(self.size, 1) };
            unsafe { dealloc(self.packet, layout) };
        }
        self.packet = ptr::null_mut();
        self.size = 0;
        self.present = 0;
    }

    fn has_space(&self, length: usize) -> bool {
        self.present
            .checked_add(length)
            .is_some_and(|end| end <= self.size)
    }
}

fn feed(reassembly: &mut Reassembly, sequence: u32, payload: *const u8, length: usize) -> bool {
    const MAX_OVERLAP: u32 = 0x10_0000;
    let forward = sequence.wrapping_sub(reassembly.sequence);
    if forward != 0 && forward < MAX_OVERLAP {
        return false;
    }
    let overlap = reassembly.sequence.wrapping_sub(sequence);
    if overlap > MAX_OVERLAP {
        return false;
    }
    let ignored = (overlap as usize).saturating_sub(reassembly.present);
    if ignored >= length {
        return true;
    }
    let copied = length - ignored;
    let overlap = overlap as usize - ignored;
    let offset = reassembly.present - overlap;
    if offset
        .checked_add(copied)
        .is_none_or(|end| end > reassembly.size)
    {
        return false;
    }
    // The C API requires non-overlapping readable input and a writable buffer
    // covering size bytes. Check the destination bounds before constructing it.
    unsafe {
        ptr::copy_nonoverlapping(payload.add(ignored), reassembly.packet.add(offset), copied)
    };
    if copied > overlap {
        let added = copied - overlap;
        reassembly.present += added;
        reassembly.sequence = reassembly.sequence.wrapping_add(added as u32);
    }
    true
}

// Connection descriptors are zero-initialized in C. Only this module changes
// their allocation, size and initialized length.
#[unsafe(no_mangle)]
unsafe extern "C" fn ReasmInit(reassembly: *mut Reassembly, size: usize, sequence: u32) -> bool {
    unsafe { &mut *reassembly }.initialize(size, sequence)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ReasmClear(reassembly: *mut Reassembly) {
    unsafe { &mut *reassembly }.clear();
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ReasmFeed(
    reassembly: *mut Reassembly,
    sequence: u32,
    payload: *const u8,
    length: usize,
) -> bool {
    feed(unsafe { &mut *reassembly }, sequence, payload, length)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn ReasmHasSpace(reassembly: *const Reassembly, length: usize) -> bool {
    unsafe { &*reassembly }.has_space(length)
}

const _: () = {
    let pointer = size_of::<usize>();
    assert!(size_of::<Reassembly>() == 4 * pointer);
    assert!(offset_of!(Reassembly, sequence) == pointer);
    assert!(offset_of!(Reassembly, size) == 2 * pointer);
    assert!(offset_of!(Reassembly, present) == 3 * pointer);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_replaces_bytes_and_sequence_wrap_is_retained() {
        let mut bytes = [0u8; 8];
        let mut reassembly = Reassembly {
            packet: bytes.as_mut_ptr(),
            sequence: u32::MAX - 1,
            size: bytes.len(),
            present: 0,
        };
        assert!(feed(&mut reassembly, u32::MAX - 1, b"abcd".as_ptr(), 4));
        assert_eq!(reassembly.sequence, 2);
        assert!(feed(&mut reassembly, 0, b"XYef".as_ptr(), 4));
        assert_eq!(&bytes[..6], b"abXYef");
        assert_eq!(reassembly.sequence, 4);
        assert_eq!(reassembly.present, 6);
        assert!(!feed(&mut reassembly, 5, b"gap".as_ptr(), 3));
        assert!(!feed(&mut reassembly, 4, b"overflow".as_ptr(), 8));
        assert_eq!(&bytes[..6], b"abXYef");
        assert_eq!(reassembly.present, 6);
    }

    #[test]
    fn bytes_before_the_requested_start_are_ignored() {
        let mut bytes = [0u8; 4];
        let mut reassembly = Reassembly {
            packet: bytes.as_mut_ptr(),
            sequence: 100,
            size: bytes.len(),
            present: 0,
        };
        assert!(feed(&mut reassembly, 98, b"xxAB".as_ptr(), 4));
        assert_eq!(&bytes[..2], b"AB");
        assert_eq!(reassembly.sequence, 102);
        assert_eq!(reassembly.present, 2);
    }

    #[test]
    fn space_rejects_size_overflow_and_preserves_exact_fit() {
        let mut buffer = [0u8; 8];
        let reassembly = Reassembly {
            packet: buffer.as_mut_ptr(),
            sequence: 100,
            size: buffer.len(),
            present: 3,
        };
        unsafe {
            assert!(ReasmHasSpace(&reassembly, 5));
            assert!(!ReasmHasSpace(&reassembly, 6));
            assert!(!ReasmHasSpace(&reassembly, usize::MAX));
            assert!(!ReasmHasSpace(&reassembly, usize::MAX - 2));
        }
    }
}
