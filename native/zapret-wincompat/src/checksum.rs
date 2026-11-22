//! Internet checksum arithmetic for the native engine's wire-format adapters.
mod lua;
pub(super) mod wire;
use std::slice;

#[inline]
pub(super) fn fold(sum: u64) -> u16 {
    // End-around carries first reduce 64 to 32 bits, then 32 to 16 bits.
    // A carried addition cannot overflow again, retaining negative zero.
    let (sum, carry) = (sum as u32).overflowing_add((sum >> 32) as u32);
    let sum = sum.wrapping_add(u32::from(carry));
    let (sum, carry) = (sum as u16).overflowing_add((sum >> 16) as u16);
    sum.wrapping_add(u16::from(carry))
}

pub(super) fn internet_sum(bytes: &[u8]) -> u16 {
    // Little-endian words produce a native scalar ready for a wire header field.
    // Sum aligned-independent eight-byte blocks with end-around carry.
    let mut sum = 0u64;
    let mut words = bytes.chunks_exact(8);
    for block in words.by_ref() {
        let block = u64::from_le_bytes([
            block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
        ]);
        let (value, carry) = sum.overflowing_add(block);
        sum = value + u64::from(carry);
    }
    // At most seven remaining bytes: direct bounded loads avoid a CRT memcpy
    // call, including the common empty tail. Slice patterns validate each load.
    let tail = match words.remainder() {
        [] => 0,
        [a] => u64::from(*a),
        [a, b] => u64::from(u16::from_le_bytes([*a, *b])),
        [a, b, c] => u64::from(u16::from_le_bytes([*a, *b])) | u64::from(*c) << 16,
        [a, b, c, d] => u64::from(u32::from_le_bytes([*a, *b, *c, *d])),
        [a, b, c, d, e] => u64::from(u32::from_le_bytes([*a, *b, *c, *d])) | u64::from(*e) << 32,
        [a, b, c, d, e, f] => {
            u64::from(u32::from_le_bytes([*a, *b, *c, *d]))
                | u64::from(u16::from_le_bytes([*e, *f])) << 32
        }
        [a, b, c, d, e, f, g] => {
            u64::from(u32::from_le_bytes([*a, *b, *c, *d]))
                | u64::from(u16::from_le_bytes([*e, *f])) << 32
                | u64::from(*g) << 48
        }
        _ => unreachable!(),
    };
    let (value, carry) = sum.overflowing_add(tail);
    fold(value + u64::from(carry))
}

/// # Safety
/// For a nonempty input, data must cover len readable bytes.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_internet_sum(data: *const u8, len: usize) -> u16 {
    if len == 0 {
        return 0;
    }
    internet_sum(unsafe { slice::from_raw_parts(data, len) }).to_le()
}

#[unsafe(no_mangle)]
extern "C" fn csum_tcpudp_magic(
    source: u32,
    destination: u32,
    len: usize,
    proto: u8,
    sum: u16,
) -> u16 {
    let length_protocol = (len as u32).wrapping_add(u32::from(proto)).to_be();
    !fold(u64::from(source) + u64::from(destination) + u64::from(sum) + u64::from(length_protocol))
}

/// # Safety
/// Both address pointers must cover 16 readable bytes. No alignment is needed.
#[unsafe(no_mangle)]
unsafe extern "C" fn csum_ipv6_magic(
    source: *const u8,
    destination: *const u8,
    len: usize,
    proto: u8,
    sum: u16,
) -> u16 {
    let source = unsafe { slice::from_raw_parts(source, 16) };
    let destination = unsafe { slice::from_raw_parts(destination, 16) };
    let length_protocol = (len as u32).wrapping_add(u32::from(proto)).to_be();
    let sum = u64::from(sum)
        + u64::from(length_protocol)
        + u64::from(internet_sum(source).to_le())
        + u64::from(internet_sum(destination).to_le());
    !fold(sum)
}

/// # Safety
/// For a nonempty input, data must cover len readable bytes.
#[unsafe(no_mangle)]
unsafe extern "C" fn ip4_compute_csum(data: *const u8, len: usize) -> u16 {
    !unsafe { zapret_internet_sum(data, len) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folding_matches_modular_arithmetic_at_full_width_and_negative_zero() {
        let mut values = vec![
            0,
            1,
            65_535,
            65_536,
            65_537,
            u32::MAX as u64,
            u64::MAX,
            0x1_0000_ffff,
        ];
        let mut state = 0xa2bc_d985_7193_f261u64;
        for _ in 0..65_536 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            values.push(state);
        }
        for sum in values {
            let remainder = sum % 65_535;
            let expected = if sum != 0 && remainder == 0 {
                u16::MAX
            } else {
                remainder as u16
            };
            assert_eq!(fold(sum), expected, "sum={sum}");
        }
    }

    #[test]
    fn matches_scalar_reference_at_every_offset() {
        let mut pattern = Vec::new();
        let mut state = 1u32;
        for _ in 0..264 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            pattern.push((state >> 24) as u8);
        }
        for data in [pattern, vec![0; 264], vec![255; 264], vec![0x7f; 264]] {
            for offset in 0..8 {
                for len in 0..=256 {
                    let input = &data[offset..offset + len];
                    let mut sum = 0u32;
                    for pair in input.chunks(2) {
                        sum += u32::from(pair[0]) + (u32::from(*pair.get(1).unwrap_or(&0)) << 8);
                        sum = (sum & 0xffff) + (sum >> 16);
                    }
                    assert_eq!(
                        internet_sum(input),
                        sum as u16,
                        "offset {offset}, length {len}"
                    );
                }
            }
        }
    }
}
