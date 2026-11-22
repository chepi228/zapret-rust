//! Packet position bounds and merging of the Lua packet actions.
use crate::conntrack::Position;

pub(super) const VERDICT_PASS: u8 = 0;
pub(super) const VERDICT_MODIFY: u8 = 1;
pub(super) const VERDICT_DROP: u8 = 2;
pub(super) const VERDICT_MASK: u8 = 3;
const VERDICT_PRESERVE_NEXT: u8 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Limit {
    pub(super) mode: u8,
    pub(super) value: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Range {
    pub(super) from: Limit,
    pub(super) to: Limit,
    pub(super) upper_cutoff: bool,
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_packet_position(pos: *const Position, mode: u8) -> u64 {
    if pos.is_null() {
        return 0;
    }
    // Read only the fields that C initializes, without borrowing the padding
    // in the whole connection snapshot.
    unsafe {
        match mode {
            b'n' => (*pos).packets,
            b'd' => (*pos).data_packets,
            b'b' => (*pos).bytes,
            b's' => u64::from((*pos).sequence.wrapping_sub((*pos).initial_sequence)),
            b'p' => u64::from((*pos).position.wrapping_sub((*pos).initial_sequence)),
            _ => 0,
        }
    }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_packet_position_overflow(
    pos: *const Position,
    mode: u8,
) -> bool {
    matches!(mode, b's' | b'p') && !pos.is_null() && unsafe { (*pos).over_2g != 0 }
}

impl Limit {
    unsafe fn permits(&self, pos: *const Position, compare: impl FnOnce(u64, u64) -> bool) -> bool {
        match self.mode {
            b'a' => true,
            b'x' => false,
            mode => {
                !pos.is_null()
                    && !unsafe { zapret_packet_position_overflow(pos, mode) }
                    && compare(
                        unsafe { zapret_packet_position(pos, mode) },
                        u64::from(self.value),
                    )
            }
        }
    }
}

impl Range {
    unsafe fn from(&self, pos: *const Position) -> bool {
        unsafe { self.from.permits(pos, |position, lower| position >= lower) }
    }

    unsafe fn to(&self, pos: *const Position) -> bool {
        unsafe {
            self.to.permits(pos, |position, upper| {
                position < upper || (!self.upper_cutoff && position == upper)
            })
        }
    }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_check_packet_cutoff(
    pos: *const Position,
    range: &Range,
) -> bool {
    !unsafe { range.to(pos) } || (pos.is_null() && !unsafe { range.from(pos) })
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_check_packet_range(
    pos: *const Position,
    range: &Range,
) -> bool {
    unsafe { range.from(pos) && range.to(pos) }
}

#[unsafe(no_mangle)]
pub(super) extern "C" fn zapret_verdict_aggregate(first: u8, next: u8) -> u8 {
    let action = match next & VERDICT_MASK {
        VERDICT_DROP => VERDICT_DROP,
        VERDICT_MODIFY if first & VERDICT_MASK == VERDICT_PASS => VERDICT_MODIFY,
        _ => first & VERDICT_MASK,
    };
    (first & !VERDICT_MASK) | action | (next & VERDICT_PRESERVE_NEXT)
}
