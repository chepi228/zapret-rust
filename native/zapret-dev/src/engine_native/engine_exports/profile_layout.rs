//! Profile fields borrowed by the Windows entry. C checks engine_profile_exports_abi.h.

pub(super) const POINTER: usize = size_of::<*const ()>();
pub(super) const SIZE: usize = if POINTER == 4 { 120 } else { 184 };
pub(super) const FIRST_COLLECTION: usize = if POINTER == 4 { 40 } else { 72 };
pub(super) const AUTO_HOSTLIST: usize = FIRST_COLLECTION + 4 * POINTER;
pub(super) const FIRST_HOSTLIST_LIMIT: usize = AUTO_HOSTLIST + POINTER;
pub(super) const LUA_CALLS: usize = if POINTER == 4 { 104 } else { 160 };
pub(super) const FIRST_EXPLICIT: usize = LUA_CALLS + POINTER;
