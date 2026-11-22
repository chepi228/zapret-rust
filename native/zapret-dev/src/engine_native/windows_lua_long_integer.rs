//! Conversion used by the engine's Lua 5.1 wide-number aliases on Windows x86.

pub(super) fn from_number(number: f64) -> i64 {
    const MINIMUM: f64 = i64::MIN as f64;
    if (MINIMUM..-MINIMUM).contains(&number) {
        number as i64
    } else {
        // Match the engine's signed conversion sentinel for invalid input.
        i64::MIN
    }
}
