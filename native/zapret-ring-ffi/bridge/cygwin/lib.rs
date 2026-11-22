//! The Windows ring DLL loader and Lua bridge policy linked into the Cygwin host.
#![no_std]

#[cfg(not(all(
    windows,
    target_arch = "x86_64",
    target_env = "gnu",
    feature = "cygwin-host"
)))]
compile_error!("The Cygwin ring archive requires x86_64-pc-windows-gnu and cygwin-host");

#[path = "../../../zapret-wincompat/src/ring_bridge_policy.rs"]
mod ring_bridge_policy;
#[path = "../../../zapret-wincompat/src/ring_loader.rs"]
mod ring_loader;
#[allow(non_snake_case)]
#[path = "../../../zapret-wincompat/src/protocol/tls.rs"]
mod tls;
#[path = "../../../zapret-dev/src/engine_native/engine_exports/ring_loader.rs"]
mod vm_loader;
#[path = "../../../zapret-wincompat/src/protocol/wire.rs"]
mod wire;

#[unsafe(no_mangle)]
extern "C" fn zapret_cygwin_tls_resize_fits(
    size: usize,
    capacity: usize,
    record: u16,
    delta: isize,
) -> bool {
    wire::length_with_delta(size, delta, capacity).is_some()
        && wire::length_with_delta(usize::from(record), delta, usize::from(u16::MAX)).is_some()
}

unsafe extern "C" {
    fn abort() -> !;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { abort() }
}
