//! Shared file records and ordered profile references for hostlists and ipsets.
mod policy;
#[cfg(windows)]
mod startup;
use crate::{
    allocate::try_allocate,
    host_pool::{HostPool, zapret_host_destroy},
    ip_pool::{IpPool, zapret_ip_destroy},
};
use std::{
    cell::{Cell, UnsafeCell},
    collections::VecDeque,
    ffi::{CStr, c_char},
    ptr::{self, NonNull},
};

#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
struct Stamp {
    seconds: i64,
    nanoseconds: i32,
    size: i64,
}

#[derive(Default)]
#[repr(C)]
struct IpSet {
    ipv4: *mut IpPool,
    ipv6: *mut IpPool,
}

#[repr(C)]
pub(super) struct ListFile {
    pub(super) filename: *const c_char,
    stamp: UnsafeCell<Stamp>,
    pub(super) hosts: UnsafeCell<*mut HostPool>,
    ips: UnsafeCell<IpSet>,
    // Preserve the C prefix's tail padding before the private Rust fields on Win32.
    #[cfg(target_pointer_width = "32")]
    _prefix_padding: [u8; 4],
    filename_storage: Vec<u8>,
    checked_in_search: Cell<u64>,
}

// One engine thread owns a registry. Profiles can share the same ListFile.
// Give one walk a consistent view without delaying file edits until a timer fires.
thread_local! {
    static LAST_SEARCH: Cell<u64> = const { Cell::new(0) };
    static ACTIVE_SEARCH: Cell<u64> = const { Cell::new(0) };
}

pub(super) struct ReloadScope(u64);

impl ReloadScope {
    pub(super) fn enter() -> Self {
        let next = LAST_SEARCH.with(|last| {
            let next = last.get().checked_add(1).unwrap_or(0);
            if next != 0 {
                last.set(next);
            }
            next
        });
        Self(ACTIVE_SEARCH.replace(next))
    }
}

impl Drop for ReloadScope {
    fn drop(&mut self) {
        ACTIVE_SEARCH.set(self.0);
    }
}

impl ListFile {
    fn try_new(name: Option<&CStr>) -> Option<NonNull<Self>> {
        let mut filename_storage = Vec::new();
        let filename = if let Some(name) = name {
            let bytes = name.to_bytes_with_nul();
            filename_storage.try_reserve_exact(bytes.len()).ok()?;
            filename_storage.extend_from_slice(bytes);
            filename_storage.as_ptr().cast()
        } else {
            ptr::null()
        };
        try_allocate(Self {
            filename,
            stamp: UnsafeCell::new(Stamp::default()),
            hosts: UnsafeCell::new(ptr::null_mut()),
            ips: UnsafeCell::new(IpSet::default()),
            #[cfg(target_pointer_width = "32")]
            _prefix_padding: [0; 4],
            filename_storage,
            checked_in_search: Cell::new(0),
        })
    }

    fn name(&self) -> Option<&CStr> {
        if self.filename.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(self.filename) })
        }
    }

    #[cfg(windows)]
    pub(super) unsafe fn ip_pools(
        file: *const Self,
    ) -> (*const std::ffi::c_void, *const std::ffi::c_void) {
        let ips = unsafe { (*file).ips.get().read() };
        (ips.ipv4.cast(), ips.ipv6.cast())
    }

    fn empty(&self) -> bool {
        let ips = unsafe { &*self.ips.get() };
        unsafe { (*self.hosts.get()).is_null() && ips.ipv4.is_null() && ips.ipv6.is_null() }
    }

    fn clear_contents(&self) {
        // These slots contain opaque pools allocated by the corresponding
        // Rust APIs. Clear them in place so every profile sees the same file.
        unsafe {
            zapret_host_destroy(self.hosts.get());
            zapret_ip_destroy(&mut (*self.ips.get()).ipv4);
            zapret_ip_destroy(&mut (*self.ips.get()).ipv6);
        }
    }
}

impl Drop for ListFile {
    fn drop(&mut self) {
        self.clear_contents();
    }
}

#[derive(Default)]
pub(super) struct FileRegistry(Vec<NonNull<ListFile>>);

impl Drop for FileRegistry {
    fn drop(&mut self) {
        for file in self.0.drain(..).rev() {
            drop(unsafe { Box::from_raw(file.as_ptr()) });
        }
    }
}

#[derive(Default)]
pub(super) struct Collection(VecDeque<NonNull<ListFile>>);

// All slots belong to the engine thread. The registry owns stable records;
// collections borrow them and are destroyed before their registry.
unsafe fn slot_or_init<T: Default>(slot: &mut *mut T) -> Option<&mut T> {
    if slot.is_null() {
        *slot = try_allocate(T::default())?.as_ptr();
    }
    unsafe { slot.as_mut() }
}

unsafe fn destroy<T>(slot: *mut *mut T) {
    let allocation = unsafe { slot.replace(ptr::null_mut()) };
    if !allocation.is_null() {
        drop(unsafe { Box::from_raw(allocation) });
    }
}

fn register(
    registry: &mut FileRegistry,
    collection: &mut Collection,
    name: Option<&CStr>,
) -> Option<NonNull<ListFile>> {
    // Windows path resolution happens before registration. Compare the same
    // filename bytes as upstream, and allocate each anonymous file separately.
    let existing = name.and_then(|name| {
        registry
            .0
            .iter()
            .rev()
            .copied()
            .find(|file| unsafe { file.as_ref().name() == Some(name) })
    });
    if let Some(file) = existing {
        if !collection.0.contains(&file) {
            collection.0.try_reserve(1).ok()?;
            collection.0.push_front(file);
        }
        return Some(file);
    }
    // Reserve both slots before publishing a new file and its first reference.
    registry.0.try_reserve(1).ok()?;
    collection.0.try_reserve(1).ok()?;
    let file = ListFile::try_new(name)?;
    registry.0.push(file);
    collection.0.push_front(file);
    Some(file)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_register(
    registry: *mut *mut FileRegistry,
    collection: *mut *mut Collection,
    name: *const c_char,
) -> *mut ListFile {
    let name = (!name.is_null()).then(|| unsafe { CStr::from_ptr(name) });
    let Some(registry) = (unsafe { slot_or_init(&mut *registry) }) else {
        return ptr::null_mut();
    };
    let Some(collection) = (unsafe { slot_or_init(&mut *collection) }) else {
        return ptr::null_mut();
    };
    register(registry, collection, name).map_or(ptr::null_mut(), NonNull::as_ptr)
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_list_files_at(
    registry: *const FileRegistry,
    index: usize,
) -> *mut ListFile {
    let Some(registry) = (unsafe { registry.as_ref() }) else {
        return ptr::null_mut();
    };
    registry
        .0
        .len()
        .checked_sub(index.saturating_add(1))
        .map_or(ptr::null_mut(), |offset| registry.0[offset].as_ptr())
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_files_reset(registry: *const FileRegistry) {
    if let Some(registry) = unsafe { registry.as_ref() } {
        for file in &registry.0 {
            let file = unsafe { file.as_ref() };
            unsafe { file.stamp.get().write(Stamp::default()) };
            file.checked_in_search.set(0);
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_files_destroy(slot: *mut *mut FileRegistry) {
    unsafe { destroy(slot) };
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_list_collection_at(
    collection: *const Collection,
    index: usize,
) -> *mut ListFile {
    unsafe { collection.as_ref() }
        .and_then(|collection| collection.0.get(index))
        .map_or(ptr::null_mut(), |file| file.as_ptr())
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_list_collection_empty(
    collection: *const Collection,
) -> bool {
    unsafe { collection.as_ref() }.is_none_or(|collection| {
        collection
            .0
            .iter()
            .all(|file| unsafe { file.as_ref().empty() })
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_collection_copy(
    to: *mut *mut Collection,
    from: *const Collection,
) -> bool {
    let Some(from) = (unsafe { from.as_ref() }) else {
        return true;
    };
    if from.0.is_empty() {
        return true;
    }
    if ptr::eq(unsafe { *to }, from) {
        return false;
    }
    let Some(to) = (unsafe { slot_or_init(&mut *to) }) else {
        return false;
    };
    if to.0.try_reserve(from.0.len()).is_err() {
        return false;
    }
    // A template appends its current order, including shared references that
    // already occur in the importing profile.
    to.0.extend(from.0.iter().copied());
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_collection_destroy(slot: *mut *mut Collection) {
    unsafe { destroy(slot) };
}

type ReadStamp = unsafe extern "C" fn(*const c_char, *mut Stamp, *const c_char) -> bool;
type Probe = unsafe extern "C" fn(*const c_char, *const c_char) -> bool;
type Append = unsafe extern "C" fn(*mut ListFile) -> bool;

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_reload(
    file: *mut ListFile,
    changed: *mut bool,
    kind: *const c_char,
    stat: ReadStamp,
    probe: Probe,
    append: Append,
) -> bool {
    let filename = unsafe { (*file).filename };
    if filename.is_null() {
        return true;
    }
    let search = ACTIVE_SEARCH.get();
    if search != 0 && unsafe { (*file).checked_in_search.get() } == search {
        return true;
    }
    let mut current = Stamp::default();
    if !unsafe { stat(filename, &mut current, kind) } {
        return true;
    }
    let stamp = unsafe { (*file).stamp.get() };
    if unsafe { *stamp } == current {
        unsafe { (*file).checked_in_search.set(search) };
        return true;
    }
    if !unsafe { probe(filename, kind) } {
        return true;
    }
    if !changed.is_null() {
        unsafe { changed.write(true) };
    }
    unsafe { (*file).clear_contents() };
    // The callbacks do filesystem work and can replace the contents. No Rust
    // references to the file or its pools are kept across these calls.
    if !unsafe { append(file) } {
        unsafe { (*file).clear_contents() };
        return false;
    }
    unsafe { stamp.write(current) };
    unsafe { (*file).checked_in_search.set(search) };
    true
}

const _: () = {
    use std::mem::{offset_of, size_of};
    assert!(size_of::<Stamp>() == 24);
    assert!(offset_of!(Stamp, size) == 16);
    assert!(offset_of!(ListFile, stamp) == 8);
    assert!(offset_of!(ListFile, hosts) == 32);
    assert!(offset_of!(ListFile, ips) == 32 + size_of::<usize>());
    let prefix_size = if cfg!(target_pointer_width = "64") {
        56
    } else {
        48
    };
    assert!(offset_of!(ListFile, filename_storage) == prefix_size);
};

#[cfg(test)]
mod tests {
    use super::*;
    thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
        static AVAILABLE: Cell<bool> = const { Cell::new(true) };
    }
    unsafe extern "C" fn stamp(_: *const c_char, out: *mut Stamp, _: *const c_char) -> bool {
        CALLS.set(CALLS.get() + 1);
        unsafe {
            out.write(Stamp {
                seconds: 1,
                ..Stamp::default()
            })
        };
        AVAILABLE.get()
    }
    unsafe extern "C" fn readable(_: *const c_char, _: *const c_char) -> bool {
        true
    }
    unsafe extern "C" fn append(_: *mut ListFile) -> bool {
        true
    }

    #[test]
    fn shared_file_checked_once_per_search_but_failures_and_resets_retry() {
        let file = ListFile::try_new(Some(c"list.txt")).unwrap();
        let registry = FileRegistry(vec![file]);
        let reload = || unsafe {
            assert!(zapret_list_reload(
                file.as_ptr(),
                ptr::null_mut(),
                c"ipset".as_ptr(),
                stamp,
                readable,
                append
            ));
        };
        CALLS.set(0);
        {
            let _scope = ReloadScope::enter();
            AVAILABLE.set(false);
            reload();
            AVAILABLE.set(true);
            reload();
            reload();
            assert_eq!(CALLS.get(), 2);
            unsafe { zapret_list_files_reset(&registry) };
            reload();
            assert_eq!(CALLS.get(), 3);
        }
        {
            let _scope = ReloadScope::enter();
            reload();
            reload();
        }
        reload();
        reload();
        assert_eq!(CALLS.get(), 6);
    }
}
