//! Stable native engine cache records. C may mutate their public payloads
//! between calls; Rust owns their indexes and host-failure strings.
use std::{
    borrow::Borrow,
    cell::UnsafeCell,
    collections::{BTreeMap, HashMap},
    ffi::{CStr, CString, c_char},
    hash::Hash,
    ops::Bound::{Excluded, Unbounded},
    ptr, slice,
    sync::atomic::{AtomicU64, Ordering},
};

const IFACE_SIZE: usize = 44;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[repr(C)]
struct Stored<K, V> {
    data: UnsafeCell<V>,
    id: u64,
    key: K,
}

impl<K, V> Stored<K, V> {
    fn data_ptr(&self) -> *mut V {
        // Keep provenance for the whole allocation: remove reads the private
        // id after the public prefix. Only that UnsafeCell prefix is mutable
        // through C, while the id and indexed key remain read-only.
        ptr::from_ref(self).cast_mut().cast()
    }
}

struct Store<K, V> {
    names: HashMap<K, Vec<u64>>,
    records: BTreeMap<u64, Box<Stored<K, V>>>,
    buckets: Option<BucketOrder>,
}

impl<K, V> Default for Store<K, V> {
    fn default() -> Self {
        Self {
            names: HashMap::new(),
            records: BTreeMap::new(),
            buckets: None,
        }
    }
}

trait CacheKey {
    fn legacy_hash(&self) -> Option<u32> {
        None
    }
}

impl CacheKey for CString {
    fn legacy_hash(&self) -> Option<u32> {
        Some(self.as_bytes().iter().fold(0u32, |hash, &byte| {
            hash.wrapping_mul(33).wrapping_add(u32::from(byte))
        }))
    }
}

#[derive(Clone, Default)]
struct Bucket {
    count: usize,
    expansion: usize,
}

struct BucketOrder {
    buckets: Vec<Bucket>,
    inefficient: usize,
    stopped: bool,
}

impl Default for BucketOrder {
    fn default() -> Self {
        Self {
            buckets: vec![Bucket::default(); 32],
            inefficient: 0,
            stopped: false,
        }
    }
}

impl BucketOrder {
    fn add(&mut self, hash: u32) -> bool {
        let index = hash as usize & (self.buckets.len() - 1);
        let bucket = &mut self.buckets[index];
        bucket.count += 1;
        !self.stopped && bucket.count >= (bucket.expansion + 1) * 10
    }

    fn grow(&mut self, total: usize, hashes: impl Iterator<Item = u32>) {
        let mut buckets = vec![Bucket::default(); self.buckets.len() * 2];
        let ideal = total.div_ceil(buckets.len());
        let mut nonideal = 0;
        for hash in hashes {
            let index = hash as usize & (buckets.len() - 1);
            let bucket = &mut buckets[index];
            bucket.count += 1;
            if bucket.count > ideal {
                nonideal += 1;
                if bucket.count > bucket.expansion * ideal {
                    bucket.expansion += 1;
                }
            }
        }
        self.inefficient = if nonideal > total / 2 {
            self.inefficient + 1
        } else {
            0
        };
        self.stopped = self.inefficient > 1;
        self.buckets = buckets;
    }

    fn remove(&mut self, hash: u32) {
        let index = hash as usize & (self.buckets.len() - 1);
        self.buckets[index].count -= 1;
    }
}

impl<K: Eq + Hash + Clone + CacheKey, V> Store<K, V> {
    fn add(&mut self, key: K, data: V) -> *mut V {
        if self.names.try_reserve(1).is_err() {
            return ptr::null_mut();
        }
        let ids = self.names.entry(key.clone()).or_default();
        if ids.try_reserve(1).is_err() {
            return ptr::null_mut();
        }
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let legacy_hash = key.legacy_hash();
        let record = Box::new(Stored {
            data: UnsafeCell::new(data),
            id,
            key,
        });
        let result = record.data_ptr();
        ids.push(id);
        self.records.insert(id, record);
        if let Some(hash) = legacy_hash {
            let mut buckets = self.buckets.take().unwrap_or_default();
            if buckets.add(hash) {
                buckets.grow(
                    self.records.len(),
                    self.records
                        .values()
                        .filter_map(|record| record.key.legacy_hash()),
                );
                // Pinned uthash reverses bucket chains on expansion. Entries
                // with the same string reverse relative order as well.
                for ids in self.names.values_mut() {
                    ids.reverse();
                }
            }
            self.buckets = Some(buckets);
        }
        result
    }

    fn find<Q: Eq + Hash + ?Sized>(&self, key: &Q) -> *mut V
    where
        K: Borrow<Q>,
    {
        self.names
            .get(key)
            .and_then(|ids| ids.last())
            .and_then(|id| self.records.get(id))
            .map_or(ptr::null_mut(), |record| record.data_ptr())
    }

    fn after(&self, cursor: &mut u64) -> Option<&Stored<K, V>> {
        let (&id, record) = self.records.range((Excluded(*cursor), Unbounded)).next()?;
        *cursor = id;
        Some(record)
    }

    unsafe fn remove(&mut self, data: *const V) {
        // repr(C) and UnsafeCell's transparent layout place the public C
        // payload at offset zero in the Rust-owned, stable allocation.
        let id = unsafe { (*data.cast::<Stored<K, V>>()).id };
        if let Some(record) = self.records.remove(&id) {
            if let Some(hash) = record.key.legacy_hash() {
                if let Some(buckets) = self.buckets.as_mut() {
                    buckets.remove(hash);
                }
            }
            if let Some(ids) = self.names.get_mut(&record.key) {
                ids.retain(|&value| value != id);
                if ids.is_empty() {
                    self.names.remove(&record.key);
                }
            }
        }
    }
}

unsafe fn add<K: Eq + Hash + Clone + CacheKey, V>(
    slot: *mut *mut Store<K, V>,
    key: K,
    data: V,
) -> *mut V {
    let slot = unsafe { &mut *slot };
    if slot.is_null() {
        let mut store = Box::<Store<K, V>>::default();
        let result = store.add(key, data);
        if !result.is_null() {
            *slot = Box::into_raw(store);
        }
        result
    } else {
        unsafe { &mut **slot }.add(key, data)
    }
}

unsafe fn remove<K: Eq + Hash + Clone + CacheKey, V>(slot: *mut *mut Store<K, V>, data: *const V) {
    let slot = unsafe { &mut *slot };
    let Some(store) = (unsafe { slot.as_mut() }) else {
        return;
    };
    unsafe { store.remove(data) };
    if store.records.is_empty() {
        let store = std::mem::replace(slot, ptr::null_mut());
        drop(unsafe { Box::from_raw(store) });
    }
}

#[repr(C)]
pub(super) struct Failure {
    name: *const c_char,
    pub(super) counter: i32,
    expires: i64,
}
type Failures = Store<CString, Failure>;

// Private ABI: roots belong to the engine thread; all names are terminated.
// Returned records remain valid until removal, expiry or destruction. C field
// access occurs after Rust calls return, through UnsafeCell-backed payloads.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_hostfail_add(
    slot: *mut *mut Failures,
    name: *const c_char,
    timeout: i32,
    now: i64,
) -> *mut Failure {
    let name = unsafe { CStr::from_ptr(name) }.to_owned();
    let data = Failure {
        name: name.as_ptr(),
        counter: 0,
        expires: now.wrapping_add(i64::from(timeout)),
    };
    unsafe { add(slot, name, data) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_hostfail_find(
    store: *const Failures,
    name: *const c_char,
) -> *mut Failure {
    unsafe { store.as_ref() }.map_or(ptr::null_mut(), |store| {
        store.find(unsafe { CStr::from_ptr(name) })
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_hostfail_after(
    store: *const Failures,
    cursor: *mut u64,
) -> *mut Failure {
    unsafe { store.as_ref() }
        .and_then(|store| store.after(unsafe { &mut *cursor }))
        .map_or(ptr::null_mut(), |record| record.data_ptr())
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_hostfail_remove(slot: *mut *mut Failures, data: *const Failure) {
    unsafe { remove(slot, data) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_hostfail_destroy(slot: *mut *mut Failures) {
    let store = unsafe { slot.replace(ptr::null_mut()) };
    if !store.is_null() {
        drop(unsafe { Box::from_raw(store) });
    }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_hostfail_increment(data: *mut Failure) {
    let data = unsafe { &mut *data };
    data.counter = data.counter.wrapping_add(1);
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_hostfail_expired(data: *const Failure, now: i64) -> i32 {
    i32::from(now >= unsafe { (*data).expires })
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct IpKey {
    iface: [u8; IFACE_SIZE],
    address: [u8; 16],
}

impl CacheKey for IpKey {}

unsafe fn ip_key(address: *const u8, length: usize, iface: *const c_char) -> IpKey {
    let mut key = IpKey {
        iface: [0; IFACE_SIZE],
        address: [0; 16],
    };
    key.address[..length].copy_from_slice(unsafe { slice::from_raw_parts(address, length) });
    if !iface.is_null() {
        let text = unsafe { CStr::from_ptr(iface) }.to_bytes();
        let copied = text.len().min(IFACE_SIZE - 1);
        key.iface[..copied].copy_from_slice(&text[..copied]);
    }
    key
}

#[repr(C)]
pub(super) struct IpItem {
    last: i64,
    pub(super) hostname: *mut c_char,
    pub(super) hostname_is_ip: u8,
    pub(super) ttl: u8,
}
type IpCache = Store<IpKey, IpItem>;

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ipcache_find(
    store: *const IpCache,
    address: *const u8,
    length: usize,
    iface: *const c_char,
) -> *mut IpItem {
    let Some(store) = (unsafe { store.as_ref() }) else {
        return ptr::null_mut();
    };
    store.find(&unsafe { ip_key(address, length, iface) })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ipcache_add(
    slot: *mut *mut IpCache,
    address: *const u8,
    length: usize,
    iface: *const c_char,
    now: i64,
) -> *mut IpItem {
    let key = unsafe { ip_key(address, length, iface) };
    if let Some(store) = unsafe { (*slot).as_ref() } {
        let found = store.find(&key);
        if !found.is_null() {
            return found;
        }
    }
    unsafe {
        add(
            slot,
            key,
            IpItem {
                last: now,
                hostname: ptr::null_mut(),
                hostname_is_ip: 0,
                ttl: 0,
            },
        )
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ipcache_touch(data: *mut IpItem, now: i64) {
    unsafe { (*data).last = now };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ipcache_hostname(item: *const IpItem) -> *mut c_char {
    unsafe { (*item).hostname }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ipcache_after(
    store: *const IpCache,
    cursor: *mut u64,
    address: *mut u8,
    iface: *mut u8,
) -> *mut IpItem {
    let Some(record) =
        (unsafe { store.as_ref() }).and_then(|store| store.after(unsafe { &mut *cursor }))
    else {
        return ptr::null_mut();
    };
    if !address.is_null() {
        unsafe { ptr::copy_nonoverlapping(record.key.address.as_ptr(), address, 16) };
    }
    if !iface.is_null() {
        unsafe { ptr::copy_nonoverlapping(record.key.iface.as_ptr(), iface, IFACE_SIZE) };
    }
    record.data_ptr()
}

// C frees the optional hostname with the allocator that created it, then calls
// remove. No Rust callback or borrow spans that C allocation boundary.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ipcache_remove(slot: *mut *mut IpCache, data: *const IpItem) {
    unsafe { remove(slot, data) };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ipcache_expired(data: *const IpItem, lifetime: i64, now: i64) -> i32 {
    i32::from(lifetime != 0 && now >= unsafe { (*data).last }.wrapping_add(lifetime))
}

#[unsafe(no_mangle)]
extern "C" fn zapret_cache_purge_due(previous: i64, now: i64) -> i32 {
    i32::from(previous != now)
}

const _: () = {
    use std::mem::{offset_of, size_of};
    let pointer = size_of::<usize>();
    assert!(size_of::<Failure>() == 2 * pointer + 8);
    assert!(offset_of!(Failure, expires) == 2 * pointer);
    assert!(size_of::<IpItem>() == 2 * pointer + 8);
    assert!(offset_of!(IpItem, ttl) == pointer + 9);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_failures_find_the_newest_and_deleting_it_reveals_the_older_record() {
        let mut root = ptr::null_mut();
        unsafe {
            let first = zapret_hostfail_add(&mut root, c"example.test".as_ptr(), 10, 100);
            zapret_hostfail_increment(first);
            let second = zapret_hostfail_add(&mut root, c"example.test".as_ptr(), 20, 100);
            assert_eq!(zapret_hostfail_find(root, c"example.test".as_ptr()), second);
            assert_eq!((*first).counter, 1);
            assert_eq!(zapret_hostfail_expired(first, 109), 0);
            assert_eq!(zapret_hostfail_expired(first, 110), 1);
            zapret_hostfail_remove(&mut root, second);
            assert_eq!(zapret_hostfail_find(root, c"example.test".as_ptr()), first);
            let mut cursor = 0;
            assert_eq!(zapret_hostfail_after(root, &mut cursor), first);
            zapret_hostfail_remove(&mut root, first);
            assert!(root.is_null());
            zapret_hostfail_destroy(&mut root);
        }
    }

    #[test]
    fn failure_duplicate_lookup_retains_pinned_bucket_expansion_order() {
        let mut root = ptr::null_mut();
        unsafe {
            let first = zapret_hostfail_add(&mut root, c"same".as_ptr(), 10, 100);
            for _ in 1..10 {
                zapret_hostfail_add(&mut root, c"same".as_ptr(), 10, 100);
            }
            assert_eq!(zapret_hostfail_find(root, c"same".as_ptr()), first);
            let newest = zapret_hostfail_add(&mut root, c"same".as_ptr(), 10, 100);
            assert_eq!(zapret_hostfail_find(root, c"same".as_ptr()), newest);
            zapret_hostfail_destroy(&mut root);
        }
    }

    #[test]
    fn failure_payloads_and_names_stay_valid_when_the_index_grows() {
        let mut root = ptr::null_mut();
        unsafe {
            let first = zapret_hostfail_add(&mut root, c"first".as_ptr(), -3, 100);
            let name = (*first).name;
            for index in 0..1000 {
                let text = CString::new(index.to_string()).unwrap();
                zapret_hostfail_add(&mut root, text.as_ptr(), 20, 100);
            }
            assert_eq!(CStr::from_ptr(name), c"first");
            assert_eq!(zapret_hostfail_find(root, name), first);
            assert_eq!((*first).expires, 97);
            zapret_hostfail_destroy(&mut root);
            assert!(root.is_null());
        }
    }

    #[test]
    fn interface_keys_truncate_bytes_and_touch_retains_the_payload() {
        let address = [192, 0, 2, 1];
        let mut root = ptr::null_mut();
        let prefix = "x".repeat(IFACE_SIZE - 1);
        let first_iface = CString::new(format!("{prefix}a")).unwrap();
        let second_iface = CString::new(format!("{prefix}b")).unwrap();
        unsafe {
            let item =
                zapret_ipcache_add(&mut root, address.as_ptr(), 4, first_iface.as_ptr(), 100);
            (*item).ttl = 64;
            assert_eq!(
                zapret_ipcache_find(root, address.as_ptr(), 4, second_iface.as_ptr()),
                item
            );
            assert!(zapret_ipcache_find(root, address.as_ptr(), 4, ptr::null()).is_null());
            zapret_ipcache_touch(item, 200);
            assert_eq!((*item).last, 200);
            assert_eq!((*item).ttl, 64);
            assert_eq!(zapret_ipcache_expired(item, 0, i64::MAX), 0);
            assert_eq!(zapret_ipcache_expired(item, 10, 209), 0);
            assert_eq!(zapret_ipcache_expired(item, 10, 210), 1);
            zapret_ipcache_remove(&mut root, item);
            assert!(root.is_null());
        }
    }

    #[test]
    fn purge_rate_limit_tracks_a_second_even_when_the_clock_moves_backwards() {
        assert_eq!(zapret_cache_purge_due(0, 0), 0);
        assert_eq!(zapret_cache_purge_due(100, 100), 0);
        assert_eq!(zapret_cache_purge_due(100, 99), 1);
        assert_eq!(zapret_cache_purge_due(100, 101), 1);
    }
}
