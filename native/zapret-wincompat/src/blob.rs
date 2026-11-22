//! Engine blob storage and startup input. The existing C ABI owns allocations.
mod startup;

use crate::{
    files::{open_file, path_input},
    filters::file_spec,
    helpers::{identifier, zapret_helper_parse_hex_str},
};
use std::{
    ffi::{CStr, c_char, c_void},
    fs::File,
    io::{Seek, SeekFrom},
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr::{self, NonNull},
};
use windows_sys::Win32::Storage::FileSystem::ReadFile;

#[repr(C)]
pub(super) struct Blob {
    pub(super) data: *mut u8,
    pub(super) size: usize,
    pub(super) capacity: usize,
    pub(super) name: *mut c_char,
    extra: *mut c_void,
    pub(super) next: *mut Blob,
    previous: *mut *mut Blob,
}

#[repr(C)]
pub(super) struct Allocator {
    allocate: unsafe extern "C" fn(usize) -> *mut c_void,
    release: unsafe extern "C" fn(*mut c_void),
}

#[repr(u32)]
#[derive(Clone, Copy)]
enum Error {
    Identifier = 1,
    Allocation,
    Duplicate,
    Offset,
    Access,
    BeyondEnd,
    Read,
    Hex,
    Size,
}

struct Allocation<'a>(NonNull<c_void>, &'a Allocator);
impl<'a> Allocation<'a> {
    fn new(size: usize, allocator: &'a Allocator) -> Result<Self, Error> {
        if size > isize::MAX as usize {
            return Err(Error::Size);
        }
        NonNull::new(unsafe { (allocator.allocate)(size.max(1)) })
            .map(|pointer| Self(pointer, allocator))
            .ok_or(Error::Allocation)
    }

    fn pointer<T>(&self) -> *mut T {
        self.0.cast().as_ptr()
    }

    fn into_raw<T>(self) -> *mut T {
        let pointer = self.pointer();
        std::mem::forget(self);
        pointer
    }
}
impl Drop for Allocation<'_> {
    fn drop(&mut self) {
        unsafe { (self.1.release)(self.0.as_ptr()) };
    }
}

#[repr(C)]
struct InputDetails {
    source: *const c_char,
    offset: u64,
    file_size: u64,
    name_length: usize,
}
impl InputDetails {
    fn new(source: *const c_char) -> Self {
        Self {
            source,
            offset: 0,
            file_size: 0,
            name_length: 0,
        }
    }
}

enum Source<'a> {
    Hex(&'a CStr),
    File(File),
}
impl<'a> Source<'a> {
    fn open(input: &'a CStr, details: &mut InputDetails) -> Result<Self, Error> {
        let bytes = input.to_bytes();
        if bytes.starts_with(b"0x") {
            let hex = unsafe { CStr::from_ptr(input.as_ptr().add(2)) };
            details.source = hex.as_ptr();
            return Ok(Self::Hex(hex));
        }
        let (offset, advance) = file_spec(bytes).ok_or(Error::Offset)?;
        if offset > i64::MAX as u64 {
            return Err(Error::Offset);
        }
        details.source = unsafe { input.as_ptr().add(advance) };
        details.offset = offset;
        let path = path_input(details.source).map_err(|_| Error::Access)?;
        let handle =
            open_file(&path, libc::O_RDONLY | libc::O_NOINHERIT, 0).map_err(|_| Error::Access)?;
        // The handle was opened for synchronous access and belongs to this File.
        Ok(Self::File(unsafe { File::from_raw_handle(handle.cast()) }))
    }

    fn capacity(&self, max_hex: usize, details: &mut InputDetails) -> Result<usize, Error> {
        match self {
            Self::Hex(hex) => Ok(hex.to_bytes().len().div_ceil(2).min(max_hex)),
            Self::File(file) => {
                let metadata = file.metadata().map_err(|_| Error::Access)?;
                if !metadata.is_file() {
                    return Err(Error::Access);
                }
                let length = metadata.len();
                details.file_size = length;
                if length == 0 {
                    return Ok(0);
                }
                if details.offset >= length {
                    return Err(Error::BeyondEnd);
                }
                usize::try_from(length - details.offset).map_err(|_| Error::Size)
            }
        }
    }

    unsafe fn read(self, output: *mut u8, capacity: usize, offset: u64) -> Result<usize, Error> {
        if capacity > isize::MAX as usize {
            return Err(Error::Size);
        }
        match self {
            Self::Hex(hex) => {
                let mut size = capacity;
                if unsafe { zapret_helper_parse_hex_str(hex.as_ptr(), output, &mut size) }
                    && size != 0
                {
                    Ok(size)
                } else {
                    Err(Error::Hex)
                }
            }
            Self::File(mut file) => {
                if offset != 0 {
                    file.seek(SeekFrom::Start(offset))
                        .map_err(|_| Error::Read)?;
                }
                let mut read = 0;
                while read < capacity {
                    let requested = (capacity - read).min(16 * 1024 * 1024) as u32;
                    let mut count = 0;
                    // ReadFile may write directly into the caller's uninitialized allocation.
                    if unsafe {
                        ReadFile(
                            file.as_raw_handle().cast(),
                            output.add(read),
                            requested,
                            &mut count,
                            ptr::null_mut(),
                        )
                    } == 0
                    {
                        return Err(Error::Read);
                    }
                    if count == 0 {
                        break;
                    }
                    read += count as usize;
                }
                Ok(read)
            }
        }
    }
}

fn split_name(input: &CStr, details: &mut InputDetails) -> Result<usize, Error> {
    let bytes = input.to_bytes();
    let length = bytes
        .iter()
        .position(|byte| *byte == b':')
        .unwrap_or(bytes.len());
    details.name_length = length;
    if !identifier(&bytes[..length]) {
        return Err(Error::Identifier);
    }
    Ok(length + usize::from(length < bytes.len()))
}

fn copy_name<'a>(
    input: &CStr,
    length: usize,
    allocator: &'a Allocator,
) -> Result<Allocation<'a>, Error> {
    let allocation = Allocation::new(length + 1, allocator)?;
    unsafe {
        ptr::copy_nonoverlapping(input.as_ptr(), allocation.pointer(), length);
        allocation.pointer::<c_char>().add(length).write(0);
    }
    Ok(allocation)
}

unsafe fn find(mut blob: *mut Blob, name: &[u8]) -> *mut Blob {
    while !blob.is_null() {
        let entry = unsafe { &*blob };
        if !entry.name.is_null() && unsafe { CStr::from_ptr(entry.name) }.to_bytes() == name {
            return blob;
        }
        blob = entry.next;
    }
    blob
}

unsafe fn append(
    head: *mut *mut Blob,
    allocation: Allocation<'_>,
    data: Option<Allocation<'_>>,
    name: Option<Allocation<'_>>,
    size: usize,
    capacity: usize,
) -> *mut Blob {
    let mut tail = head;
    while !unsafe { tail.read() }.is_null() {
        tail = unsafe { ptr::addr_of_mut!((*tail.read()).next) };
    }
    let entry: *mut Blob = allocation.into_raw();
    unsafe {
        entry.write(Blob {
            data: data.map_or(ptr::null_mut(), Allocation::into_raw),
            size,
            capacity,
            name: name.map_or(ptr::null_mut(), Allocation::into_raw),
            extra: ptr::null_mut(),
            next: ptr::null_mut(),
            previous: tail,
        });
        tail.write(entry);
    }
    entry
}

unsafe fn add_bytes(
    head: *mut *mut Blob,
    allocator: &Allocator,
    name: Option<&CStr>,
    source: *const u8,
    size: usize,
    reserve: usize,
) -> Result<*mut Blob, Error> {
    let capacity = size.checked_add(reserve).ok_or(Error::Size)?;
    let entry = Allocation::new(size_of::<Blob>(), allocator)?;
    let name = name
        .map(|name| copy_name(name, name.to_bytes().len(), allocator))
        .transpose()?;
    let data = if capacity != 0 {
        let data = Allocation::new(capacity, allocator)?;
        if size != 0 && !source.is_null() {
            unsafe { ptr::copy_nonoverlapping(source, data.pointer(), size) };
        }
        Some(data)
    } else {
        None
    };
    Ok(unsafe { append(head, entry, data, name, size, capacity) })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_blob_add(
    head: *mut *mut Blob,
    allocator: &Allocator,
    source: *const u8,
    size: usize,
    reserve: usize,
) -> *mut Blob {
    unsafe { add_bytes(head, allocator, None, source, size, reserve) }.unwrap_or(ptr::null_mut())
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_blob_find(head: *mut *mut Blob, name: *const c_char) -> *mut Blob {
    unsafe { find(head.read(), CStr::from_ptr(name).to_bytes()) }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_blob_destroy(blob: *mut Blob, allocator: &Allocator) {
    if !blob.is_null() {
        unsafe {
            (allocator.release)((*blob).extra);
            (allocator.release)((*blob).name.cast());
            (allocator.release)((*blob).data.cast());
            (allocator.release)(blob.cast());
        }
    }
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_blob_pop(head: *mut *mut Blob) -> *mut Blob {
    let first = unsafe { head.read() };
    if !first.is_null() {
        let next = unsafe { (*first).next };
        unsafe { head.write(next) };
        if !next.is_null() {
            unsafe { (*next).previous = head };
        }
        unsafe {
            (*first).next = ptr::null_mut();
            (*first).previous = ptr::null_mut();
        }
    }
    first
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_blob_destroy_list(head: *mut *mut Blob, allocator: &Allocator) {
    loop {
        let entry = unsafe { zapret_blob_pop(head) };
        if entry.is_null() {
            break;
        }
        unsafe { zapret_blob_destroy(entry, allocator) };
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_blob_load_argument(
    text: *const c_char,
    output: *mut u8,
    size: &mut usize,
    details: &mut InputDetails,
) -> u32 {
    *details = InputDetails::new(text);
    let result = (|| {
        let source = Source::open(unsafe { CStr::from_ptr(text) }, details)?;
        *size = unsafe { source.read(output, *size, details.offset) }?;
        Ok(())
    })();
    result.map_or_else(|error: Error| error as u32, |()| 0)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_blob_load_named(
    head: *mut *mut Blob,
    text: *const c_char,
    max_hex: usize,
    reserve: usize,
    allocator: &Allocator,
    details: &mut InputDetails,
    output: &mut *mut Blob,
) -> u32 {
    *details = InputDetails::new(text);
    let result = (|| {
        let text = unsafe { CStr::from_ptr(text) };
        let advance = split_name(text, details)?;
        let name = &text.to_bytes()[..details.name_length];
        let source = Source::open(
            unsafe { CStr::from_ptr(text.as_ptr().add(advance)) },
            details,
        )?;
        let capacity = source.capacity(max_hex, details)?;
        if !unsafe { find(head.read(), name) }.is_null() {
            return Err(Error::Duplicate);
        }
        let capacity_with_reserve = capacity.checked_add(reserve).ok_or(Error::Size)?;
        let entry = Allocation::new(size_of::<Blob>(), allocator)?;
        let name = copy_name(text, details.name_length, allocator)?;
        let data = Allocation::new(capacity_with_reserve, allocator)?;
        let size = unsafe { source.read(data.pointer(), capacity, details.offset) }?;
        *output = unsafe { append(head, entry, Some(data), Some(name), size, size + reserve) };
        Ok(())
    })();
    result.map_or_else(|error: Error| error as u32, |()| 0)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_blob_load_const(
    head: *mut *mut Blob,
    name: *const c_char,
    source: *const u8,
    size: usize,
    reserve: usize,
    allocator: &Allocator,
    output: &mut *mut Blob,
) -> u32 {
    let result = (|| {
        let name = unsafe { CStr::from_ptr(name) };
        if !unsafe { find(head.read(), name.to_bytes()) }.is_null() {
            return Err(Error::Duplicate);
        }
        *output = unsafe { add_bytes(head, allocator, Some(name), source, size, reserve) }?;
        Ok(())
    })();
    result.map_or_else(|error: Error| error as u32, |()| 0)
}
