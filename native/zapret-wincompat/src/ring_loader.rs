//! The trusted loader runs from the engine's static library, before any DLL code.
use core::{
    ffi::{CStr, c_char},
    mem::{size_of, transmute},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, FARPROC, FreeLibrary, GENERIC_READ, HANDLE, HMODULE, INVALID_HANDLE_VALUE,
    },
    Security::{
        Cryptography::{
            BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE, BCRYPT_SHA256_ALGORITHM,
            BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
            BCryptHashData, BCryptOpenAlgorithmProvider,
        },
        SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, GetFileSizeEx, OPEN_EXISTING, ReadFile,
    },
    System::{
        IO::OVERLAPPED,
        LibraryLoader::{
            GetModuleFileNameW, GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
            LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
        },
    },
};

const PATH_CAPACITY: usize = 32768;
const FILE_LIMIT: i64 = 32 * 1024 * 1024;
const READ_SIZE: usize = 16384;
const DLL_NAME: &[u8] = b"zapret-ring.dll\0";

type Operation = Option<unsafe extern "C" fn()>;

#[repr(C)]
struct Api {
    size: usize,
    version: u32,
    invoke: Operation,
    drop_object: Operation,
}

#[repr(C)]
struct Binding {
    api: *const Api,
    pin: HANDLE,
    module: HMODULE,
}

#[repr(C)]
struct Native {
    filename: unsafe extern "system" fn(HMODULE, *mut u16, u32) -> u32,
    open_file: unsafe extern "system" fn(
        *const u16,
        u32,
        u32,
        *const SECURITY_ATTRIBUTES,
        u32,
        u32,
        HANDLE,
    ) -> HANDLE,
    file_size: unsafe extern "system" fn(HANDLE, *mut i64) -> i32,
    open_provider:
        unsafe extern "system" fn(*mut BCRYPT_ALG_HANDLE, *const u16, *const u16, u32) -> i32,
    create_hash: unsafe extern "system" fn(
        BCRYPT_ALG_HANDLE,
        *mut BCRYPT_HASH_HANDLE,
        *mut u8,
        u32,
        *const u8,
        u32,
        u32,
    ) -> i32,
    read: unsafe extern "system" fn(HANDLE, *mut u8, u32, *mut u32, *mut OVERLAPPED) -> i32,
    hash_data: unsafe extern "system" fn(BCRYPT_HASH_HANDLE, *const u8, u32, u32) -> i32,
    finish: unsafe extern "system" fn(BCRYPT_HASH_HANDLE, *mut u8, u32, u32) -> i32,
    load: unsafe extern "system" fn(*const u16, HANDLE, u32) -> HMODULE,
    symbol: unsafe extern "system" fn(HMODULE, *const u8) -> FARPROC,
    unload: unsafe extern "system" fn(HMODULE) -> i32,
    destroy_hash: unsafe extern "system" fn(BCRYPT_HASH_HANDLE) -> i32,
    close_provider: unsafe extern "system" fn(BCRYPT_ALG_HANDLE, u32) -> i32,
    close_file: unsafe extern "system" fn(HANDLE) -> i32,
}

const WINDOWS: Native = Native {
    filename: GetModuleFileNameW,
    open_file: CreateFileW,
    file_size: GetFileSizeEx,
    open_provider: BCryptOpenAlgorithmProvider,
    create_hash: BCryptCreateHash,
    read: ReadFile,
    hash_data: BCryptHashData,
    finish: BCryptFinishHash,
    load: LoadLibraryExW,
    symbol: GetProcAddress,
    unload: FreeLibrary,
    destroy_hash: BCryptDestroyHash,
    close_provider: BCryptCloseAlgorithmProvider,
    close_file: CloseHandle,
};

struct Verification<'a> {
    native: &'a Native,
    pin: HANDLE,
    provider: BCRYPT_ALG_HANDLE,
    hash: BCRYPT_HASH_HANDLE,
}

impl Drop for Verification<'_> {
    fn drop(&mut self) {
        unsafe {
            if !self.hash.is_null() {
                (self.native.destroy_hash)(self.hash);
            }
            if !self.provider.is_null() {
                (self.native.close_provider)(self.provider, 0);
            }
            if self.pin != INVALID_HANDLE_VALUE {
                (self.native.close_file)(self.pin);
            }
        }
    }
}

fn sibling_path(path: &mut [u16; PATH_CAPACITY], length: usize) -> bool {
    if length == 0 || length >= path.len() {
        return false;
    }
    let directory = path[..length]
        .iter()
        .rposition(|&unit| unit == u16::from(b'\\') || unit == u16::from(b'/'))
        .map_or(0, |separator| separator + 1);
    if directory + DLL_NAME.len() >= path.len() {
        return false;
    }
    for (unit, byte) in path[directory..].iter_mut().zip(DLL_NAME) {
        *unit = u16::from(*byte);
    }
    true
}

fn hex_pin(digest: [u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = [0; 64];
    for (byte, pair) in digest.into_iter().zip(output.chunks_exact_mut(2)) {
        pair[0] = HEX[usize::from(byte >> 4)];
        pair[1] = HEX[usize::from(byte & 15)];
    }
    output
}

impl Verification<'_> {
    unsafe fn digest(&mut self) -> Option<[u8; 32]> {
        unsafe {
            let mut size = 0;
            if (self.native.file_size)(self.pin, &mut size) == 0
                || !(1..=FILE_LIMIT).contains(&size)
            {
                return None;
            }
            if (self.native.open_provider)(
                &mut self.provider,
                BCRYPT_SHA256_ALGORITHM,
                ptr::null(),
                0,
            ) < 0
                || (self.native.create_hash)(
                    self.provider,
                    &mut self.hash,
                    ptr::null_mut(),
                    0,
                    ptr::null(),
                    0,
                    0,
                ) < 0
            {
                return None;
            }
            let mut bytes = [0; READ_SIZE];
            let mut read = 0;
            loop {
                if (self.native.read)(
                    self.pin,
                    bytes.as_mut_ptr(),
                    READ_SIZE as u32,
                    &mut read,
                    ptr::null_mut(),
                ) == 0
                {
                    return None;
                }
                if read == 0 {
                    break;
                }
                if read as usize > bytes.len()
                    || (self.native.hash_data)(self.hash, bytes.as_ptr(), read, 0) < 0
                {
                    return None;
                }
            }
            let mut digest = [0; 32];
            ((self.native.finish)(self.hash, digest.as_mut_ptr(), 32, 0) >= 0).then_some(digest)
        }
    }
}

unsafe fn load_api(native: &Native, module: HMODULE) -> *const Api {
    let Some(symbol) = (unsafe { (native.symbol)(module, c"zapret_ring_api_v1".as_ptr().cast()) })
    else {
        return ptr::null();
    };
    let get: unsafe extern "C" fn() -> *const Api = unsafe { transmute(symbol) };
    let api = unsafe { get() };
    // A rejected API can be shorter than our full view. Preserve the pinned
    // version, size, invoke and drop checks and their short-circuit order.
    if api.is_null()
        || unsafe {
            (*api).version != 1
                || (*api).size != size_of::<Api>()
                || (*api).invoke.is_none()
                || (*api).drop_object.is_none()
        }
    {
        ptr::null()
    } else {
        api
    }
}

unsafe fn bind(binding: *mut Binding, expected: *const c_char, native: &Native) -> bool {
    if !unsafe { (*binding).api }.is_null() {
        return true;
    }
    let mut path = [0; PATH_CAPACITY];
    let length =
        unsafe { (native.filename)(ptr::null_mut(), path.as_mut_ptr(), PATH_CAPACITY as u32) };
    if !sibling_path(&mut path, length as usize) {
        return false;
    }
    let pin = unsafe {
        (native.open_file)(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if pin == INVALID_HANDLE_VALUE {
        return false;
    }
    let mut verification = Verification {
        native,
        pin,
        provider: ptr::null_mut(),
        hash: ptr::null_mut(),
    };
    let Some(digest) = (unsafe { verification.digest() }) else {
        return false;
    };
    if unsafe { CStr::from_ptr(expected) }.to_bytes() != hex_pin(digest) {
        return false;
    }

    let module = unsafe {
        (native.load)(
            path.as_ptr(),
            ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return false;
    }
    let api = unsafe { load_api(native, module) };
    if api.is_null() {
        unsafe { (native.unload)(module) };
        return false;
    }
    // Keep both the file pin and the module alive for the v1 table's entire lifetime.
    unsafe {
        (*binding).api = api;
        (*binding).pin = pin;
        (*binding).module = module;
    }
    verification.pin = INVALID_HANDLE_VALUE;
    true
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ring_load(binding: *mut Binding, expected: *const c_char) -> bool {
    unsafe { bind(binding, expected, &WINDOWS) }
}

// Used only by the old/new conformance executable. The linker drops this entry
// from the engine, whose loader always uses WINDOWS.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_ring_load_fixture(
    binding: *mut Binding,
    expected: *const c_char,
    native: &Native,
) -> bool {
    unsafe { bind(binding, expected, native) }
}

const _: () = {
    let pointer = size_of::<usize>();
    assert!(size_of::<Api>() == 4 * pointer);
    assert!(core::mem::offset_of!(Api, version) == pointer);
    assert!(core::mem::offset_of!(Api, invoke) == 2 * pointer);
    assert!(core::mem::offset_of!(Api, drop_object) == 3 * pointer);
    assert!(size_of::<Binding>() == 3 * pointer && size_of::<Native>() == 14 * pointer);
};
