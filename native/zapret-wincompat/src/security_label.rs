//! Native integrity labels and owned known-folder initialization.
use crate::files::path_input;
use std::{
    ffi::{c_char, c_void},
    mem::size_of,
    ptr, slice,
};
use windows_sys::{
    Win32::{
        Foundation::{
            ERROR_FILENAME_EXCED_RANGE, ERROR_GEN_FAILURE, ERROR_INVALID_DATA,
            ERROR_INVALID_PARAMETER, ERROR_NO_UNICODE_TRANSLATION, GetLastError, HANDLE,
            RPC_E_CHANGED_MODE,
        },
        Security::{
            ACL, ACL_REVISION, ACL_REVISION_DS, AddMandatoryAce,
            Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW, SetSecurityInfo},
            InitializeAcl, LABEL_SECURITY_INFORMATION, SID, SID_IDENTIFIER_AUTHORITY,
        },
        Storage::FileSystem::{
            FILE_ATTRIBUTE_DIRECTORY, GetFileAttributesW, INVALID_FILE_ATTRIBUTES,
        },
        System::{
            Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoTaskMemFree, CoUninitialize},
            Environment::SetEnvironmentVariableW,
        },
        UI::Shell::{FOLDERID_LocalAppDataLow, SHGetKnownFolderPath},
    },
    core::GUID,
};

pub(crate) fn label_device() -> u32 {
    unsafe { zapret_security_label_file(c"\\\\.\\WinDivert".as_ptr(), 4096, 0, ptr::null()) }
}
pub(crate) unsafe fn label_directory(path: *const u16) -> u32 {
    unsafe { zapret_security_label_w(path, 4096, 3, ptr::null()) }
}

#[repr(C)]
struct Ops {
    initialize_acl: unsafe extern "system" fn(*mut ACL, u32, u32) -> i32,
    add: unsafe extern "system" fn(*mut ACL, u32, u32, u32, *mut c_void) -> i32,
    attributes: unsafe extern "system" fn(*const u16) -> u32,
    named: unsafe extern "system" fn(
        *const u16,
        i32,
        u32,
        *mut c_void,
        *mut c_void,
        *const ACL,
        *const ACL,
    ) -> u32,
    object: unsafe extern "system" fn(
        HANDLE,
        i32,
        u32,
        *mut c_void,
        *mut c_void,
        *const ACL,
        *const ACL,
    ) -> u32,
    error: unsafe extern "system" fn() -> u32,
    folder: unsafe extern "system" fn(*const GUID, u32, HANDLE, *mut *mut u16) -> i32,
    free: unsafe extern "system" fn(*const c_void),
    environment: unsafe extern "system" fn(*const u16, *const u16) -> i32,
    initialize_com: unsafe extern "system" fn(*const c_void, u32) -> i32,
    uninitialize_com: unsafe extern "system" fn(),
}
const NATIVE: Ops = Ops {
    initialize_acl: InitializeAcl,
    add: AddMandatoryAce,
    attributes: GetFileAttributesW,
    named: SetNamedSecurityInfoW,
    object: SetSecurityInfo,
    error: GetLastError,
    folder: SHGetKnownFolderPath,
    free: CoTaskMemFree,
    environment: SetEnvironmentVariableW,
    initialize_com: CoInitializeEx,
    uninitialize_com: CoUninitialize,
};
unsafe fn ops<'a>(input: *const Ops) -> &'a Ops {
    if input.is_null() {
        &NATIVE
    } else {
        unsafe { &*input }
    }
}
fn failure(ops: &Ops) -> u32 {
    match unsafe { (ops.error)() } {
        0 => ERROR_GEN_FAILURE,
        error => error,
    }
}
fn status(result: Result<(), u32>) -> u32 {
    result.err().unwrap_or(0)
}
#[repr(C, align(4))]
struct LabelAcl {
    header: ACL,
    space: [u8; 24],
}
fn acl(rid: u32, revision: u32, flags: u32, ops: &Ops) -> Result<LabelAcl, u32> {
    let mut value = LabelAcl {
        header: ACL::default(),
        space: [0; 24],
    };
    let mut sid = SID {
        Revision: 1,
        SubAuthorityCount: 1,
        IdentifierAuthority: SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 16],
        },
        SubAuthority: [rid],
    };
    if unsafe {
        (ops.initialize_acl)(
            &mut value.header,
            size_of::<LabelAcl>() as u32,
            ACL_REVISION,
        )
    } == 0
    {
        return Err(failure(ops));
    }
    if unsafe {
        (ops.add)(
            &mut value.header,
            revision,
            flags,
            1,
            ptr::addr_of_mut!(sid).cast(),
        )
    } == 0
    {
        return Err(failure(ops));
    }
    Ok(value)
}
unsafe fn device(path: *const u16) -> bool {
    for (index, unit) in [92u16, 92, 46, 92].into_iter().enumerate() {
        if unsafe { path.add(index).read() } != unit {
            return false;
        }
    }
    true
}
unsafe fn file(path: *const u16, rid: u32, flags: u32, ops: &Ops) -> Result<(), u32> {
    if path.is_null() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let attributes = if unsafe { device(path) } {
        0
    } else {
        unsafe { (ops.attributes)(path) }
    };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return Err(failure(ops));
    }
    let acl = acl(
        rid,
        if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            ACL_REVISION_DS
        } else {
            ACL_REVISION
        },
        flags,
        ops,
    )?;
    let error = unsafe {
        (ops.named)(
            path,
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            &acl.header,
        )
    };
    if error == 0 { Ok(()) } else { Err(error) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_security_label_w(
    path: *const u16,
    rid: u32,
    flags: u32,
    input: *const Ops,
) -> u32 {
    status(unsafe { file(path, rid, flags, ops(input)) })
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_security_label_file(
    path: *const c_char,
    rid: u32,
    flags: u32,
    input: *const Ops,
) -> u32 {
    status((|| {
        let path = path_input(path)?;
        unsafe { file(path.as_ptr(), rid, flags, ops(input)) }
    })())
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_security_ensure(
    path: *const c_char,
    directory: bool,
    input: *const Ops,
) -> u32 {
    unsafe { zapret_security_label_file(path, 4096, if directory { 3 } else { 0 }, input) }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_security_label_object(
    handle: HANDLE,
    kind: i32,
    rid: u32,
    revision: u32,
    flags: u32,
    input: *const Ops,
) -> u32 {
    if handle.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let ops = unsafe { ops(input) };
    status((|| {
        let acl = acl(rid, revision, flags, ops)?;
        let error = unsafe {
            (ops.object)(
                handle,
                kind,
                LABEL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
                &acl.header,
            )
        };
        if error == 0 { Ok(()) } else { Err(error) }
    })())
}
struct Apartment<'a> {
    ops: &'a Ops,
    owned: bool,
}
impl Drop for Apartment<'_> {
    fn drop(&mut self) {
        if self.owned {
            unsafe { (self.ops.uninitialize_com)() };
        }
    }
}
struct Folder<'a> {
    ops: &'a Ops,
    path: *mut u16,
}
impl Drop for Folder<'_> {
    fn drop(&mut self) {
        if !self.path.is_null() {
            unsafe { (self.ops.free)(self.path.cast()) };
        }
    }
}
fn hresult(value: i32) -> u32 {
    let value = value as u32;
    if value & 0xffff_0000 == 0x8007_0000 && value & 65535 != 0 {
        value & 65535
    } else {
        ERROR_GEN_FAILURE
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_security_appdata(input: *const Ops) -> u32 {
    let ops = unsafe { ops(input) };
    status((|| {
        let hr = unsafe { (ops.initialize_com)(ptr::null(), COINIT_APARTMENTTHREADED as u32) };
        if hr < 0 && hr != RPC_E_CHANGED_MODE {
            return Err(hresult(hr));
        }
        let _apartment = Apartment {
            ops,
            owned: hr >= 0,
        };
        let mut path = ptr::null_mut();
        let hr = unsafe { (ops.folder)(&FOLDERID_LocalAppDataLow, 0, ptr::null_mut(), &mut path) };
        // The documented ownership rule applies even to a failed folder query.
        let folder = Folder { ops, path };
        if hr < 0 {
            return Err(hresult(hr));
        }
        if folder.path.is_null() {
            return Err(ERROR_INVALID_DATA);
        }
        let length = (0..32_768)
            .find(|&index| unsafe { folder.path.add(index).read() } == 0)
            .ok_or(ERROR_FILENAME_EXCED_RANGE)?;
        if length == 0 {
            return Err(ERROR_INVALID_DATA);
        }
        if char::decode_utf16(
            unsafe { slice::from_raw_parts(folder.path, length) }
                .iter()
                .copied(),
        )
        .any(|unit| unit.is_err())
        {
            return Err(ERROR_NO_UNICODE_TRANSLATION);
        }
        const NAME: &[u16] = &[65, 80, 80, 68, 65, 84, 65, 76, 79, 87, 0];
        if unsafe { (ops.environment)(NAME.as_ptr(), folder.path) } == 0 {
            return Err(failure(ops));
        }
        Ok(())
    })())
}
