//! Bounded native token snapshots and fail-closed privilege transitions.
use std::{
    ffi::{c_char, c_void},
    mem::{offset_of, size_of},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_GEN_FAILURE, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA,
        ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY, ERROR_PRIVILEGE_NOT_HELD, GetLastError,
        HANDLE, LUID, SetLastError,
    },
    Security::{
        AdjustTokenPrivileges, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueA,
        LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_REMOVED, SID, SID_AND_ATTRIBUTES,
        SID_IDENTIFIER_AUTHORITY, SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_GROUPS,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY,
        TokenIntegrityLevel, TokenPrivileges,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

const MAX_INFO: u32 = 1024 * 1024;
const MAX_NAMES: usize = 256;
pub(crate) fn remove_privileges() -> u32 {
    unsafe { zapret_security_remove(ptr::null()) }
}
pub(crate) fn low_integrity() -> u32 {
    unsafe { zapret_security_low(ptr::null()) }
}
#[repr(C)]
struct Ops {
    process: unsafe extern "system" fn() -> HANDLE,
    open: unsafe extern "system" fn(HANDLE, u32, *mut HANDLE) -> i32,
    query: unsafe extern "system" fn(HANDLE, i32, *mut c_void, u32, *mut u32) -> i32,
    lookup: unsafe extern "system" fn(*const u8, *const u8, *mut LUID) -> i32,
    adjust: unsafe extern "system" fn(
        HANDLE,
        i32,
        *const TOKEN_PRIVILEGES,
        u32,
        *mut TOKEN_PRIVILEGES,
        *mut u32,
    ) -> i32,
    set: unsafe extern "system" fn(HANDLE, i32, *const c_void, u32) -> i32,
    close: unsafe extern "system" fn(HANDLE) -> i32,
    error: unsafe extern "system" fn() -> u32,
    set_error: unsafe extern "system" fn(u32),
    lookup_w: unsafe extern "system" fn(*const u16, *const u16, *mut LUID) -> i32,
}
const NATIVE: Ops = Ops {
    process: GetCurrentProcess,
    open: OpenProcessToken,
    query: GetTokenInformation,
    lookup: LookupPrivilegeValueA,
    adjust: AdjustTokenPrivileges,
    set: SetTokenInformation,
    close: CloseHandle,
    error: GetLastError,
    set_error: SetLastError,
    lookup_w: LookupPrivilegeValueW,
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
        value => value,
    }
}
struct Token<'a> {
    handle: HANDLE,
    ops: &'a Ops,
}
impl Drop for Token<'_> {
    fn drop(&mut self) {
        unsafe { (self.ops.close)(self.handle) };
    }
}
fn open(ops: &Ops, access: u32) -> Result<Token<'_>, u32> {
    let mut handle = ptr::null_mut();
    if unsafe { (ops.open)((ops.process)(), access, &mut handle) } == 0 {
        return Err(failure(ops));
    }
    if handle.is_null() {
        return Err(ERROR_INVALID_DATA);
    }
    Ok(Token { handle, ops })
}
struct Snapshot {
    storage: Vec<u64>,
    bytes: u32,
    count: usize,
}
impl Snapshot {
    fn load(token: HANDLE, ops: &Ops) -> Result<Self, u32> {
        let mut needed = 0;
        let result =
            unsafe { (ops.query)(token, TokenPrivileges, ptr::null_mut(), 0, &mut needed) };
        if result != 0 {
            return Err(ERROR_INVALID_DATA);
        }
        if unsafe { (ops.error)() } != ERROR_INSUFFICIENT_BUFFER {
            return Err(failure(ops));
        }
        for _ in 0..3 {
            if !(size_of::<u32>() as u32..=MAX_INFO).contains(&needed) {
                return Err(ERROR_INVALID_DATA);
            }
            let mut storage = Vec::new();
            let words = (needed as usize).div_ceil(size_of::<u64>());
            storage
                .try_reserve_exact(words)
                .map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
            storage.resize(words, 0);
            let capacity = needed;
            let mut bytes = 0;
            if unsafe {
                (ops.query)(
                    token,
                    TokenPrivileges,
                    storage.as_mut_ptr().cast(),
                    capacity,
                    &mut bytes,
                )
            } == 0
            {
                let error = failure(ops);
                if error == ERROR_INSUFFICIENT_BUFFER && bytes > capacity {
                    needed = bytes;
                    continue;
                }
                return Err(error);
            }
            if bytes < size_of::<u32>() as u32 || bytes > capacity {
                return Err(ERROR_INVALID_DATA);
            }
            let count = unsafe { storage.as_ptr().cast::<u32>().read() } as usize;
            let required = offset_of!(TOKEN_PRIVILEGES, Privileges)
                .checked_add(
                    count
                        .checked_mul(size_of::<LUID_AND_ATTRIBUTES>())
                        .ok_or(ERROR_INVALID_DATA)?,
                )
                .ok_or(ERROR_INVALID_DATA)?;
            if required > bytes as usize {
                return Err(ERROR_INVALID_DATA);
            }
            return Ok(Self {
                storage,
                bytes,
                count,
            });
        }
        Err(ERROR_INSUFFICIENT_BUFFER)
    }
    fn records(&mut self) -> &mut [LUID_AND_ATTRIBUTES] {
        // The validated native byte count covers every initialized record.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.storage
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add(offset_of!(TOKEN_PRIVILEGES, Privileges))
                    .cast(),
                self.count,
            )
        }
    }
    fn apply(&self, token: HANDLE, ops: &Ops) -> Result<(), u32> {
        unsafe { (ops.set_error)(0) };
        if unsafe {
            (ops.adjust)(
                token,
                0,
                self.storage.as_ptr().cast(),
                self.bytes,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(failure(ops));
        }
        // TRUE also permits ERROR_NOT_ALL_ASSIGNED: all requested changes must
        // have succeeded before the engine treats the transition as complete.
        match unsafe { (ops.error)() } {
            0 => Ok(()),
            error => Err(error),
        }
    }
}
fn same_luid(left: LUID, right: LUID) -> bool {
    left.LowPart == right.LowPart && left.HighPart == right.HighPart
}
unsafe fn adjust(
    token: HANDLE,
    names: *const *const c_void,
    enable: bool,
    wide: bool,
    ops: &Ops,
) -> Result<(), u32> {
    if token.is_null() || names.is_null() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let mut snapshot = Snapshot::load(token, ops)?;
    for index in 0..=MAX_NAMES {
        let name = unsafe { names.add(index).read() };
        if name.is_null() {
            return snapshot.apply(token, ops);
        }
        if index == MAX_NAMES {
            return Err(ERROR_INVALID_PARAMETER);
        }
        let mut luid = LUID::default();
        let found = unsafe {
            if wide {
                (ops.lookup_w)(ptr::null(), name.cast(), &mut luid)
            } else {
                (ops.lookup)(ptr::null(), name.cast(), &mut luid)
            }
        };
        if found == 0 {
            return Err(failure(ops));
        }
        let record = snapshot
            .records()
            .iter_mut()
            .find(|record| same_luid(record.Luid, luid))
            .ok_or(ERROR_PRIVILEGE_NOT_HELD)?;
        if enable {
            record.Attributes |= SE_PRIVILEGE_ENABLED;
        } else {
            record.Attributes &= !SE_PRIVILEGE_ENABLED;
        }
    }
    unreachable!()
}
fn result(value: Result<(), u32>) -> u32 {
    value.err().unwrap_or(0)
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_security_adjust(
    token: HANDLE,
    names: *const *const c_char,
    enable: bool,
    input: *const Ops,
) -> u32 {
    result(unsafe { adjust(token, names.cast(), enable, false, ops(input)) })
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_security_adjust_current(
    names: *const *const c_char,
    enable: bool,
    input: *const Ops,
) -> u32 {
    let ops = unsafe { ops(input) };
    result((|| {
        let token = open(ops, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES)?;
        unsafe { adjust(token.handle, names.cast(), enable, false, ops) }
    })())
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_security_adjust_w(
    token: HANDLE,
    names: *const *const u16,
    enable: bool,
    input: *const Ops,
) -> u32 {
    result(unsafe { adjust(token, names.cast(), enable, true, ops(input)) })
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_security_adjust_current_w(
    names: *const *const u16,
    enable: bool,
    input: *const Ops,
) -> u32 {
    let ops = unsafe { ops(input) };
    result((|| {
        let token = open(ops, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES)?;
        unsafe { adjust(token.handle, names.cast(), enable, true, ops) }
    })())
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_security_remove(input: *const Ops) -> u32 {
    let ops = unsafe { ops(input) };
    result((|| {
        let mut keep = LUID::default();
        if unsafe {
            (ops.lookup)(
                ptr::null(),
                c"SeChangeNotifyPrivilege".as_ptr().cast(),
                &mut keep,
            )
        } == 0
        {
            return Err(failure(ops));
        }
        let token = open(
            ops,
            TOKEN_QUERY | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_PRIVILEGES,
        )?;
        let mut snapshot = Snapshot::load(token.handle, ops)?;
        for record in snapshot.records() {
            if !same_luid(record.Luid, keep) {
                record.Attributes = SE_PRIVILEGE_REMOVED;
            }
        }
        snapshot.apply(token.handle, ops)
    })())
}
#[repr(C)]
struct LowLabel {
    label: TOKEN_MANDATORY_LABEL,
    sid: SID,
}
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_security_low(input: *const Ops) -> u32 {
    let ops = unsafe { ops(input) };
    result((|| {
        let mut label = LowLabel {
            label: TOKEN_MANDATORY_LABEL {
                Label: SID_AND_ATTRIBUTES {
                    Sid: ptr::null_mut(),
                    Attributes: 0x20,
                },
            },
            sid: SID {
                Revision: 1,
                SubAuthorityCount: 1,
                IdentifierAuthority: SID_IDENTIFIER_AUTHORITY {
                    Value: [0, 0, 0, 0, 0, 16],
                },
                SubAuthority: [4096],
            },
        };
        label.label.Label.Sid = ptr::addr_of_mut!(label.sid).cast();
        let token = open(ops, TOKEN_ADJUST_DEFAULT)?;
        let length = (size_of::<TOKEN_MANDATORY_LABEL>() + size_of::<SID>()) as u32;
        if unsafe {
            (ops.set)(
                token.handle,
                TokenIntegrityLevel,
                ptr::addr_of!(label).cast(),
                length,
            )
        } == 0
        {
            return Err(failure(ops));
        }
        Ok(())
    })())
}
