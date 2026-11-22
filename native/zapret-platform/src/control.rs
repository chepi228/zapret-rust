use crate::{
    process::{Handle, wide},
    storage::no_reparse,
};
use anyhow::{Result, ensure};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Write,
    mem::{size_of, zeroed},
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::FILE_SHARE_READ,
    System::Threading::*,
};

thread_local! {static DEPTH:RefCell<BTreeMap<PathBuf,u32>>=const{RefCell::new(BTreeMap::new())};}
pub(crate) fn current_sid() -> Result<String> {
    unsafe {
        let mut raw = null_mut();
        ensure!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) != 0,
            "OpenProcessToken: {}",
            std::io::Error::last_os_error()
        );
        let token = Handle(raw);
        let mut bytes = 0;
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut bytes);
        ensure!(bytes > 0 && bytes < 65536, "Token user size invalid");
        let mut data = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
        ensure!(
            GetTokenInformation(
                token.0,
                TokenUser,
                data.as_mut_ptr().cast(),
                bytes,
                &mut bytes
            ) != 0,
            "GetTokenInformation: {}",
            std::io::Error::last_os_error()
        );
        let user = &*data.as_ptr().cast::<TOKEN_USER>();
        let mut text = null_mut();
        ensure!(
            ConvertSidToStringSidW(user.User.Sid, &mut text) != 0,
            "ConvertSidToStringSid: {}",
            std::io::Error::last_os_error()
        );
        let s = crate::system::text16(text);
        LocalFree(text.cast());
        Ok(s)
    }
}
pub(crate) struct Descriptor(pub PSECURITY_DESCRIPTOR);
impl Descriptor {
    fn from_sddl(s: &str) -> Result<Self> {
        let text = wide(s)?;
        let mut raw = null_mut();
        ensure!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    1,
                    &mut raw,
                    null_mut(),
                )
            } != 0,
            "Security descriptor: {}",
            std::io::Error::last_os_error()
        );
        Ok(Self(raw))
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
/// The same global mutex used by the legacy controller, plus a per-package read lease.
/// Guards are recursive on their owning thread; move neither a guard nor control work to another thread.
pub struct ControlGuard {
    mutex: Handle,
    _file: Option<File>,
    root: PathBuf,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl ControlGuard {
    pub fn acquire(root: &Path, action: &str) -> Result<Self> {
        no_reparse(root)?;
        let root = std::fs::canonicalize(root)?;
        no_reparse(&root)?;
        let sd = Descriptor::from_sddl(&format!(
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{})",
            current_sid()?
        ))?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        // Share the lease with previous controllers while a renamed package is upgraded.
        let name = wide(r"Global\chepi1.zapret2.control.v2")?;
        let mutex = Handle::new(unsafe { CreateMutexW(&sa, 0, name.as_ptr()) })?;
        let state = unsafe { WaitForSingleObject(mutex.0, 0) };
        ensure!(
            state == WAIT_OBJECT_0 || state == WAIT_ABANDONED,
            "Другая операция управляет обходом; действие отложено."
        );
        let result = (|| -> Result<Option<File>> {
            let nested = DEPTH.with(|d| d.borrow().contains_key(&root));
            if nested {
                return Ok(None);
            }
            let runtime = root.join("runtime");
            no_reparse(&runtime)?;
            std::fs::create_dir_all(&runtime)?;
            let path = runtime.join("control.lock");
            no_reparse(&path)?;
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .share_mode(FILE_SHARE_READ)
                .open(path)?;
            f.set_len(0)?;
            write!(
                f,
                "{} {} {}",
                std::process::id(),
                crate::time_filetime(),
                action.replace(['\r', '\n'], " ")
            )?;
            f.sync_data()?;
            Ok(Some(f))
        })();
        let file = match result {
            Ok(f) => f,
            Err(e) => {
                unsafe {
                    ReleaseMutex(mutex.0);
                }
                return Err(e);
            }
        };
        DEPTH.with(|d| *d.borrow_mut().entry(root.clone()).or_default() += 1);
        Ok(Self {
            mutex,
            _file: file,
            root,
            _thread: std::marker::PhantomData,
        })
    }
}
impl Drop for ControlGuard {
    fn drop(&mut self) {
        self._file.take();
        DEPTH.with(|d| {
            let mut d = d.borrow_mut();
            if let Some(n) = d.get_mut(&self.root) {
                *n -= 1;
                if *n == 0 {
                    d.remove(&self.root);
                }
            }
        });
        unsafe {
            ReleaseMutex(self.mutex.0);
        }
    }
}

/// Administrator/SYSTEM-only data state, matching recovery.ps1's trust boundary.
pub(crate) fn protect(path: &Path) -> Result<()> {
    protect_with(path, "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
}
const READABLE_SDDL: &str = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)";
pub(crate) fn protect_readable(path: &Path) -> Result<()> {
    protect_with(path, READABLE_SDDL)
}
fn protect_with(path: &Path, sddl: &str) -> Result<()> {
    unsafe {
        no_reparse(path)?;
        let sd = Descriptor::from_sddl(sddl)?;
        let mut owner = null_mut();
        let mut defaulted = 0;
        ensure!(
            GetSecurityDescriptorOwner(sd.0, &mut owner, &mut defaulted) != 0,
            "Security owner unavailable"
        );
        let mut dacl = null_mut();
        let mut present = 0;
        ensure!(
            GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) != 0
                && present != 0,
            "Security DACL unavailable"
        );
        let mut p = wide(path)?;
        let e = SetNamedSecurityInfoW(
            p.as_mut_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            null_mut(),
            dacl,
            null(),
        );
        ensure!(e == 0, "Protect trusted state: {e}");
        Ok(())
    }
}
pub(crate) fn unprotect(path: &Path) -> Result<()> {
    unsafe {
        no_reparse(path)?;
        // An empty, unprotected ACL receives the parent's inheritable permissions.
        let descriptor = Descriptor::from_sddl("D:AI")?;
        let mut acl = null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        ensure!(
            GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) != 0
                && present != 0
                && !acl.is_null(),
            "Inherited ACL descriptor unavailable"
        );
        let mut name = wide(path)?;
        let result = SetNamedSecurityInfoW(
            name.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null(),
        );
        ensure!(
            result == 0,
            "Restore inherited package ACL: Windows error {result}"
        );
        Ok(())
    }
}
pub(crate) fn trusted(path: &Path) -> Result<bool> {
    unsafe {
        no_reparse(path)?;
        let p = wide(path)?;
        let mut sd = null_mut();
        let mut owner = null_mut();
        let mut acl = null_mut();
        let e = GetNamedSecurityInfoW(
            p.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut sd,
        );
        ensure!(e == 0, "Read trusted state ACL: {e}");
        let _sd = Descriptor(sd);
        if owner.is_null() || acl.is_null() {
            return Ok(false);
        }
        let mut owner_text = null_mut();
        ensure!(
            ConvertSidToStringSidW(owner, &mut owner_text) != 0,
            "Read owner SID"
        );
        let owner = crate::system::text16(owner_text);
        LocalFree(owner_text.cast());
        if !["S-1-5-18", "S-1-5-32-544"].contains(&owner.as_str()) {
            return Ok(false);
        }
        let mut info: ACL_SIZE_INFORMATION = zeroed();
        ensure!(
            GetAclInformation(
                acl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation
            ) != 0,
            "Read ACL information"
        );
        if info.AceCount == 0 {
            return Ok(false);
        }
        for i in 0..info.AceCount {
            let mut ace = null_mut();
            ensure!(GetAce(acl, i, &mut ace) != 0, "Read ACE");
            let header = &*ace.cast::<ACE_HEADER>();
            if u32::from(header.AceType) == ACCESS_ALLOWED_ACE_TYPE {
                let a = &*ace.cast::<ACCESS_ALLOWED_ACE>();
                let writers = 0x40000000
                    | 0x10000000
                    | 0x00010000
                    | 0x00040000
                    | 0x00080000
                    | 0x00000002
                    | 0x00000004
                    | 0x00000040
                    | 0x00000010
                    | 0x00000100;
                if a.Mask & writers != 0 {
                    let sid = (&a.SidStart as *const u32).cast_mut().cast();
                    let mut s = null_mut();
                    ensure!(ConvertSidToStringSidW(sid, &mut s) != 0, "Read writer SID");
                    let who = crate::system::text16(s);
                    LocalFree(s.cast());
                    if !["S-1-5-18", "S-1-5-32-544"].contains(&who.as_str()) {
                        return Ok(false);
                    }
                }
            } else if u32::from(header.AceType) == ACCESS_ALLOWED_OBJECT_ACE_TYPE
                || u32::from(header.AceType) == ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                || u32::from(header.AceType) == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ};
    #[test]
    fn published_file_dacl_retains_builtin_users_read_execute_without_write() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("published.txt");
        std::fs::write(&path, b"published fixture").unwrap();
        unsafe {
            let descriptor = Descriptor::from_sddl(READABLE_SDDL).unwrap();
            let mut acl = null_mut();
            let mut present = 0;
            let mut defaulted = 0;
            assert_ne!(
                GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted),
                0
            );
            assert_ne!(present, 0);
            // Apply only this fixture's DACL. Owner BA is checked from the descriptor;
            // ordinary test runs do not request administrator owner-assignment rights.
            let mut name = wide(&path).unwrap();
            assert_eq!(
                SetNamedSecurityInfoW(
                    name.as_mut_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    acl,
                    null()
                ),
                0
            );
            let mut actual = null_mut();
            let mut actual_acl = null_mut();
            assert_eq!(
                GetNamedSecurityInfoW(
                    name.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    &mut actual_acl,
                    null_mut(),
                    &mut actual
                ),
                0
            );
            let _actual = Descriptor(actual);
            let mut info: ACL_SIZE_INFORMATION = zeroed();
            assert_ne!(
                GetAclInformation(
                    actual_acl,
                    (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation
                ),
                0
            );
            let mut users = None;
            for index in 0..info.AceCount {
                let mut raw = null_mut();
                assert_ne!(GetAce(actual_acl, index, &mut raw), 0);
                let ace = &*raw.cast::<ACCESS_ALLOWED_ACE>();
                assert_eq!(u32::from(ace.Header.AceType), ACCESS_ALLOWED_ACE_TYPE);
                let mut sid = null_mut();
                assert_ne!(
                    ConvertSidToStringSidW(
                        (&ace.SidStart as *const u32).cast_mut().cast(),
                        &mut sid
                    ),
                    0
                );
                let text = crate::system::text16(sid);
                LocalFree(sid.cast());
                if text == "S-1-5-32-545" {
                    users = Some(ace.Mask);
                }
            }
            let rights = users.expect("published files must allow BUILTIN\\Users");
            assert!(rights & GENERIC_READ != 0 || rights & FILE_GENERIC_READ == FILE_GENERIC_READ);
            assert!(
                rights & GENERIC_EXECUTE != 0
                    || rights & FILE_GENERIC_EXECUTE == FILE_GENERIC_EXECUTE
            );
            let write_rights = GENERIC_WRITE
                | GENERIC_ALL
                | 0x00010000
                | 0x00040000
                | 0x00080000
                | 0x00000002
                | 0x00000004
                | 0x00000010
                | 0x00000100
                | 0x00000040;
            assert_eq!(rights & write_rights, 0);
            let mut owner = null_mut();
            assert_ne!(
                GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut defaulted),
                0
            );
            let mut sid = null_mut();
            assert_ne!(ConvertSidToStringSidW(owner, &mut sid), 0);
            assert_eq!(crate::system::text16(sid), "S-1-5-32-544");
            LocalFree(sid.cast());
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"published fixture");
        unprotect(&path).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b" after unprotect")
            .unwrap();
        assert_eq!(
            std::fs::read(path).unwrap(),
            b"published fixture after unprotect"
        );
    }
}
