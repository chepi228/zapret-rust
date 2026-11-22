//! Certificate-store notices use local metadata only and never alter trust stores.
use crate::{process::wide, storage::hash};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{Foundation::*, Security::Cryptography::*};

struct Store(HCERTSTORE);
impl Drop for Store {
    fn drop(&mut self) {
        unsafe {
            CertCloseStore(self.0, 0);
        }
    }
}
struct Certificate(*const CERT_CONTEXT);
impl Certificate {
    fn next(&mut self, store: &Store) -> Result<bool> {
        // CertEnumCertificatesInStore releases its previous context, including on failure.
        self.0 = unsafe { CertEnumCertificatesInStore(store.0, self.0) };
        if self.0.is_null() {
            let error = unsafe { GetLastError() };
            ensure!(
                error == CRYPT_E_NOT_FOUND as u32 || error == ERROR_NO_MORE_ITEMS,
                "Certificate enumeration incomplete: Windows error {error}"
            );
            return Ok(false);
        }
        Ok(true)
    }
    fn name(&self, issuer: bool) -> Result<String> {
        let flag = if issuer { CERT_NAME_ISSUER_FLAG } else { 0 };
        let length = unsafe {
            CertGetNameStringW(
                self.0,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                flag,
                null(),
                null_mut(),
                0,
            )
        };
        ensure!(
            (1..=8192).contains(&length),
            "Certificate name exceeds budget"
        );
        let mut buffer = vec![0u16; length as usize];
        let read = unsafe {
            CertGetNameStringW(
                self.0,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                flag,
                null(),
                buffer.as_mut_ptr(),
                length,
            )
        };
        ensure!(
            read > 0 && read <= length,
            "Certificate name decoding failed"
        );
        buffer.truncate(read as usize - 1);
        Ok(String::from_utf16_lossy(&buffer))
    }
}
impl Drop for Certificate {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CertFreeCertificateContext(self.0);
            }
        }
    }
}
fn notice_name(subject: &str, issuer: &str) -> bool {
    let text = format!("{subject} {issuer}").to_lowercase();
    [
        "russian trusted",
        "минцифр",
        "mincifr",
        "ministry of digital development",
    ]
    .iter()
    .any(|name| text.contains(name))
}
pub(crate) fn inspect() -> Result<Value> {
    let mut suspicious = Vec::new();
    let mut unavailable = Vec::new();
    let mut scanned = 0;
    let mut encoded_bytes = 0u64;
    let mut truncated = false;
    let end = Instant::now() + Duration::from_secs(5);
    'stores: for (location, scope) in [
        (CERT_SYSTEM_STORE_CURRENT_USER, "CurrentUser"),
        (CERT_SYSTEM_STORE_LOCAL_MACHINE, "LocalMachine"),
    ] {
        for kind in ["ROOT", "CA"] {
            let name = wide(kind)?;
            let raw = unsafe {
                CertOpenStore(
                    CERT_STORE_PROV_SYSTEM_W,
                    0,
                    0,
                    location | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
                    name.as_ptr().cast(),
                )
            };
            if raw.is_null() {
                unavailable.push(format!(
                    "{scope}/{kind}: {}",
                    std::io::Error::last_os_error()
                ));
                continue;
            }
            let store = Store(raw);
            let mut certificate = Certificate(null());
            while certificate.next(&store)? {
                if scanned >= 16384 || suspicious.len() >= 512 || Instant::now() >= end {
                    truncated = true;
                    break 'stores;
                }
                scanned += 1;
                let subject = certificate.name(false)?;
                let issuer = certificate.name(true)?;
                if !notice_name(&subject, &issuer) {
                    continue;
                }
                let context = unsafe { &*certificate.0 };
                ensure!(
                    context.cbCertEncoded <= 8 * 1024 * 1024 && !context.pbCertEncoded.is_null(),
                    "Invalid certificate encoding size"
                );
                encoded_bytes += u64::from(context.cbCertEncoded);
                if encoded_bytes > 64 * 1024 * 1024 {
                    truncated = true;
                    break 'stores;
                }
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        context.pbCertEncoded,
                        context.cbCertEncoded as usize,
                    )
                };
                suspicious.push(json!({"scope":scope,"store":kind,"subject":subject,"issuer":issuer,"sha256":hash(bytes)}));
            }
        }
    }
    Ok(
        json!({"read_only":true,"scanned":scanned,"suspicious":suspicious,"unavailable":unavailable,"truncated":truncated,"known":unavailable.is_empty()&&!truncated}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn certificate_notice_matches_metadata_without_claiming_any_trust_change() {
        assert!(notice_name("Russian Trusted Root CA", "fixture"));
        assert!(notice_name("fixture", "МИНЦИФРЫ"));
        assert!(!notice_name("Normal public root", "Normal issuer"));
    }
}
