use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};

/// Stage in the destination directory, flush the complete file, then atomically replace.
/// An interrupted or failed write leaves the previous target intact.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("File has no parent")?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".zapret-rust-")
        .suffix(".tmp")
        .tempfile_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    let staged = temporary.into_temp_path();
    atomic_replace_file(&staged, path)
}

/// Atomically publish an already flushed staged file, retaining its prepared ACL.
pub fn atomic_replace_file(staged: &Path, path: &Path) -> Result<()> {
    ensure!(
        staged.parent() == path.parent(),
        "Atomic staging must use the destination directory"
    );
    #[cfg(windows)]
    {
        use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_RENAME_INFO, FileRenameInfoEx, SetFileInformationByHandle,
        };
        let source = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .access_mode(0xc0010000)
            .open(staged)?;
        // Preserve the ordinary Windows contract for callers that deny deletion.
        let _target = if path.exists() {
            Some(
                fs::OpenOptions::new()
                    .read(true)
                    .access_mode(0x80010000)
                    .open(path)?,
            )
        } else {
            None
        };
        let name: Vec<u16> = std::path::absolute(path)?
            .as_os_str()
            .encode_wide()
            .collect();
        let offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
        let length = offset + (name.len() + 1) * 2;
        let mut buffer = vec![0u64; length.div_ceil(8)];
        // Aligned storage has room for the fixed header plus the complete UTF-16
        // path. POSIX rename keeps old reader handles valid without a missing-name gap.
        let ok = unsafe {
            let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
            (*info).Anonymous.Flags = 3;
            (*info).RootDirectory = std::ptr::null_mut();
            (*info).FileNameLength = (name.len() * 2) as u32;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                buffer.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>(),
                name.len(),
            );
            SetFileInformationByHandle(
                source.as_raw_handle(),
                FileRenameInfoEx,
                buffer.as_ptr().cast(),
                length as u32,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("Replace {}", path.display()));
        }
    }
    #[cfg(not(windows))]
    fs::rename(staged, path).with_context(|| format!("Replace {}", path.display()))?;
    #[cfg(unix)]
    File::open(path.parent().context("No parent")?)?.sync_all()?;
    Ok(())
}

pub fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("Read {}", path.display()))?;
    ensure!(
        file.metadata()?.len() <= max_bytes,
        "File exceeds size limit: {}",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= max_bytes,
        "File grew beyond size limit: {}",
        path.display()
    );
    Ok(bytes)
}

pub fn read_text(path: &Path, max_bytes: u64) -> Result<String> {
    let bytes = read_bounded(path, max_bytes)?;
    if bytes.starts_with(&[0xff, 0xfe]) {
        ensure!((bytes.len() - 2) % 2 == 0, "Invalid UTF-16 text");
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        return String::from_utf16(&units).context("Invalid UTF-16 text");
    }
    if bytes.starts_with(&[0xfe, 0xff]) {
        ensure!((bytes.len() - 2) % 2 == 0, "Invalid UTF-16 text");
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .collect();
        return String::from_utf16(&units).context("Invalid UTF-16 text");
    }
    let mut text = String::from_utf8(bytes)?;
    let prefix = text.len() - text.trim_start_matches('\u{feff}').len();
    if prefix != 0 {
        text.drain(..prefix);
    }
    Ok(text)
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:X}", Sha256::digest(bytes))
}
pub fn sha256_file(path: &Path) -> Result<String> {
    sha256_reader(File::open(path)?).map(|(digest, _)| digest)
}
/// Hash the bytes from the supplied handle and report how many were consumed.
pub fn sha256_reader(mut reader: impl Read) -> Result<(String, u64)> {
    let mut sha = Sha256::new();
    let mut block = [0u8; 65536];
    let mut length = 0;
    loop {
        let n = reader.read(&mut block)?;
        if n == 0 {
            break;
        }
        sha.update(&block[..n]);
        length += n as u64;
    }
    Ok((format!("{:X}", sha.finalize()), length))
}
pub(crate) fn hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Developer installer sidecars are not executable/configuration inputs.
/// Keep the match narrow: other dot-prefixed paths still undergo validation.
pub fn is_native_build_artifact(relative: &str) -> bool {
    relative
        .strip_prefix("bin/.native-build-")
        .and_then(|tail| {
            tail.strip_suffix(".tmp.old")
                .or_else(|| tail.strip_suffix(".tmp"))
        })
        .is_some_and(|id| hex(id, 32))
}

/// PowerShell 5.1 Sort-Object uses the Windows user's culture and word sorting.
pub(crate) fn legacy_compare(left: &str, right: &str) -> std::cmp::Ordering {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Globalization::{CompareStringEx, NORM_IGNORECASE};
        let a: Vec<u16> = left.encode_utf16().collect();
        let b: Vec<u16> = right.encode_utf16().collect();
        // All referenced buffers outlive this read-only comparison.
        let result = unsafe {
            CompareStringEx(
                std::ptr::null(),
                NORM_IGNORECASE,
                a.as_ptr(),
                a.len() as i32,
                b.as_ptr(),
                b.len() as i32,
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
            )
        };
        if (1..=3).contains(&result) {
            return result.cmp(&2);
        }
    }
    let word = |text: &str| text.to_lowercase().replace(['-', '\''], "");
    word(left)
        .cmp(&word(right))
        .then_with(|| left.to_lowercase().cmp(&right.to_lowercase()))
}
