//! Route files and source loading through the engine's shared Windows file policy.
use std::{
    ffi::{CString, c_char, c_int, c_void},
    io::{self, Read, Seek, SeekFrom, Write},
    ptr::NonNull,
};

unsafe extern "C" {
    fn wf_fopen(path: *const c_char, mode: *const c_char) -> *mut c_void;
    fn wf_remove(path: *const c_char) -> c_int;
    fn wf_rename(from: *const c_char, to: *const c_char) -> c_int;
    fn _errno() -> *const c_int;
    fn fclose(file: *mut c_void) -> c_int;
    fn fread(output: *mut u8, size: usize, count: usize, file: *mut c_void) -> usize;
    fn fwrite(input: *const u8, size: usize, count: usize, file: *mut c_void) -> usize;
    fn ferror(file: *mut c_void) -> c_int;
    fn fflush(file: *mut c_void) -> c_int;
    fn _ftelli64(file: *mut c_void) -> i64;
    fn _fseeki64(file: *mut c_void, offset: i64, origin: c_int) -> c_int;
}

fn c_string(bytes: &[u8]) -> CString {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    CString::new(&bytes[..end]).expect("C string prefix contains no NUL")
}

fn last_error() -> io::Error {
    super::lib_io::posix_error(unsafe { _errno().read() })
}

fn status(code: c_int) -> io::Result<()> {
    if code == 0 { Ok(()) } else { Err(last_error()) }
}

/// A file opened under the engine's native path and mode policy.
#[derive(Debug)]
pub enum File {
    /// A stream the interpreter creates itself, such as an anonymous scratch file.
    Standard(std::fs::File),
    /// An owned UCRT FILE pointer from the engine's `wf_fopen`.
    Crt(NonNull<c_void>),
}

impl From<std::fs::File> for File {
    fn from(file: std::fs::File) -> Self {
        Self::Standard(file)
    }
}

impl Drop for File {
    fn drop(&mut self) {
        if let Self::Crt(file) = self {
            unsafe { fclose(file.as_ptr()) };
        }
    }
}

impl Read for File {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Standard(file) => file.read(output),
            Self::Crt(file) => {
                let count = unsafe { fread(output.as_mut_ptr(), 1, output.len(), file.as_ptr()) };
                if count == 0 && unsafe { ferror(file.as_ptr()) } != 0 {
                    Err(last_error())
                } else {
                    Ok(count)
                }
            }
        }
    }
}

impl Write for File {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        match self {
            Self::Standard(file) => file.write(input),
            Self::Crt(file) => {
                let count = unsafe { fwrite(input.as_ptr(), 1, input.len(), file.as_ptr()) };
                if count == 0 && unsafe { ferror(file.as_ptr()) } != 0 {
                    Err(last_error())
                } else {
                    Ok(count)
                }
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Standard(file) => file.flush(),
            Self::Crt(file) => status(unsafe { fflush(file.as_ptr()) }),
        }
    }
}

impl Seek for File {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let Self::Crt(file) = self else {
            let Self::Standard(file) = self else {
                unreachable!()
            };
            return file.seek(from);
        };
        let (offset, origin) = match from {
            SeekFrom::Start(offset) => (
                i64::try_from(offset).map_err(|_| io::ErrorKind::InvalidInput)?,
                0,
            ),
            SeekFrom::Current(offset) => (offset, 1),
            SeekFrom::End(offset) => (offset, 2),
        };
        status(unsafe { _fseeki64(file.as_ptr(), offset, origin) })?;
        u64::try_from(unsafe { _ftelli64(file.as_ptr()) }).map_err(|_| last_error())
    }
}

pub(crate) fn open(path: &[u8], mode: &[u8]) -> io::Result<File> {
    let path = c_string(path);
    let mode = c_string(mode);
    let file = unsafe { wf_fopen(path.as_ptr(), mode.as_ptr()) };
    NonNull::new(file).map(File::Crt).ok_or_else(last_error)
}

pub(crate) fn read_source(path: &[u8], limit: usize) -> io::Result<Vec<u8>> {
    let mut content = Vec::new();
    open(path, b"rb")?
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut content)?;
    Ok(content)
}

pub(crate) fn remove(path: &[u8]) -> io::Result<()> {
    let path = c_string(path);
    status(unsafe { wf_remove(path.as_ptr()) })
}

pub(crate) fn rename(from: &[u8], to: &[u8]) -> io::Result<()> {
    let (from, to) = (c_string(from), c_string(to));
    status(unsafe { wf_rename(from.as_ptr(), to.as_ptr()) })
}
