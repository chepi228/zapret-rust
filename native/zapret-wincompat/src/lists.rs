//! Compatibility readers for native engine host lists and IP sets.

use std::{
    ffi::{c_char, c_void},
    io::{self, BufRead, BufReader, Read, Seek},
    ops::Range,
};

#[derive(Clone, Copy)]
enum ListKind {
    Hosts,
    IpSet,
}

impl ListKind {
    fn plain_chunk(self) -> usize {
        // The pinned fgets calls use 4096 for hosts and 4095 for IP sets.
        match self {
            Self::Hosts => 4095,
            Self::IpSet => 4094,
        }
    }
}

struct Entry {
    token: Option<Range<usize>>,
    strict: bool,
    next: usize,
}

fn entry(bytes: &mut [u8], hosts: bool) -> Entry {
    let mut start = 0;
    while bytes.get(start).is_some_and(|b| matches!(b, b' ' | b'\t')) {
        start += 1;
    }
    let mut cursor = start;
    let mut strict = false;
    let append = bytes
        .get(start)
        .is_some_and(|b| !matches!(b, b'#' | b';' | b'/' | b'\r' | b'\n'));
    if append {
        if hosts && bytes[start] == b'^' {
            strict = true;
            start += 1;
            cursor = start;
        }
        while bytes
            .get(cursor)
            .is_some_and(|b| !matches!(b, 0 | b' ' | b'\t' | b'\r' | b'\n'))
        {
            if hosts {
                bytes[cursor].make_ascii_lowercase();
            }
            cursor += 1;
        }
    }
    let token = append.then_some(start..cursor);
    while bytes
        .get(cursor)
        .is_some_and(|b| !matches!(b, 0 | b'\r' | b'\n'))
    {
        cursor += 1;
    }
    while bytes
        .get(cursor)
        .is_some_and(|b| matches!(b, 0 | b'\r' | b'\n'))
    {
        cursor += 1;
    }
    Entry {
        token,
        strict,
        next: cursor,
    }
}

#[derive(Debug)]
enum LoadError {
    Io(io::Error),
    Compression,
    Memory,
    Insert,
}

impl From<io::Error> for LoadError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[repr(C)]
#[derive(Default)]
struct LoadInfo {
    count: u64,
    decompressed_size: u64,
    compressed: u32,
    error: u32,
}

type Insert = unsafe extern "C" fn(*mut c_void, *const u8, usize, u32) -> i32;

fn emit(
    input: &mut [u8],
    kind: ListKind,
    insert: &mut impl FnMut(&[u8], u32) -> Result<bool, LoadError>,
) -> Result<(usize, bool), LoadError> {
    let parsed = entry(input, matches!(kind, ListKind::Hosts));
    let appended = match parsed.token {
        Some(token) => insert(&input[token], u32::from(parsed.strict))?,
        None => false,
    };
    Ok((parsed.next, appended))
}

fn read_chunk(reader: &mut impl BufRead, chunk: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < chunk.len() {
        let bytes = match reader.fill_buf() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if bytes.is_empty() {
            break;
        }
        let available = bytes.len().min(chunk.len() - filled);
        let end = bytes[..available]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(available, |i| i + 1);
        chunk[filled..filled + end].copy_from_slice(&bytes[..end]);
        let newline = bytes[end - 1] == b'\n';
        reader.consume(end);
        filled += end;
        if newline {
            break;
        }
    }
    Ok(filled)
}

fn load(
    reader: impl Read + Seek,
    kind: ListKind,
    insert: &mut impl FnMut(&[u8], u32) -> Result<bool, LoadError>,
    info: &mut LoadInfo,
) -> Result<(), LoadError> {
    let mut reader = BufReader::new(reader);
    let mut magic = [0; 2];
    let compressed = reader.read_exact(&mut magic).is_ok() && magic == [0x1f, 0x8b];
    reader.rewind()?;
    info.compressed = u32::from(compressed);
    if compressed {
        // Finish decoding before changing a pool, as in the pinned z_readfile.
        let mut decoded = Vec::new();
        let mut chunk = [0u8; 16_384];
        let mut decoder = flate2::bufread::GzDecoder::new(reader);
        loop {
            let length = match decoder.read(&mut chunk) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.raw_os_error().is_some() => return Err(LoadError::Io(error)),
                Err(_) => return Err(LoadError::Compression),
                Ok(length) => length,
            };
            if length == 0 {
                break;
            }
            decoded.try_reserve(length).map_err(|_| LoadError::Memory)?;
            decoded.extend_from_slice(&chunk[..length]);
        }
        info.decompressed_size = decoded.len() as u64;
        let mut cursor = 0;
        while cursor < decoded.len() {
            let (next, appended) = emit(&mut decoded[cursor..], kind, insert)?;
            cursor += next;
            info.count += u64::from(appended);
        }
    } else {
        let mut chunk = [0u8; 4095];
        loop {
            let length = read_chunk(&mut reader, &mut chunk[..kind.plain_chunk()])?;
            if length == 0 {
                break;
            }
            // strlen hides the remainder of a fgets result after an embedded NUL.
            let end = chunk[..length]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(length);
            let (_, appended) = emit(&mut chunk[..end], kind, insert)?;
            info.count += u64::from(appended);
        }
    }
    Ok(())
}

unsafe fn c_insert(
    insert: Insert,
    context: *mut c_void,
    input: &[u8],
    flags: u32,
) -> Result<bool, LoadError> {
    // Callers copy the token during the callback and never raise a Lua error.
    match unsafe { insert(context, input.as_ptr(), input.len(), flags) } {
        -1 => Err(LoadError::Insert),
        result => Ok(result != 0),
    }
}

// Private ABI. The caller owns the token buffer for the entire call.
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_item(
    data: *mut u8,
    length: usize,
    hosts: i32,
    insert: Insert,
    context: *mut c_void,
) -> i32 {
    let bytes = if length == 0 {
        &mut []
    } else {
        unsafe { std::slice::from_raw_parts_mut(data, length) }
    };
    let kind = if hosts != 0 {
        ListKind::Hosts
    } else {
        ListKind::IpSet
    };
    i32::from(
        emit(bytes, kind, &mut |token, flags| unsafe {
            c_insert(insert, context, token, flags)
        })
        .is_ok(),
    )
}

// Private Win32 ABI. Inputs are borrowed C strings and callbacks own pool writes.
#[cfg(windows)]
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_load(
    path: *const c_char,
    hosts: i32,
    insert: Insert,
    context: *mut c_void,
    out: *mut LoadInfo,
) -> i32 {
    use crate::files::{open_file, path_input};
    use std::{fs::File, os::windows::io::FromRawHandle};
    use windows_sys::Win32::Foundation::{ERROR_GEN_FAILURE, ERROR_NOT_ENOUGH_MEMORY};

    let mut info = LoadInfo::default();
    let file =
        path_input(path).and_then(|wide| open_file(&wide, libc::O_RDONLY | libc::O_NOINHERIT, 0));
    let kind = if hosts != 0 {
        ListKind::Hosts
    } else {
        ListKind::IpSet
    };
    let result = match file {
        Ok(handle) => {
            let file = unsafe { File::from_raw_handle(handle) };
            match load(
                file,
                kind,
                &mut |token, flags| unsafe { c_insert(insert, context, token, flags) },
                &mut info,
            ) {
                Ok(()) => 0,
                Err(LoadError::Io(error)) => {
                    info.error = error
                        .raw_os_error()
                        .map_or(ERROR_GEN_FAILURE, |value| value as u32);
                    2
                }
                Err(LoadError::Compression) => 3,
                Err(LoadError::Memory | LoadError::Insert) => {
                    info.error = ERROR_NOT_ENOUGH_MEMORY;
                    4
                }
            }
        }
        Err(error) => {
            info.error = error;
            1
        }
    };
    unsafe { out.write(info) };
    result
}

#[cfg(windows)]
#[repr(C)]
struct AppendOps {
    load: unsafe extern "C" fn(*const c_char, i32, Insert, *mut c_void, *mut LoadInfo) -> i32,
    message: crate::native_logging_entry::LogSink,
    error: crate::native_logging_entry::LogSink,
    perror: unsafe extern "C" fn(*const c_char) -> i32,
    set_error: unsafe extern "C" fn(u32),
}

#[cfg(windows)]
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_list_append_file(
    filename: *const c_char,
    hosts: i32,
    insert: Insert,
    context: *mut c_void,
    ops: &AppendOps,
) -> bool {
    let (loading, label, memory, loaded) = if hosts != 0 {
        (
            c"Loading hostlist %s\n",
            c"AppendHostList",
            c"Not enough memory to store host list : %s\n",
            c"Loaded %d hosts from %s\n",
        )
    } else {
        (
            c"Loading ipset %s\n",
            c"AppendIpset",
            c"Not enough memory to store ipset : %s\n",
            c"Loaded %d ip/subnets from %s\n",
        )
    };
    unsafe {
        (ops.message)(loading.as_ptr(), filename);
        let mut info = LoadInfo::default();
        let status = (ops.load)(filename, hosts, insert, context, &mut info);
        if status != 0 {
            if info.error != 0 {
                (ops.set_error)(info.error);
            }
            match status {
                1 => (ops.error)(c"Could not open %s\n".as_ptr(), filename),
                2 => (ops.perror)(label.as_ptr()),
                3 => (ops.error)(c"zlib decompression failed : result -3\n".as_ptr()),
                4 => (ops.error)(memory.as_ptr(), filename),
                _ => 0,
            };
            return false;
        }
        if info.compressed != 0 {
            (ops.message)(
                c"zlib compression detected. uncompressed size : %zu\n".as_ptr(),
                info.decompressed_size as usize,
            );
        } else {
            (ops.message)(c"loading plain text list\n".as_ptr());
        }
        (ops.message)(loaded.as_ptr(), info.count as i32, filename);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn records(data: &[u8], kind: ListKind, gzip: bool) -> Vec<(Vec<u8>, u32)> {
        let mut info = LoadInfo::default();
        let mut result = Vec::new();
        let mut encoded = Vec::new();
        if gzip {
            let mut encoder =
                flate2::write::GzEncoder::new(&mut encoded, flate2::Compression::default());
            encoder.write_all(data).unwrap();
            encoder.finish().unwrap();
        } else {
            encoded.extend_from_slice(data);
        }
        load(
            Cursor::new(encoded),
            kind,
            &mut |bytes, flags| {
                result.push((bytes.to_vec(), flags));
                Ok(true)
            },
            &mut info,
        )
        .unwrap();
        assert_eq!(info.count, result.len() as u64);
        result
    }

    #[test]
    fn preserves_host_normalization_strict_prefix_comments_and_empty_tokens() {
        let data = b" #comment\r\n\t^EXAMPLE.COM trailing\nA.Example\n^ \n/\n;\n\xff.EXAMPLE\n";
        let expected = vec![
            (b"example.com".to_vec(), 1),
            (b"a.example".to_vec(), 0),
            (Vec::new(), 1),
            (b"\xff.example".to_vec(), 0),
        ];
        assert_eq!(records(data, ListKind::Hosts, false), expected);
        assert_eq!(records(data, ListKind::Hosts, true), expected);
    }

    #[test]
    fn retains_different_plain_and_compressed_nul_and_long_line_semantics() {
        let data = b"first\0second\n\0third\n";
        assert_eq!(
            records(data, ListKind::Hosts, false),
            vec![(b"first".to_vec(), 0)]
        );
        assert_eq!(
            records(data, ListKind::Hosts, true),
            vec![
                (b"first".to_vec(), 0),
                (b"second".to_vec(), 0),
                (b"third".to_vec(), 0)
            ]
        );
        let data = vec![b'A'; 4096];
        let plain = records(&data, ListKind::Hosts, false);
        assert_eq!(
            plain
                .iter()
                .map(|(token, _)| token.len())
                .collect::<Vec<_>>(),
            [4095, 1]
        );
        assert_eq!(
            records(&data, ListKind::Hosts, true),
            [(vec![b'a'; 4096], 0)]
        );
        assert_eq!(
            records(&data, ListKind::IpSet, false)
                .iter()
                .map(|(token, _)| token.len())
                .collect::<Vec<_>>(),
            [4094, 2]
        );
    }

    #[test]
    fn corrupted_gzip_preserves_the_existing_pool() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"valid.example\n").unwrap();
        let mut input = encoder.finish().unwrap();
        let end = input.len() - 8;
        input[end] ^= 1;
        let mut changed = false;
        let mut info = LoadInfo::default();
        assert!(matches!(
            load(
                Cursor::new(input),
                ListKind::Hosts,
                &mut |_, _| {
                    changed = true;
                    Ok(true)
                },
                &mut info
            ),
            Err(LoadError::Compression)
        ));
        assert!(!changed);
    }
}
