//! Read-only NLM diagnostics. Network and adapter snapshots are acquired once.
use super::{
    ComObject, ComString, Dispatch, Enumerator, Environment, Manager, Network, hresult, parse_guid,
    same_guid, vtable as table, win32_hresult,
};
use crate::files::{buffer, utf8};
use std::{
    ffi::c_void,
    fmt::{self, Write},
    ptr,
};
use windows_sys::{
    Win32::{
        Foundation::{
            E_POINTER, ERROR_INVALID_DATA, ERROR_NO_MORE_ITEMS, ERROR_NOT_ENOUGH_MEMORY,
            ERROR_WRITE_FAULT,
        },
        System::Registry::{
            HKEY, HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, RRF_RT_REG_SZ,
            RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW,
        },
    },
    core::GUID,
};

const CONNECTED_NETWORKS: i32 = 1;
const ALL_NETWORKS: i32 = 3;

#[repr(C)]
struct NetworkDetails {
    base: Network,
    domain_type: usize,
    connections: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32,
    timestamps: usize,
    internet: unsafe extern "system" fn(*mut c_void, *mut i16) -> i32,
    connected: unsafe extern "system" fn(*mut c_void, *mut i16) -> i32,
    connectivity: usize,
    category: unsafe extern "system" fn(*mut c_void, *mut i32) -> i32,
}

#[repr(C)]
struct ConnectionDetails {
    base: Dispatch,
    other: [usize; 5],
    adapter: unsafe extern "system" fn(*mut c_void, *mut GUID) -> i32,
}

unsafe fn read<T: Default>(
    raw: *mut c_void,
    query: unsafe extern "system" fn(*mut c_void, *mut T) -> i32,
) -> Result<T, u32> {
    let mut value = T::default();
    hresult(unsafe { query(raw, &mut value) })?;
    Ok(value)
}

unsafe fn next(enumerator: &ComObject) -> Result<Option<ComObject>, u32> {
    let mut raw = ptr::null_mut();
    let mut fetched = 0;
    let code = unsafe {
        ((*table::<Enumerator>(enumerator.0)).next)(enumerator.0, 1, &mut raw, &mut fetched)
    };
    hresult(code)?;
    if code != 0 || fetched == 0 {
        Ok(None)
    } else {
        ComObject::new(raw).map(Some)
    }
}

struct GuidText<'a>(&'a GUID);
impl fmt::Display for GuidText<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id = self.0;
        write!(
            output,
            "{:08X}-{:04X}-{:04X}-",
            id.data1, id.data2, id.data3
        )?;
        for (index, byte) in id.data4.iter().enumerate() {
            if index == 2 {
                output.write_char('-')?;
            }
            write!(output, "{byte:02X}")?;
        }
        Ok(())
    }
}

type WriteOutput = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> bool;
type AdapterOverride = unsafe extern "C" fn(*mut c_void, *const GUID, *mut u8, usize) -> usize;

struct Output {
    context: *mut c_void,
    write: WriteOutput,
}
impl fmt::Write for Output {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if unsafe { (self.write)(self.context, text.as_ptr(), text.len()) } {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

fn write_error(_: fmt::Error) -> u32 {
    win32_hresult(ERROR_WRITE_FAULT)
}

struct RegistryKey(HKEY);
impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}
impl RegistryKey {
    fn open(root: HKEY, name: *const u16, access: u32) -> Option<Self> {
        let mut key = ptr::null_mut();
        let status = unsafe { RegOpenKeyExW(root, name, 0, access, &mut key) };
        if status == 0 && !key.is_null() {
            Some(Self(key))
        } else {
            None
        }
    }

    fn string(&self, name: *const u16) -> Option<Vec<u16>> {
        let mut bytes = 0;
        let status = unsafe {
            RegGetValueW(
                self.0,
                ptr::null(),
                name,
                RRF_RT_REG_SZ,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut bytes,
            )
        };
        if status != 0 || bytes == 0 || bytes & 1 != 0 || bytes > 64 * 1024 {
            return None;
        }
        let mut wide = buffer::<u16>(bytes as usize / 2 + 1).ok()?;
        bytes += 2;
        let status = unsafe {
            RegGetValueW(
                self.0,
                ptr::null(),
                name,
                RRF_RT_REG_SZ,
                ptr::null_mut(),
                wide.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        (status == 0).then_some(wide)
    }
}

fn service_guid(name: &[u16]) -> Option<GUID> {
    let end = name.iter().position(|&ch| ch == 0)?;
    let wide = name[..end]
        .strip_prefix(&[b'{' as u16])?
        .strip_suffix(&[b'}' as u16])?;
    let mut ascii = [0u8; 36];
    if wide.len() != ascii.len() {
        return None;
    }
    for (byte, &ch) in ascii.iter_mut().zip(wide) {
        *byte = u8::try_from(ch).ok()?;
    }
    parse_guid(&ascii)
}

fn adapter_names() -> Vec<(GUID, String)> {
    let mut names = Vec::new();
    let Some(root) = RegistryKey::open(
        HKEY_LOCAL_MACHINE,
        windows_sys::core::w!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards"),
        KEY_ENUMERATE_SUB_KEYS,
    ) else {
        return names;
    };
    let mut name = [0u16; 256];
    for index in 0..u32::MAX {
        let mut length = name.len() as u32;
        let status = unsafe {
            RegEnumKeyExW(
                root.0,
                index,
                name.as_mut_ptr(),
                &mut length,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if status != 0 {
            break;
        }
        let Some(terminator) = name.get_mut(length as usize) else {
            continue;
        };
        *terminator = 0;
        let Some(key) = RegistryKey::open(root.0, name.as_ptr(), KEY_QUERY_VALUE) else {
            continue;
        };
        let Some(id) = key
            .string(windows_sys::core::w!("ServiceName"))
            .as_deref()
            .and_then(service_guid)
        else {
            continue;
        };
        let Some(description) = key.string(windows_sys::core::w!("Description")) else {
            continue;
        };
        let Ok(mut bytes) = (unsafe { utf8(description.as_ptr()) }) else {
            continue;
        };
        bytes.pop();
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        if names.try_reserve(1).is_err() {
            break;
        }
        names.push((id, text));
    }
    names
}

trait AdapterNames {
    fn lookup(&mut self, id: &GUID) -> Option<&str>;
}

#[derive(Default)]
struct RegistryNames(Option<Vec<(GUID, String)>>);
impl AdapterNames for RegistryNames {
    fn lookup(&mut self, id: &GUID) -> Option<&str> {
        self.0
            .get_or_insert_with(adapter_names)
            .iter()
            .find_map(|(adapter, name)| same_guid(adapter, id).then_some(name.as_str()))
    }
}

struct FixtureNames {
    context: *mut c_void,
    lookup: AdapterOverride,
    name: [u8; 512],
}
impl AdapterNames for FixtureNames {
    fn lookup(&mut self, id: &GUID) -> Option<&str> {
        let size =
            unsafe { (self.lookup)(self.context, id, self.name.as_mut_ptr(), self.name.len()) };
        if size == 0 {
            return None;
        }
        std::str::from_utf8(self.name.get(..size)?).ok()
    }
}

struct Row {
    id: GUID,
    name: String,
    internet: bool,
    category: i32,
}
impl Row {
    unsafe fn read(network: &ComObject, details: *const NetworkDetails) -> Result<Self, u32> {
        let internet = unsafe { read(network.0, (*details).internet) }? != 0;
        let id = unsafe { read(network.0, (*details).base.id) }?;
        let category = unsafe { read(network.0, (*details).category) }?;
        let name = ComString(unsafe { read(network.0, (*details).base.name) }?);
        if name.0.is_null() {
            return Err(E_POINTER as u32);
        }
        let mut bytes = unsafe { utf8(name.0) }.map_err(win32_hresult)?;
        bytes.pop();
        let name = String::from_utf8(bytes).map_err(|_| win32_hresult(ERROR_INVALID_DATA))?;
        Ok(Self {
            id,
            name,
            internet,
            category,
        })
    }

    fn write(&self, output: &mut Output, connected: bool) -> Result<(), u32> {
        let state = if connected { " (connected)" } else { "" };
        let internet = if self.internet { " (inet)" } else { "" };
        let category = match self.category {
            0 => "public",
            1 => "private",
            2 => "domain",
            _ => "unknown",
        };
        writeln!(
            output,
            "Name    : {}{state}{internet} ({category})\nNetID   : {}",
            self.name,
            GuidText(&self.id)
        )
        .map_err(write_error)
    }
}

unsafe fn adapters(
    network: &ComObject,
    details: *const NetworkDetails,
    output: &mut Output,
    names: &mut impl AdapterNames,
) -> Result<(), u32> {
    // Adapter details are supplemental. Leave the network row available if an
    // adapter disappears while Windows supplies its connections.
    let Ok(enumerator) =
        unsafe { read(network.0, (*details).connections) }.and_then(ComObject::new)
    else {
        return Ok(());
    };
    while let Ok(Some(connection)) = unsafe { next(&enumerator) } {
        let table = unsafe { table::<ConnectionDetails>(connection.0) };
        let Ok(id) = (unsafe { read(connection.0, (*table).adapter) }) else {
            continue;
        };
        if let Some(name) = names.lookup(&id) {
            writeln!(output, "Adapter : {name} ({})", GuidText(&id)).map_err(write_error)?;
        } else {
            writeln!(output, "Adapter : {}", GuidText(&id)).map_err(write_error)?;
        }
    }
    Ok(())
}

unsafe fn list(
    manager: *mut c_void,
    all: bool,
    output: &mut Output,
    names: &mut impl AdapterNames,
) -> Result<(), u32> {
    if manager.is_null() {
        return Err(E_POINTER as u32);
    }
    let table_manager = unsafe { table::<Manager>(manager) };
    let mut raw = ptr::null_mut();
    let flags = if all {
        ALL_NETWORKS
    } else {
        CONNECTED_NETWORKS
    };
    hresult(unsafe { ((*table_manager).networks)(manager, flags, &mut raw) })?;
    let enumerator = ComObject::new(raw)?;
    let mut disconnected = Vec::new();
    while let Some(network) = unsafe { next(&enumerator) }? {
        let details = unsafe { table::<NetworkDetails>(network.0) };
        let connected = unsafe { read(network.0, (*details).connected) }? != 0;
        if !connected && !all {
            continue;
        }
        let row = unsafe { Row::read(&network, details) }?;
        if connected {
            row.write(output, true)?;
            unsafe { adapters(&network, details, output, names) }?;
            writeln!(output).map_err(write_error)?;
        } else {
            disconnected
                .try_reserve(1)
                .map_err(|_| win32_hresult(ERROR_NOT_ENOUGH_MEMORY))?;
            disconnected.push(row);
        }
    }
    for row in disconnected {
        row.write(output, false)?;
        writeln!(output).map_err(write_error)?;
    }
    Ok(())
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_network_environment_list(
    all: bool,
    context: *mut c_void,
    write: WriteOutput,
    error: &mut u32,
) -> bool {
    let result = (|| {
        let environment = unsafe { Environment::create(false, true) }?;
        let manager = environment.manager.as_ref().ok_or(E_POINTER as u32)?;
        unsafe {
            list(
                manager.0,
                all,
                &mut Output { context, write },
                &mut RegistryNames::default(),
            )
        }
    })();
    *error = result.err().unwrap_or(0);
    *error == 0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_nlm_test_list(
    manager: *mut c_void,
    all: bool,
    context: *mut c_void,
    write: WriteOutput,
    lookup: AdapterOverride,
    error: &mut u32,
) -> bool {
    let mut names = FixtureNames {
        context,
        lookup,
        name: [0; 512],
    };
    *error = unsafe { list(manager, all, &mut Output { context, write }, &mut names) }
        .err()
        .unwrap_or(0);
    *error == 0
}
