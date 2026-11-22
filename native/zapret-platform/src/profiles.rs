//! Read-only Network List Manager COM ABI. Keep one windows-sys import implementation
//! throughout the GNU build; mixing raw import library generators breaks its IAT.
use crate::com::{Apartment, Dispatch, Object, StringValue, check};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    ffi::c_void,
    ptr::{null, null_mut},
};
use windows_sys::{
    Win32::System::Com::*,
    core::{BSTR, GUID},
};

// INetworkListManager, IEnumNetworks and INetwork extend IDispatch (seven slots).
#[repr(C)]
struct Manager {
    base: Dispatch,
    get_networks: unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> i32,
}
#[repr(C)]
struct Enumerator {
    base: Dispatch,
    new_enum: usize,
    next: unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void, *mut u32) -> i32,
}
#[repr(C)]
struct Network {
    base: Dispatch,
    get_name: unsafe extern "system" fn(*mut c_void, *mut BSTR) -> i32,
    name_description: [usize; 3],
    get_id: unsafe extern "system" fn(*mut c_void, *mut GUID) -> i32,
    properties: [usize; 6],
    get_category: unsafe extern "system" fn(*mut c_void, *mut i32) -> i32,
}
fn guid(value: &GUID) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        value.data1,
        value.data2,
        value.data3,
        value.data4[0],
        value.data4[1],
        value.data4[2],
        value.data4[3],
        value.data4[4],
        value.data4[5],
        value.data4[6],
        value.data4[7]
    )
}
pub(crate) fn read() -> Result<Value> {
    let _apartment = Apartment::enter("NLM COM apartment")?;
    unsafe {
        let clsid = GUID {
            data1: 0xdcb00c01,
            data2: 0x570f,
            data3: 0x4a9b,
            data4: [0x8d, 0x69, 0x19, 0x9f, 0xdb, 0xa5, 0x72, 0x3b],
        };
        let iid = GUID {
            data1: 0xdcb00000,
            ..clsid
        };
        let mut raw = null_mut();
        check(
            CoCreateInstance(&clsid, null_mut(), CLSCTX_ALL, &iid, &mut raw),
            "Create Network List Manager",
        )?;
        let manager = Object::new(raw)?;
        let mut raw = null_mut();
        check(
            (manager.table::<Manager>().get_networks)(manager.0, 1, &mut raw),
            "Enumerate connected networks",
        )?;
        let enumerator = Object::new(raw)?;
        let mut profiles = Vec::new();
        loop {
            let mut fetched = 0;
            let mut raw = null_mut();
            check(
                (enumerator.table::<Enumerator>().next)(enumerator.0, 1, &mut raw, &mut fetched),
                "Read connected network",
            )?;
            if fetched == 0 {
                break;
            }
            ensure!(profiles.len() < 1024, "Too many connected network profiles");
            let network = Object::new(raw)?;
            let table = network.table::<Network>();
            let mut name = null();
            check(
                (table.get_name)(network.0, &mut name),
                "Read network profile name",
            )?;
            let text = StringValue(name).read(32768)?;
            let mut id = GUID::default();
            check(
                (table.get_id)(network.0, &mut id),
                "Read network profile identity",
            )?;
            let mut category = 0;
            check(
                (table.get_category)(network.0, &mut category),
                "Read network profile category",
            )?;
            profiles.push(json!({"id":guid(&id),"name":text,"category":category}));
        }
        profiles.sort_by_key(ToString::to_string);
        Ok(json!(profiles))
    }
}
