//! Local StandardCimv2 access. Callers own the apartment and a bounded worker.
use crate::com::{Object, StringValue, Unknown, check, read_bstr};
use anyhow::{Result, ensure};
use std::{
    ffi::c_void,
    ptr::{null, null_mut},
    time::Instant,
};
use windows_sys::{
    Win32::System::{
        Com::*,
        Ole::{SafeArrayCreateVector, SafeArrayPutElement},
        Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE},
        Variant::*,
        Wmi::*,
    },
    core::{BSTR, GUID, PCWSTR},
};

#[repr(C)]
struct Locator {
    base: Unknown,
    connect: unsafe extern "system" fn(
        *mut c_void,
        BSTR,
        BSTR,
        BSTR,
        BSTR,
        i32,
        BSTR,
        *mut c_void,
        *mut *mut c_void,
    ) -> i32,
}
#[repr(C)]
struct Services {
    base: Unknown,
    before_get: [usize; 3],
    get: unsafe extern "system" fn(
        *mut c_void,
        BSTR,
        i32,
        *mut c_void,
        *mut *mut c_void,
        *mut *mut c_void,
    ) -> i32,
    before_put: [usize; 7],
    put: unsafe extern "system" fn(
        *mut c_void,
        *mut c_void,
        i32,
        *mut c_void,
        *mut *mut c_void,
    ) -> i32,
    before_query: [usize; 5],
    query: unsafe extern "system" fn(
        *mut c_void,
        BSTR,
        BSTR,
        i32,
        *mut c_void,
        *mut *mut c_void,
    ) -> i32,
}
#[repr(C)]
struct Enumerator {
    base: Unknown,
    reset: usize,
    next: unsafe extern "system" fn(*mut c_void, i32, u32, *mut *mut c_void, *mut u32) -> i32,
}
#[repr(C)]
struct ClassObject {
    base: Unknown,
    qualifier: usize,
    get: unsafe extern "system" fn(
        *mut c_void,
        PCWSTR,
        i32,
        *mut VARIANT,
        *mut i32,
        *mut i32,
    ) -> i32,
    put: unsafe extern "system" fn(*mut c_void, PCWSTR, i32, *const VARIANT, i32) -> i32,
}
#[repr(C)]
struct CallResult {
    base: Unknown,
    results: [usize; 3],
    status: unsafe extern "system" fn(*mut c_void, i32, *mut i32) -> i32,
}
#[repr(C)]
struct UpdateContext {
    base: Unknown,
    before_set: [usize; 5],
    set: unsafe extern "system" fn(*mut c_void, PCWSTR, i32, *const VARIANT) -> i32,
    #[cfg(test)]
    get: unsafe extern "system" fn(*mut c_void, PCWSTR, i32, *mut VARIANT) -> i32,
}

fn update_context(properties: &[&str]) -> Result<Object> {
    const CLSID: GUID = GUID::from_u128(0x674b6698_ee92_11d0_ad71_00c04fd8fdff);
    const IID: GUID = GUID::from_u128(0x44aca674_e8fc_11d0_a07c_00c04fb68820);
    ensure!(
        !properties.is_empty() && properties.len() <= 16,
        "Invalid WMI update property count"
    );
    unsafe {
        let mut raw = null_mut();
        check(
            CoCreateInstance(&CLSID, null_mut(), CLSCTX_INPROC_SERVER, &IID, &mut raw),
            "Create WMI update context",
        )?;
        let context = Object::new(raw)?;
        let mut enabled = VARIANT::default();
        enabled.Anonymous.Anonymous.vt = VT_BOOL;
        enabled.Anonymous.Anonymous.Anonymous.boolVal = -1;
        for name in [
            "__PUT_EXTENSIONS",
            "__PUT_EXT_CLIENT_REQUEST",
            "__PUT_EXT_ATOMIC",
        ] {
            let name = StringValue::allocate(name)?;
            check(
                (context.table::<UpdateContext>().set)(context.0, name.0, 0, &enabled),
                "Set WMI partial update flag",
            )?;
        }
        let array = SafeArrayCreateVector(VT_BSTR, 0, properties.len() as u32);
        ensure!(!array.is_null(), "Create WMI update property array");
        let mut names = Variant(VARIANT::default());
        names.0.Anonymous.Anonymous.vt = VT_ARRAY | VT_BSTR;
        names.0.Anonymous.Anonymous.Anonymous.parray = array;
        for (index, name) in properties.iter().enumerate() {
            let index = index as i32;
            let name = StringValue::allocate(name)?;
            check(
                SafeArrayPutElement(array, &index, name.0.cast()),
                "Set WMI update property",
            )?;
        }
        let name = StringValue::allocate("__PUT_EXT_PROPERTIES")?;
        check(
            (context.table::<UpdateContext>().set)(context.0, name.0, 0, &names.0),
            "Restrict WMI updated properties",
        )?;
        Ok(context)
    }
}

pub(crate) struct Variant(pub(crate) VARIANT);
impl Drop for Variant {
    fn drop(&mut self) {
        unsafe {
            VariantClear(&mut self.0);
        }
    }
}
pub(crate) struct Instance(pub(crate) Object);
impl Instance {
    pub(crate) fn property(&self, name: &str) -> Result<Variant> {
        let name = StringValue::allocate(name)?;
        let mut value = Variant(VARIANT::default());
        unsafe {
            check(
                (self.0.table::<ClassObject>().get)(
                    self.0.0,
                    name.0,
                    0,
                    &mut value.0,
                    null_mut(),
                    null_mut(),
                ),
                "Read WMI property",
            )?;
        }
        Ok(value)
    }
    pub(crate) fn text(&self, name: &str) -> Result<Option<String>> {
        let value = self.property(name)?;
        unsafe {
            let inner = value.0.Anonymous.Anonymous;
            if matches!(inner.vt, VT_NULL | VT_EMPTY) {
                return Ok(None);
            }
            ensure!(inner.vt == VT_BSTR, "WMI {name} is not a string");
            read_bstr(inner.Anonymous.bstrVal, 32768).map(Some)
        }
    }
    pub(crate) fn number(&self, name: &str) -> Result<Option<u32>> {
        let value = self.property(name)?;
        unsafe {
            let inner = value.0.Anonymous.Anonymous;
            match inner.vt {
                VT_NULL | VT_EMPTY => Ok(None),
                VT_I4 => Ok(Some(inner.Anonymous.lVal as u32)),
                VT_UI4 => Ok(Some(inner.Anonymous.ulVal)),
                VT_UI1 => Ok(Some(inner.Anonymous.bVal.into())),
                _ => anyhow::bail!("WMI {name} is not an unsigned integer"),
            }
        }
    }
    pub(crate) fn set_number(&self, name: &str, value: u32) -> Result<()> {
        let name = StringValue::allocate(name)?;
        let mut variant = VARIANT::default();
        variant.Anonymous.Anonymous.vt = VT_I4;
        variant.Anonymous.Anonymous.Anonymous.lVal = value as i32;
        unsafe {
            check(
                (self.0.table::<ClassObject>().put)(self.0.0, name.0, 0, &variant, 0),
                "Prepare WMI property",
            )
        }
    }
}

pub(crate) struct Connection {
    services: Object,
    deadline: Instant,
}
impl Connection {
    pub(crate) fn open(deadline: Instant) -> Result<Self> {
        const CLSID: GUID = GUID::from_u128(0x4590f811_1d3a_11d0_891f_00aa004b2e24);
        const IID: GUID = GUID::from_u128(0xdc12a687_737f_11cf_884d_00aa004b2e24);
        let namespace = StringValue::allocate(r"ROOT\StandardCimv2")?;
        unsafe {
            let mut raw = null_mut();
            check(
                CoCreateInstance(&CLSID, null_mut(), CLSCTX_INPROC_SERVER, &IID, &mut raw),
                "Create WMI locator",
            )?;
            let locator = Object::new(raw)?;
            raw = null_mut();
            check(
                (locator.table::<Locator>().connect)(
                    locator.0,
                    namespace.0,
                    null(),
                    null(),
                    null(),
                    WBEM_FLAG_CONNECT_USE_MAX_WAIT,
                    null(),
                    null_mut(),
                    &mut raw,
                ),
                "Open local StandardCimv2",
            )?;
            let services = Object::new(raw)?;
            check(
                CoSetProxyBlanket(
                    services.0,
                    RPC_C_AUTHN_WINNT,
                    RPC_C_AUTHZ_NONE,
                    null(),
                    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                    RPC_C_IMP_LEVEL_IMPERSONATE,
                    null(),
                    EOAC_NONE as u32,
                ),
                "Set local WMI authentication",
            )?;
            let result = Self { services, deadline };
            result.remaining()?;
            Ok(result)
        }
    }
    fn remaining(&self) -> Result<i32> {
        let left = self
            .deadline
            .saturating_duration_since(Instant::now())
            .as_millis();
        ensure!(left > 0, "Windows network settings deadline reached");
        Ok(left.min(i32::MAX as u128) as i32)
    }
    pub(crate) fn query(&self, query: &str, limit: usize) -> Result<Vec<Instance>> {
        self.remaining()?;
        let language = StringValue::allocate("WQL")?;
        let query = StringValue::allocate(query)?;
        unsafe {
            let mut raw = null_mut();
            check(
                (self.services.table::<Services>().query)(
                    self.services.0,
                    language.0,
                    query.0,
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    null_mut(),
                    &mut raw,
                ),
                "Query Windows network settings",
            )?;
            let enumerator = Object::new(raw)?;
            let mut rows = Vec::new();
            loop {
                let mut raw = null_mut();
                let mut count = 0;
                let status = (enumerator.table::<Enumerator>().next)(
                    enumerator.0,
                    self.remaining()?,
                    1,
                    &mut raw,
                    &mut count,
                );
                check(status, "Read Windows network settings")?;
                ensure!(
                    status != WBEM_S_TIMEDOUT,
                    "Windows network settings query timed out"
                );
                if count == 0 && status == WBEM_S_FALSE {
                    return Ok(rows);
                }
                let instance = Instance(Object::new(raw)?);
                ensure!(
                    count == 1 && rows.len() < limit,
                    "Windows network settings query exceeded its row limit"
                );
                rows.push(instance);
            }
        }
    }
    pub(crate) fn get(&self, path: &str) -> Result<Instance> {
        self.remaining()?;
        let path = StringValue::allocate(path)?;
        unsafe {
            let mut raw = null_mut();
            check(
                (self.services.table::<Services>().get)(
                    self.services.0,
                    path.0,
                    0,
                    null_mut(),
                    &mut raw,
                    null_mut(),
                ),
                "Read exact Windows network setting",
            )?;
            Object::new(raw).map(Instance)
        }
    }
    pub(crate) fn update(&self, instance: &Instance, properties: &[&str]) -> Result<()> {
        self.remaining()?;
        let context = update_context(properties)?;
        unsafe {
            let mut raw = null_mut();
            check(
                (self.services.table::<Services>().put)(
                    self.services.0,
                    instance.0.0,
                    WBEM_FLAG_UPDATE_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    context.0,
                    &mut raw,
                ),
                "Update Windows network setting",
            )?;
            let result = Object::new(raw)?;
            let mut provider = 0;
            let status =
                (result.table::<CallResult>().status)(result.0, self.remaining()?, &mut provider);
            check(status, "Wait for Windows network setting")?;
            ensure!(
                status == 0,
                "Windows network setting did not complete: {status:#010x}"
            );
            check(provider, "Complete Windows network setting")?;
            ensure!(
                provider == 0,
                "Unexpected Windows network provider result {provider:#010x}"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::com::Apartment;
    use anyhow::Context;
    use std::time::Duration;
    #[test]
    fn partial_update_context_keeps_only_the_requested_properties() {
        use windows_sys::Win32::System::Ole::{SafeArrayGetElement, SafeArrayGetUBound};
        let _apartment = Apartment::enter("WMI partial update context test").unwrap();
        let context = update_context(&["Timestamps"]).unwrap();
        unsafe {
            let mut value = Variant(VARIANT::default());
            let name = StringValue::allocate("__PUT_EXT_PROPERTIES").unwrap();
            check(
                (context.table::<UpdateContext>().get)(context.0, name.0, 0, &mut value.0),
                "Read partial update context",
            )
            .unwrap();
            let inner = value.0.Anonymous.Anonymous;
            assert_eq!(inner.vt, VT_ARRAY | VT_BSTR);
            let array = inner.Anonymous.parray;
            let mut upper = 0;
            check(
                SafeArrayGetUBound(array, 1, &mut upper),
                "Read update property bound",
            )
            .unwrap();
            assert_eq!(upper, 0);
            let index = 0;
            let mut name: BSTR = null();
            check(
                SafeArrayGetElement(array, &index, (&raw mut name).cast()),
                "Read update property name",
            )
            .unwrap();
            assert_eq!(StringValue(name).read(100).unwrap(), "Timestamps");
        }
    }
    #[test]
    fn network_provider_returns_typed_read_only_rows() {
        let _apartment = Apartment::enter("Network provider test").unwrap();
        let connection = Connection::open(Instant::now() + Duration::from_secs(5)).unwrap();
        let rows = connection
            .query("SELECT * FROM MSFT_NetPrefixPolicy", 256)
            .unwrap();
        for row in rows {
            assert!(row.text("Prefix").unwrap().is_some());
            assert!(row.number("Store").unwrap().is_some_and(|v| v <= 1));
            assert!(row.number("Precedence").unwrap().is_some());
            assert!(row.number("Label").unwrap().is_some());
        }
        let rows = connection
            .query("SELECT * FROM MSFT_NetTCPSetting", 64)
            .unwrap();
        assert!(!rows.is_empty());
        for row in rows {
            let name = row.text("SettingName").unwrap().unwrap();
            let timestamps = row.number("Timestamps").unwrap();
            assert!(timestamps.is_some_and(|v| v <= 2) || name == "Automatic");
        }
    }
    #[test]
    fn preparing_a_property_is_local_and_does_not_write_the_provider() {
        let _apartment = Apartment::enter("Network property staging test").unwrap();
        let connection = Connection::open(Instant::now() + Duration::from_secs(5)).unwrap();
        let rows = connection
            .query(
                "SELECT * FROM MSFT_NetTCPSetting WHERE SettingName='Internet'",
                1,
            )
            .unwrap();
        let row = rows.first().context("Internet template").unwrap();
        let previous = row.number("Timestamps").unwrap().unwrap();
        row.set_number("Timestamps", if previous == 1 { 2 } else { 1 })
            .unwrap();
        assert_eq!(
            row.number("Timestamps").unwrap(),
            Some(if previous == 1 { 2 } else { 1 })
        );
        let again = connection
            .query(
                "SELECT * FROM MSFT_NetTCPSetting WHERE SettingName='Internet'",
                1,
            )
            .unwrap();
        assert_eq!(again[0].number("Timestamps").unwrap(), Some(previous));
    }
}
