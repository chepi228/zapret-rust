use crate::com::{Apartment, Object, StringValue, Unknown, check, read_bstr};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::c_void,
    net::IpAddr,
    ptr::{null, null_mut},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use windows_sys::{
    Win32::System::{
        Com::*,
        Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE},
        Variant::{VARIANT, VT_BSTR, VT_I4, VT_UI4, VariantClear},
        Wmi::*,
    },
    core::{BSTR, GUID, PCWSTR, w},
};

const MAX_CACHE_ROWS: usize = 8192;
const MAX_NAMES_PER_PEER: usize = 8;
const FLUSH_TIMEOUT: Duration = Duration::from_secs(8);
static FLUSH_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

// Vtable prefixes from wbemcli.h.
#[repr(C)]
struct Locator {
    base: Unknown,
    connect_server: unsafe extern "system" fn(
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
    before_get_object: [usize; 3],
    get_object: unsafe extern "system" fn(
        *mut c_void,
        BSTR,
        i32,
        *mut c_void,
        *mut *mut c_void,
        *mut *mut c_void,
    ) -> i32,
    before_exec_query: [usize; 13],
    exec_query: unsafe extern "system" fn(
        *mut c_void,
        BSTR,
        BSTR,
        i32,
        *mut c_void,
        *mut *mut c_void,
    ) -> i32,
    before_exec_method: [usize; 3],
    exec_method: unsafe extern "system" fn(
        *mut c_void,
        BSTR,
        BSTR,
        i32,
        *mut c_void,
        *mut c_void,
        *mut *mut c_void,
        *mut *mut c_void,
    ) -> i32,
}
#[repr(C)]
struct CallResult {
    base: Unknown,
    get_result_object: unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> i32,
    before_get_call_status: [usize; 2],
    get_call_status: unsafe extern "system" fn(*mut c_void, i32, *mut i32) -> i32,
}
#[repr(C)]
struct Enumerator {
    base: Unknown,
    reset: usize,
    next: unsafe extern "system" fn(*mut c_void, i32, u32, *mut *mut c_void, *mut u32) -> i32,
}
#[repr(C)]
struct Instance {
    base: Unknown,
    get_qualifier_set: usize,
    get: unsafe extern "system" fn(
        *mut c_void,
        PCWSTR,
        i32,
        *mut VARIANT,
        *mut i32,
        *mut i32,
    ) -> i32,
    #[cfg(test)]
    before_get_method: [usize; 14],
    #[cfg(test)]
    get_method: unsafe extern "system" fn(
        *mut c_void,
        PCWSTR,
        i32,
        *mut *mut c_void,
        *mut *mut c_void,
    ) -> i32,
}

struct Variant(VARIANT);
impl Drop for Variant {
    fn drop(&mut self) {
        unsafe { VariantClear(&mut self.0) };
    }
}

fn property(instance: &Object, name: PCWSTR) -> Result<Variant> {
    let mut value = Variant(VARIANT::default());
    // The instance is an IWbemClassObject. WMI initializes the VARIANT on success.
    unsafe {
        check(
            (instance.table::<Instance>().get)(
                instance.0,
                name,
                0,
                &mut value.0,
                null_mut(),
                null_mut(),
            ),
            "Read DNS cache property",
        )?;
    }
    Ok(value)
}

fn string_property(instance: &Object, name: PCWSTR) -> Result<Option<String>> {
    let value = property(instance, name)?;
    unsafe {
        let inner = value.0.Anonymous.Anonymous;
        if inner.vt != VT_BSTR {
            return Ok(None);
        }
        read_bstr(inner.Anonymous.bstrVal, 254).map(Some)
    }
}

#[derive(Default)]
pub struct ForwardDnsCache {
    pub names: BTreeMap<IpAddr, BTreeSet<String>>,
    pub enumerated: bool,
    pub names_truncated: bool,
}

impl ForwardDnsCache {
    fn record(&mut self, address: IpAddr, name: &str) {
        let name = name.trim_end_matches('.');
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return;
        }
        let name = name.to_ascii_lowercase();
        let names = self.names.entry(address).or_default();
        if names.len() < MAX_NAMES_PER_PEER {
            names.insert(name);
        } else if !names.contains(&name) {
            self.names_truncated = true;
        }
    }
}

fn dns_cache_services() -> Result<Object> {
    const CLSID_LOCATOR: GUID = GUID::from_u128(0x4590f811_1d3a_11d0_891f_00aa004b2e24);
    const IID_LOCATOR: GUID = GUID::from_u128(0xdc12a687_737f_11cf_884d_00aa004b2e24);
    let namespace = StringValue::allocate(r"ROOT\StandardCimv2")?;
    unsafe {
        let mut raw = null_mut();
        check(
            CoCreateInstance(
                &CLSID_LOCATOR,
                null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_LOCATOR,
                &mut raw,
            ),
            "Create WMI locator",
        )?;
        let locator = Object::new(raw)?;
        raw = null_mut();
        check(
            (locator.table::<Locator>().connect_server)(
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
            "Open local DNS cache namespace",
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
            "Set local DNS cache authentication",
        )?;
        Ok(services)
    }
}

/// Read the local Windows DNS client cache and retain only names for these peers.
pub fn forward_dns_cache(peers: &[IpAddr], budget: Duration) -> Result<ForwardDnsCache> {
    let deadline = Instant::now() + budget;
    let _apartment = Apartment::enter("DNS cache COM apartment")?;
    let services = dns_cache_services()?;
    let language = StringValue::allocate("WQL")?;
    let query = StringValue::allocate(
        "SELECT Entry, Data FROM MSFT_DNSClientCache WHERE Status = 0 AND (Type = 1 OR Type = 28)",
    )?;
    let mut cache = ForwardDnsCache::default();
    unsafe {
        let mut raw = null_mut();
        check(
            (services.table::<Services>().exec_query)(
                services.0,
                language.0,
                query.0,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                null_mut(),
                &mut raw,
            ),
            "Query DNS client cache",
        )?;
        let enumerator = Object::new(raw)?;
        let next = enumerator.table::<Enumerator>().next;
        for _ in 0..MAX_CACHE_ROWS {
            let millis = deadline
                .saturating_duration_since(Instant::now())
                .as_millis();
            if millis == 0 {
                break;
            }
            let mut count = 0;
            let mut raw = null_mut();
            let result = next(
                enumerator.0,
                millis.min(i32::MAX as u128) as i32,
                1,
                &mut raw,
                &mut count,
            );
            check(result, "Read DNS cache instance")?;
            if result == WBEM_S_FALSE && count == 0 {
                cache.enumerated = true;
                return Ok(cache);
            }
            if result == WBEM_S_TIMEDOUT && count == 0 {
                break;
            }
            ensure!(count == 1, "Unexpected DNS cache instance count: {count}");
            let instance = Object::new(raw)?;
            if let Some(address) = string_property(&instance, w!("Data"))?
                .and_then(|text| text.parse::<IpAddr>().ok())
                .filter(|address| peers.contains(address))
            {
                if let Some(name) = string_property(&instance, w!("Entry"))? {
                    cache.record(address, &name);
                }
            }
        }
    }
    Ok(cache)
}

fn clear_return_code(value: &Variant) -> Result<u32> {
    unsafe {
        let inner = value.0.Anonymous.Anonymous;
        match inner.vt {
            // WMI can marshal a CIM uint32 as a VARIANT with VT_I4.
            VT_I4 => Ok(inner.Anonymous.lVal as u32),
            VT_UI4 => Ok(inner.Anonymous.ulVal),
            _ => anyhow::bail!("DNS cache provider returned no numeric result"),
        }
    }
}

fn clear(deadline: Instant) -> Result<Option<u32>> {
    let _apartment = Apartment::enter("DNS cache COM apartment")?;
    let services = dns_cache_services()?;
    let class = StringValue::allocate("MSFT_DNSClientCache")?;
    let method = StringValue::allocate("Clear")?;
    if Instant::now() >= deadline {
        return Ok(None);
    }
    unsafe {
        let mut result = null_mut();
        check(
            (services.table::<Services>().exec_method)(
                services.0,
                class.0,
                method.0,
                WBEM_FLAG_RETURN_IMMEDIATELY,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut result,
            ),
            "Request DNS cache clear",
        )?;
        let result = Object::new(result).context("Get DNS cache clear call")?;
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .as_millis() as i32;
        let mut provider_status = 0;
        let status =
            (result.table::<CallResult>().get_call_status)(result.0, timeout, &mut provider_status);
        if status == WBEM_S_TIMEDOUT {
            return Ok(None);
        }
        check(status, "Wait for DNS cache clear")?;
        ensure!(
            status == 0,
            "Unexpected DNS cache call status {status:#010x}"
        );
        check(provider_status, "Complete DNS cache clear")?;
        ensure!(
            provider_status == 0,
            "Unexpected DNS cache provider status {provider_status:#010x}"
        );
        let mut output = null_mut();
        let status = (result.table::<CallResult>().get_result_object)(result.0, 0, &mut output);
        check(status, "Get DNS cache clear result")?;
        ensure!(
            status == 0,
            "Unexpected DNS cache result status {status:#010x}"
        );
        if output.is_null() {
            // Some Windows providers complete Clear with S_OK and no output
            // object, as Clear-DnsClientCache does. GetCallStatus confirmed
            // completion; a merely accepted request never reaches this branch.
            return Ok(Some(0));
        }
        clear_return_code(&property(&Object::new(output)?, w!("ReturnValue"))?).map(Some)
    }
}

pub(crate) fn flush() -> Value {
    let result = (|| {
        ensure!(
            !FLUSH_IN_PROGRESS.swap(true, Ordering::AcqRel),
            "Another DNS cache clear is still finishing"
        );
        struct FlushSlot;
        impl Drop for FlushSlot {
            fn drop(&mut self) {
                FLUSH_IN_PROGRESS.store(false, Ordering::Release);
            }
        }
        let slot = FlushSlot;
        let deadline = Instant::now() + FLUSH_TIMEOUT;
        let (send, receive) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("dns-cache-clear".into())
            .spawn(move || {
                let result = clear(deadline);
                drop(slot);
                let _ = send.send(result);
            })
            .context("Start DNS cache worker")?;
        match receive.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(error) => Err(error).context("DNS cache worker ended without a result"),
        }
    })();
    let (code, timed_out, message) = match result {
        Ok(Some(0)) => (0, false, String::new()),
        Ok(Some(code)) => (code, false, format!("DNS cache provider returned {code}")),
        Ok(None) => (1, true, "DNS cache clear was not confirmed in time".into()),
        Err(error) => (1, false, format!("{error:#}")),
    };
    // Keep the diagnostic fields used by existing hosts and uninstall callers.
    json!({"exit_code":code,"timed_out":timed_out,"stdout":"","stderr":message,
        "output_truncated":false,"backend":"WindowsDnsClientCache"})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_cache_normalizes_names_and_limits_aliases() {
        let peer = "2001:4860:4860::8888".parse().unwrap();
        let mut cache = ForwardDnsCache::default();
        cache.record(peer, "Example.NET.");
        cache.record(peer, "example.net");
        cache.record(peer, "example.net/path");
        assert_eq!(cache.names[&peer], BTreeSet::from(["example.net".into()]));
        for index in 0..MAX_NAMES_PER_PEER {
            cache.record(peer, &format!("alias{index}.example.net"));
        }
        assert_eq!(cache.names[&peer].len(), MAX_NAMES_PER_PEER);
        assert!(cache.names_truncated);
    }

    #[test]
    fn local_dns_cache_provider_accepts_the_read_only_query() {
        let peer = "8.8.8.8".parse().unwrap();
        let cache = forward_dns_cache(&[peer], Duration::from_secs(3)).unwrap();
        assert!(cache.enumerated);
        assert!(cache.names.keys().all(|address| *address == peer));
    }

    #[test]
    fn a_missing_clear_result_is_never_interpreted_as_success() {
        let mut empty = Variant(VARIANT::default());
        assert!(clear_return_code(&empty).is_err());
        empty.0.Anonymous.Anonymous.vt = VT_I4;
        empty.0.Anonymous.Anonymous.Anonymous.lVal = 5;
        assert_eq!(clear_return_code(&empty).unwrap(), 5);
        empty.0.Anonymous.Anonymous.vt = VT_UI4;
        empty.0.Anonymous.Anonymous.Anonymous.ulVal = 0;
        assert_eq!(clear_return_code(&empty).unwrap(), 0);
    }

    #[test]
    fn local_dns_cache_provider_exposes_clear_without_flushing() {
        let _apartment = Apartment::enter("DNS cache method metadata test").unwrap();
        let services = dns_cache_services().unwrap();
        let path = StringValue::allocate("MSFT_DNSClientCache").unwrap();
        let mut class = null_mut();
        unsafe {
            check(
                (services.table::<Services>().get_object)(
                    services.0,
                    path.0,
                    0,
                    null_mut(),
                    &mut class,
                    null_mut(),
                ),
                "Read DNS cache CIM class",
            )
            .unwrap();
            let class = Object::new(class).unwrap();
            let mut output = null_mut();
            check(
                (class.table::<Instance>().get_method)(
                    class.0,
                    w!("Clear"),
                    0,
                    null_mut(),
                    &mut output,
                ),
                "Inspect DNS cache Clear method signature",
            )
            .unwrap();
            let output = Object::new(output).unwrap();
            assert!(property(&output, w!("ReturnValue")).is_ok());
        }
    }

    #[test]
    #[ignore = "clears the machine-wide Windows DNS cache"]
    fn live_flush_confirms_the_windows_provider_result() {
        let result = flush();
        assert_eq!(result["exit_code"], 0, "{result}");
        assert_eq!(result["timed_out"], false);
    }
}
