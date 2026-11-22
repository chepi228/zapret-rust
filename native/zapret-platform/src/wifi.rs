//! Bounded, read-only WLAN disconnect evidence. This never enables an event log.
use crate::process::wide;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    ptr::null_mut,
    time::{Duration, Instant},
};
use windows_sys::{
    Win32::{
        Foundation::*,
        NetworkManagement::{IpHelper::ConvertInterfaceLuidToGuid, Ndis::NET_LUID_LH},
        System::{EventLog::*, Time::SystemTimeToFileTime},
    },
    core::GUID,
};

const CHANNEL: &str = "Microsoft-Windows-WLAN-AutoConfig/Operational";
const PROVIDER: &str = "Microsoft-Windows-WLAN-AutoConfig";
const QUERY: &str = "*[System[Provider[@Name='Microsoft-Windows-WLAN-AutoConfig'] and EventID=8003 and TimeCreated[timediff(@SystemTime) >= 0 and timediff(@SystemTime) <= 30000]]]";
const UNIX_EPOCH: u64 = 116444736000000000;
const TICKS_PER_SECOND: u64 = 10000000;

pub(crate) fn normalize_id(value: &str) -> Option<String> {
    let value = value
        .strip_prefix('{')
        .and_then(|v| v.strip_suffix('}'))
        .unwrap_or(value);
    let compact = if value.len() == 36 {
        if [8, 13, 18, 23]
            .into_iter()
            .any(|i| value.as_bytes()[i] != b'-')
        {
            return None;
        }
        value.replace('-', "")
    } else {
        value.into()
    };
    (compact.len() == 32
        && compact.bytes().all(|b| b.is_ascii_hexdigit())
        && compact.bytes().any(|b| b != b'0'))
    .then(|| compact.to_ascii_lowercase())
}
pub(crate) fn interface_id(luid: &NET_LUID_LH) -> Option<String> {
    let mut id = GUID::default();
    if unsafe { ConvertInterfaceLuidToGuid(luid, &mut id) } != 0 {
        return None;
    }
    normalize_id(&format!(
        "{:08x}{:04x}{:04x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        id.data1,
        id.data2,
        id.data3,
        id.data4[0],
        id.data4[1],
        id.data4[2],
        id.data4[3],
        id.data4[4],
        id.data4[5],
        id.data4[6],
        id.data4[7]
    ))
}
fn routed_scope(adapters: &Value) -> Result<BTreeSet<String>> {
    let mut scope = BTreeSet::new();
    for adapter in adapters.as_array().context("Adapter list missing")? {
        if adapter["if_type"] != 71 || adapter["up"] != true {
            continue;
        }
        let routed = adapter["gateways"].as_array().is_some_and(|gateways| {
            gateways.iter().any(|gateway| {
                gateway
                    .as_str()
                    .is_some_and(|address| !["0.0.0.0", "::"].contains(&address))
            })
        });
        if routed {
            let id = adapter["id"]
                .as_str()
                .and_then(normalize_id)
                .context("Routed Wi-Fi interface identity unavailable")?;
            scope.insert(id);
        }
    }
    ensure!(scope.len() <= 16, "Too many routed Wi-Fi interfaces");
    Ok(scope)
}
struct EventHandle(EVT_HANDLE);
impl EventHandle {
    fn new(handle: EVT_HANDLE) -> Result<Self> {
        ensure!(
            handle != 0,
            "Read WLAN event log: {}",
            std::io::Error::last_os_error()
        );
        Ok(Self(handle))
    }
}
impl Drop for EventHandle {
    fn drop(&mut self) {
        unsafe {
            EvtClose(self.0);
        }
    }
}
fn render(event: &EventHandle) -> Result<String> {
    let mut bytes = 0;
    let mut count = 0;
    let first = unsafe {
        EvtRender(
            0,
            event.0,
            EvtRenderEventXml,
            0,
            null_mut(),
            &mut bytes,
            &mut count,
        )
    };
    ensure!(
        first == 0 && unsafe { GetLastError() } == ERROR_INSUFFICIENT_BUFFER,
        "WLAN event XML size unavailable"
    );
    ensure!(
        (2..=65536).contains(&bytes) && bytes % 2 == 0,
        "WLAN event XML exceeds budget"
    );
    let mut buffer = vec![0u16; bytes as usize / 2];
    ensure!(
        unsafe {
            EvtRender(
                0,
                event.0,
                EvtRenderEventXml,
                bytes,
                buffer.as_mut_ptr().cast(),
                &mut bytes,
                &mut count,
            )
        } != 0,
        "Render WLAN event: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        bytes as usize <= buffer.len() * 2 && bytes % 2 == 0,
        "Invalid WLAN event XML size"
    );
    buffer.truncate(bytes as usize / 2);
    if buffer.last() == Some(&0) {
        buffer.pop();
    }
    Ok(String::from_utf16(&buffer)?)
}
fn filetime(text: &str) -> Option<u64> {
    if !text.is_ascii() || !text.ends_with('Z') {
        return None;
    }
    let text = &text[..text.len() - 1];
    let (time, fraction) = text.split_once('.').unwrap_or((text, ""));
    if time.len() != 19
        || fraction.len() > 7
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || time.as_bytes()[4] != b'-'
        || time.as_bytes()[7] != b'-'
        || time.as_bytes()[10] != b'T'
        || time.as_bytes()[13] != b':'
        || time.as_bytes()[16] != b':'
    {
        return None;
    }
    let number = |range: std::ops::Range<usize>| time.get(range)?.parse::<u16>().ok();
    let value = SYSTEMTIME {
        wYear: number(0..4)?,
        wMonth: number(5..7)?,
        wDay: number(8..10)?,
        wHour: number(11..13)?,
        wMinute: number(14..16)?,
        wSecond: number(17..19)?,
        wDayOfWeek: 0,
        wMilliseconds: 0,
    };
    let mut result = FILETIME::default();
    if unsafe { SystemTimeToFileTime(&value, &mut result) } == 0 {
        return None;
    }
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u64>().ok()? * 10u64.pow(7 - fraction.len() as u32)
    };
    (u64::from(result.dwHighDateTime) << 32 | u64::from(result.dwLowDateTime)).checked_add(fraction)
}
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Disconnect {
    at: u64,
    sequence: u64,
}
fn disconnect(xml: &str, scope: &BTreeSet<String>, now: u64) -> Option<Disconnect> {
    let document = roxmltree::Document::parse(xml).ok()?;
    let event = document.root_element();
    if !event.has_tag_name("Event") {
        return None;
    }
    let system = event.children().find(|node| node.has_tag_name("System"))?;
    let child = |name| system.children().find(|node| node.has_tag_name(name));
    if child("EventID")?.text()? != "8003"
        || child("Provider")?.attribute("Name")? != PROVIDER
        || child("Channel")?.text()? != CHANNEL
    {
        return None;
    }
    let at = filetime(child("TimeCreated")?.attribute("SystemTime")?)?;
    if at < UNIX_EPOCH || at > now || now - at > 30 * TICKS_PER_SECOND {
        return None;
    }
    let sequence = child("EventRecordID")?.text()?.parse::<u64>().ok()?;
    if sequence == 0 {
        return None;
    }
    let data = event
        .children()
        .find(|node| node.has_tag_name("EventData"))?;
    let mut ids = data.children().filter(|node| {
        node.has_tag_name("Data")
            && node
                .attribute("Name")
                .is_some_and(|name| name.eq_ignore_ascii_case("InterfaceGuid"))
    });
    let id = normalize_id(ids.next()?.text()?)?;
    if ids.next().is_some() || !scope.contains(&id) {
        return None;
    }
    Some(Disconnect { at, sequence })
}
fn query(scope: &BTreeSet<String>) -> Result<Value> {
    if scope.is_empty() {
        return Ok(
            json!({"known":true,"last_disconnect_unix":null,"sequence":0,"events_checked":0,"truncated":false}),
        );
    }
    let channel = wide(CHANNEL)?;
    let filter = wide(QUERY)?;
    let query = EventHandle::new(unsafe {
        EvtQuery(
            0,
            channel.as_ptr(),
            filter.as_ptr(),
            EvtQueryChannelPath | EvtQueryReverseDirection,
        )
    })?;
    let now = crate::time_filetime();
    let end = Instant::now() + Duration::from_secs(2);
    let mut checked = 0;
    let mut last = None;
    let mut exhausted = false;
    while checked < 64 && Instant::now() < end {
        let mut raw = 0;
        let mut count = 0;
        if unsafe { EvtNext(query.0, 1, &mut raw, 100, 0, &mut count) } == 0 {
            let error = unsafe { GetLastError() };
            ensure!(
                error == ERROR_NO_MORE_ITEMS,
                "Read WLAN events: Windows error {error}"
            );
            exhausted = true;
            break;
        }
        let event = EventHandle::new(raw)?;
        ensure!(count == 1, "Invalid WLAN event count");
        checked += 1;
        if let Some(event) = disconnect(&render(&event)?, scope, now) {
            if last.as_ref().is_none_or(|prior| event > *prior) {
                last = Some(event);
            }
        }
    }
    Ok(
        json!({"known":true,"last_disconnect_unix":last.as_ref().map(|event| (event.at-UNIX_EPOCH)/TICKS_PER_SECOND),"sequence":last.as_ref().map_or(0,|event|event.sequence),"events_checked":checked,"truncated":!exhausted}),
    )
}
pub(crate) fn for_adapters(adapters: &Value) -> Value {
    let result = routed_scope(adapters).and_then(|scope| query(&scope));
    result.unwrap_or_else(|error| json!({"known":false,"last_disconnect_unix":null,"sequence":0,"error":error.to_string()}))
}
pub(crate) fn events(args: &Value) -> Result<Value> {
    let Some(values) = args.get("interface_ids") else {
        return Ok(for_adapters(&crate::system::adapters()?));
    };
    let values = values
        .as_array()
        .context("interface_ids must be an array")?;
    ensure!(
        values.len() <= 16,
        "At most 16 Wi-Fi interface identities are allowed"
    );
    let scope = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .and_then(normalize_id)
                .context("Invalid Wi-Fi interface identity")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    Ok(query(&scope).unwrap_or_else(|error| json!({"known":false,"last_disconnect_unix":null,"sequence":0,"error":error.to_string()})))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(id: &str, at: &str) -> String {
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='{PROVIDER}'/><EventID>8003</EventID><TimeCreated SystemTime='{at}'/><EventRecordID>42</EventRecordID><Channel>{CHANNEL}</Channel></System><EventData><Data Name='InterfaceGuid'>{id}</Data><Data Name='SSID'>private fixture</Data></EventData></Event>"
        )
    }
    #[test]
    fn wlan_events_require_exact_adapter_id_type_provider_and_recent_time() {
        let id = "11111111111111111111111111111111";
        let scope = BTreeSet::from([id.into()]);
        let now = filetime("2026-11-11T01:00:00Z").unwrap();
        let xml = event(
            "{11111111-1111-1111-1111-111111111111}",
            "2026-11-11T00:59:59.1234567Z",
        );
        assert_eq!(disconnect(&xml, &scope, now).unwrap().sequence, 42);
        assert!(disconnect(&xml, &BTreeSet::new(), now).is_none());
        for bad in [
            xml.replace("8003", "8001"),
            xml.replace(PROVIDER, "another-provider"),
            event(id, "2026-11-11T00:59:29Z"),
            event(id, "2026-11-11T01:00:01Z"),
            xml.replace("<Data Name='SSID'>", "<Data Name='InterfaceGuid'>"),
        ] {
            assert!(disconnect(&bad, &scope, now).is_none(), "{bad}");
        }
    }
    #[test]
    fn wlan_scope_requires_routed_wifi_and_strict_nonzero_guid() {
        assert!(normalize_id("00000000-0000-0000-0000-000000000000").is_none());
        assert!(normalize_id("1-1111111111111111111111111111111").is_none());
        let id = "abcdefabcdefabcdefabcdefabcdefab";
        let adapters = json!([
            {"id":id,"if_type":71,"up":true,"gateways":["192.168.1.1"]},
            {"id":"22222222222222222222222222222222","if_type":71,"up":true,"gateways":[]},
            {"id":"33333333333333333333333333333333","if_type":6,"up":true,"gateways":["192.168.1.1"]}
        ]);
        assert_eq!(
            routed_scope(&adapters).unwrap(),
            BTreeSet::from([id.into()])
        );
        assert_eq!(
            query(&BTreeSet::new()).unwrap()["last_disconnect_unix"],
            Value::Null
        );
    }
}
