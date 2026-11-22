//! Ordered payload detection, including the engine's existing disable filters.
use super::{
    names::l7_payload_match,
    tls::{IsTLSClientHelloPartial, IsTLSServerHelloPartial},
    *,
};

pub(crate) const UNKNOWN: u32 = 1;
pub(crate) const HTTP_REQUEST: u32 = 7;
pub(crate) const TLS_CLIENT_HELLO: u32 = 9;
pub(crate) const TLS_SERVER_HELLO: u32 = 10;
pub(crate) const QUIC_INITIAL: u32 = 13;
pub(crate) const DNS_RESPONSE: u32 = 27;

const HTTP: u32 = 3;
const TLS: u32 = 4;
const DTLS: u32 = 5;
const QUIC: u32 = 6;
const WIREGUARD: u32 = 7;
const DHT: u32 = 8;
const DISCORD: u32 = 9;
const STUN: u32 = 10;
const XMPP: u32 = 11;
const DNS: u32 = 12;
const MTPROTO: u32 = 13;
const BITTORRENT: u32 = 14;
const UTP_BITTORRENT: u32 = 15;

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct Probe {
    payload: u32,
    protocol: u32,
    check: unsafe extern "C" fn(*const u8, usize) -> bool,
    same_protocol: bool,
}

const fn detect(
    payload: u32,
    protocol: u32,
    check: unsafe extern "C" fn(*const u8, usize) -> bool,
) -> Probe {
    Probe {
        payload,
        protocol,
        check,
        same_protocol: false,
    }
}

pub(crate) const TCP_CLIENT: &[Probe] = &[
    detect(TLS_CLIENT_HELLO, TLS, IsTLSClientHelloPartial),
    detect(HTTP_REQUEST, HTTP, IsHttp),
    detect(22, XMPP, IsXMPPStream),
    detect(23, XMPP, IsXMPPStartTLS),
    detect(29, BITTORRENT, IsBTHandshake),
];
pub(crate) const TCP_SERVER: &[Probe] = &[
    detect(TLS_SERVER_HELLO, TLS, IsTLSServerHelloPartial),
    detect(8, HTTP, IsHttpReply),
    detect(22, XMPP, IsXMPPStream),
    detect(24, XMPP, IsXMPPProceedTLS),
    detect(25, XMPP, IsXMPPFeatures),
    detect(29, BITTORRENT, IsBTHandshake),
];
pub(crate) const TCP_FIRST: &[Probe] = &[detect(28, MTPROTO, IsMTProto)];
pub(crate) const UDP: &[Probe] = &[
    detect(QUIC_INITIAL, QUIC, IsQUICInitial),
    detect(20, DISCORD, IsDiscordIpDiscoveryRequest),
    detect(21, STUN, IsStunMessage),
    detect(26, DNS, IsDNSQuery),
    detect(DNS_RESPONSE, DNS, IsDNSResponse),
    detect(19, DHT, IsDht),
    detect(11, DTLS, IsDTLSClientHello),
    detect(12, DTLS, IsDTLSServerHello),
    detect(30, UTP_BITTORRENT, IsUTP_BTHandshake),
    detect(14, WIREGUARD, IsWireguardHandshakeInitiation),
    detect(15, WIREGUARD, IsWireguardHandshakeResponse),
    detect(16, WIREGUARD, IsWireguardHandshakeCookie),
    detect(17, WIREGUARD, IsWireguardKeepalive),
    Probe {
        same_protocol: true,
        ..detect(18, WIREGUARD, IsWireguardData)
    },
];

#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn probe_payload(
    probes: *const Probe,
    count: i32,
    data: *const u8,
    length: usize,
    tracked_protocol: *mut u32,
    protocol: *mut u32,
    payload: *mut u32,
    disabled: u64,
) -> bool {
    if disabled == 0 {
        return false;
    }
    for index in 0..count {
        // Do not retain references over detector callbacks. The C API
        // also permits the output fields to alias one another or the tracker.
        let probe = unsafe { probes.add(index as usize).read() };
        if l7_payload_match(probe.payload, disabled)
            || probe.same_protocol && unsafe { protocol.read() } != probe.protocol
            || !unsafe { (probe.check)(data, length) }
        {
            continue;
        }
        unsafe { payload.write(probe.payload) };
        if unsafe { protocol.read() } == UNKNOWN {
            unsafe { protocol.write(probe.protocol) };
            if !tracked_protocol.is_null() && unsafe { tracked_protocol.read() } == UNKNOWN {
                unsafe { tracked_protocol.write(protocol.read()) };
            }
        }
        return true;
    }
    false
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zapret_protocol_probe(
    probes: *const Probe,
    count: i32,
    data: *const u8,
    length: usize,
    tracked_protocol: *mut u32,
    protocol: *mut u32,
    payload: *mut u32,
    disabled: u64,
    report: Option<unsafe extern "C" fn(u32)>,
) {
    let matched = unsafe {
        probe_payload(
            probes,
            count,
            data,
            length,
            tracked_protocol,
            protocol,
            payload,
            disabled,
        )
    };
    if let (true, Some(report)) = (matched, report) {
        unsafe { report(payload.read()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    unsafe extern "C" fn yes(_: *const u8, _: usize) -> bool {
        true
    }

    #[test]
    fn empty_table_and_disabled_entries_do_not_access_outputs() {
        for count in [0, -1, i32::MIN] {
            unsafe {
                zapret_protocol_probe(
                    ptr::null(),
                    count,
                    ptr::null(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    1,
                    None,
                )
            };
        }
        let probe = Probe {
            payload: 7,
            protocol: 3,
            check: yes,
            same_protocol: true,
        };
        // A zero filter means "all" in the existing engine API.
        unsafe {
            zapret_protocol_probe(
                &probe,
                1,
                ptr::null(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                None,
            )
        };
    }

    #[test]
    fn aliased_outputs_follow_c_assignment_order() {
        let probe = Probe {
            payload: 7,
            protocol: 3,
            check: yes,
            same_protocol: false,
        };
        let mut result = UNKNOWN;
        let mut tracked = UNKNOWN;
        let output = ptr::from_mut(&mut result);
        unsafe {
            zapret_protocol_probe(
                &probe,
                1,
                ptr::null(),
                0,
                &mut tracked,
                output,
                output,
                1,
                None,
            )
        };
        assert_eq!((result, tracked), (7, UNKNOWN));
    }
}
