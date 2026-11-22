//! Application protocol parsing through the pinned engine's C ABI.
#![allow(non_snake_case)]

mod detect;
pub(super) mod http;
mod names;
mod positions;
pub(super) mod probe;
pub(super) mod quic;
pub(super) mod tls;
mod tls_mod;
mod wire;

pub(super) use http::HttpReplyLooksLikeDPIRedirect;
pub(super) use names::{l7_payload_match, l7_proto_match, l7payload_str, l7proto_str};
pub(super) use wire::bytes;
use wire::{be16, be24, copy_lower};

macro_rules! detectors {
    ($($name:ident => $predicate:path),* $(,)?) => {
        $(
            #[unsafe(no_mangle)]
            unsafe extern "C" fn $name(data: *const u8, length: usize) -> bool {
                $predicate(unsafe { bytes(data, length) })
            }
        )*
    };
}

detectors! {
    IsHttp => http::request,
    IsHttpReply => http::reply,
    IsQUICInitial => quic::initial,
    QUICIsLongHeader => quic::long_header,
    IsXMPPStream => detect::xmpp_stream,
    IsXMPPStartTLS => detect::xmpp_starttls,
    IsXMPPProceedTLS => detect::xmpp_proceed,
    IsXMPPFeatures => detect::xmpp_features,
    IsDNSQuery => detect::dns_query,
    IsDNSResponse => detect::dns_response,
    IsWireguardHandshakeInitiation => detect::wireguard_initiation,
    IsWireguardHandshakeResponse => detect::wireguard_response,
    IsWireguardHandshakeCookie => detect::wireguard_cookie,
    IsWireguardKeepalive => detect::wireguard_keepalive,
    IsWireguardData => detect::wireguard_data,
    IsDht => detect::dht,
    IsDiscordIpDiscoveryRequest => detect::discord_discovery,
    IsStunMessage => detect::stun,
    IsMTProto => detect::mtproto,
    IsDTLS => detect::dtls,
    IsDTLSClientHello => detect::dtls_client,
    IsDTLSServerHello => detect::dtls_server,
    IsBTHandshake => detect::bittorrent,
    IsUTP_BTHandshake => detect::utp_bittorrent,
}
