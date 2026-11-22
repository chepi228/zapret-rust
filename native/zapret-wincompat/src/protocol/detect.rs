use super::be16;
use aes::{
    Aes256,
    cipher::{BlockEncrypt, KeyInit},
};

pub(super) fn xmpp_stream(data: &[u8]) -> bool {
    (data.len() >= 16 && data.starts_with(b"<stream:stream "))
        || (data.len() >= 36
            && data.starts_with(b"<?xml ")
            && data[21..]
                .windows(15)
                .any(|part| part == b"<stream:stream "))
}

pub(super) fn xmpp_starttls(data: &[u8]) -> bool {
    data.starts_with(b"<starttls ")
}

pub(super) fn xmpp_proceed(data: &[u8]) -> bool {
    data.starts_with(b"<proceed ")
}

pub(super) fn xmpp_features(data: &[u8]) -> bool {
    data.len() >= 17 && data.starts_with(b"<stream:features")
}

pub(super) fn dns_query(data: &[u8]) -> bool {
    data.len() >= 12
        && data[2] & 0xfe == 0
        && data[4..10] == [0, 1, 0, 0, 0, 0]
        && be16(data, 10) <= Some(3)
}

pub(super) fn dns_response(data: &[u8]) -> bool {
    data.len() >= 12
        && data[2] & 0xf8 == 0x80
        && be16(data, 4) == Some(1)
        && be16(data, 6) <= Some(100)
        && be16(data, 8) <= Some(100)
        && be16(data, 10) <= Some(100)
}

pub(super) fn wireguard_initiation(data: &[u8]) -> bool {
    data.len() == 148 && data.starts_with(&[1, 0, 0, 0])
}

pub(super) fn wireguard_response(data: &[u8]) -> bool {
    data.len() == 92 && data.starts_with(&[2, 0, 0, 0])
}

pub(super) fn wireguard_cookie(data: &[u8]) -> bool {
    data.len() == 64 && data.starts_with(&[3, 0, 0, 0])
}

pub(super) fn wireguard_keepalive(data: &[u8]) -> bool {
    data.len() == 32 && data.starts_with(&[4, 0, 0, 0])
}

pub(super) fn wireguard_data(data: &[u8]) -> bool {
    data.len() >= 52 && data.starts_with(&[4, 0, 0, 0])
}

pub(super) fn dht(data: &[u8]) -> bool {
    data.len() >= 5
        && data[0] == b'd'
        && data[2] == b':'
        && data.last() == Some(&b'e')
        && matches!(
            (data[1], data[3], data[4]),
            (b'1', b'a', b'd') | (b'1', b'r', b'd') | (b'2', b'i', b'p') | (b'1', b'e', b'l')
        )
}

pub(super) fn discord_discovery(data: &[u8]) -> bool {
    data.len() == 74
        && data.starts_with(&[0, 1, 0, 70])
        && data[8..72].iter().all(|byte| *byte == 0)
}

pub(super) fn stun(data: &[u8]) -> bool {
    data.len() >= 20
        && data[0] & 0xc0 == 0
        && data[3] & 3 == 0
        && data[4..8] == [0x21, 0x12, 0xa4, 0x42]
        && be16(data, 2) <= Some(data.len() - 20)
}

pub(super) fn mtproto(data: &[u8]) -> bool {
    if data.len() < 64 {
        return false;
    }
    let cipher = Aes256::new(aes::cipher::Key::<Aes256>::from_slice(&data[8..40]));
    let mut counter = aes::cipher::Block::<Aes256>::clone_from_slice(&data[40..56]);
    let mut carry = 3u16;
    for byte in counter.iter_mut().rev() {
        carry += u16::from(*byte);
        *byte = carry as u8;
        carry >>= 8;
    }
    cipher.encrypt_block(&mut counter);
    counter[8..12]
        .iter()
        .zip(&data[56..60])
        .all(|(key, value)| key ^ value == 0xef)
}

pub(super) fn dtls(data: &[u8]) -> bool {
    data.len() > 13
        && (0x14..=0x17).contains(&data[0])
        && matches!((data[1], data[2]), (0xfe, 0xff | 0xfd | 0xfc) | (1, 0))
        && be16(data, 11).is_some_and(|length| length + 13 <= data.len())
}

pub(super) fn dtls_client(data: &[u8]) -> bool {
    dtls(data) && data[0] == 0x16 && data[13] == 1
}

pub(super) fn dtls_server(data: &[u8]) -> bool {
    dtls(data) && data[0] == 0x16 && data[13] == 2
}

pub(super) fn bittorrent(data: &[u8]) -> bool {
    data.len() >= 68 && data.starts_with(b"\x13BitTorrent protocol")
}

pub(super) fn utp_bittorrent(data: &[u8]) -> bool {
    data.len() >= 88 && data[0] == 1 && data[20..].starts_with(b"\x13BitTorrent protocol")
}
