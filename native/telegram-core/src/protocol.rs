use aes::Aes256;
use anyhow::{Context, Result, bail, ensure};
use bytes::{Buf, Bytes};
use ctr::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) type AesCtr = ctr::Ctr128BE<Aes256>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tag {
    Abridged,
    Intermediate,
    Padded,
}
pub(crate) struct Handshake {
    pub dc: u16,
    pub media: bool,
    pub test: bool,
    pub tag: Tag,
    pub decrypt: AesCtr,
    pub encrypt: AesCtr,
}
pub(crate) fn authenticate(
    wire: &[u8; 64],
    secret: &[u8; 16],
    force_test: bool,
) -> Result<Handshake> {
    let mut decrypt = secret_cipher(&wire[8..56], secret);
    let mut plain = *wire;
    decrypt.apply_keystream(&mut plain);
    let tag = match &plain[56..60] {
        [0xef, 0xef, 0xef, 0xef] => Tag::Abridged,
        [0xee, 0xee, 0xee, 0xee] => Tag::Intermediate,
        [0xdd, 0xdd, 0xdd, 0xdd] => Tag::Padded,
        _ => bail!("invalid MTProto authentication"),
    };
    let dc_index = i16::from_le_bytes([plain[60], plain[61]]);
    let mut dc = dc_index.unsigned_abs();
    let test = force_test || dc >= 10000;
    if dc >= 10000 {
        dc -= 10000;
    }
    ensure!(
        crate::config::supported_dc(dc, test),
        "unsupported Telegram DC"
    );
    let mut reverse = wire[8..56].to_vec();
    reverse.reverse();
    Ok(Handshake {
        dc,
        media: dc_index < 0,
        test,
        tag,
        decrypt,
        encrypt: secret_cipher(&reverse, secret),
    })
}
pub(crate) fn secret_cipher(prekey_iv: &[u8], secret: &[u8; 16]) -> AesCtr {
    let mut hash = Sha256::new();
    hash.update(&prekey_iv[..32]);
    hash.update(secret);
    AesCtr::new(&hash.finalize(), prekey_iv[32..48].into())
}

pub(crate) const MAX_PACKET: usize = 4 * 1024 * 1024;
pub(crate) struct Frame {
    pub wire: Vec<u8>,
    pub header: usize,
    pub quick: bool,
}
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    cipher: &mut AesCtr,
    tag: Tag,
) -> Result<Option<Frame>> {
    let mut prefix = [0u8; 4];
    if reader.read(&mut prefix[..1]).await? == 0 {
        return Ok(None);
    }
    cipher.apply_keystream(&mut prefix[..1]);
    let header = if tag == Tag::Abridged && prefix[0] & 0x7f != 0x7f {
        1
    } else {
        4
    };
    if header == 4 {
        reader.read_exact(&mut prefix[1..]).await?;
        cipher.apply_keystream(&mut prefix[1..]);
    }
    let (length, quick) = if tag == Tag::Abridged {
        let words = if header == 1 {
            u32::from(prefix[0] & 0x7f)
        } else {
            u32::from_le_bytes([prefix[1], prefix[2], prefix[3], 0])
        };
        (words as usize * 4, prefix[0] & 0x80 != 0)
    } else {
        let value = u32::from_le_bytes(prefix);
        ((value & 0x7fff_ffff) as usize, value & 0x8000_0000 != 0)
    };
    let limit = MAX_PACKET + if tag == Tag::Padded { 256 } else { 0 };
    ensure!(
        length > 0 && length <= limit,
        "MTProto packet length exceeds supported bound"
    );
    let mut wire = vec![0u8; header + length];
    wire[..header].copy_from_slice(&prefix[..header]);
    reader.read_exact(&mut wire[header..]).await?;
    cipher.apply_keystream(&mut wire[header..]);
    Ok(Some(Frame {
        wire,
        header,
        quick,
    }))
}
pub(crate) fn http_body(frame: Frame, tag: Tag) -> Result<Bytes> {
    let body = &frame.wire[frame.header..];
    ensure!(body.len() >= 24, "HTTP MTProto request is too short");
    let length = if tag == Tag::Padded {
        let (length, max_padding) = if body[..8] == [0; 8] {
            (
                20usize
                    .checked_add(u32::from_le_bytes(body[16..20].try_into()?) as usize)
                    .context("invalid MTProto plaintext length")?,
                256,
            )
        } else {
            (24 + (body.len() - 24) / 16 * 16, 15)
        };
        ensure!(
            length >= 24 && length <= body.len() && body.len() - length <= max_padding,
            "invalid MTProto padding"
        );
        length
    } else {
        body.len()
    };
    ensure!(
        length % 4 == 0 && length <= MAX_PACKET,
        "invalid HTTP MTProto packet alignment or size"
    );
    let mut body = Bytes::from(frame.wire);
    body.advance(frame.header);
    body.truncate(length);
    Ok(body)
}
pub(crate) fn encode_reply(body: &[u8], tag: Tag) -> Result<Vec<u8>> {
    ensure!(
        !body.is_empty() && body.len() % 4 == 0 && body.len() <= MAX_PACKET,
        "invalid HTTP MTProto reply length"
    );
    let mut result = Vec::with_capacity(body.len() + 7);
    if tag == Tag::Abridged {
        let words = body.len() / 4;
        if words < 127 {
            result.push(words as u8);
        } else {
            result.push(127);
            result.extend_from_slice(&(words as u32).to_le_bytes()[..3]);
        }
        result.extend_from_slice(body);
    } else {
        let mut padding = [0u8; 4];
        let count = if tag == Tag::Padded {
            random(&mut padding)?;
            (padding[0] % 4) as usize
        } else {
            0
        };
        result.extend_from_slice(&((body.len() + count) as u32).to_le_bytes());
        result.extend_from_slice(body);
        result.extend_from_slice(&padding[..count]);
    }
    Ok(result)
}
pub(crate) fn random(bytes: &mut [u8]) -> Result<()> {
    getrandom::fill(bytes).map_err(|_| anyhow::anyhow!("operating system random source failed"))
}

pub(crate) struct Relay {
    pub init: [u8; 64],
    pub encrypt: AesCtr,
    pub decrypt: AesCtr,
}
pub(crate) fn relay(auth: &Handshake) -> Result<Relay> {
    let mut init = [0u8; 64];
    loop {
        random(&mut init)?;
        if init[0] == 0xef || init[4..8] == [0; 4] {
            continue;
        }
        if [
            *b"HEAD",
            *b"POST",
            *b"GET ",
            *b"OPTI",
            [0xee; 4],
            [0xdd; 4],
            [0x16, 3, 1, 2],
        ]
        .contains(&init[..4].try_into()?)
        {
            continue;
        }
        break;
    }
    let tag = match auth.tag {
        Tag::Abridged => 0xef,
        Tag::Intermediate => 0xee,
        Tag::Padded => 0xdd,
    };
    let mut plain = init;
    plain[56..60].fill(tag);
    let signed = if auth.media {
        -(auth.dc as i16)
    } else {
        auth.dc as i16
    };
    plain[60..62].copy_from_slice(&signed.to_le_bytes());
    let mut encrypt = AesCtr::new(init[8..40].into(), init[40..56].into());
    encrypt.apply_keystream(&mut plain);
    init[56..].copy_from_slice(&plain[56..]);
    let reverse: Vec<u8> = init[8..56].iter().rev().copied().collect();
    Ok(Relay {
        init,
        encrypt,
        decrypt: AesCtr::new(reverse[..32].into(), reverse[32..].into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    // Generated independently with Python cryptography 50.0.2's AES-CTR;
    // secret=00..0f, public prekey=08..37, signed dc=-10002.
    const INIT: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536377fb7a7ad57d05925";
    #[test]
    fn authenticates_upstream_obfuscated2_fixture() {
        let wire: [u8; 64] = bytes(INIT).try_into().unwrap();
        let secret = std::array::from_fn(|i| i as u8);
        let mut handshake = authenticate(&wire, &secret, false).unwrap();
        assert_eq!(
            (handshake.dc, handshake.media, handshake.test, handshake.tag),
            (2, true, true, Tag::Padded)
        );
        let mut ciphertext = bytes(
            "7edeccea711a0726b7284a623b5a56376617583ba70b85f53985aa36fd76df26cbac00c28c40fa4c927fa01a",
        );
        handshake.decrypt.apply_keystream(&mut ciphertext);
        assert_eq!(&ciphertext[..4], &[40, 0, 0, 128]);
        assert_eq!(&ciphertext[4..], &[b'k'; 40]);
        let mut reply = bytes("040000006cfeffff");
        handshake.encrypt.apply_keystream(&mut reply);
        assert_eq!(reply, bytes("a409d788e8b9aa1e"));
    }
    #[test]
    fn wrong_secret_and_corrupt_tag_are_rejected() {
        let mut wire: [u8; 64] = bytes(INIT).try_into().unwrap();
        assert!(authenticate(&wire, &[0xff; 16], false).is_err());
        wire[56] ^= 1;
        assert!(authenticate(&wire, &std::array::from_fn(|i| i as u8), false).is_err());
    }

    async fn frame(plain: &[u8], tag: Tag) -> Result<Frame> {
        use tokio::io::AsyncWriteExt;
        let mut encrypted = plain.to_vec();
        AesCtr::new(&[0u8; 32].into(), &[0u8; 16].into()).apply_keystream(&mut encrypted);
        let (mut sender, mut receiver) = tokio::io::duplex(64);
        let send = tokio::spawn(async move {
            for byte in encrypted {
                sender.write_all(&[byte]).await.unwrap();
            }
            sender.shutdown().await.unwrap();
        });
        let mut cipher = AesCtr::new(&[0u8; 32].into(), &[0u8; 16].into());
        let result = read_frame(&mut receiver, &mut cipher, tag).await;
        send.abort();
        let _ = send.await;
        result?.ok_or_else(|| anyhow::anyhow!("missing frame"))
    }
    #[tokio::test]
    async fn fragmented_extended_abridged_preserves_quickack_and_packet() {
        let mut wire = vec![255, 128, 0, 0];
        wire.extend([b'a'; 512]);
        let decoded = frame(&wire, Tag::Abridged).await.unwrap();
        assert!(decoded.quick);
        assert_eq!(decoded.wire, wire);
        let body_ptr = decoded.wire[decoded.header..].as_ptr();
        let body = http_body(decoded, Tag::Abridged).unwrap();
        assert_eq!(body, vec![b'a'; 512]);
        assert_eq!(body.as_ptr(), body_ptr);
    }
    #[tokio::test]
    async fn padded_plain_packets_strip_up_to_256_bytes_of_external_padding() {
        let mut body = vec![0; 8];
        body.extend([b'm'; 8]);
        body.extend(20u32.to_le_bytes());
        body.extend([b'p'; 20]);
        for padding in 0..=257 {
            let mut wire = ((body.len() + padding) as u32 | 0x80000000)
                .to_le_bytes()
                .to_vec();
            wire.extend(&body);
            wire.extend(vec![b'z'; padding]);
            let frame = frame(&wire, Tag::Padded).await.unwrap();
            assert!(frame.quick);
            let decoded = http_body(frame, Tag::Padded);
            if padding <= 256 {
                assert_eq!(decoded.unwrap(), body);
            } else {
                assert!(decoded.is_err());
            }
        }
    }
    #[tokio::test]
    async fn rejects_oversize_before_allocating_or_reading_body() {
        use tokio::io::AsyncWriteExt;
        let (mut sender, mut receiver) = tokio::io::duplex(64);
        let mut cipher = AesCtr::new(&[0u8; 32].into(), &[0u8; 16].into());
        let mut header = (MAX_PACKET as u32 + 1).to_le_bytes();
        cipher.apply_keystream(&mut header);
        sender.write_all(&header).await.unwrap();
        let mut cipher = AesCtr::new(&[0u8; 32].into(), &[0u8; 16].into());
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            read_frame(&mut receiver, &mut cipher, Tag::Intermediate),
        )
        .await
        .unwrap();
        assert!(result.is_err());
    }
    #[test]
    fn transport_error_replies_keep_the_selected_native_framing() {
        let body = (-404i32).to_le_bytes();
        assert_eq!(
            encode_reply(&body, Tag::Abridged).unwrap(),
            vec![1, 108, 254, 255, 255]
        );
        assert_eq!(
            encode_reply(&body, Tag::Intermediate).unwrap(),
            vec![4, 0, 0, 0, 108, 254, 255, 255]
        );
        let padded = encode_reply(&body, Tag::Padded).unwrap();
        assert_eq!(
            u32::from_le_bytes(padded[..4].try_into().unwrap()) as usize,
            padded.len() - 4
        );
        assert_eq!(&padded[4..8], &body);
        assert!(padded.len() <= 11);
    }
}
