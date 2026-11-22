//! Client Initial decryption. Publish plaintext only after authentication succeeds.
use super::{QUICDraftVersion, variable, version, version_two};
use ring::{aead, hkdf};
use std::{mem::MaybeUninit, ptr, slice, sync::OnceLock};

const HEADER_LIMIT: usize = 2048;
const PLAINTEXT_LIMIT: usize = 65535;
const SALT_BYTES: [[u8; 20]; 8] = [
    [
        0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a, 0x96, 0xcd, 0x21, 0x51, 0x9e,
        0xbd, 0x7a, 0x02, 0x64, 0x4a,
    ],
    [
        0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63,
        0x65, 0xbe, 0xf9, 0xf5, 0x02,
    ],
    [
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11,
        0xe0, 0x43, 0x90, 0xa8, 0x99,
    ],
    [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ],
    [
        0x50, 0x45, 0x74, 0xef, 0xd0, 0x66, 0xfe, 0x2f, 0x9d, 0x94, 0x5c, 0xfc, 0xdb, 0xd3, 0xa7,
        0xf0, 0xd3, 0xb5, 0x6b, 0x45,
    ],
    [
        0x7f, 0xf5, 0x79, 0xe5, 0xac, 0xd0, 0x72, 0x91, 0x55, 0x80, 0x30, 0x4c, 0x43, 0xa2, 0x36,
        0x7c, 0x60, 0x48, 0x83, 0x10,
    ],
    [
        0x7a, 0x4e, 0xde, 0xf4, 0xe7, 0xcc, 0xee, 0x5f, 0xa4, 0x50, 0x6c, 0x19, 0x12, 0x4f, 0xc8,
        0xcc, 0xda, 0x6e, 0x03, 0x3d,
    ],
    [
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
        0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
    ],
];
static SALTS: [OnceLock<hkdf::Salt>; 8] = [const { OnceLock::new() }; 8];

fn salt_index(version: u32) -> usize {
    match version {
        0x51303530 => 4,
        0x54303530 => 5,
        0x54303531 => 6,
        version => match QUICDraftVersion(version) {
            1..=22 => 0,
            23..=28 => 1,
            29..=32 => 2,
            33..=34 => 3,
            _ => 7,
        },
    }
}

struct Length(usize);
impl hkdf::KeyType for Length {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand<const N: usize>(secret: &hkdf::Prk, label: &[u8]) -> Option<[u8; N]> {
    let mut encoded = [0; 64];
    let size = label.len().checked_add(4)?;
    if size > encoded.len() || N > u16::MAX as usize {
        return None;
    }
    encoded[..2].copy_from_slice(&(N as u16).to_be_bytes());
    encoded[2] = label.len() as u8;
    encoded[3..3 + label.len()].copy_from_slice(label);
    let info = [&encoded[..size]];
    let mut output = [0; N];
    secret
        .expand(&info, Length(N))
        .ok()?
        .fill(&mut output)
        .ok()?;
    Some(output)
}

struct Keys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn keys(version: u32, dcid: &[u8]) -> Option<Keys> {
    let index = salt_index(version);
    let salt = SALTS[index].get_or_init(|| hkdf::Salt::new(hkdf::HKDF_SHA256, &SALT_BYTES[index]));
    let initial = salt.extract(dcid);
    let client: [u8; 32] = expand(&initial, b"tls13 client in")?;
    let client = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client);
    let (key, iv, hp) = if version_two(version) {
        (
            b"tls13 quicv2 key".as_slice(),
            b"tls13 quicv2 iv".as_slice(),
            b"tls13 quicv2 hp".as_slice(),
        )
    } else {
        (
            b"tls13 quic key".as_slice(),
            b"tls13 quic iv".as_slice(),
            b"tls13 quic hp".as_slice(),
        )
    };
    Some(Keys {
        key: expand(&client, key)?,
        iv: expand(&client, iv)?,
        hp: expand(&client, hp)?,
    })
}

struct Packet<'a> {
    data: &'a [u8],
    dcid: &'a [u8],
    version: u32,
    number_offset: usize,
}

fn packet(data: &[u8]) -> Option<Packet<'_>> {
    let version = version(data);
    if version == 0 || data[0] & 0xf0 != if version_two(version) { 0xd0 } else { 0xc0 } {
        return None;
    }
    let dcid_length = usize::from(*data.get(5)?);
    if !(1..=20).contains(&dcid_length) {
        return None;
    }
    let dcid = data.get(6..6 + dcid_length)?;
    let mut cursor = 6 + dcid_length;
    let scid_length = usize::from(*data.get(cursor)?);
    if scid_length > 20 {
        return None;
    }
    cursor += 1 + scid_length;
    let token = usize::try_from(variable(data, &mut cursor)?).ok()?;
    cursor = cursor.checked_add(token)?;
    let payload = usize::try_from(variable(data, &mut cursor)?).ok()?;
    if payload < 20 || cursor.checked_add(1)? > HEADER_LIMIT {
        return None;
    }
    let end = cursor.checked_add(payload)?;
    Some(Packet {
        data: data.get(..end)?,
        dcid,
        version,
        number_offset: cursor,
    })
}

pub(crate) fn decrypt(
    data: &[u8],
    scratch: &mut [MaybeUninit<u8>],
    capacity: usize,
) -> Option<usize> {
    let packet = packet(data)?;
    let material = keys(packet.version, packet.dcid)?;
    let protection =
        aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &material.hp).ok()?;
    let offset = packet.number_offset;
    let mask = protection
        .new_mask(packet.data.get(offset + 4..offset + 20)?)
        .ok()?;
    let first = packet.data[0] ^ (mask[0] & 15);
    if first & 12 != 0 {
        return None;
    }
    let number_length = usize::from((first & 3) + 1);
    let header_length = offset + number_length;
    if header_length > HEADER_LIMIT {
        return None;
    }
    let tag_offset = packet.data.len().checked_sub(16)?;
    let ciphertext = packet.data.get(header_length..tag_offset)?;
    if ciphertext.len() > capacity || ciphertext.len() > scratch.len() {
        return None;
    }

    let mut header = MaybeUninit::<[u8; HEADER_LIMIT]>::uninit();
    unsafe {
        ptr::copy_nonoverlapping(
            packet.data.as_ptr(),
            header.as_mut_ptr().cast::<u8>(),
            header_length,
        );
    }
    // Only the copied header prefix is initialized and exposed to Rust/AEAD.
    let header =
        unsafe { slice::from_raw_parts_mut(header.as_mut_ptr().cast::<u8>(), header_length) };
    header[0] = first;
    let mut number = [0; 4];
    for i in 0..number_length {
        let byte = packet.data[offset + i] ^ mask[1 + i];
        header[offset + i] = byte;
        number[4 - number_length + i] = byte;
    }
    let mut nonce = material.iv;
    for (target, value) in nonce[8..].iter_mut().zip(number) {
        *target ^= value;
    }
    let tag = aead::Tag::try_from(&packet.data[tag_offset..]).ok()?;
    let key =
        aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &material.key).ok()?);
    unsafe {
        ptr::copy_nonoverlapping(
            ciphertext.as_ptr(),
            scratch.as_mut_ptr().cast::<u8>(),
            ciphertext.len(),
        );
    }
    let plaintext =
        unsafe { slice::from_raw_parts_mut(scratch.as_mut_ptr().cast::<u8>(), ciphertext.len()) };
    key.open_in_place_separate_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(header),
        tag,
        plaintext,
        0..,
    )
    .ok()?;
    Some(plaintext.len())
}

#[unsafe(no_mangle)]
unsafe extern "C" fn QUICDecryptInitial(
    data: *const u8,
    length: usize,
    clean: *mut u8,
    clean_length: *mut usize,
) -> bool {
    if data.is_null() || length > isize::MAX as usize || clean_length.is_null() {
        return false;
    }
    let capacity = unsafe { *clean_length };
    if clean.is_null() && capacity != 0 {
        return false;
    }
    let mut scratch = [MaybeUninit::uninit(); PLAINTEXT_LIMIT];
    let data = unsafe { slice::from_raw_parts(data, length) };
    let Some(size) = decrypt(data, &mut scratch, capacity) else {
        return false;
    };
    if size != 0 {
        if clean.is_null() {
            return false;
        }
        unsafe {
            ptr::copy_nonoverlapping(scratch.as_ptr().cast::<u8>(), clean, size);
        }
    }
    unsafe {
        *clean_length = size;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(text: &str) -> Vec<u8> {
        let digits: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        (0..digits.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).unwrap())
            .collect()
    }
    fn fixture(version: u32) -> Vec<u8> {
        hex(if version == 1 {
            include_str!("../../../fixtures/quic/rfc9001-client.hex")
        } else {
            include_str!("../../../fixtures/quic/rfc9369-client.hex")
        })
    }
    #[test]
    fn rfc_client_initials_decrypt_to_the_independent_expected_plaintext() {
        let mut expected = hex(include_str!("../../../fixtures/quic/client-crypto.hex"));
        expected.resize(1162, 0);
        for version in [1, 0x6b3343cf] {
            let packet = fixture(version);
            let mut output = [0xa5; 1200];
            let mut length = output.len();
            assert!(unsafe {
                QUICDecryptInitial(
                    packet.as_ptr(),
                    packet.len(),
                    output.as_mut_ptr(),
                    &mut length,
                )
            });
            assert_eq!(length, expected.len());
            assert_eq!(&output[..length], expected);
            assert!(output[length..].iter().all(|&byte| byte == 0xa5));
        }
    }
    #[test]
    fn corrupted_tags_and_ciphertext_leave_output_and_capacity_unchanged() {
        for version in [1, 0x6b3343cf] {
            let original = fixture(version);
            for at in 0..original.len() {
                let mut packet = original.clone();
                packet[at] ^= 1;
                let mut output = [0xa5; 1200];
                let mut length = output.len();
                assert!(!unsafe {
                    QUICDecryptInitial(
                        packet.as_ptr(),
                        packet.len(),
                        output.as_mut_ptr(),
                        &mut length,
                    )
                });
                assert_eq!(length, 1200);
                assert_eq!(output, [0xa5; 1200]);
            }
        }
    }
    #[test]
    fn every_truncation_and_small_output_capacity_fails_without_writing() {
        let packet = fixture(1);
        for cut in 0..packet.len() {
            let mut output = [0xa5; 1200];
            let mut length = output.len();
            assert!(!unsafe {
                QUICDecryptInitial(packet.as_ptr(), cut, output.as_mut_ptr(), &mut length)
            });
            assert_eq!(length, 1200);
            assert_eq!(output, [0xa5; 1200]);
        }
        for capacity in [0, 1, 1161] {
            let mut output = [0xa5; 1200];
            let mut length = capacity;
            assert!(!unsafe {
                QUICDecryptInitial(
                    packet.as_ptr(),
                    packet.len(),
                    output.as_mut_ptr(),
                    &mut length,
                )
            });
            assert_eq!(length, capacity);
            assert_eq!(output, [0xa5; 1200]);
        }
    }
    #[test]
    fn coalesced_input_and_aliased_output_publish_only_the_first_plaintext() {
        let mut packet = fixture(1);
        let original = packet.len();
        packet.extend(fixture(0x6b3343cf));
        let mut length = packet.len();
        assert!(unsafe {
            QUICDecryptInitial(
                packet.as_ptr(),
                packet.len(),
                packet.as_mut_ptr(),
                &mut length,
            )
        });
        assert_eq!(length, 1162);
        assert_eq!(&packet[original..], fixture(0x6b3343cf));
    }
    #[test]
    fn initial_keys_match_the_rfc9001_key_material() {
        let key = keys(1, &hex("8394c8f03e515708")).unwrap();
        assert_eq!(key.key.as_slice(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(key.iv.as_slice(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(key.hp.as_slice(), hex("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn malformed_varints_and_null_abi_arguments_are_rejected_without_writes() {
        for tail in [&[0xff; 8][..], &[0x40][..], &[0, 0xff, 0xff][..]] {
            let mut packet = vec![0xc0, 0, 0, 0, 1, 1, 7, 0];
            packet.extend_from_slice(tail);
            let mut output = [0xa5; 64];
            let mut length = output.len();
            assert!(!unsafe {
                QUICDecryptInitial(
                    packet.as_ptr(),
                    packet.len(),
                    output.as_mut_ptr(),
                    &mut length,
                )
            });
            assert_eq!(length, 64);
            assert_eq!(output, [0xa5; 64]);
        }
        let packet = fixture(1);
        let mut length = 1200;
        assert!(!unsafe {
            QUICDecryptInitial(std::ptr::null(), 0, std::ptr::null_mut(), &mut length)
        });
        assert!(!unsafe {
            QUICDecryptInitial(
                packet.as_ptr(),
                packet.len(),
                std::ptr::null_mut(),
                &mut length,
            )
        });
        assert!(!unsafe {
            QUICDecryptInitial(
                packet.as_ptr(),
                packet.len(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        });
    }
}
