//! Read-only probes through the running local MTProxy. The optional file transfer
//! uses an in-memory test bot session and a small public sticker, never Desktop data.
use crate::{
    Config,
    protocol::{AesCtr, secret_cipher},
};
use anyhow::{Context, Result, bail, ensure};
use ctr::cipher::StreamCipher;
use grammers_mtproto::{
    DequeBuffer, mtp,
    transport::{Error, Transport, UnpackedOffset},
};
use grammers_mtsender::{InvocationError, Sender, ServerAddr};
use grammers_tl_types as tl;
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::time::timeout;

struct BridgeTransport {
    init: Option<[u8; 64]>,
    send: AesCtr,
    receive: AesCtr,
    decrypted: usize,
}
impl BridgeTransport {
    fn new(secret: &[u8; 16], dc: i16) -> Result<Self> {
        let mut init = [0u8; 64];
        loop {
            getrandom::fill(&mut init)
                .map_err(|_| anyhow::anyhow!("Недоступен генератор случайных чисел"))?;
            if init[0] != 0xef
                && init[4..8] != [0; 4]
                && !matches!(
                    &init[..4],
                    b"GET "
                        | b"POST"
                        | b"HEAD"
                        | b"OPTI"
                        | b"\x16\x03\x01\x02"
                        | b"\xdd\xdd\xdd\xdd"
                        | b"\xee\xee\xee\xee"
                )
            {
                break;
            }
        }
        init[56..60].fill(0xee);
        init[60..62].copy_from_slice(&dc.to_le_bytes());
        let mut reverse = init[8..56].to_vec();
        reverse.reverse();
        let receive = secret_cipher(&reverse, secret);
        let mut send = secret_cipher(&init[8..56], secret);
        let mut encrypted = init;
        send.apply_keystream(&mut encrypted);
        init[56..].copy_from_slice(&encrypted[56..]);
        Ok(Self {
            init: Some(init),
            send,
            receive,
            decrypted: 0,
        })
    }
}
impl Transport for BridgeTransport {
    fn pack(&mut self, buffer: &mut DequeBuffer<u8>) {
        buffer.extend_front(&(buffer.len() as u32).to_le_bytes());
        self.send.apply_keystream(buffer.as_mut());
        if let Some(init) = self.init.take() {
            buffer.extend_front(&init);
        }
    }
    fn unpack(&mut self, buffer: &mut [u8]) -> std::result::Result<UnpackedOffset, Error> {
        let tail = buffer
            .get_mut(self.decrypted..)
            .ok_or(Error::BadLen { got: -1 })?;
        self.receive.apply_keystream(tail);
        self.decrypted = buffer.len();
        let header = buffer.get(..4).ok_or(Error::MissingBytes)?;
        let n = i32::from_le_bytes(header.try_into().unwrap());
        if !(4..=1024 * 1024).contains(&n) || n % 4 != 0 {
            return Err(Error::BadLen { got: n });
        }
        let end = 4 + n as usize;
        if buffer.len() < end {
            return Err(Error::MissingBytes);
        }
        if n == 4 {
            return Err(Error::BadStatus {
                status: i32::from_le_bytes(buffer[4..8].try_into().unwrap()).unsigned_abs(),
            });
        }
        self.decrypted -= end;
        Ok(UnpackedOffset {
            data_range: 4..end,
            next_offset: end,
        })
    }
}

type Client = Sender<BridgeTransport, mtp::Encrypted>;
fn local(address: SocketAddr) -> ServerAddr {
    ServerAddr::Tcp { address }
}
async fn handshake(config: &Config, dc: i16) -> Result<()> {
    let mut client = Sender::connect(
        BridgeTransport::new(&config.secret, dc)?,
        mtp::Plain::new(),
        local(config.listen),
    )
    .await?;
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|_| anyhow::anyhow!("Генератор случайных чисел недоступен"))?;
    let tl::enums::ResPq::Pq(reply) = client.invoke(&tl::functions::ReqPqMulti { nonce }).await?;
    ensure!(
        reply.nonce == nonce
            && !reply.pq.is_empty()
            && !reply.server_public_key_fingerprints.is_empty(),
        "DC Telegram не подтвердил запрос"
    );
    Ok(())
}

struct Bot {
    app: i32,
    hash: String,
    token: String,
}
impl Bot {
    fn from_env() -> Result<Option<Self>> {
        let value = |key| std::env::var(key).ok().filter(|s| !s.is_empty());
        let creds = (
            value("ZAPRET_TEST_TG_API_ID"),
            value("ZAPRET_TEST_TG_API_HASH"),
            value("ZAPRET_TEST_TG_BOT_TOKEN"),
        );
        match creds {
            (None, None, None) => Ok(None),
            (Some(id), Some(hash), Some(token)) => {
                let app: i32 = id.parse().context("Неверный ID тестового приложения")?;
                ensure!(
                    app > 0
                        && hash.len() == 32
                        && hash.bytes().all(|b| b.is_ascii_hexdigit())
                        && token.len() <= 256,
                    "Неверные параметры тестового бота"
                );
                Ok(Some(Self { app, hash, token }))
            }
            _ => bail!("Для скачивания нужны все три параметра тестового бота"),
        }
    }
}

fn init<X>(app: i32, query: X) -> tl::functions::InvokeWithLayer<tl::functions::InitConnection<X>> {
    tl::functions::InvokeWithLayer {
        layer: tl::LAYER,
        query: tl::functions::InitConnection {
            api_id: app,
            device_model: "zapret-rust media test".into(),
            system_version: "Windows".into(),
            app_version: env!("CARGO_PKG_VERSION").into(),
            system_lang_code: "ru".into(),
            lang_pack: String::new(),
            lang_code: "ru".into(),
            proxy: None,
            params: None,
            query,
        },
    }
}
async fn open(config: &Config, dc: i16, key: Option<[u8; 256]>) -> Result<Client> {
    ensure!(
        (1..=5).contains(&dc.unsigned_abs()),
        "Неизвестный DC Telegram"
    );
    let transport = BridgeTransport::new(&config.secret, dc)?;
    Ok(match key {
        Some(key) => {
            grammers_mtsender::connect_with_auth(transport, local(config.listen), key).await?
        }
        None => grammers_mtsender::connect(transport, local(config.listen)).await?,
    })
}

const LIMIT: i32 = 128 * 1024;
const STICKERS: &str = "GreatMinds";

async fn download(config: &Config, bot: &Bot, home: i16, client: &mut Client) -> Result<Value> {
    let request = tl::functions::messages::GetStickerSet {
        stickerset: tl::types::InputStickerSetShortName {
            short_name: STICKERS.into(),
        }
        .into(),
        hash: 0,
    };
    let tl::enums::messages::StickerSet::Set(set) = client.invoke(&request).await? else {
        bail!("Telegram не вернул набор стикеров")
    };
    let doc = set
        .documents
        .into_iter()
        .filter_map(|d| match d {
            tl::enums::Document::Document(d)
                if d.mime_type == "image/webp" && (16..=i64::from(LIMIT)).contains(&d.size) =>
            {
                Some(d)
            }
            _ => None,
        })
        .min_by_key(|d| d.size)
        .context("В тестовом наборе нет небольшого WebP")?;
    let dc = i16::try_from(doc.dc_id)?;
    ensure!((1..=5).contains(&dc), "Неверный медиа-DC");
    let mut media = open(config, -dc, (dc == home).then(|| client.auth_key())).await?;
    if dc != home {
        let tl::enums::auth::ExportedAuthorization::Authorization(auth) = client
            .invoke(&tl::functions::auth::ExportAuthorization { dc_id: doc.dc_id })
            .await?;
        media
            .invoke(&init(
                bot.app,
                tl::functions::auth::ImportAuthorization {
                    id: auth.id,
                    bytes: auth.bytes,
                },
            ))
            .await?;
    }
    let location = tl::types::InputDocumentFileLocation {
        id: doc.id,
        access_hash: doc.access_hash,
        file_reference: doc.file_reference,
        thumb_size: String::new(),
    }
    .into();
    let request = tl::functions::upload::GetFile {
        precise: false,
        cdn_supported: false,
        location,
        offset: 0,
        limit: LIMIT,
    };
    let file = if dc == home {
        media.invoke(&init(bot.app, request)).await?
    } else {
        media.invoke(&request).await?
    };
    let tl::enums::upload::File::File(file) = file else {
        bail!("Файл перенаправлен в другой CDN")
    };
    validate_webp(&file.bytes, doc.size)?;
    Ok(
        json!({"state":"ok","dc":dc,"bytes":file.bytes.len(),"sha256":zapret_core::sha256(&file.bytes),"sticker_set":STICKERS}),
    )
}
fn validate_webp(data: &[u8], size: i64) -> Result<()> {
    ensure!(
        data.len() as i64 == size
            && data.len() >= 20
            && data.starts_with(b"RIFF")
            && &data[8..12] == b"WEBP"
            && matches!(&data[12..16], b"VP8 " | b"VP8L" | b"VP8X")
            && u32::from_le_bytes(data[4..8].try_into()?) as usize + 8 == data.len(),
        "Размер или формат стикера Telegram не совпал"
    );
    Ok(())
}
async fn test_file(config: &Config, bot: Bot) -> Result<Value> {
    let mut home = 2;
    for _ in 0..2 {
        let mut client = open(config, home, None).await?;
        let login = init(
            bot.app,
            tl::functions::auth::ImportBotAuthorization {
                flags: 0,
                api_id: bot.app,
                api_hash: bot.hash.clone(),
                bot_auth_token: bot.token.clone(),
            },
        );
        match client.invoke(&login).await {
            Err(InvocationError::Rpc(error)) if error.code == 303 => {
                home = error
                    .value
                    .and_then(|n| i16::try_from(n).ok())
                    .context("Неизвестный DC тестового бота")?;
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {
                let result = timeout(
                    Duration::from_secs(25),
                    download(config, &bot, home, &mut client),
                )
                .await;
                let _ = timeout(
                    Duration::from_secs(2),
                    client.invoke(&tl::functions::auth::LogOut {}),
                )
                .await;
                return result.context("Истекло время загрузки стикера")?;
            }
        }
    }
    bail!("Telegram повторно перенаправил вход на другой DC")
}

async fn route(config: &Config, dc: i16) -> Value {
    let started = Instant::now();
    let mut result = match timeout(Duration::from_secs(8), handshake(config, dc)).await {
        Ok(Ok(())) => json!({"state":"ok"}),
        Ok(Err(error)) => json!({"state":"failed","error":format!("{error:#}")}),
        Err(_) => json!({"state":"failed","error":"Тайм-аут ответа DC"}),
    };
    result["dc"] = json!(dc.abs());
    result["elapsed_ms"] = json!(started.elapsed().as_millis());
    result
}

pub fn check(config: Config) -> Result<Value> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let other_media = async {
            if config.force_test_dc { None } else { Some(route(&config, -4).await) }
        };
        let (bridge, media_route, other) = tokio::join!(route(&config, 2), route(&config, -2), other_media);
        let media_routes: Vec<_> = std::iter::once(&media_route).chain(other.as_ref()).collect();
        let file=match Bot::from_env() {
            Err(error)=>json!({"state":"unconfigured","reason":error.to_string()}),
            Ok(None)=>json!({"state":"unconfigured","reason":"Для загрузки стикера через мост нужен отдельный тестовый бот"}),
            Ok(Some(_)) if config.force_test_dc=>json!({"state":"unavailable","reason":"Мост использует тестовую сеть Telegram"}),
            Ok(Some(bot))=>match timeout(Duration::from_secs(45),test_file(&config,bot)).await {
                Ok(Ok(file))=>file,
                Ok(Err(error))=>json!({"state":"failed","error":format!("{error:#}")}),
                Err(_)=>json!({"state":"failed","error":"Истекло время проверки файла"}),
            }
        };
        Ok(json!({"bridge":bridge,"media_route":media_route,"media_routes":media_routes,"file":file}))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use grammers_tl_types::Serializable;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn a_media_route_requires_a_matching_telegram_reply_through_the_local_port() {
        for matches in [true, false] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let config = Config::from_value(
                &json!({"port":listener.local_addr().unwrap().port(),"secret":"11".repeat(16)}),
            )
            .unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut header = [0; 64];
                stream.read_exact(&mut header).await.unwrap();
                let mut auth = crate::protocol::authenticate(&header, &[0x11; 16], false).unwrap();
                assert!(auth.media && auth.dc == 2);
                let mut len = [0; 4];
                stream.read_exact(&mut len).await.unwrap();
                auth.decrypt.apply_keystream(&mut len);
                let mut payload = vec![0; u32::from_le_bytes(len) as usize];
                stream.read_exact(&mut payload).await.unwrap();
                auth.decrypt.apply_keystream(&mut payload);
                assert_eq!(payload[20..24], 0xbe7e8ef1_u32.to_le_bytes());
                let mut nonce: [u8; 16] = payload[24..40].try_into().unwrap();
                if !matches {
                    nonce[0] ^= 1
                }
                let reply = tl::enums::ResPq::Pq(tl::types::ResPq {
                    nonce,
                    server_nonce: [9; 16],
                    pq: vec![15],
                    server_public_key_fingerprints: vec![7],
                })
                .to_bytes();
                let mut data = Vec::new();
                data.extend_from_slice(&(20 + reply.len() as u32).to_le_bytes());
                data.extend_from_slice(&[0; 8]);
                let id = u64::from_le_bytes(payload[8..16].try_into().unwrap()) | 1;
                data.extend_from_slice(&id.to_le_bytes());
                data.extend_from_slice(&(reply.len() as u32).to_le_bytes());
                data.extend(reply);
                auth.encrypt.apply_keystream(&mut data);
                for part in data.chunks(7) {
                    stream.write_all(part).await.unwrap();
                    tokio::task::yield_now().await;
                }
            });
            let result = timeout(Duration::from_secs(3), handshake(&config, -2))
                .await
                .unwrap();
            server.await.unwrap();
            assert_eq!(result.is_ok(), matches, "{result:?}");
        }
    }
    #[test]
    fn media_file_requires_complete_webp_container() {
        let file = b"RIFF\x10\0\0\0WEBPVP8L\x03\0\0\0\x2f\x01\x02\0";
        validate_webp(file, file.len() as i64).unwrap();
        assert!(validate_webp(&file[..20], file.len() as i64).is_err());
        assert!(validate_webp(b"<html>successful response</html>", 32).is_err());
    }
}
