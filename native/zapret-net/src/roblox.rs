use anyhow::{Context, Result, ensure};
use http_body_util::BodyExt;
use serde::Deserialize;
use tokio_native_tls::TlsConnector;
use url::Url;

pub(crate) fn universe(url: &Url) -> Option<u64> {
    if url.scheme() != "https"
        || url.host_str() != Some("thumbnails.roblox.com")
        || url.port().is_some()
        || url.path() != "/v1/games/icons"
    {
        return None;
    }
    let mut ids = url.query_pairs().filter(|(key, _)| key == "universeIds");
    let id = ids.next()?.1.parse().ok()?;
    (ids.next().is_none() && id > 0).then_some(id)
}

#[derive(Deserialize)]
struct Icons {
    data: Vec<Icon>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Icon {
    target_id: u64,
    state: String,
    image_url: Option<String>,
}

fn image_url(body: &[u8], id: u64) -> Result<Url> {
    let reply: Icons = serde_json::from_slice(body)?;
    let icon = reply
        .data
        .into_iter()
        .find(|entry| entry.target_id == id && entry.state == "Completed")
        .context("Roblox ещё не вернул готовую иконку этой игры")?;
    let url = crate::http::checked_url(
        &icon.image_url.context("В ответе Roblox нет URL иконки")?,
        false,
    )?;
    ensure!(
        url.scheme() == "https"
            && url.port().is_none()
            && url
                .host_str()
                .is_some_and(|h| h.ends_with(".rbxcdn.com") || h == "rbxcdn.com"),
        "Некорректный адрес CDN Roblox"
    );
    Ok(url)
}

pub(crate) async fn resolve(url: &Url, connector: &TlsConnector) -> Result<Url> {
    let id = universe(url).context("Некорректный адрес Roblox API")?;
    let (mut reply, _driver) =
        crate::http::response_accept(url, "GET", connector, "application/json", &[]).await?;
    ensure!(
        reply.status() == 200,
        "Roblox API ответил HTTP {}",
        reply.status()
    );
    let mut bytes = Vec::new();
    while let Some(frame) = reply.body_mut().frame().await {
        if let Some(data) = frame?.data_ref() {
            ensure!(
                bytes.len() + data.len() <= 16384,
                "Слишком большой ответ Roblox API"
            );
            bytes.extend_from_slice(data);
        }
    }
    image_url(&bytes, id)
}

pub(crate) fn validate(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.ends_with(b"\x00\x00\x00\x00IEND\xaeB\x60\x82"),
        "Незавершённая PNG Roblox"
    );
    let mut reader = png::Decoder::new(std::io::Cursor::new(bytes)).read_info()?;
    ensure!(
        reader.info().width == 150 && reader.info().height == 150,
        "Размер иконки Roblox отличается от 150×150"
    );
    let mut pixels = vec![0; reader.output_buffer_size()];
    reader.next_frame(&mut pixels)?;
    reader.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_completed_requested_cdn_image_and_valid_pixels() {
        let reply = |state: &str, id: u64, url: &str| {
            serde_json::to_vec(
                &serde_json::json!({"data":[{"state":state,"targetId":id,"imageUrl":url}]}),
            )
            .unwrap()
        };
        let cdn = "https://tr.rbxcdn.com/example";
        assert!(image_url(&reply("Completed", 5, cdn), 5).is_ok());
        for (state, id, url) in [
            ("Pending", 5, cdn),
            ("Completed", 6, cdn),
            ("Completed", 5, "https://rbxcdn.com.evil.test/x"),
            ("Completed", 5, "http://127.0.0.1/"),
        ] {
            assert!(image_url(&reply(state, id, url), 5).is_err());
        }
        let mut bytes = Vec::new();
        {
            let mut writer = png::Encoder::new(&mut bytes, 150, 150)
                .write_header()
                .unwrap();
            writer.write_image_data(&vec![1; 150 * 150]).unwrap();
        }
        validate(&bytes).unwrap();
        assert!(validate(&bytes[..bytes.len() - 1]).is_err());
        assert!(validate(b"<html>provider</html>").is_err());
    }
}
