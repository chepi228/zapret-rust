use super::{Release, hash_valid, parse_release};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::time::Duration;
use zapret_core::sha256;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum Route {
    Direct,
    #[cfg(windows)]
    Windows,
}

impl Route {
    fn fetch(self, url: &str, limit: usize, ms: u64, accept: &str) -> Result<Vec<u8>> {
        match self {
            Self::Direct => zapret_net::fetch_with_accept(url, limit, ms, accept),
            #[cfg(windows)]
            Self::Windows => zapret_net::fetch_release_via_windows(url, limit, ms, accept),
        }
    }
}

#[cfg(not(windows))]
fn with_fallback<T>(
    preferred: Route,
    budget: Duration,
    mut request: impl FnMut(Route, u64) -> Result<T>,
) -> Result<(Route, T)> {
    request(preferred, budget.as_millis() as u64).map(|value| (preferred, value))
}

#[cfg(windows)]
fn with_fallback<T>(
    preferred: Route,
    budget: Duration,
    mut request: impl FnMut(Route, u64) -> Result<T>,
) -> Result<(Route, T)> {
    use std::time::Instant;
    let deadline = Instant::now() + budget;
    let alternate = match preferred {
        Route::Direct => Route::Windows,
        Route::Windows => Route::Direct,
    };
    // Reserve time for the other route if the first never answers.
    let first_error = match request(preferred, (budget * 2 / 3).as_millis() as u64) {
        Ok(value) => return Ok((preferred, value)),
        Err(error) => error,
    };
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .as_millis() as u64;
    ensure!(
        remaining > 0,
        "Время загрузки истекло ({preferred:?}: {first_error:#})"
    );
    request(alternate, remaining)
        .map(|value| (alternate, value))
        .with_context(|| {
            format!(
                "Оба способа загрузки не сработали ({preferred:?}: {first_error:#}). {alternate:?}"
            )
        })
}

pub(super) fn latest() -> Result<(Route, (String, Option<Release>))> {
    with_fallback(Route::Direct, Duration::from_secs(20), |route, ms| {
        let data = route.fetch(
            "https://api.github.com/repos/chepi228/zapret-rust/releases/latest",
            2 * 1024 * 1024,
            ms,
            "application/vnd.github+json",
        )?;
        let metadata: Value = serde_json::from_slice(&data)?;
        let release = parse_release(&metadata)?;
        let tag = metadata["tag_name"]
            .as_str()
            .context("GitHub release has no tag")?;
        Ok((tag.to_owned(), release))
    })
}

pub(super) fn verified_archive(
    bytes: Vec<u8>,
    expected: Option<&str>,
) -> Result<(Vec<u8>, String)> {
    let digest = sha256(&bytes);
    if let Some(expected) = expected {
        let expected = expected.strip_prefix("sha256:").unwrap_or(expected);
        ensure!(
            hash_valid(expected) && digest.eq_ignore_ascii_case(expected),
            "SHA256 архива не совпала; обновление отменено до остановки обхода"
        );
    }
    Ok((bytes, digest))
}

pub(super) fn archive(release: &Release, preferred: Route) -> Result<(Vec<u8>, String)> {
    let (_, verified) = with_fallback(preferred, Duration::from_secs(300), |route, ms| {
        let bytes = route.fetch(
            &release.url,
            release.bytes as usize,
            ms,
            "application/octet-stream",
        )?;
        ensure!(
            bytes.len() as u64 == release.bytes,
            "Размер архива отличается от указанного в релизе"
        );
        verified_archive(bytes, Some(&release.sha256))
    })?;
    Ok(verified)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn fallback_accepts_only_verified_bytes_and_keeps_the_successful_route() {
        let digest = sha256(b"archive");
        for first in [Route::Direct, Route::Windows] {
            let mut calls = Vec::new();
            let (working, (bytes, _)) =
                with_fallback(first, Duration::from_secs(5), |route, ms| {
                    calls.push(route);
                    assert!((1..=5000).contains(&ms));
                    verified_archive(
                        if route == first {
                            b"invalid"
                        } else {
                            b"archive"
                        }
                        .to_vec(),
                        Some(&digest),
                    )
                })
                .unwrap();
            assert_eq!(bytes, b"archive");
            assert_eq!(calls, [first, working]);
            assert_ne!(working, first);
            let mut requests = 0;
            with_fallback(working, Duration::from_secs(5), |route, _| {
                requests += 1;
                assert_eq!(route, working);
                Ok(())
            })
            .unwrap();
            assert_eq!(requests, 1);
        }
        let error = with_fallback(Route::Direct, Duration::from_secs(1), |_, _| {
            verified_archive(b"invalid".to_vec(), Some(&digest))
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("SHA256"));
    }

    #[test]
    fn windows_fetches_the_same_resource_after_a_direct_failure() -> Result<()> {
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
            thread,
        };
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}/archive", listener.local_addr()?);
        let server = thread::spawn(move || -> Result<()> {
            for (status, body) in [
                ("503 Service Unavailable", "unavailable"),
                ("200 OK", "archive"),
            ] {
                let (mut stream, _) = listener.accept()?;
                stream.set_read_timeout(Some(Duration::from_secs(4)))?;
                let mut headers = BufReader::new(&stream);
                let mut line = String::new();
                headers.read_line(&mut line)?;
                ensure!(line.starts_with("GET /archive "), "wrong request");
                loop {
                    line.clear();
                    if headers.read_line(&mut line)? == 0 || line == "\r\n" {
                        break;
                    }
                }
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )?;
            }
            Ok(())
        });
        let digest = sha256(b"archive");
        let (route, _) = with_fallback(Route::Direct, Duration::from_secs(5), |route, ms| {
            verified_archive(
                route.fetch(&url, 128, ms, "application/octet-stream")?,
                Some(&digest),
            )
        })?;
        assert_eq!(route, Route::Windows);
        server.join().expect("loopback release server")?;
        Ok(())
    }

    #[test]
    #[ignore = "downloads the current public release through Windows without installing it"]
    fn release_metadata_and_signed_cdn_redirect_work_via_windows() -> Result<()> {
        let body = Route::Windows.fetch(
            "https://api.github.com/repos/chepi228/zapret-rust/releases/latest",
            2 * 1024 * 1024,
            20_000,
            "application/vnd.github+json",
        )?;
        let release =
            parse_release(&serde_json::from_slice(&body)?)?.context("missing native archive")?;
        let bytes = Route::Windows.fetch(
            &release.url,
            release.bytes as usize,
            120_000,
            "application/octet-stream",
        )?;
        assert_eq!(bytes.len() as u64, release.bytes);
        verified_archive(bytes, Some(&release.sha256))?;
        Ok(())
    }
}
