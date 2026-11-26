use super::validate_download;
use anyhow::{Result, bail};
use std::time::{Duration, Instant};

const MAX_LIST_BYTES: usize = 16 * 1024 * 1024;
const REPO: &str = "Flowseal/zapret-discord-youtube";

#[derive(Clone, Copy)]
struct Route {
    api: bool,
    windows: bool,
    label: &'static str,
}

const ROUTES: &[Route] = &[
    Route {
        api: false,
        windows: false,
        label: "GitHub Raw напрямую",
    },
    #[cfg(windows)]
    Route {
        api: true,
        windows: true,
        label: "GitHub API через настройки Windows",
    },
    Route {
        api: true,
        windows: false,
        label: "GitHub API напрямую",
    },
    #[cfg(windows)]
    Route {
        api: false,
        windows: true,
        label: "GitHub Raw через настройки Windows",
    },
];

impl Route {
    fn fetch(self, source: &str, timeout_ms: u64) -> Result<Vec<u8>> {
        let (url, accept) = if self.api {
            (
                format!("https://api.github.com/repos/{REPO}/contents/{source}?ref=main"),
                "application/vnd.github.raw+json",
            )
        } else {
            (
                format!("https://raw.githubusercontent.com/{REPO}/refs/heads/main/{source}"),
                "*/*",
            )
        };
        #[cfg(windows)]
        if self.windows {
            return zapret_net::fetch_via_windows(&url, MAX_LIST_BYTES, timeout_ms, accept);
        }
        zapret_net::fetch_with_accept(&url, MAX_LIST_BYTES, timeout_ms, accept)
    }
}

pub(super) fn download(
    name: &str,
    source: &str,
    old_lines: usize,
    timeout_ms: u64,
) -> Result<(Vec<u8>, &'static str)> {
    try_routes(
        name,
        old_lines,
        Duration::from_millis(timeout_ms),
        |route, ms| route.fetch(source, ms),
    )
}

fn try_routes(
    name: &str,
    old_lines: usize,
    budget: Duration,
    mut fetch: impl FnMut(Route, u64) -> Result<Vec<u8>>,
) -> Result<(Vec<u8>, &'static str)> {
    let started = Instant::now();
    // Reserve time for each remaining route. A quick failure gives the next
    // route the unused part of its slot, with one deadline for the whole file.
    let reserve = budget / (ROUTES.len() as u32 + 1);
    let mut errors = Vec::new();
    for (index, route) in ROUTES.iter().enumerate() {
        let reserved = reserve * (ROUTES.len() - index - 1) as u32;
        let remaining = (budget - reserved).saturating_sub(started.elapsed());
        let ms = remaining.as_millis() as u64;
        if ms == 0 {
            continue;
        }
        match fetch(*route, ms).and_then(|bytes| {
            validate_download(name, &bytes, old_lines)?;
            Ok(bytes)
        }) {
            Ok(bytes) => return Ok((bytes, route.label)),
            Err(error) => errors.push(format!("{} — {error:#}", route.label)),
        }
    }
    if errors.is_empty() {
        bail!("Истекло время загрузки {name}");
    }
    bail!("Не удалось обновить {name}. {}", errors.join(". "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "accesses the public Flowseal repository using each available transport"]
    fn live_transports_return_raw_list_bytes_for_the_same_file() -> Result<()> {
        let mut first = None;
        for &route in ROUTES {
            let body = route
                .fetch("lists/list-google.txt", 15_000)
                .map_err(|err| anyhow::anyhow!("{}: {err:#}", route.label))?;
            validate_download("list-google.txt", &body, 1)?;
            assert_eq!(
                first.get_or_insert_with(|| body.clone()),
                &body,
                "{}",
                route.label
            );
        }
        Ok(())
    }

    #[test]
    fn valid_direct_response_makes_one_request_and_keeps_exact_bytes() {
        let body = b"# list\r\nexample.org\r\n";
        let mut calls = 0;
        let (bytes, route) = try_routes("list-general.txt", 1, Duration::from_secs(2), |r, ms| {
            calls += 1;
            assert!(!r.api && !r.windows && (1..=2000).contains(&ms));
            Ok(body.to_vec())
        })
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(bytes, body);
        assert_eq!(route, ROUTES[0].label);
    }

    #[test]
    fn an_html_portal_and_a_short_list_do_not_hide_a_usable_alternate_source() {
        for bad in [b"<html>sign in</html>".as_slice(), b"single.example\n"] {
            let mut calls = 0;
            let (_, route) = try_routes("list-general.txt", 5, Duration::from_secs(2), |r, _| {
                calls += 1;
                if r.api {
                    return Ok(b"a.example\nb.example\nc.example\n".to_vec());
                }
                Ok(bad.to_vec())
            })
            .unwrap();
            assert_eq!(calls, 2);
            assert_eq!(route, ROUTES[1].label);
        }
    }

    #[test]
    fn blocked_routes_share_a_deadline_and_report_all_attempts() {
        let mut attempts = Vec::new();
        let err = try_routes(
            "list-general.txt",
            0,
            Duration::from_millis(100),
            |r, ms| {
                assert!((1..=100).contains(&ms));
                attempts.push(r.label);
                bail!("offline")
            },
        )
        .unwrap_err()
        .to_string();
        assert_eq!(attempts.len(), ROUTES.len());
        assert!(attempts.iter().all(|label| err.contains(label)));
        assert!(try_routes("list-general.txt", 0, Duration::ZERO, |_, _| panic!()).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn supports_api_only_direct_and_raw_only_via_windows() {
        for (api, windows) in [(true, false), (false, true)] {
            let (_, route) = try_routes("list-general.txt", 0, Duration::from_secs(2), |r, _| {
                if (r.api, r.windows) == (api, windows) {
                    Ok(b"working.example".to_vec())
                } else {
                    bail!("unreachable")
                }
            })
            .unwrap();
            assert_eq!(
                route,
                ROUTES
                    .iter()
                    .find(|r| (r.api, r.windows) == (api, windows))
                    .unwrap()
                    .label
            );
        }
    }
}
