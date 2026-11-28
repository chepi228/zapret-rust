use super::{Cdp, CdpError};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::time::{Duration, Instant, sleep};
use url::Url;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct Sample {
    pub(super) reason: String,
    played_ms: u64,
    presented_frames: u64,
    stalls: u64,
    document_url: String,
}

impl Sample {
    pub(super) fn confirmed(&self) -> bool {
        self.reason == "PlaybackObserved" && self.played_ms >= 5000 && self.presented_frames >= 10
    }
}

pub(super) async fn measure(cdp: &mut Cdp, target: &str, deadline: Instant) -> Result<Sample> {
    let url = Url::parse(target)?;
    let host = url.host_str().unwrap_or("");
    let youtube = host == "youtube.com" || host.ends_with(".youtube.com");
    let id = if youtube {
        let id = url
            .query_pairs()
            .find(|(k, _)| k == "v")
            .map(|(_, v)| v.into_owned());
        ensure!(
            url.path() == "/watch"
                && id.as_deref().is_some_and(|v| v.len() == 11
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))),
            "expected a YouTube watch URL with a video ID"
        );
        id
    } else {
        None
    };
    // Client-side redirects and consent pages can replace the main JS context.
    // Each new document must independently qualify for the entire observation.
    loop {
        let budget = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .saturating_sub(350);
        let expression = format!("({})({}, {budget})", include_str!("playback.js"), json!(id));
        // Page loading has already completed. Discard background network events while
        // the bounded measurement runs, so a busy player cannot exhaust the event queue.
        let reply = cdp
            .rpc(
                "Runtime.evaluate",
                json!({"expression":expression,
        "returnByValue":true,"awaitPromise":true,"userGesture":true}),
                deadline,
                false,
            )
            .await;
        let reply = match reply {
            Err(error)
                if budget > 150
                    && error.downcast_ref::<CdpError>().is_some_and(|e| {
                        e.code == -32000
                            && matches!(
                                e.message.as_str(),
                                "Inspected target navigated or closed"
                                    | "Execution context was destroyed."
                                    | "Cannot find context with specified id"
                            )
                    }) =>
            {
                sleep(Duration::from_millis(100)).await;
                continue;
            }
            reply => reply?,
        };
        ensure!(
            reply.get("exceptionDetails").is_none(),
            "browser could not measure video playback"
        );
        return serde_json::from_value(reply["result"]["value"].clone())
            .context("invalid browser playback counters");
    }
}
