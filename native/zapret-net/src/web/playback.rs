use super::{Cdp, CdpError};
use anyhow::{Result, ensure};
use serde::Serialize;
use tokio::time::{Duration, Instant, sleep_until};
use url::Url;

mod browser;
use browser::{Media, Reader};

const REQUIRED_MS: u64 = 5000;
const REQUIRED_FRAMES: u64 = 10;
const POLL_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Clone, Debug, Serialize)]
pub(super) struct Sample {
    pub(super) reason: String,
    played_ms: u64,
    presented_frames: u64,
    stalls: u64,
    document_url: String,
}

impl Sample {
    pub(super) fn confirmed(&self) -> bool {
        self.reason == "PlaybackObserved"
            && self.played_ms >= REQUIRED_MS
            && self.presented_frames >= REQUIRED_FRAMES
    }
}

#[derive(Default)]
struct Progress {
    previous: Option<(Instant, f64, u64)>,
    played_ms: f64,
    frames: u64,
    stalls: u64,
    stalled_since: Option<Instant>,
}

impl Progress {
    fn observe(&mut self, now: Instant, media: &Media, frames: u64) {
        let position = media.current_time * 1000.0;
        if let Some((then, last_position, last_frames)) = self.previous {
            let elapsed_ms = now.duration_since(then).as_secs_f64() * 1000.0;
            let delta = position - last_position;
            if delta < -1.0
                || delta > elapsed_ms * media.playback_rate.max(1.0) + 350.0
                || frames < last_frames
            {
                *self = Self::default();
            } else {
                self.played_ms += delta.max(0.0);
                self.frames += frames - last_frames;
                if delta < 10.0 && !media.paused && !media.ended {
                    let since = *self.stalled_since.get_or_insert(then);
                    let threshold = since + Duration::from_secs(1);
                    if then < threshold && now >= threshold {
                        self.stalls += 1;
                    }
                } else {
                    self.stalled_since = None;
                }
            }
        }
        self.previous = Some((now, position, frames));
    }
}

#[derive(Default)]
struct Observation {
    document: Option<i64>,
    url: String,
    video: Option<(i64, String)>,
    play_promise: Option<String>,
    progress: Progress,
}

impl Observation {
    fn clear_video(&mut self) {
        self.video = None;
        self.play_promise = None;
        self.progress = Progress::default();
    }

    fn select_video(&mut self, node: i64, source: &str) -> bool {
        if self
            .video
            .as_ref()
            .is_some_and(|(id, src)| *id == node && src == source)
        {
            return false;
        }
        self.clear_video();
        self.video = Some((node, source.to_owned()));
        true
    }

    fn sample(self, reason: &str) -> Sample {
        Sample {
            reason: reason.into(),
            played_ms: self.progress.played_ms as u64,
            presented_frames: self.progress.frames,
            stalls: self.progress.stalls,
            document_url: self.url,
        }
    }
}

fn youtube_host(url: &Url) -> bool {
    url.host_str()
        .is_some_and(|h| h == "youtube.com" || h.ends_with(".youtube.com"))
}

fn watch_id(url: &Url) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == "v")
        .map(|(_, id)| id.into_owned())
}

fn watch_issue(url: &Url, expected: &str) -> Option<&'static str> {
    if matches!(
        url.host_str(),
        Some("consent.youtube.com" | "consent.google.com" | "accounts.google.com")
    ) {
        return Some("InteractionRequired");
    }
    if url.scheme() != "https"
        || !youtube_host(url)
        || url.path() != "/watch"
        || watch_id(url).as_deref() != Some(expected)
    {
        return Some("UnexpectedVideo");
    }
    None
}

fn changed_document(error: &anyhow::Error) -> bool {
    error.downcast_ref::<CdpError>().is_some_and(|e| {
        e.code == -32000
            && matches!(
                e.message.as_str(),
                "Inspected target navigated or closed"
                    | "Execution context was destroyed."
                    | "Cannot find context with specified id"
                    | "Cannot find object with given id"
                    | "Could not find node with given id"
                    | "No node with given id found"
                    | "Node with given id does not belong to the document"
            )
    })
}

enum Poll {
    Continue,
    Finish(&'static str),
}

async fn poll(
    reader: &mut Reader<'_>,
    state: &mut Observation,
    expected: Option<&str>,
) -> Result<Poll> {
    let document = reader.document().await?;
    let url = Url::parse(&document.url)?;
    state.url = format!("{}{}", url.origin().ascii_serialization(), url.path());
    if state.document != Some(document.backend_node_id) {
        state.clear_video();
        state.document = Some(document.backend_node_id);
        reader.forget_world();
    }

    let (selector, player) = if let Some(id) = expected {
        if let Some(reason) = watch_issue(&url, id) {
            state.clear_video();
            return Ok(Poll::Finish(reason));
        }
        let player = reader.youtube_player(document.node_id).await?;
        if let Some(reason) = player.issue() {
            state.clear_video();
            return Ok(Poll::Finish(reason));
        }
        if !player.shows(id) {
            state.clear_video();
            return Ok(Poll::Continue);
        }
        ("#movie_player video.html5-main-video", player.object)
    } else {
        ("video", None)
    };

    let Some((node, video)) = reader.video(document.node_id, selector).await? else {
        state.clear_video();
        return Ok(Poll::Continue);
    };
    let media = reader.media(&video).await?;
    if state.select_video(node, &media.current_src) {
        state.play_promise = reader
            .start(&video, player.as_deref().filter(|_| media.paused))
            .await?;
    }
    if let Some(promise) = &state.play_promise {
        match reader.play_status(promise).await? {
            browser::PlayStatus::Blocked => return Ok(Poll::Finish("InteractionRequired")),
            browser::PlayStatus::Settled => state.play_promise = None,
            browser::PlayStatus::Pending => {}
        }
    }
    if media.error.is_some() {
        return Ok(Poll::Finish("MediaError"));
    }
    if media.seeking || media.video_width == 0 || media.current_src.is_empty() {
        state.progress = Progress::default();
        return Ok(Poll::Continue);
    }

    if let Some(frames) = reader.presented_frames(&video).await? {
        state.progress.observe(Instant::now(), &media, frames);
        if state.progress.played_ms >= REQUIRED_MS as f64
            && state.progress.frames >= REQUIRED_FRAMES
        {
            return Ok(Poll::Finish("PlaybackObserved"));
        }
        if media.ended {
            return Ok(Poll::Finish("PlaybackUnconfirmed"));
        }
    } else {
        state.progress = Progress::default();
    }
    Ok(Poll::Continue)
}

pub(super) async fn measure(
    cdp: &mut Cdp,
    target: &str,
    frame: &str,
    deadline: Instant,
) -> Result<Sample> {
    let target = Url::parse(target)?;
    let expected = if youtube_host(&target) {
        let id = watch_id(&target);
        ensure!(
            target.path() == "/watch"
                && id.as_deref().is_some_and(|v| v.len() == 11
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))),
            "expected a YouTube watch URL with a video ID"
        );
        id
    } else {
        None
    };
    let mut state = Observation::default();
    let mut reader = Reader::new(cdp, frame, deadline);
    let until = deadline - Duration::from_millis(350);
    let result = loop {
        let outcome = poll(&mut reader, &mut state, expected.as_deref()).await;
        reader.release_poll().await?;
        match outcome {
            Ok(Poll::Finish(reason)) => break Ok(state.sample(reason)),
            Ok(Poll::Continue) => {}
            Err(error) if changed_document(&error) => {
                state.clear_video();
                state.document = None;
                reader.forget_world();
            }
            Err(error) => break Err(error),
        }
        if Instant::now() >= until {
            let reason = if state.video.is_some() {
                "PlaybackUnconfirmed"
            } else {
                "NoVideo"
            };
            break Ok(state.sample(reason));
        }
        sleep_until(until.min(Instant::now() + POLL_INTERVAL)).await;
    };
    reader.release_start().await?;
    result
}

#[cfg(test)]
mod tests;
