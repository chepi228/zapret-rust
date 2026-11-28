use super::*;

fn media(position_ms: u64) -> Media {
    Media {
        current_time: position_ms as f64 / 1000.0,
        current_src: "clip.webm".into(),
        playback_rate: 1.0,
        video_width: 320,
        paused: false,
        ended: false,
        seeking: false,
        error: None,
    }
}

#[test]
fn clock_and_new_frames_must_both_advance() {
    let start = Instant::now();
    for (media_ms, new_frames, confirmed) in [
        (5000, 10, true),
        (5000, 0, false),
        (4900, 100, false),
        (0, 100, false),
    ] {
        let mut state = Observation::default();
        state.progress.observe(start, &media(0), 50);
        state.progress.observe(
            start + Duration::from_secs(5),
            &media(media_ms),
            50 + new_frames,
        );
        assert_eq!(state.sample("PlaybackObserved").confirmed(), confirmed);
    }
}

#[test]
fn one_stall_per_interval_only_while_playing() {
    let start = Instant::now();
    let mut progress = Progress::default();
    for (elapsed, position, paused) in [
        (0, 0, false),
        (4000, 4000, false),
        (4400, 4000, false),
        (5000, 4000, false),
        (6000, 4000, false),
        (6300, 4300, false),
        (7500, 4300, true),
        (8000, 4800, false),
        (9200, 4800, false),
    ] {
        let mut video = media(position);
        video.paused = paused;
        progress.observe(
            start + Duration::from_millis(elapsed),
            &video,
            position / 40,
        );
    }
    assert_eq!(progress.stalls, 2);
    assert_eq!(progress.played_ms, 4800.0);
}

#[test]
fn seek_and_decoder_reset_start_new_intervals() {
    let start = Instant::now();
    for (position, frames) in [(9000, 105), (200, 105), (4200, 3)] {
        let mut progress = Progress::default();
        progress.observe(start, &media(0), 0);
        progress.observe(start + Duration::from_secs(4), &media(4000), 100);
        progress.observe(
            start + POLL_INTERVAL + Duration::from_secs(4),
            &media(position),
            frames,
        );
        assert_eq!(progress.played_ms, 0.0);
        assert_eq!(progress.frames, 0);
    }
}

#[test]
fn clock_progress_respects_the_requested_playback_rate() {
    let now = Instant::now();
    let mut progress = Progress::default();
    progress.observe(now, &media(0), 0);
    let mut fast = media(5000);
    fast.playback_rate = 2.0;
    progress.observe(now + Duration::from_millis(2500), &fast, 30);
    assert_eq!(progress.played_ms, 5000.0);
    assert_eq!(progress.frames, 30);
}

#[test]
fn replacing_an_element_source_or_document_discards_earlier_evidence() {
    let start = Instant::now();
    let mut state = Observation::default();
    for (node, source) in [(1, "first"), (1, "second"), (2, "second")] {
        assert!(state.select_video(node, source));
        assert_eq!(state.progress.frames, 0);
        assert_eq!(state.progress.played_ms, 0.0);
        state.progress.observe(start, &media(0), 100);
        state
            .progress
            .observe(start + Duration::from_secs(3), &media(3000), 190);
        assert!(!state.select_video(node, source));
        assert_eq!(state.progress.frames, 90);
    }
    state.clear_video();
    assert_eq!(state.sample("NoVideo").presented_frames, 0);
}

#[test]
fn youtube_requires_the_requested_content_and_excludes_ads() {
    let player = |status: &str, id: &str, classes: &str| browser::Player {
        status: Some(status.into()),
        video_id: Some(id.into()),
        classes: classes.into(),
        object: None,
    };
    assert!(player("OK", "wanted", "html5-video-player").shows("wanted"));
    assert!(!player("OK", "other", "").shows("wanted"));
    for class in ["ad-showing", "ad-interrupting"] {
        assert!(!player("OK", "wanted", &format!("player {class} active")).shows("wanted"));
    }
    assert_eq!(
        player("AGE_CHECK_REQUIRED", "", "").issue(),
        Some("InteractionRequired")
    );
    assert_eq!(
        player("OK", "wanted", "ytp-error").issue(),
        Some("PlayerUnavailable")
    );
    assert_eq!(
        player("UNPLAYABLE", "", "").issue(),
        Some("PlayerUnavailable")
    );
    let issue = |url: &str| watch_issue(&Url::parse(url).unwrap(), "wanted");
    assert_eq!(issue("https://www.youtube.com/watch?v=wanted"), None);
    assert_eq!(
        issue("https://www.youtube.com/watch?v=other"),
        Some("UnexpectedVideo")
    );
    assert_eq!(
        issue("https://youtube.com.example/watch?v=wanted"),
        Some("UnexpectedVideo")
    );
    assert_eq!(
        issue("https://consent.google.com/m"),
        Some("InteractionRequired")
    );
}
