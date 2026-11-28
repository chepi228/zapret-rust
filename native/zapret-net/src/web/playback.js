async function measurePlayback(expectedId, budgetMs) {
    const deadline = performance.now() + budgetMs;
    const sample = {reason: "NoVideo", played_ms: 0, presented_frames: 0, stalls: 0,
        document_url: location.origin + location.pathname};
    let tracked = null;
    let source = "";
    let previous = null;
    let stalledAt = null;
    let stallCounted = false;
    let blocked = false;

    function reset() {
        previous = null;
        stalledAt = null;
        stallCounted = false;
        sample.played_ms = 0;
        sample.presented_frames = 0;
        sample.stalls = 0;
    }

    while (performance.now() < deadline) {
        let video;
        let player;
        if (expectedId) {
            if (["consent.youtube.com", "consent.google.com", "accounts.google.com"].includes(location.hostname)) {
                sample.reason = "InteractionRequired";
                break;
            }
            const page = new URL(location.href);
            if (!(page.protocol === "https:" && (page.hostname === "youtube.com" || page.hostname.endsWith(".youtube.com"))
                    && page.pathname === "/watch" && page.searchParams.get("v") === expectedId)) {
                sample.reason = "UnexpectedVideo";
                break;
            }
            player = document.getElementById("movie_player");
            const status = window.ytInitialPlayerResponse?.playabilityStatus?.status;
            if (status === "LOGIN_REQUIRED" || status === "AGE_CHECK_REQUIRED") {
                sample.reason = "InteractionRequired";
                break;
            }
            if (status === "UNPLAYABLE" || status === "ERROR" || player?.classList.contains("ytp-error")) {
                sample.reason = "PlayerUnavailable";
                break;
            }
            if (player?.getVideoData?.()?.video_id === expectedId
                    && !player.matches(".ad-showing, .ad-interrupting")) {
                video = player.querySelector("video.html5-main-video");
            }
        } else {
            video = document.querySelector("video");
        }
        if (!video || video !== tracked || video.currentSrc !== source) {
            tracked = video;
            source = video?.currentSrc ?? "";
            blocked = false;
            reset();
            if (video) {
                video.muted = true;
                if (video.paused) player?.playVideo?.();
                const playing = video.play();
                playing?.catch(error => {
                    if (video === tracked && error.name === "NotAllowedError") blocked = true;
                });
            }
        }
        if (video?.error || blocked) {
            sample.reason = blocked ? "InteractionRequired" : "MediaError";
            break;
        }
        if (video?.seeking) {
            reset();
        } else if (video && video.videoWidth > 0 && source && video.getVideoPlaybackQuality) {
            const quality = video.getVideoPlaybackQuality();
            const frames = quality.totalVideoFrames - quality.droppedVideoFrames;
            const now = performance.now();
            const media = video.currentTime * 1000;
            if (previous) {
                const delta = media - previous.media;
                const elapsed = now - previous.now;
                // A seek, changed source or reset of the decoder is a new observation.
                if (delta < -1 || delta > elapsed * Math.max(1, video.playbackRate) + 350 || frames < previous.frames) {
                    reset();
                } else {
                    sample.played_ms += Math.max(0, delta);
                    sample.presented_frames += frames - previous.frames;
                    if (delta < 10 && !video.paused && !video.ended) {
                        stalledAt ??= previous.now;
                        if (!stallCounted && now - stalledAt >= 1000) {
                            sample.stalls++;
                            stallCounted = true;
                        }
                    } else {
                        stalledAt = null;
                        stallCounted = false;
                    }
                }
            }
            previous = {media, frames, now};
            sample.reason = "PlaybackUnconfirmed";
            if (sample.played_ms >= 5000 && sample.presented_frames >= 10) {
                sample.reason = "PlaybackObserved";
                break;
            }
            if (video.ended) break;
        } else if (video) {
            sample.reason = "PlaybackUnconfirmed";
        }
        await new Promise(resolve => setTimeout(resolve, Math.max(0, Math.min(200, deadline - performance.now()))));
    }
    sample.played_ms = Math.floor(sample.played_ms);
    return sample;
}
