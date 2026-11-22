use super::parse::{Options, Profile, value};
use anyhow::{Result, bail, ensure};

pub(super) fn selectors(profile: &Profile, kind: &str) -> Result<()> {
    let ip_excludes = [
        ("--ipset-exclude", "%LISTS%ipset-exclude.txt"),
        ("--ipset-exclude", "%LISTS%ipset-exclude-user.txt"),
    ];
    let host_excludes = [
        ("--hostlist-exclude", "%LISTS%list-exclude.txt"),
        ("--hostlist-exclude", "%LISTS%list-exclude-user.txt"),
    ];
    let general = [
        ("--hostlist", "%LISTS%list-general.txt"),
        ("--hostlist", "%LISTS%list-general-user.txt"),
    ];
    let ipset = [("--ipset", "%LISTS%ipset-all.txt")];
    let actual: Vec<_> = profile
        .iter()
        .filter(|(key, _)| key.starts_with("--hostlist") || key.starts_with("--ipset"))
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    let mut expected = Vec::new();
    match kind {
        "quic" | "general" => {
            expected.extend(general);
            expected.extend(host_excludes);
            expected.extend(ip_excludes);
        }
        "quic_ipset" | "ipset_tcp" => {
            expected.extend(ipset);
            expected.extend(host_excludes);
            let fonts = ("--hostlist-exclude-domains", "fonts.googleapis.com");
            if kind == "ipset_tcp" && actual.contains(&fonts) {
                expected.push(fonts);
            }
            expected.extend(ip_excludes);
        }
        "discord_udp" => {}
        "discord_media" => expected.push(("--hostlist-domains", "discord.media")),
        "google" => expected.push(("--hostlist", "%LISTS%list-google.txt")),
        "game_tcp" | "game_udp" => {
            expected.extend(ipset);
            expected.extend(ip_excludes);
        }
        "all_tcp" => expected.extend(ip_excludes),
        _ => bail!("Unsupported section {kind}"),
    }
    ensure!(
        actual == expected,
        "Unrepresentable list/domain conditions for {kind}"
    );
    Ok(())
}

pub(super) fn actions(profile: &Profile, options: &Options, kind: &str) -> Result<()> {
    let action_options: Vec<_> = profile
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| name.starts_with("--dpi-desync") || *name == "--ip-id")
        .collect();
    if matches!(kind, "quic" | "quic_ipset" | "discord_udp" | "game_udp") {
        return udp_actions(profile, options, kind, &action_options);
    }
    for key in action_options {
        let consumers: &[&str] = match key {
            "--dpi-desync" | "--dpi-desync-cutoff" | "--dpi-desync-any-protocol" | "--ip-id" => &[],
            "--dpi-desync-repeats" | "--dpi-desync-fooling" | "--dpi-desync-badseq-increment" => {
                &["fake", "fakedsplit", "hostfakesplit"]
            }
            "--dpi-desync-fake-tls"
            | "--dpi-desync-fake-tls-mod"
            | "--dpi-desync-fake-http"
            | "--dpi-desync-fake-unknown" => &["fake"],
            "--dpi-desync-split-pos" => &["multisplit", "multidisorder", "fakedsplit"],
            "--dpi-desync-split-seqovl" | "--dpi-desync-split-seqovl-pattern" => {
                &["multisplit", "multidisorder"]
            }
            "--dpi-desync-fakedsplit-pattern" => &["fakedsplit"],
            "--dpi-desync-hostfakesplit-mod" => &["hostfakesplit"],
            _ => bail!("Unsupported/unused TCP action option {key}"),
        };
        ensure!(
            consumers.is_empty()
                || options
                    .modes
                    .iter()
                    .any(|mode| consumers.contains(&mode.as_str())),
            "Action does not consume {key}"
        );
        ensure!(
            !matches!(kind, "google" | "discord_media")
                || !matches!(
                    key,
                    "--dpi-desync-fake-http"
                        | "--dpi-desync-fake-unknown"
                        | "--dpi-desync-any-protocol"
                ),
            "TLS-only section does not represent {key}"
        );
    }
    ensure!(
        value(profile, "--dpi-desync-badseq-increment").is_none()
            || options.fooling.iter().any(|mode| mode == "badseq"),
        "Badseq increment requires badseq fooling"
    );
    ensure!(
        options.unknown.is_empty() || options.any,
        "Unknown TCP fake requires any-protocol=1"
    );
    Ok(())
}

fn udp_actions(profile: &Profile, options: &Options, kind: &str, actions: &[&str]) -> Result<()> {
    for key in actions {
        let allowed = matches!(
            (*key, kind),
            ("--dpi-desync" | "--dpi-desync-repeats", _)
                | ("--dpi-desync-fake-quic", "quic" | "quic_ipset")
                | (
                    "--dpi-desync-fake-discord" | "--dpi-desync-fake-stun",
                    "discord_udp"
                )
                | (
                    "--dpi-desync-fake-unknown-udp"
                        | "--dpi-desync-any-protocol"
                        | "--dpi-desync-cutoff",
                    "discord_udp" | "game_udp",
                )
        );
        ensure!(allowed, "Unsupported/unused UDP action option {key}");
    }
    if kind == "discord_udp" {
        let l7 = if options.unknown_udp.is_empty() {
            "discord,stun"
        } else {
            "discord,stun,unknown"
        };
        ensure!(
            value(profile, "--filter-l7") == Some(l7)
                && !options.discord.is_empty()
                && !options.stun.is_empty(),
            "Voice L7 condition and explicit Discord/STUN fakes are required"
        );
        ensure!(
            options.unknown_udp.is_empty() || options.any,
            "Unknown voice payload requires any-protocol=1"
        );
        ensure!(
            !options.unknown_udp.is_empty()
                || value(profile, "--dpi-desync-any-protocol").is_none(),
            "Voice any-protocol without unknown payload is not represented"
        );
    }
    if kind == "game_udp" {
        ensure!(
            options.any && !options.cutoff.is_empty() && !options.unknown_udp.is_empty(),
            "Game UDP requires any-protocol=1, cutoff and explicit fake payloads"
        );
    }
    Ok(())
}
