use super::parse::Options;
use anyhow::{Result, bail, ensure};

fn option(key: &str, value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        format!("{key}={value}")
    }
}

fn action(parts: &[&str]) -> String {
    let parts: Vec<_> = parts
        .iter()
        .copied()
        .filter(|text| !text.is_empty())
        .collect();
    format!("--lua-desync={}", parts.join(":"))
}

fn fooling(options: &Options) -> Result<String> {
    let has = |value: &str| options.fooling.iter().any(|mode| mode == value);
    let mut parts = Vec::new();
    if has("ts") {
        parts.push(
            if has("md5sig") {
                "tcp_ts=-600000:tcp_ts_up"
            } else {
                "tcp_ts=-600000:tcp_ts_up:fool=ts_or_md5"
            }
            .into(),
        );
    }
    if has("md5sig") {
        parts.push("tcp_md5".into());
    }
    if has("badseq") {
        parts.push(format!("tcp_seq={}:tcp_ack=-66000", options.badseq));
    }
    ensure!(
        options
            .fooling
            .iter()
            .all(|mode| matches!(mode.as_str(), "ts" | "md5sig" | "badseq")),
        "Unsupported fooling mode"
    );
    Ok(parts.join(":"))
}

pub(super) fn tcp(
    options: &Options,
    kind: &str,
    warnings: &mut Vec<String>,
) -> Result<Vec<String>> {
    let range = if kind == "game_tcp" {
        format!(
            "--out-range=<{}",
            if options.cutoff.is_empty() {
                "n4"
            } else {
                &options.cutoff
            }
        )
    } else {
        ensure!(options.cutoff.is_empty(), "Cutoff in section {kind}");
        "--out-range=-d10".into()
    };
    let mut lines = vec![range];
    let fooling = fooling(options)?;
    let repeats = option("repeats", &options.repeats);
    let ip_id = if options.ip_id_zero { "ip_id=zero" } else { "" };
    ensure!(
        !options.modes.is_empty(),
        "TCP profile has no desync action"
    );
    if options.modes.iter().any(|mode| mode == "syndata") {
        lines.extend(["--payload=empty".into(), "--lua-desync=syndata".into()]);
    }
    let mut payloads = vec![("tls_client_hello", "")];
    if matches!(kind, "general" | "ipset_tcp" | "game_tcp") {
        payloads.push(("http_req", ""));
    }
    if options.any {
        payloads.push(("unknown", "payload=unknown"));
    }
    for (payload, inline) in payloads {
        let mut body = Vec::new();
        for mode in &options.modes {
            match mode.as_str() {
                "fake" => {
                    for (blob, modifier) in fakes(options, payload, kind, warnings)? {
                        body.push(action(&[
                            "fake",
                            inline,
                            &option("blob", &blob),
                            &option("tls_mod", &modifier),
                            &fooling,
                            &repeats,
                            ip_id,
                        ]));
                    }
                }
                "multisplit" | "multidisorder" => {
                    let overlap = if options.seqovl.is_empty() {
                        String::new()
                    } else {
                        let mut value = option("seqovl", &options.seqovl);
                        if !options.seqovl_pattern.is_empty() {
                            value.push(':');
                            value.push_str(&option("seqovl_pattern", &options.seqovl_pattern));
                        }
                        value
                    };
                    body.push(action(&[
                        mode,
                        inline,
                        &option("pos", &options.pos),
                        &overlap,
                        ip_id,
                    ]));
                }
                "fakedsplit" => {
                    ensure!(
                        !options.pos.contains(','),
                        "Multiple fakedsplit positions are not representable per payload"
                    );
                    body.push(action(&[
                        "fakedsplit",
                        inline,
                        &option("pos", &options.pos),
                        &option("pattern", &options.fakedsplit_pattern),
                        &fooling,
                        &repeats,
                        ip_id,
                    ]));
                }
                "hostfakesplit" if payload != "unknown" => {
                    let action_name = if options.host_alt_order {
                        "hostfakesplit_alt"
                    } else {
                        "hostfakesplit"
                    };
                    body.push(action(&[
                        action_name,
                        &option("host", &options.host),
                        &fooling,
                        &repeats,
                        ip_id,
                    ]));
                }
                "hostfakesplit" | "syndata" => {}
                _ => bail!("Unsupported action {mode}"),
            }
        }
        if !body.is_empty() {
            lines.push(format!("--payload={payload}"));
            lines.extend(body);
        }
    }
    Ok(lines)
}

fn fakes(
    options: &Options,
    payload: &str,
    kind: &str,
    warnings: &mut Vec<String>,
) -> Result<Vec<(String, String)>> {
    match payload {
        "tls_client_hello" => {
            ensure!(
                options.default_tls_mod.is_empty() || options.tls.is_empty(),
                "fake-tls-mod before fake-tls"
            );
            if options.tls.is_empty() {
                let modifier = if options.default_tls_mod.is_empty() {
                    "rnd,rndsni,dupsid"
                } else {
                    &options.default_tls_mod
                };
                Ok(vec![("fake_default_tls".into(), modifier.into())])
            } else {
                Ok(options.tls.clone())
            }
        }
        "http_req" => Ok(default_blobs(&options.http, "fake_default_http")
            .into_iter()
            .map(|blob| (blob, String::new()))
            .collect()),
        _ => {
            if options.unknown.is_empty() {
                warnings.push(format!("нет fake-unknown для {kind}"));
            }
            Ok(
                default_blobs(&options.unknown, &format!("0x{}", "00".repeat(256)))
                    .into_iter()
                    .map(|blob| (blob, String::new()))
                    .collect(),
            )
        }
    }
}

fn default_blobs(blobs: &[String], default: &str) -> Vec<String> {
    if blobs.is_empty() {
        vec![default.into()]
    } else {
        blobs.to_vec()
    }
}

pub(super) fn udp(
    options: &Options,
    kind: &str,
    warnings: &mut Vec<String>,
) -> Result<Vec<String>> {
    ensure!(options.modes == ["fake"], "Unsupported UDP action sequence");
    let repeats = option("repeats", &options.repeats);
    let mut lines = Vec::new();
    match kind {
        "quic" | "quic_ipset" => {
            lines.extend(["--out-range=-n10".into(), "--payload=quic_initial".into()]);
            for blob in default_blobs(&options.quic, "fake_default_quic") {
                lines.push(action(&["fake", &option("blob", &blob), &repeats]));
            }
        }
        "discord_udp" => {
            lines.push(if options.cutoff.is_empty() {
                "--out-range=a".into()
            } else {
                format!("--out-range=<{}", options.cutoff)
            });
            for (payload, blobs) in [
                ("discord_ip_discovery", &options.discord),
                ("stun", &options.stun),
            ] {
                if !blobs.is_empty() {
                    lines.push(format!("--payload={payload}"));
                    for blob in blobs {
                        lines.push(action(&["fake", &option("blob", blob), &repeats]));
                    }
                }
            }
            if !options.unknown_udp.is_empty() {
                warnings.push(
                    "голос Discord: неизвестный UDP не перенесён (фильтр профиля - discord,stun)"
                        .into(),
                );
            }
        }
        _ => {
            lines.push(format!(
                "--out-range=<{}",
                if options.cutoff.is_empty() {
                    "n4"
                } else {
                    &options.cutoff
                }
            ));
            lines.push("--payload=all".into());
            for blob in &options.unknown_udp {
                lines.push(action(&[
                    "fake",
                    "payload=all",
                    &option("blob", blob),
                    &repeats,
                ]));
            }
        }
    }
    Ok(lines)
}
