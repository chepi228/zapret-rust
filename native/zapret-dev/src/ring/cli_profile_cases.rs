//! Exercise actual profile filter parsers, Lua context snapshots and profile reset.
use super::engine_case;
use anyhow::{Result, ensure};
use std::{ffi::OsString, path::Path};

pub(super) fn check(bin: &Path, logs: &Path) -> Result<usize> {
    let mut args: Vec<OsString> = [
        "--dry-run",
        "--intercept=0",
        "--wf-dup-check=0",
        "--debug",
        "--name=context",
        "--filter-l3=ipv4",
        "--filter-l3=ipv6",
        "--filter-tcp=80",
        "--filter-tcp=443",
        "--filter-udp=443",
        "--filter-icmp=8:0",
        "--filter-ipp=17",
        "--filter-l7=http,tls",
        "--payload-disable=tls_client_hello",
        "--payload-disable",
        "--reasm-disable=quic_initial",
        "--reasm-disable",
        "--payload=tls_client_hello",
        "--in-range=n2<n5",
        "--out-range=n1-n3",
        "--lua-desync=first:arg=1",
        "--payload=http_req",
        "--in-range=x",
        "--out-range=a",
        "--lua-desync=second:arg=2",
        "--new=reset",
        "--lua-desync=third",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    let text = engine_case(bin, &args, 0, &[])?;
    for expected in [
        "profile 1 (context) lua first(arg=\"1\" range_in=n2<n5 range_out=n1-n3 payload_type= tls_client_hello)",
        "profile 1 (context) lua second(arg=\"2\" range_in=x0-x0 range_out=a0-a0 payload_type= http_req)",
        "profile 2 (reset) lua third( range_in=x0-x0 range_out=a0-a0 payload_type= all)",
    ] {
        ensure!(
            text.contains(expected),
            "Rule context or new-profile reset differs: {expected}"
        );
    }
    zapret_core::atomic_write(&logs.join("cli-profile-rule-context.log"), text.as_bytes())?;
    let mut count = 1;
    for (option, invalid, diagnostic) in [
        ("filter-l3", "ipv7", "bad value for --filter-l3"),
        ("filter-tcp", "65536", "Invalid port filter"),
        ("filter-udp", "10-1", "Invalid port filter"),
        ("filter-icmp", "256", "Invalid icmp filter"),
        ("filter-ipp", "256", "Invalid ip protocol filter"),
        ("filter-l7", "tls,unknown_protocol", "Invalid l7 filter"),
        (
            "payload-disable",
            "unknown_payload",
            "Invalid payload filter",
        ),
        (
            "reasm-disable",
            "unknown_payload",
            "Invalid l7 protocol list",
        ),
        ("payload", "unknown_payload", "Invalid payload filter"),
        ("out-range", "z1", "invalid packet range value"),
        ("in-range", "n4294967296", "invalid packet range value"),
        ("lua-desync", "bad-name", "invalid lua function call"),
    ] {
        args = vec![
            "--dry-run".into(),
            "--intercept=0".into(),
            "--wf-dup-check=0".into(),
            format!("--{option}={invalid}").into(),
        ];
        let text = engine_case(bin, &args, 1, &[])?;
        ensure!(
            text.contains(diagnostic),
            "Invalid {option} lost its diagnostic"
        );
        zapret_core::atomic_write(
            &logs.join(format!("cli-profile-invalid-{option}.log")),
            text.as_bytes(),
        )?;
        count += 1;
    }
    println!("ok real engine: profile filter validation, owned rule context and new-profile reset");
    Ok(count)
}
