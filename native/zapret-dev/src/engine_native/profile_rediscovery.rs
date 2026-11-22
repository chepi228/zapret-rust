//! Extract the pinned discovery reference before replacing its C state machine.
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

fn section<'a>(source: &'a str, first: &str, last: &str) -> Result<&'a str> {
    let start = source
        .find(first)
        .with_context(|| format!("Missing {first}"))?;
    let length = source[start..]
        .find(last)
        .with_context(|| format!("Missing {last}"))?;
    ensure!(length > 0, "Empty profile discovery reference");
    Ok(&source[start..start + length])
}

pub(super) fn reference(source: &str, output: &Path) -> Result<()> {
    let code = [
        section(
            source,
            "static void ctrack_stop_retrans_counter(",
            "static void auto_hostlist_reset_fail_counter(",
        )?,
        section(
            source,
            "static void dp_changed(",
            "static bool play_prolog(",
        )?,
        section(
            source,
            "static bool dp_rediscovery(",
            "static uint8_t dpi_desync_tcp_packet_play(",
        )?,
    ]
    .concat();
    fs::write(output.join("profile_rediscovery_reference.inc"), code)?;
    Ok(())
}

pub(super) fn apply(source: &mut String) -> Result<()> {
    let old = section(
        source,
        "static bool dp_rediscovery(",
        "static uint8_t dpi_desync_tcp_packet_play(",
    )?
    .to_owned();
    *source = source.replacen(&old, "#include \"profile_rediscovery_windows.inc\"\n\n", 1);
    let old = section(source, "static void dp_changed(", "struct play_state\n")?.to_owned();
    *source = source.replacen(&old, "", 1);
    ensure!(
        !source.contains("static bool dp_rediscovery(")
            && !source.contains("static void dp_changed("),
        "Pinned C profile discovery was not fully replaced"
    );
    Ok(())
}
