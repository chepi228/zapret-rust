//! Compare packet setup before replacing the pinned C implementation.
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

fn section<'a>(source: &'a str, first: &str, last: &str) -> Result<&'a str> {
    let start = source
        .find(first)
        .with_context(|| format!("Missing {first}"))?;
    let len = source[start..]
        .find(last)
        .with_context(|| format!("Missing {last}"))?;
    ensure!(len > 0, "Empty pinned play setup");
    Ok(&source[start..start + len])
}

pub(super) fn reference(source: &str, nfq: &Path, output: &Path) -> Result<()> {
    fs::write(
        output.join("play_prolog_reference.inc"),
        [
            section(
                source,
                "static void setup_direction(",
                "static void dp_changed(",
            )?,
            section(
                source,
                "static bool play_prolog(",
                "static bool dp_rediscovery(",
            )?,
        ]
        .concat(),
    )?;
    let helpers = fs::read_to_string(nfq.join("darkmagic.c"))?;
    fs::write(
        output.join("play_prolog_helpers.inc"),
        [
            section(
                &helpers,
                "void extract_endpoints(",
                "const char *proto_name(",
            )?,
            section(&helpers, "uint8_t ttl46(", "\n}\n")?,
            "\n}\n",
        ]
        .concat(),
    )?;
    Ok(())
}

pub(super) fn apply(source: &mut String) -> Result<()> {
    let old = section(
        source,
        "static bool play_prolog(",
        "static bool dp_rediscovery(",
    )?
    .to_owned();
    *source = source.replacen(&old, "#include \"play_prolog_windows.inc\"\n\n", 1);
    let old = section(
        source,
        "static void setup_direction(",
        "static void dp_changed(",
    )?
    .to_owned();
    *source = source.replacen(&old, "", 1);
    ensure!(
        !source.contains("static bool play_prolog(")
            && !source.contains("static void setup_direction("),
        "Pinned C play setup was not replaced"
    );
    Ok(())
}
