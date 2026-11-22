//! Compare complete original presenters before selecting the Rust borrowed views.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
fn span(source: &str, signature: &str) -> Result<std::ops::Range<usize>> {
    let start = source
        .find(signature)
        .with_context(|| format!("Original diagnostic {signature}"))?;
    let end = start + source[start..].find("\n}\n").context("Diagnostic end")? + 3;
    Ok(start..end)
}
pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Diagnostic view parent")?
        .join("native-diagnostic-views-check");
    fs::create_dir(&directory)?;
    let groups = [
        (
            "hostlist.c",
            vec!["static void HostlistsDebugProfile(", "void HostlistsDebug("],
            "native_host_diagnostics_windows.inc",
        ),
        (
            "ipset.c",
            vec![
                "static const char *dbg_ipset_fill(",
                "void IpsetsDebugProfile(",
                "void IpsetsDebug(",
            ],
            "native_ip_diagnostics_windows.inc",
        ),
        (
            "nfqws.c",
            vec!["static void BlobDebug(", "static void LuaDesyncDebug("],
            "native_collection_diagnostics_windows.inc",
        ),
    ];
    let mut reference = String::new();
    let mut changes = Vec::new();
    for (name, signatures, include) in groups {
        let path = nfq.join(name);
        let original = fs::read_to_string(&path)?;
        let mut selected = original.clone();
        for (i, signature) in signatures.iter().enumerate() {
            let section = span(&original, signature)?;
            reference.push_str(&original[section]);
            let section = span(&selected, signature)?;
            selected.replace_range(
                section,
                &if i == 0 {
                    format!("#include \"{include}\"\n")
                } else {
                    String::new()
                },
            );
        }
        changes.push((path, selected));
    }
    fs::write(directory.join("native_diagnostic_reference.inc"), reference)?;
    let exe = directory.join("native-diagnostic-views-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu11",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-DLUAJIT",
        "-Wno-macro-redefined",
    ]);
    for include in [
        &directory,
        shim,
        &shim.join("include"),
        nfq,
        &nfq.join("windows"),
        lua,
    ] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("native_diagnostic_views_oracle.c"))
        .arg(library)
        .args([
            "-Wl,--gc-sections",
            "-static",
            "-lws2_32",
            "-lbcrypt",
            "-lntdll",
            "-luserenv",
            "-ladvapi32",
            "-luser32",
            "-lwinpthread",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(
        &command,
        &directory,
        "Compile complete borrowed diagnostic presenter comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare diagnostic bytes/fragments and deferred native links/fields",
    )?;
    ensure!(
        result.starts_with("PASS native_diagnostic_views "),
        "Incomplete diagnostic view comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    for (path, selected) in changes {
        fs::write(path, selected)?;
    }
    Ok(())
}
