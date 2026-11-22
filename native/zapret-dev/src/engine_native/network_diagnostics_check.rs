//! Compare the actual listing layout on fake COM interfaces, without using host networks.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    [library, object]: [&Path; 2],
    lua: &Path,
    source: &mut String,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Network listing source parent")?
        .join("network-listing-check");
    fs::create_dir(&directory)?;
    let mut reference = String::new();
    for (start, replacement) in [
        ("static void guid2str(", ""),
        (
            "bool nlm_list(",
            "#include \"network_diagnostics_windows.inc\"\n",
        ),
        ("static const char *sNetworkCards=", ""),
    ] {
        let first = source
            .find(start)
            .with_context(|| format!("Missing pinned network listing block: {start}"))?;
        let end = first
            + source[first..]
                .find("\n}\n")
                .context("Pinned network listing block end")?
            + 3;
        if !start.starts_with("static const") {
            reference.push_str(&source[first..end]);
        }
        source.replace_range(first..end, replacement);
    }
    fs::write(
        directory.join("network_diagnostics_reference.inc"),
        reference,
    )?;
    let mut results = String::new();
    for direct in [false, true] {
        let exe = directory.join(if direct {
            "network-listing-rust-check.exe"
        } else {
            "network-listing-check.exe"
        });
        let mut command = Command::new(tools.compiler);
        command.args([
            "-O2",
            "-std=gnu99",
            "-ffunction-sections",
            "-fdata-sections",
            "-DZAPRET_WINDOWS=1",
            "-DZAPRET_NATIVE_WINDOWS=1",
            "-D_POSIX_C_SOURCE=200809L",
            "-DLUAJIT",
            "-Wno-macro-redefined",
        ]);
        for include in [
            &directory,
            shim,
            &shim.join("include"),
            &nfq.join("windows"),
            lua,
            nfq,
        ] {
            command.arg(format!("-I{}", include.display()));
        }
        command
            .arg("-include")
            .arg(shim.join("win_platform.h"))
            .arg(shim.join("network_diagnostics_oracle.c"));
        if direct {
            command.args([
                "-DZAPRET_DIRECT_NETWORK_REPORT=1",
                "-Wl,--wrap=zapret_network_environment_list,--wrap=__acrt_iob_func,--wrap=fwrite",
            ]).arg(object);
        }
        command
            .arg(library)
            .args([
                "-Wl,--gc-sections",
                "-static",
                "-lole32",
                "-loleaut32",
                "-lws2_32",
                "-lbcrypt",
                "-lntdll",
                "-luserenv",
                "-ladvapi32",
                "-lwinpthread",
                "-o",
            ])
            .arg(&exe);
        tools.run_command(&command, &directory, "Compile NLM listing comparison")?;
        let result = tools.run_command(&Command::new(exe), &directory, "Compare NLM listing")?;
        ensure!(
            result.starts_with("PASS network_listing ")
                && (!direct || result.contains("rust_stdio=16")),
            "Incomplete NLM listing comparison"
        );
        print!("{result}");
        results.push_str(&result);
    }
    fs::write(output, results)?;
    Ok(())
}
