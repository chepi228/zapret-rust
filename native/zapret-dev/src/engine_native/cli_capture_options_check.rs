//! Preserve the Windows CLI contract and replace its capture decisions and hash.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    object: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Capture options source parent")?
        .join("cli-capture-options-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&path)?;
    let first = source
        .find("\t\tcase IDX_WF_IFACE:")
        .context("Pinned capture options")?;
    let last = first
        + source[first..]
            .find("\n#endif")
            .context("Pinned capture options end")?;
    fs::write(
        directory.join("cli_capture_options_reference.inc"),
        &source[first..last],
    )?;
    let mut results = String::new();
    for direct in [false, true] {
        let exe = directory.join(if direct {
            "cli-capture-options-rust-check.exe"
        } else {
            "cli-capture-options-check.exe"
        });
        let mut command = Command::new(tools.compiler);
        command.args([
            "-O2",
            "-std=gnu99",
            "-ffunction-sections",
            "-fdata-sections",
            "-DZAPRET_WINDOWS=1",
            "-DZAPRET_NATIVE_WINDOWS=1",
            "-DCAPTURE_INTEGRATED_CHECK",
            "-Wno-macro-redefined",
        ]);
        for include in [&directory, shim, &shim.join("include"), nfq] {
            command.arg(format!("-I{}", include.display()));
        }
        command
            .arg("-include")
            .arg(shim.join("win_platform.h"))
            .arg(shim.join("cli_capture_options_oracle.c"));
        if direct {
            command.args([
                "-DZAPRET_CAPTURE_BINDING_DIRECT=1",
                "-Wl,--wrap=zapret_filter_clauses,--wrap=zapret_filter_ip_versions,--wrap=zapret_engine_load_file,--wrap=zapret_cli_set_number,--wrap=wf_error",
            ]).arg(object);
        }
        command
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
            "Compile Windows capture option and hash comparison",
        )?;
        let result = tools.run_command(
            &Command::new(&exe),
            &directory,
            "Compare capture decisions, hash boundaries and I/O failures",
        )?;
        ensure!(
            if direct {
                result.contains("rust_binding=1 private_paths=16")
            } else {
                result.starts_with("PASS cli_capture_options ")
            },
            "Incomplete capture option comparison"
        );
        print!("{result}");
        results.push_str(&result);
    }
    fs::write(output, results)?;
    source.replace_range(first..last, "");
    let hash = source
        .find("static unsigned int hash_jen(")
        .context("Pinned capture argument hash")?;
    let hash_end = hash
        + source[hash..]
            .find("\n}\n")
            .context("Pinned capture argument hash end")?
        + 3;
    source.replace_range(hash..hash_end, concat!(
        "uint32_t zapret_cli_capture_hash(const void *,uint32_t);\n",
        "static unsigned int hash_jen(const void *data,unsigned int length)\n{\n\treturn zapret_cli_capture_hash(data,length);\n}\n"));
    let marker = "} t_wf_index;";
    ensure!(
        source.matches(marker).count() == 1,
        "Pinned capture state enum"
    );
    source = source.replace(
        marker,
        &format!("{marker}\n#include \"cli_capture_options_windows.inc\""),
    );
    let setup = "\tsize_t argument_cursor = 1;";
    ensure!(
        source.matches(setup).count() == 1,
        "Pinned capture context setup"
    );
    source = source.replace(setup, &format!("\tzapret_capture_cli capture_cli = {{wf_save_file,sizeof(wf_save_file),&wf_ipv4,&wf_ipv6,&wf_filter_lan,&wf_filter_loopback,&wf_tcp_empty,&bDupCheck,&IfIdx,&SubIfIdx,hash_wf}};\n{setup}"));
    let anchor = "\t\tswitch (option_index)";
    ensure!(
        source.matches(anchor).count() == 1,
        "Pinned capture option dispatch"
    );
    source = source.replace(anchor, concat!(
        "\t\t{\n\t\t\tint capture = engine_capture_option(option_index, optarg, &capture_cli);\n",
        "\t\t\tif (capture < 0) exit_clean(1);\n\t\t\tif (capture == 2) exit_clean(0);\n\t\t\tif (capture > 0) continue;\n\t\t}\n",
        "\t\tswitch (option_index)"));
    fs::write(path, source)?;
    Ok(())
}
