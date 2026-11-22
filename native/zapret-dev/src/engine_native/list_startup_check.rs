//! Validate original registration, file preflight and automatic sentinels.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

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
        .context("List startup parent")?
        .join("list-startup-check");
    fs::create_dir(&directory)?;
    let mut reference = String::new();
    let mut changes = Vec::new();
    for (file, entries) in [
        (
            "hostlist.c",
            &[
                (
                    "bool NonEmptyHostlist(",
                    "#include \"list_startup_sentinel_windows.inc\"\n",
                ),
                ("static void MakeAutolistsNonEmpty(", ""),
                (
                    "struct zapret_list_file *RegisterHostlist(",
                    "#define ZAPRET_LIST_STARTUP_HOSTS 1\n#include \"list_startup_register_windows.inc\"\n#undef ZAPRET_LIST_STARTUP_HOSTS\n",
                ),
            ][..],
        ),
        (
            "ipset.c",
            &[(
                "struct zapret_list_file *RegisterIpset(",
                "#define ZAPRET_LIST_STARTUP_HOSTS 0\n#include \"list_startup_register_windows.inc\"\n#undef ZAPRET_LIST_STARTUP_HOSTS\n",
            )],
        ),
        (
            "nfqws.c",
            &[(
                "static bool test_list_files(",
                "#include \"list_startup_probe_windows.inc\"\n",
            )],
        ),
    ] {
        let path = nfq.join(file);
        let mut source = fs::read_to_string(&path)?;
        for &(name, replacement) in entries {
            let start = source
                .find(name)
                .with_context(|| format!("Pinned list startup {name}"))?;
            let end = start + source[start..].find("\n}\n").context("List startup end")? + 3;
            reference.push_str(&source[start..end]);
            reference.push('\n');
            source.replace_range(start..end, replacement);
        }
        changes.push((path, source));
    }
    fs::write(directory.join("list_startup_reference.inc"), reference)?;
    let exe = directory.join("list-startup-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu11",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-DLUAJIT",
        "-D_FILE_OFFSET_BITS=64",
        "-D_POSIX_C_SOURCE=200809L",
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
        .arg(shim.join("list_startup_oracle.c"))
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
        "Compile Windows list startup comparison",
    )?;
    let text = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare list probing, registration and sentinel behavior",
    )?;
    ensure!(
        text.starts_with("PASS list_startup "),
        "Incomplete list startup comparison"
    );
    fs::write(output, &text)?;
    print!("{text}");
    for (path, source) in changes {
        fs::write(path, source)?;
    }
    Ok(())
}
