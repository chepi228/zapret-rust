//! Compare socket representations and host edits before replacing their C bodies.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Address helper source parent")?
        .join("address-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("helpers.c");
    let mut source = fs::read_to_string(&path)?;
    let names = [
        "strip_host_to_ip",
        "ntopa46",
        "ntop46",
        "ntop46_port",
        "saport",
        "sa_has_addr",
    ];
    let mut reference = String::new();
    for name in names {
        reference.push_str(&format!("#define {name} reference_{name}\n"));
    }
    for name in names {
        let start = source
            .lines()
            .scan(0, |offset, line| {
                let start = *offset;
                *offset += line.len() + 1;
                Some((start, line))
            })
            .find_map(|(start, line)| line.contains(&format!(" {name}(")).then_some(start))
            .with_context(|| format!("Pinned address helper: {name}"))?;
        let end = source[start..]
            .find("\n}\n")
            .context("Pinned address helper end")?
            + start
            + 3;
        reference.push_str(&source[start..end]);
        source.replace_range(start..end, "");
    }
    for name in names {
        reference.push_str(&format!("#undef {name}\n"));
    }
    fs::write(directory.join("address_reference.inc"), reference)?;
    let exe = directory.join("address-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
    ]);
    for include in [&directory, shim, &shim.join("include"), nfq] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("address_oracle.c"))
        .arg(library)
        .args([
            "-Wl,--gc-sections",
            "-static",
            "-lws2_32",
            "-lbcrypt",
            "-lntdll",
            "-luserenv",
            "-ladvapi32",
            "-lwinpthread",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(&command, &directory, "Compile address helper comparison")?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Compare engine address helpers",
    )?;
    ensure!(
        result.starts_with("PASS engine_address "),
        "Incomplete address helper comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    fs::write(path, source)?;
    let header = nfq.join("helpers.h");
    let mut source = fs::read_to_string(&header)?;
    source.insert_str(0, "#include \"address_windows.h\"\n");
    fs::write(header, source)?;
    Ok(())
}
