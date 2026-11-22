//! Preserve CIDR rendering and mask bytes, with atomic parsing on invalid input.
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
        .context("Address prefix parent")?
        .join("address-prefix-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("filter.c");
    let mut filter = fs::read_to_string(&path)?;
    let start = filter
        .find("void str_cidr4(")
        .context("Pinned CIDR conversion")?;
    let helpers_path = nfq.join("helpers.c");
    let mut helpers = fs::read_to_string(&helpers_path)?;
    let masks = helpers
        .find("#ifdef ZAPRET_WINDOWS\nuint32_t mask_from_bitcount(")
        .context("Pinned address masks")?;
    let reference = format!("{}\n{}", &filter[start..], &helpers[masks..]);
    fs::write(directory.join("address_prefix_reference.inc"), reference)?;
    let exe = directory.join("address-prefix-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
    ]);
    for include in [&directory, shim, &shim.join("include"), nfq] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("address_prefix_oracle.c"))
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
    tools.run_command(&command, &directory, "Compile CIDR and mask comparison")?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Check engine address prefixes",
    )?;
    ensure!(
        result.starts_with("PASS address_prefix "),
        "Incomplete address prefix comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    filter.replace_range(start.., "#include \"address_prefix_windows.inc\"\n");
    helpers.truncate(masks);
    fs::write(path, filter)?;
    fs::write(helpers_path, helpers)?;
    let header = nfq.join("helpers.h");
    let mut source = fs::read_to_string(&header)?;
    source.insert_str(0, "#include \"address_prefix_windows.h\"\n");
    fs::write(header, source)?;
    Ok(())
}
