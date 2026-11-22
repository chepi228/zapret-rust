//! Validate the old CLI syntax before switching its filter parsers.
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
        .context("Filter options source parent")?
        .join("filter-config-check");
    fs::create_dir(&directory)?;
    let cli = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&cli)?;
    let start = source
        .find("static bool parse_l7_list(")
        .context("Pinned CLI L7 parser")?;
    let end = start
        + source[start..]
            .find("static bool parse_pf_list(")
            .context("Pinned CLI L7 parser end")?;
    fs::write(directory.join("mask_reference.inc"), &source[start..end])?;
    let ip_list = end
        + source[end..]
            .find("static bool parse_ipp_list(")
            .context("Pinned IP protocol list parser")?;
    let list_end = ip_list
        + source[ip_list..]
            .find("\n}\n")
            .context("Pinned filter list end")?
        + "\n}\n".len();
    fs::write(
        directory.join("filter_list_reference.inc"),
        &source[end..list_end],
    )?;
    let file_start = source
        .find("static bool parse_filespec(")
        .context("Pinned file spec parser")?;
    let file_end = file_start
        + source[file_start..]
            .find("static void load_file_or_exit(")
            .context("Pinned file spec end")?;
    fs::write(
        directory.join("filespec_reference.inc"),
        &source[file_start..file_end],
    )?;
    let version_start = source
        .find("static bool wf_make_l3(")
        .context("Pinned IP version parser")?;
    let version_end = version_start
        + source[version_start..]
            .find("\n}\n")
            .context("Pinned IP version end")?
        + "\n}\n".len();
    fs::write(
        directory.join("version_filter_reference.inc"),
        &source[version_start..version_end],
    )?;
    let render_start = source
        .find("static bool wf_make_pf(")
        .context("Pinned capture expression start")?;
    let render_end = render_start
        + source[render_start..]
            .find("static unsigned int hash_jen(")
            .context("Pinned capture expression end")?;
    fs::write(
        directory.join("capture_filter_reference.inc"),
        &source[render_start..render_end],
    )?;
    let filters = nfq.join("filter.c");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-D_POSIX_C_SOURCE=200809L",
        "-Wno-macro-redefined",
    ]);
    for include in [
        &directory,
        shim,
        &shim.join("include"),
        &nfq.join("windows"),
        nfq,
    ] {
        command.arg(format!("-I{}", include.display()));
    }
    let executable = directory.join("filter-config-check.exe");
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("filter_config_oracle.c"))
        .arg(&filters)
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
        .arg(&executable);
    tools.run_command(
        &command,
        &directory,
        "Compile configuration filter comparison",
    )?;
    let result = tools.run_command(
        &Command::new(executable),
        &directory,
        "Compare configuration filters",
    )?;
    ensure!(
        result.starts_with("PASS filter_config ")
            && result
                .lines()
                .any(|line| line.starts_with("PASS startup_arguments "))
            && result
                .lines()
                .any(|line| line.starts_with("PASS capture_filter ")),
        "Incomplete configuration filter comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(
        render_start..render_end,
        "#include \"windivert_filter_windows.inc\"\n\n",
    );
    source.replace_range(version_start..version_end,
        "bool zapret_filter_ip_versions(const char *, bool *, bool *);\n#define wf_make_l3 zapret_filter_ip_versions\n");
    source.replace_range(end..list_end, "#include \"filter_lists_windows.inc\"\n\n");
    source.replace_range(
        start..end,
        concat!(
            "#include \"filters_windows.h\"\n",
            "#define parse_l7_list zapret_parse_l7_list\n",
            "#define parse_l7p_list zapret_parse_payload_list\n\n",
        ),
    );
    source.replace_range(
        file_start..file_end,
        "#include \"filespec_windows.inc\"\n\n",
    );
    fs::write(cli, source)?;
    let mut codec = fs::read_to_string(&filters)?;
    let start = codec
        .find("bool pf_match(")
        .context("Pinned filter functions")?;
    let end = start
        + codec[start..]
            .find("void str_cidr4(")
            .context("Pinned filter function end")?;
    codec.replace_range(start..end, "#include \"filters_windows.inc\"\n\n");
    fs::write(filters, codec)?;
    Ok(())
}
