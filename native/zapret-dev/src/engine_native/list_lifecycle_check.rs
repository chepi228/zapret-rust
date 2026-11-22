//! Gate the complete list facade fragments before selecting native adapters.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};
fn function(source: &str, name: &str) -> Result<std::ops::Range<usize>> {
    let at = source
        .find(&format!("{name}("))
        .with_context(|| format!("Pinned list lifecycle {name}"))?;
    let start = source[..at].rfind('\n').map_or(0, |n| n + 1);
    let end = start
        + source[start..]
            .find("\n}\n")
            .context("List lifecycle body end")?
        + 3;
    Ok(start..end)
}
pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("List lifecycle parent")?
        .join("list-lifecycle-check");
    fs::create_dir(&directory)?;
    let mut changes = Vec::new();
    let filter = fs::read_to_string(shim.join("filter_lists_windows.inc"))?;
    ensure!(
        filter.contains("FILTER_LIST_ADAPTER"),
        "Pinned list rollback adapter changed"
    );
    fs::write(directory.join("list_lifecycle_before_filter.inc"), filter)?;
    changes.push((
        shim.join("filter_lists_windows.inc"),
        "#include \"list_lifecycle_filter_windows.inc\"\n".to_owned(),
    ));
    for (file, name, kind) in [
        ("hostlist_windows.c", "insert_host", "host"),
        ("ipset_windows.c", "insert_ip", "ip"),
        (
            "list_registry_windows.c",
            "zapret_list_register_path",
            "registry",
        ),
    ] {
        let path = shim.join(file);
        let mut source = fs::read_to_string(&path)?;
        let range = function(&source, name)?;
        fs::write(
            directory.join(format!("list_lifecycle_before_{kind}.inc")),
            &source[range.clone()],
        )?;
        source.replace_range(
            range,
            &format!("#include \"list_lifecycle_{kind}_windows.inc\"\n"),
        );
        if kind != "registry" {
            let (function_name, target, hosts) = if kind == "host" {
                ("AppendHostList", "hostlist", 1)
            } else {
                ("AppendIpset", "ips", 0)
            };
            let range = function(&source, function_name)?;
            let body = &source[range.clone()];
            fs::write(
                directory.join(format!("list_lifecycle_before_{kind}_load.inc")),
                body,
            )?;
            let (signature, _) = body
                .split_once("\n{")
                .context("Pinned list load signature")?;
            let selected = format!(
                "{signature}\n{{\n    return append_list_file({target}, filename, {hosts}, {name});\n}}\n"
            );
            fs::write(
                directory.join(format!("list_lifecycle_{kind}_load.inc")),
                &selected,
            )?;
            source.replace_range(
                range,
                &format!("#include \"list_append_windows.inc\"\n\n{selected}"),
            );
        }
        changes.push((path, source));
    }
    let exe = directory.join("list-lifecycle-check.exe");
    let mut c = Command::new(tools.compiler);
    c.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-D_FILE_OFFSET_BITS=64",
        "-D_POSIX_C_SOURCE=200809L",
        "-Wno-macro-redefined",
    ]);
    for p in [
        &directory,
        shim,
        &shim.join("include"),
        &nfq.join("windows"),
        nfq,
    ] {
        c.arg(format!("-I{}", p.display()));
    }
    c.arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("list_lifecycle_oracle.c"))
        .arg(library)
        .args([
            "-Wl,--gc-sections",
            "-static",
            "-lws2_32",
            "-lbcrypt",
            "-lntdll",
            "-luserenv",
            "-ladvapi32",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(
        &c,
        &directory,
        "Compile whole list rollback/insertion/path comparison",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare full list facade entries, failures, backlinks and native observation order",
    )?;
    ensure!(
        result.starts_with("PASS list_lifecycle entries=8 "),
        "Incomplete list lifecycle comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    for (path, source) in changes {
        fs::write(path, source)?;
    }
    Ok(())
}
