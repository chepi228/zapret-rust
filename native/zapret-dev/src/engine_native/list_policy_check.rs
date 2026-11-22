//! Compare active file traversal, reload order and packet include/exclude rules.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn function(source: &str, name: &str) -> Result<String> {
    let start = source
        .find(&format!(" {name}("))
        .with_context(|| format!("Pinned list policy function {name}"))?;
    let start = source[..start].rfind('\n').map_or(0, |index| index + 1);
    let end = source[start..]
        .find("\n}\n")
        .context("Pinned list policy function end")?
        + start
        + 3;
    Ok(source[start..end].to_owned())
}
fn remove(source: &mut String, names: &[&str]) -> Result<()> {
    for name in names {
        let body = function(source, name)?;
        *source = source.replacen(&body, "", 1);
    }
    Ok(())
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
        .context("List policy parent")?
        .join("list-policy-check");
    fs::create_dir(&directory)?;
    let hosts_path = nfq.join("hostlist.c");
    let ips_path = nfq.join("ipset.c");
    let mut hosts = fs::read_to_string(&hosts_path)?;
    let mut ips = fs::read_to_string(&ips_path)?;
    let host_names = [
        "LoadHostLists",
        "LoadAllHostLists",
        "HostlistsReloadCheck",
        "HostlistsReloadCheckForProfile",
        "HostlistCheck_",
        "HostlistCheck",
    ];
    let ip_names = [
        "LoadIpsets",
        "LoadAllIpsets",
        "SearchIpset",
        "IpsetsReloadCheck",
        "IpsetsReloadCheckForProfile",
        "IpsetCheck_",
        "IpsetCheck",
    ];
    let mut reference = String::new();
    for name in host_names.into_iter().chain(ip_names) {
        reference.push_str(&format!("#define {name} reference_{name}\n"));
    }
    for name in host_names {
        reference.push_str(&function(&hosts, name)?);
    }
    for name in ip_names {
        reference.push_str(&function(&ips, name)?);
    }
    for name in host_names.into_iter().chain(ip_names) {
        reference.push_str(&format!("#undef {name}\n"));
    }
    fs::write(directory.join("list_policy_reference.inc"), reference)?;
    let exe = directory.join("list-policy-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
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
        &nfq.join("windows"),
        lua,
        nfq,
    ] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("list_policy_oracle.c"))
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
    tools.run_command(
        &command,
        &directory,
        "Compile host and IP list policy comparison",
    )?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Check host and IP list policy",
    )?;
    ensure!(
        result.starts_with("PASS list_policy "),
        "Incomplete list policy comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    remove(&mut hosts, &host_names)?;
    remove(&mut ips, &ip_names)?;
    let marker = "#include \"host_search_windows.c\"";
    ensure!(
        hosts.matches(marker).count() == 1,
        "Pinned host search adapter changed"
    );
    hosts = hosts.replace(marker, "#include \"host_policy_windows.inc\"");
    let marker = "#include \"list_reload_windows.inc\"";
    ensure!(
        ips.matches(marker).count() == 1,
        "Pinned IP reload adapter changed"
    );
    ips = ips.replace(
        marker,
        &format!("{marker}\n#include \"ip_policy_windows.inc\""),
    );
    fs::write(hosts_path, hosts)?;
    fs::write(ips_path, ips)?;
    Ok(())
}
