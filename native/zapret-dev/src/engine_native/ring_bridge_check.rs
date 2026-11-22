//! Compare both complete Lua bridges before selecting the Rust policy.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    rust_vm: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Ring bridge parent")?
        .join("ring-bridge-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("rust_ring.c");
    let source = fs::read_to_string(&path)?;
    let loader = source
        .find("static int rr_load(")
        .context("Pinned ring loader")?;
    let gc = source
        .find("static int rr_gc(")
        .context("Pinned ring finalizer")?;
    let entry = source
        .find("static int rr_call(")
        .context("Pinned ring entry")?;
    ensure!(loader < gc && gc < entry, "Pinned ring bridge boundaries");
    fs::write(directory.join("ring_bridge_types.inc"), &source[..loader])?;
    fs::write(directory.join("ring_bridge_gc.inc"), &source[gc..entry])?;
    fs::write(
        directory.join("ring_bridge_reference.inc"),
        &source[entry..],
    )?;
    let names_start = source
        .find("const char *names[]={")
        .context("Pinned ring catalog")?;
    let names_end = names_start
        + source[names_start..]
            .find("};")
            .context("End of ring catalog")?
        + 2;
    fs::write(
        directory.join("ring_bridge_names.inc"),
        &source[names_start..names_end],
    )?;

    let mut reports = String::new();
    for (label, vm_object) in [("ring_bridge", None), ("ring_rust_vm", Some(rust_vm))] {
        let exe = directory.join(format!("{label}.exe"));
        let mut command = Command::new(tools.compiler);
        command.args([
            "-O2",
            "-fexceptions",
            "-std=gnu11",
            "-ffunction-sections",
            "-fdata-sections",
        ]);
        for include in [&directory, shim, lua, nfq] {
            command.arg(format!("-I{}", include.display()));
        }
        command
            .arg(shim.join("ring_bridge_oracle.c"))
            .arg(shim.join("win_files.c"));
        if let Some(object) = vm_object {
            command
                .args(["-DZAPRET_RUST_RING_VM=1", "-Wl,--wrap=lua_setfield"])
                .arg(object);
        }
        command
            .arg(lua.join("libluajit.a"))
            .arg(library)
            .args([
                "-Wl,--gc-sections",
                "-static",
                "-lws2_32",
                "-lbcrypt",
                "-lntdll",
                "-luserenv",
                "-ladvapi32",
                "-lole32",
                "-lshell32",
                "-luser32",
                "-lwinpthread",
                "-o",
            ])
            .arg(&exe);
        tools.run_command(&command, &directory, &format!("Compile {label} comparison"))?;
        let text = tools.run_command(
            &Command::new(&exe),
            &directory,
            "Compare ring registration, operands, results, finalizers and VM faults",
        )?;
        ensure!(
            text.starts_with(&format!("PASS {label} ")),
            "Incomplete ring comparison"
        );
        reports.push_str(&text);
        print!("{text}");
    }
    fs::write(output, reports)?;
    let candidate = format!(
        "{}#include \"ring_gc_windows.inc\"\n#include \"ring_bridge_policy_windows.inc\"\n",
        &source[..gc]
    );
    fs::write(path, candidate)?;
    Ok(())
}
