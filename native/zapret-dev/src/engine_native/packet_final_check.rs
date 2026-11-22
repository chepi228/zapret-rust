//! Compare complete final packet flows before selecting the new C dispatchers.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let start = source
        .find(anchor)
        .with_context(|| format!("Missing final-flow {anchor}"))?;
    let end = start
        + source[start..]
            .find("\n}\n")
            .context("Final-flow function end")?
        + 3;
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
    let parent = nfq.parent().context("Final packet flow parent")?;
    let directory = parent.join("packet-final-check");
    fs::create_dir(&directory)?;
    let invocation = parent.join("lua-invocation-check");
    for name in [
        "engine_lua.h",
        "lua_invocation_common.inc",
        "lua_invocation_reference.inc",
    ] {
        fs::copy(invocation.join(name), directory.join(name))?;
    }
    for (name, entry, replacement) in [
        (
            "lua_invocation_oracle.c",
            "int main(void)",
            "static int invocation_contract_main(void)",
        ),
        (
            "packet_play_oracle.c",
            "int main(void)",
            "static int packet_contract_main(void)",
        ),
    ] {
        let source = fs::read_to_string(shim.join(name))?;
        ensure!(
            source.matches(entry).count() == 1,
            "Pinned whole-flow oracle entry changed"
        );
        fs::write(
            directory.join(if name.starts_with("lua_") {
                "desync_invocation_contract.inc"
            } else {
                "packet_finish_contract.inc"
            }),
            source.replace(entry, replacement),
        )?;
    }
    fs::write(
        directory.join("lua_invocation_candidate.inc"),
        "#include \"desync_policy_windows.inc\"\n",
    )?;
    let lua_source = fs::read_to_string(nfq.join("lua.c"))?;
    let mut panic_reference = String::new();
    for anchor in ["static void lua_perror(", "static int lua_panic("] {
        panic_reference.push_str(&lua_source[function(&lua_source, anchor)?]);
        panic_reference.push('\n');
    }
    fs::write(
        directory.join("desync_panic_reference.inc"),
        panic_reference,
    )?;
    for name in [
        "packet_checksum_reference.inc",
        "packet_play_reference.inc",
        "packet_play_state.inc",
        "packet_route_reference.inc",
    ] {
        fs::copy(
            parent.join("packet-play-check").join(name),
            directory.join(name),
        )?;
    }
    let play_path = shim.join("packet_play_windows.inc");
    let mut play = fs::read_to_string(&play_path)?;
    let body = function(&play, "static uint8_t packet_play_finish(")?;
    play.replace_range(body, "#include \"packet_finish_policy_windows.inc\"\n");
    fs::write(directory.join("packet_play_windows.inc"), &play)?;
    let mut log = String::new();
    for (domain, prefix) in [
        ("desync", "PASS desync_final "),
        ("packet_finish", "PASS packet_finish "),
    ] {
        let exe = directory.join(format!("{domain}-check.exe"));
        let mut command = Command::new(tools.compiler);
        command.args([
            "-O2",
            "-std=gnu99",
            "-ffunction-sections",
            "-fdata-sections",
            "-DZAPRET_WINDOWS=1",
            "-DZAPRET_NATIVE_WINDOWS=1",
            "-D_FILE_OFFSET_BITS=64",
            "-D_POSIX_C_SOURCE=200809L",
            "-DLUAJIT",
            "-Wno-macro-redefined",
        ]);
        for include in [
            &directory,
            &parent.join("protocol-check"),
            &parent.join("packet-input-check"),
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
            .arg(shim.join(format!("{domain}_policy_oracle.c")));
        if domain == "desync" {
            command
                .arg(shim.join("win_files.c"))
                .arg(lua.join("libluajit.a"));
        } else {
            command.arg(nfq.join("checksum.c"));
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
                "-lole32",
                "-lshell32",
                "-luser32",
                "-lwinpthread",
                "-o",
            ])
            .arg(&exe);
        tools.run_command(
            &command,
            &directory,
            "Compile complete final packet flow comparison",
        )?;
        let text = tools.run_command(
            &Command::new(exe),
            &directory,
            "Compare complete LuaJIT final/replay and packet play flows",
        )?;
        ensure!(
            text.lines().any(|line| line.starts_with(prefix)),
            "Incomplete final flow comparison: {domain}"
        );
        log.push_str(&text);
    }
    fs::write(output, &log)?;
    print!("{log}");
    // Select only after both independent whole-entry comparisons succeeded.
    let path = nfq.join("desync.c");
    let mut source = fs::read_to_string(&path)?;
    let body = function(&source, "static uint8_t desync(\n")?;
    ensure!(
        source[body.clone()].contains("native_lua_invocation("),
        "Final flow must follow invocation migration"
    );
    source.replace_range(body, "#include \"desync_policy_windows.inc\"\n");
    fs::write(path, source)?;
    fs::write(play_path, play)?;
    Ok(())
}
