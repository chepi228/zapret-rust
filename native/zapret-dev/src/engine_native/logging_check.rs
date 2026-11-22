//! Preserve buffered diagnostics and hex output while checking thread boundaries.
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
        .context("Logging source parent")?
        .join("logging-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("params.c");
    let mut source = fs::read_to_string(&path)?;
    let mut reference = String::new();
    for (name, include) in [
        ("log_buffered", "logging_windows.inc"),
        ("hexdump_limited_dlog", "logging_hex_windows.inc"),
    ] {
        let start = source
            .find(&format!("void {name}("))
            .context("Pinned diagnostic function")?;
        let start = source[..start].rfind('\n').map_or(0, |index| index + 1);
        let end = source[start..]
            .find("\n}\n")
            .context("Pinned diagnostic function end")?
            + start
            + 3;
        reference.push_str(&source[start..end]);
        source.replace_range(start..end, &format!("#include \"{include}\"\n"));
    }
    for declaration in [
        "static char log_buf[4096];\n",
        "static size_t log_buf_sz=0;\n",
    ] {
        ensure!(
            source.matches(declaration).count() == 1,
            "Pinned log buffer changed"
        );
        source = source.replace(declaration, "");
    }
    fs::write(directory.join("logging_reference.inc"), reference)?;
    let exe = directory.join("logging-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
    ]);
    for include in [&directory, shim] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg(shim.join("logging_oracle.c"))
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
    tools.run_command(&command, &directory, "Compile engine diagnostic comparison")?;
    let result = tools.run_command(
        &Command::new(exe),
        &directory,
        "Compare engine diagnostic output",
    )?;
    ensure!(
        result.starts_with("PASS engine_logging "),
        "Incomplete engine logging comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    fs::write(path, source)?;
    Ok(())
}

pub(super) fn snapshot_sources(nfq: &Path, shim: &Path, lua: &Path, snapshot: &Path) -> Result<()> {
    let native_sources = snapshot.join("nfq2");
    if native_sources.is_dir() {
        for entry in fs::read_dir(&native_sources)? {
            let entry = entry?;
            if entry.file_type()?.is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "c")
                && !nfq.join(entry.file_name()).is_file()
            {
                fs::remove_file(entry.path())?;
            }
        }
    }
    snapshot_headers(nfq, &native_sources, true, false)?;
    snapshot_headers(shim, &snapshot.join("windows-support"), false, true)?;
    let lua_target = snapshot.join("luajit");
    fs::create_dir_all(&lua_target)?;
    for name in ["lua.h", "luaconf.h", "lauxlib.h", "lualib.h", "luajit.h"] {
        fs::copy(lua.join(name), lua_target.join(name))?;
    }
    let mut units = fs::read_dir(nfq)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    units.retain(|path| path.extension().is_some_and(|extension| extension == "c"));
    units.sort();
    let mut compiled = String::new();
    for file in units {
        compiled.push_str(&format!(
            "nfq2/{}\n",
            file.file_name().context("C unit name")?.to_string_lossy()
        ));
    }
    fs::write(snapshot.join("compiled-units.txt"), compiled)?;
    Ok(())
}

fn snapshot_headers(source: &Path, target: &Path, root_units: bool, shims: bool) -> Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let path = entry.path();
        let destination = target.join(entry.file_name());
        if kind.is_dir() {
            snapshot_headers(&path, &destination, false, false)?;
        } else if kind.is_file()
            && (path
                .extension()
                .is_some_and(|extension| extension == "h" || extension == "inc")
                || root_units && path.extension().is_some_and(|extension| extension == "c")
                || shims
                    && path.extension().is_some_and(|extension| extension == "c")
                    && !entry.file_name().to_string_lossy().contains("_oracle")
                    && !entry.file_name().to_string_lossy().contains("_reference"))
        {
            fs::copy(path, destination)?;
        }
    }
    Ok(())
}
