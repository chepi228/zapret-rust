#![cfg_attr(all(windows, not(test)), windows_subsystem = "windows")]
//! Native hidden host for the interactive user's scheduled helpers. Its job owns the real
//! controller from the first instruction and ends with this process.
use anyhow::{Context, Result, ensure};
use std::{
    ffi::OsString,
    io::{self, Read, Seek, SeekFrom, Write},
    path::PathBuf,
    time::Duration,
};
use zapret_platform::{OwnedChild, RunOptions};

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("zapret-rust worker: {error:#}");
            1
        }
    };
    std::process::exit(code);
}

fn run() -> Result<i32> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|value| value == "--self-check") {
        ensure!(
            args.len() == 1 || args.len() == 2 && args[1] == "--wait",
            "Invalid worker self-check arguments"
        );
        let has_console =
            !unsafe { windows_sys::Win32::System::Console::GetConsoleWindow() }.is_null();
        println!(
            "{}",
            serde_json::json!({"worker":"RustWindowsGui","console_window":has_console,"pid":std::process::id()})
        );
        io::stdout().flush()?;
        if args.len() == 2 {
            io::stdin().read_line(&mut String::new())?;
        }
        return Ok(0);
    }
    let (root, command) = parse(&args)?;
    let image = std::env::current_exe()?;
    let installed_root = image
        .parent()
        .and_then(|path| path.parent())
        .context("Native worker installation directory")?;
    ensure!(
        std::fs::canonicalize(&root)? == std::fs::canonicalize(installed_root)?,
        "Native worker and controller must belong to the same package"
    );
    let controller = root.join("bin/zapret-rust.exe");
    ensure!(controller.is_file(), "Native controller is missing");
    console_controller(&controller)?;
    let mut arguments = vec![OsString::from("--root"), root.as_os_str().to_owned()];
    arguments.extend(command);
    let child = OwnedChild::spawn(
        &controller,
        &arguments,
        &RunOptions {
            cwd: Some(root),
            timeout: Duration::from_secs(30),
            max_output_bytes: 65536,
            ..Default::default()
        },
    )?;
    let result = child.supervise()?;
    // Scheduled helpers have no console; retain bounded redirected output for
    // explicit invocation and fixture diagnostics without backpressure on them.
    let _ = io::stdout().write_all(&result.stdout);
    let _ = io::stderr().write_all(&result.stderr);
    Ok(result.exit_code as i32)
}

fn console_controller(path: &std::path::Path) -> Result<()> {
    let mut file = std::fs::File::open(path)?;
    let mut dos = [0u8; 64];
    file.read_exact(&mut dos)?;
    let offset = u32::from_le_bytes(dos[0x3c..0x40].try_into()?);
    ensure!(
        &dos[..2] == b"MZ" && (64..=65536).contains(&offset),
        "Invalid native controller header"
    );
    file.seek(SeekFrom::Start(offset.into()))?;
    let mut pe = [0u8; 94];
    file.read_exact(&mut pe)?;
    ensure!(
        &pe[..4] == b"PE\0\0"
            && u16::from_le_bytes(pe[4..6].try_into()?) == 0x8664
            && u16::from_le_bytes(pe[24..26].try_into()?) == 0x20b
            && u16::from_le_bytes(pe[92..94].try_into()?) == 3,
        "Background host requires the native console controller, not another GUI host"
    );
    Ok(())
}

fn parse(args: &[OsString]) -> Result<(PathBuf, Vec<OsString>)> {
    ensure!(
        args.len() >= 3 && args[0] == "--root",
        "Expected --root PACKAGE and a background command"
    );
    let root = PathBuf::from(&args[1]);
    ensure!(
        root.is_absolute() && root.is_dir(),
        "Background package root must be an existing absolute directory"
    );
    let command = &args[2..];
    let values = command
        .iter()
        .map(|value| value.to_str().context("Background command must be text"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        matches!(
            values.as_slice(),
            ["notify", "--watch"] | ["telegram", "supervise"]
        ),
        "Unsupported background command"
    );
    Ok((std::path::absolute(root)?, command.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_accepts_only_the_scheduled_background_commands() {
        let temporary = tempfile::tempdir().unwrap();
        for command in [vec!["notify", "--watch"], vec!["telegram", "supervise"]] {
            let mut args = vec![
                OsString::from("--root"),
                temporary.path().as_os_str().into(),
            ];
            args.extend(command.iter().map(OsString::from));
            assert!(parse(&args).is_ok());
        }
        for command in [
            vec!["menu"],
            vec!["start"],
            vec!["watch"],
            vec!["autotune"],
            vec!["watch", "--unknown"],
            vec!["telegram", "stop"],
            vec!["notify"],
        ] {
            let mut args = vec![
                OsString::from("--root"),
                temporary.path().as_os_str().into(),
            ];
            args.extend(command.iter().map(OsString::from));
            assert!(parse(&args).is_err());
        }
    }
}
