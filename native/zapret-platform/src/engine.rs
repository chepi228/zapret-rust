//! Validation never calls WinDivertOpen: dry-run export plus the pinned filter compiler.
use crate::{
    RunOptions, RunOutput,
    process::{same_path, wide},
    storage::{Pins, hash, read_limited},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    ffi::{CStr, OsString, c_char},
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{FreeLibrary, HMODULE},
    System::LibraryLoader::*,
};

const FILTER_LIMIT: usize = 1024 * 1024;
type Compile =
    unsafe extern "C" fn(*const u8, i32, *mut u8, u32, *mut *const c_char, *mut u32) -> i32;
struct Module(HMODULE);
impl Drop for Module {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.0);
        }
    }
}
struct Compiler {
    _module: Module,
    compile: Compile,
    manifest: zapret_core::CoreManifest,
    pins: Pins,
}
impl Compiler {
    fn load(root: &Path) -> Result<Self> {
        let manifest = zapret_core::read_core_manifest(&root.join("tools/upstream.txt"))?;
        let mut pins = Pins::new();
        for directory in [root.to_path_buf(), root.join("bin"), root.join("tools")] {
            pins.directory(&directory)?;
        }
        let bytes = pins.file(&root.join("tools/upstream.txt"))?;
        ensure!(
            hash(&bytes) == manifest.content_hash,
            "Core manifest changed before compiler lease"
        );
        let path = root.join("bin/WinDivert.dll");
        let (digest, _) = pins.file_hash(&path)?;
        ensure!(
            digest.eq_ignore_ascii_case(&manifest.hashes["bin/WinDivert.dll"]),
            "Pinned WinDivert.dll integrity check failed"
        );
        let name = wide(&path)?;
        let raw = unsafe {
            LoadLibraryExW(
                name.as_ptr(),
                null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        ensure!(
            !raw.is_null(),
            "Load pinned WinDivert.dll: {}",
            std::io::Error::last_os_error()
        );
        let module = Module(raw);
        let mut actual = vec![0u16; 32768];
        let length =
            unsafe { GetModuleFileNameW(module.0, actual.as_mut_ptr(), actual.len() as u32) };
        ensure!(
            length > 0
                && (length as usize) < actual.len()
                && same_path(
                    &PathBuf::from(std::ffi::OsString::from_wide(&actual[..length as usize])),
                    &path
                ),
            "Loaded filter compiler path differs from the pinned DLL"
        );
        let symbol =
            unsafe { GetProcAddress(module.0, c"WinDivertHelperCompileFilter".as_ptr().cast()) }
                .context("WinDivertHelperCompileFilter export is unavailable")?;
        let compile: Compile = unsafe { std::mem::transmute(symbol) };
        Ok(Self {
            _module: module,
            compile,
            manifest,
            pins,
        })
    }
    fn pin_engine(&mut self, root: &Path) -> Result<()> {
        for name in self.manifest.hashes.keys() {
            let path = root.join(name);
            self.pins
                .directory(path.parent().context("Core input parent missing")?)?;
            let (digest, _) = self.pins.file_hash(&path)?;
            ensure!(
                digest.eq_ignore_ascii_case(&self.manifest.hashes[name]),
                "Pinned engine input differs from its manifest: {name}"
            );
        }
        Ok(())
    }
    fn validate(&self, bytes: &[u8]) -> Result<Value> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= FILTER_LIMIT,
            "WinDivert filter export must contain 1..1048576 bytes"
        );
        ensure!(
            !bytes.contains(&0),
            "WinDivert filter contains an embedded NUL"
        );
        std::str::from_utf8(bytes).context("WinDivert filter export is not UTF-8")?;
        // Preserve every original UTF-8 byte, including an invalid-for-WinDivert BOM.
        let mut terminated = bytes.to_vec();
        terminated.push(0);
        let mut error = null();
        let mut position = 0;
        let accepted = unsafe {
            (self.compile)(
                terminated.as_ptr(),
                0,
                null_mut(),
                0,
                &mut error,
                &mut position,
            )
        };
        if accepted == 0 {
            let message = if error.is_null() {
                "filter rejected".into()
            } else {
                unsafe { CStr::from_ptr(error) }
                    .to_string_lossy()
                    .into_owned()
            };
            anyhow::bail!("WinDivert filter rejected at byte {position}: {message}");
        }
        Ok(
            json!({"ok":true,"compiler":"WinDivertHelperCompileFilter","filter_bytes":bytes.len(),"filter_sha256":hash(bytes)}),
        )
    }
}
pub fn validate_capture_filter(root: &Path, bytes: &[u8]) -> Result<Value> {
    Compiler::load(root)?.validate(bytes)
}
fn forced_arguments(root: &Path, arguments: &[String], export: &Path) -> Result<Vec<OsString>> {
    ensure!(
        arguments.len() <= 8192
            && arguments
                .iter()
                .all(|argument| !argument.starts_with("--wf-save")
                    && !argument.starts_with("--dry-run=")),
        "Validation owns the dry-run mode and filter export path"
    );
    let mut checked = vec!["--dry-run".to_owned()];
    checked.extend(
        arguments
            .iter()
            .filter(|argument| argument.as_str() != "--dry-run")
            .cloned(),
    );
    checked.push(format!("--wf-save={}", export.display()));
    checked.push("--wf-dup-check=0".into());
    Ok(zapret_core::checked_command_line(root, &checked)?
        .into_iter()
        .map(OsString::from)
        .collect())
}
fn validate_export(
    root: &Path,
    arguments: &[String],
    retry_delay: Duration,
    privileged: bool,
    mut runner: impl FnMut(&[OsString], &Path) -> Result<RunOutput>,
    mut compiler: impl FnMut(&[u8]) -> Result<Value>,
) -> Result<Value> {
    let directory = tempfile::Builder::new()
        .prefix("zapret-rust-filter-")
        .tempdir()?;
    if privileged {
        crate::protect_path(directory.path())?;
    }
    let file = tempfile::Builder::new()
        .prefix("zapret-rust-filter-")
        .suffix(".txt")
        .tempfile_in(directory.path())?;
    let export = file.into_temp_path();
    let arguments = forced_arguments(root, arguments, &export)?;
    let mut attempts = 0;
    let output = loop {
        attempts += 1;
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&export)?
            .sync_all()?;
        let output = runner(&arguments, &export)?;
        let silent_startup_failure = output.exit_code != 0
            && !output.timed_out
            && !output.output_truncated
            && output.stdout.is_empty()
            && output.stderr.is_empty();
        if silent_startup_failure && attempts == 1 {
            std::thread::sleep(retry_delay);
            continue;
        }
        break output;
    };
    ensure!(
        !output.timed_out && !output.output_truncated && output.exit_code == 0,
        "Engine dry-run failed (exit {}, timeout {}, truncated {}): {} {}",
        output.exit_code,
        output.timed_out,
        output.output_truncated,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = read_limited(&export, FILTER_LIMIT as u64)?;
    ensure!(
        !bytes.is_empty(),
        "Engine exited without exporting the full capture filter"
    );
    let mut result = compiler(&bytes)?;
    result["attempts"] = json!(attempts);
    result["output"] = json!(String::from_utf8_lossy(&output.stdout));
    result["stderr"] = json!(String::from_utf8_lossy(&output.stderr));
    Ok(result)
}
pub fn validate_engine_args(root: &Path, arguments: &[String]) -> Result<Value> {
    let mut compiler = Compiler::load(root)?;
    compiler.pin_engine(root)?;
    let mut options = RunOptions {
        cwd: Some(root.join("bin")),
        timeout: Duration::from_secs(15),
        max_output_bytes: FILTER_LIMIT,
        ..Default::default()
    };
    let privileged = crate::is_admin()?;
    if !privileged {
        options
            .env
            .insert("__COMPAT_LAYER".into(), "RunAsInvoker".into());
    }
    validate_export(
        root,
        arguments,
        Duration::from_millis(500),
        privileged,
        |arguments, _| crate::run_owned(&root.join("bin/winws2.exe"), arguments, &options),
        |bytes| compiler.validate(bytes),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn output(exit_code: u32) -> RunOutput {
        RunOutput {
            identity: crate::ProcessIdentity {
                pid: 1,
                created_filetime: 1,
                executable: "C:/fixture.exe".into(),
            },
            exit_code,
            timed_out: false,
            stdout: Vec::new(),
            stderr: Vec::new(),
            output_truncated: false,
        }
    }
    #[test]
    fn real_pinned_compiler_accepts_valid_bytes_and_rejects_unknown_fields_bom_and_nul() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        // Cross-target tests use an extracted fixture with a matching pinned DLL.
        let fixture = std::env::var_os("ZAPRET_TEST_WINDIVERT_ROOT").map(PathBuf::from);
        let root = fixture.as_deref().unwrap_or(repo);
        let compiler = Compiler::load(root)
            .expect("the test root must contain a pinned WinDivert DLL for the test architecture");
        for valid in [
            b"true".as_slice(),
            b"outbound and tcp",
            b"ipv6 and inbound and tcp.Syn",
        ] {
            assert_eq!(compiler.validate(valid).unwrap()["ok"], true);
        }
        for invalid in [
            b"outbound and zapret_unknown_field".as_slice(),
            b"\xef\xbb\xbftrue",
            b"tcp\0 or udp",
            b"",
        ] {
            assert!(compiler.validate(invalid).is_err());
        }
    }
    #[test]
    fn complete_export_is_required_and_timeout_or_truncation_never_becomes_success() {
        let root = tempfile::tempdir().unwrap();
        for mode in ["missing", "empty", "oversized", "timeout", "truncated"] {
            let mut path = None;
            let result = validate_export(
                root.path(),
                &["--wf-raw=outbound and tcp".into()],
                Duration::ZERO,
                false,
                |arguments, export| {
                    path = Some(export.to_path_buf());
                    assert!(arguments.iter().any(|argument| argument == "--dry-run"));
                    assert!(
                        arguments
                            .iter()
                            .any(|argument| argument == "--wf-dup-check=0")
                    );
                    let mut result = output(0);
                    match mode {
                        "missing" => std::fs::remove_file(export)?,
                        "empty" => {}
                        "oversized" => std::fs::write(export, vec![b'a'; FILTER_LIMIT + 1])?,
                        "timeout" => result.timed_out = true,
                        "truncated" => result.output_truncated = true,
                        _ => unreachable!(),
                    }
                    Ok(result)
                },
                |_| panic!("incomplete native output must not be compiled"),
            );
            assert!(result.is_err(), "{mode}");
            assert!(
                !path.unwrap().exists(),
                "Owned export must be removed for {mode}"
            );
        }
    }
    #[test]
    fn only_one_silent_startup_retry_is_allowed_and_exact_export_bytes_are_preserved() {
        let root = tempfile::tempdir().unwrap();
        let mut attempts = 0;
        let mut path = None;
        let result = validate_export(
            root.path(),
            &[],
            Duration::ZERO,
            false,
            |_, export| {
                path = Some(export.to_path_buf());
                attempts += 1;
                if attempts == 1 {
                    return Ok(output(0xc0000142));
                }
                std::fs::write(export, b"\xef\xbb\xbftrue")?;
                Ok(output(0))
            },
            |bytes| {
                assert_eq!(bytes, b"\xef\xbb\xbftrue");
                anyhow::bail!("fixture rejects unchanged BOM")
            },
        );
        assert!(result.is_err());
        assert_eq!(attempts, 2);
        assert!(!path.unwrap().exists());
        let mut attempts = 0;
        assert!(
            validate_export(
                root.path(),
                &[],
                Duration::ZERO,
                false,
                |_, _| {
                    attempts += 1;
                    Ok(output(1))
                },
                |_| panic!("failed startup cannot compile a filter")
            )
            .is_err()
        );
        assert_eq!(attempts, 2);
    }
}
