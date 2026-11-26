mod http;
mod live;
mod menu;
mod package;
mod probe;

pub(crate) use live::run as live;
pub(crate) use menu::run as menu;
pub(crate) use package::run as package;
pub(crate) use probe::run as probe;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use zapret_core::{atomic_write, sha256_file};
use zapret_platform::{RunOptions, RunOutput, run_owned};

#[derive(Default)]
struct Evidence {
    passed: Vec<String>,
    observations: BTreeMap<String, Value>,
}
impl Evidence {
    fn check(&mut self, condition: bool, name: impl Into<String>) -> Result<()> {
        let name = name.into();
        ensure!(condition, "{name}");
        println!("ok {name}");
        self.passed.push(name);
        Ok(())
    }

    fn save(&self, output: &Path, archive: Option<&Path>, result: &Result<()>) -> Result<()> {
        let value = json!({"schema":1,"status":if result.is_ok(){"Passed"}else{"Failed"},
            "error":result.as_ref().err().map(|error|format!("{error:#}")),
            "passed":self.passed,"count":self.passed.len(),"observations":self.observations,
            "archive_sha256":archive.map(sha256_file).transpose()?,"live_changes":false,
            "privileged_install_or_restart":"NotExecuted","interactive_navigation":"NotExecuted"});
        atomic_write(
            &std::path::absolute(output)?,
            &serde_json::to_vec_pretty(&value)?,
        )?;
        println!(
            "{} {} checks; {}",
            if result.is_ok() { "PASS" } else { "FAIL" },
            self.passed.len(),
            output.display()
        );
        Ok(())
    }
}

struct Runner {
    root: PathBuf,
    executable: PathBuf,
}
impl Runner {
    fn new(root: &Path) -> Self {
        Self {
            root: root.into(),
            executable: root.join("bin/zapret-rust.exe"),
        }
    }
    fn raw(
        &self,
        args: &[&str],
        json: bool,
        expected: u32,
        input: Option<Vec<u8>>,
    ) -> Result<RunOutput> {
        let mut command = vec![OsString::from("--root"), self.root.as_os_str().into()];
        if json {
            command.push("--json".into());
        }
        command.extend(args.iter().map(OsString::from));
        invoke(
            &self.executable,
            &command,
            Some(&self.root),
            expected,
            input,
        )
    }
    fn json(&self, args: &[&str]) -> Result<Value> {
        let result = self.raw(args, true, 0, None)?;
        serde_json::from_slice(&result.stdout).with_context(|| format!("JSON from {args:?}"))
    }
    fn launcher_from_shell(
        &self,
        args: &[&str],
        architecture: &str,
        expected: u32,
    ) -> Result<RunOutput> {
        let cmd = PathBuf::from(std::env::var_os("SystemRoot").context("SystemRoot missing")?)
            .join(architecture)
            .join("cmd.exe");
        let mut command = vec![
            "/d".into(),
            "/c".into(),
            self.root.join("zapret-rust.exe").into_os_string(),
        ];
        command.extend(args.iter().map(OsString::from));
        invoke(&cmd, &command, Some(&self.root), expected, None)
    }
}

fn invoke(
    exe: &Path,
    args: &[OsString],
    cwd: Option<&Path>,
    expected: u32,
    input: Option<Vec<u8>>,
) -> Result<RunOutput> {
    let result = run_owned(
        &std::path::absolute(exe)?,
        args,
        &RunOptions {
            timeout: Duration::from_secs(90),
            cwd: cwd.map(Path::to_path_buf),
            stdin: input,
            max_output_bytes: 16 * 1024 * 1024,
            ..Default::default()
        },
    )?;
    ensure!(
        !result.timed_out && !result.output_truncated,
        "Subprocess exceeded its budget: {args:?}"
    );
    ensure!(
        result.exit_code == expected,
        "{args:?}: exit {}\n{}\n{}",
        result.exit_code,
        String::from_utf8_lossy(&result.stderr),
        String::from_utf8_lossy(&result.stdout[..result.stdout.len().min(2000)])
    );
    Ok(result)
}

fn text(result: &RunOutput) -> Result<String> {
    Ok(String::from_utf8(result.stdout.clone())?)
}

// Read each entry into a newly created private TEMP tree. Never trust ZIP paths,
// case aliases, symlinks or unbounded declared/actual sizes in a developer input.
fn extract(archive: &Path, destination: &Path, only: Option<&[&str]>) -> Result<Vec<String>> {
    let mut zip = zip::ZipArchive::new(File::open(archive)?)?;
    ensure!(zip.len() <= 10000, "Too many ZIP entries");
    let mut names = Vec::new();
    let mut aliases = BTreeSet::new();
    let mut total = 0u64;
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index)?;
        let name = entry.name().to_owned();
        let parts = name.split('/').collect::<Vec<_>>();
        ensure!(
            parts.first() == Some(&"zapret-rust")
                && parts.len() > 1
                && !name.contains(['\\', ':', '\0'])
                && parts
                    .iter()
                    .enumerate()
                    .all(|(i, part)| !matches!(*part, "." | "..")
                        && (!part.is_empty() || i == parts.len() - 1)),
            "Unsafe ZIP path: {name}"
        );
        ensure!(
            aliases.insert(name.to_lowercase()),
            "ZIP path alias: {name}"
        );
        ensure!(
            entry
                .unix_mode()
                .is_none_or(|mode| mode & 0o170000 != 0o120000),
            "ZIP symlink: {name}"
        );
        total = total
            .checked_add(entry.size())
            .context("ZIP size overflow")?;
        ensure!(
            entry.size() <= 64 * 1024 * 1024 && total <= 512 * 1024 * 1024,
            "ZIP exceeds extraction budget"
        );
        names.push(name.clone());
        let relative = parts[1..].join("/");
        if entry.is_dir() {
            continue;
        }
        if only.is_some_and(|entries| !entries.contains(&relative.as_str())) {
            continue;
        }
        let target = destination.join(&relative);
        fs::create_dir_all(target.parent().context("ZIP parent")?)?;
        let mut bytes = Vec::new();
        entry
            .by_ref()
            .take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == entry.size(),
            "ZIP size mismatch: {name}"
        );
        File::create_new(target)?.write_all(&bytes)?;
    }
    Ok(names)
}

fn hashes(root: &Path) -> Result<BTreeMap<String, String>> {
    fn visit(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            ensure!(
                !entry.file_type()?.is_symlink(),
                "Unexpected extracted link"
            );
            if path.is_dir() {
                visit(root, &path, out)?
            } else {
                let name = path
                    .strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/");
                if !matches!(name.as_str(), "package-manifest.json" | "runtime/.keep") {
                    out.insert(name, sha256_file(&path)?);
                }
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out)?;
    Ok(out)
}

// Only read-only --wait previews use an open stdin. Their owned children are
// terminated and reaped on every exit path. Engine tests use Windows Job owners.
struct Preview(Child, Option<BufReader<std::process::ChildStdout>>);
impl Preview {
    fn spawn(exe: &Path, args: &[&str], root: &Path) -> Result<(Self, String)> {
        let child = Command::new(exe)
            .args(args)
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(0x08000000)
            .spawn()?;
        let mut preview = Self(child, None);
        let stdout = preview.0.stdout.take().context("Preview stdout")?;
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let mut first = String::new();
            let mut reader = BufReader::new(stdout);
            let result = reader.read_line(&mut first).map(|_| (reader, first));
            let _ = send.send(result);
        });
        let (stdout, line) = receive
            .recv_timeout(Duration::from_secs(10))
            .context("Preview did not become ready")??;
        // The preview can still be writing its frame/prompt after the first
        // line. Closing stdout here would give it an unrelated broken pipe.
        preview.1 = Some(stdout);
        reader
            .join()
            .map_err(|_| anyhow::anyhow!("Preview reader panicked"))?;
        ensure!(
            preview.0.try_wait()?.is_none(),
            "Preview exited before installation"
        );
        Ok((preview, line))
    }
    fn alive(&mut self) -> Result<bool> {
        Ok(self.0.try_wait()?.is_none())
    }
}
impl Drop for Preview {
    fn drop(&mut self) {
        if let Some(mut stdin) = self.0.stdin.take() {
            let _ = stdin.write_all(b"\n");
        }
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            if self.0.try_wait().is_ok_and(|result| result.is_some()) {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(crate) fn install(build: &crate::Build<'_>, output: &Path) -> Result<()> {
    let mut evidence = Evidence::default();
    let result = (|| {
        let temporary = tempfile::Builder::new()
            .prefix("zapret-install-check-")
            .tempdir()?;
        let root = temporary.path();
        let bin = root.join("bin");
        fs::create_dir(&bin)?;
        for name in [
            "zapret-rust.exe",
            "zapret-rust-recovery.exe",
            "zapret-rust-worker.exe",
        ] {
            fs::copy(build.root.join("bin").join(name), bin.join(name))?;
        }
        let binary = bin.join("zapret-rust.exe");
        let worker = bin.join("zapret-rust-worker.exe");
        let before = sidecars(&bin)?;
        let target = root.join("release-inputs");
        let release = target.join("release");
        fs::create_dir_all(&release)?;
        let (mut preview, line) = Preview::spawn(
            &binary,
            &["menu-preview", "--width", "55", "--height", "16", "--wait"],
            root,
        )?;
        evidence.check(
            line.starts_with('╭') && line.contains("zapret-rust v"),
            "mapped menu preview is ready",
        )?;
        let (mut host, line) = Preview::spawn(&worker, &["--self-check", "--wait"], root)?;
        evidence.check(
            serde_json::from_str::<Value>(&line)?["console_window"] == false,
            "mapped GUI host is ready",
        )?;
        build.release(Some("zapret"), false)?;
        for name in ["zapret.exe", "zapret-worker.exe", "zapret-launcher.exe"] {
            fs::copy(build.target.join("release").join(name), release.join(name))?;
        }
        crate::install::publish(root, &target)?;
        evidence.check(preview.alive()?, "mapped menu survives publication")?;
        evidence.check(host.alive()?, "mapped background host survives publication")?;
        let compiled = sha256_file(&release.join("zapret.exe"))?;
        evidence.check(
            sha256_file(&binary)? == compiled
                && sha256_file(&bin.join("zapret-rust-recovery.exe"))? == compiled,
            "controller and recovery match the release",
        )?;
        let worker_hash = sha256_file(&release.join("zapret-worker.exe"))?;
        evidence.check(
            sha256_file(&worker)? == worker_hash,
            "worker matches the release",
        )?;
        evidence.check(
            sidecars(&bin)?.is_subset(&before),
            "publication leaves no new sidecars in bin",
        )?;
        evidence.observations.insert("installation".into(),json!({"build_exit":0,"mapped_preview_survived":true,
            "mapped_background_survived":true,"new_sidecars_in_bin":[],"binary_sha256":compiled,"worker_sha256":worker_hash,
            "retained_outside_bin":sidecars(&target.join("previous-controllers"))?,"private_temp_package":true,"live_bypass_or_service_control":false}));
        Ok(())
    })();
    evidence.save(output, None, &result)?;
    result
}
fn sidecars(dir: &Path) -> Result<BTreeSet<String>> {
    if !dir.exists() {
        return Ok(BTreeSet::new());
    }
    Ok(fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<BTreeSet<_>>>()?
        .into_iter()
        .filter(|name| name.starts_with(".native-build-") || name.ends_with(".old"))
        .collect())
}
