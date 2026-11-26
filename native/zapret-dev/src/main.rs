mod checks;
mod engine_native;
mod flowseal;
mod install;
mod licenses;
mod memory;
mod perf;
mod release_package;
mod ring;
mod ring_build;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use std::{
    env,
    fs::{self, File, OpenOptions},
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

#[derive(Parser)]
#[command(
    name = "cargo zapret",
    about = "Build and package zapret-rust on Windows"
)]
struct Cli {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Build and verify the pinned native engine; queue activates on next start.
    BuildRing {
        #[arg(long)]
        queue: bool,
        /// Build the native Windows engine with built-in rules and Luna.
        #[arg(long)]
        native_windows: bool,
        /// Build the LuaJIT compatibility engine with the legacy updater files.
        #[arg(long, requires = "native_windows")]
        compatibility: bool,
        /// Run pinned C and LuaJIT conformance comparisons alongside the build.
        #[arg(long, requires = "native_windows")]
        conformance: bool,
    },
    /// Run timer, Lua VM and sandbox fixtures on the selected engine without a driver.
    CheckEngine {
        #[arg(long)]
        pkg: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long,value_parser=["storetest.lua","watchtest.lua","linkguardtest.lua","hostcachetest.lua","luatest.lua","storeiotest.lua","foolingtest.lua","timertest.lua","conntracktest.lua","packetwritetest.lua","protocoltest.lua","registrytest.lua","native-platform.lua","native-lua-modules.lua"])]
        fixture: Option<String>,
    },
    /// Replay the ring/store/context/host fixtures through the native Rust ABI.
    CheckRing {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Native live regression scenarios. --validate-only has no machine side effects.
    CheckLive {
        #[arg(long)]
        allow_live_changes: bool,
        #[arg(long)]
        network: bool,
        #[arg(long)]
        validate_only: bool,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Export PNG previews from the installed native menu frames.
    MenuPreview {
        #[arg(long)]
        out_dir: Option<PathBuf>,
        #[arg(long, default_value_t = 80)]
        width: usize,
        #[arg(long)]
        binary: Option<PathBuf>,
    },
    /// Replay historical finalists-v1/v2 journals without probes or process control.
    PerfBench {
        #[arg(long)]
        plan_file: PathBuf,
        #[arg(long)]
        journal_file: PathBuf,
        #[arg(long)]
        out_file: PathBuf,
    },
    /// Test image replacement in a TEMP package while old previews hold the images.
    CheckInstall {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Exercise a release ZIP in a private TEMP package using the actual CLI.
    CheckPackage {
        archive: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Exercise the public EXE and read-only menu routes in a private TEMP package.
    CheckMenu {
        archive: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Test the real probe executable against local HTTP/TLS fixtures.
    CheckProbe {
        binary: PathBuf,
        #[arg(long)]
        subcommand: Option<String>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 3)]
        benchmark_rounds: usize,
        #[arg(long)]
        compare_legacy: bool,
    },
    /// Benchmark Lua ring memory against a fixed baseline on a virtual filesystem.
    MemoryBench {
        #[arg(long)]
        pkg: Option<PathBuf>,
        #[arg(long)]
        baseline: PathBuf,
        #[arg(long)]
        baseline_ref: Option<String>,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 1000)]
        hosts: usize,
        #[arg(long, default_value_t = 7)]
        rounds: usize,
        #[arg(long, default_value_t = 10000)]
        warm: usize,
    },
    /// Sample one recorded process lifetime and save CPU/memory measurements.
    PerfProbe {
        #[arg(long)]
        process_id: u32,
        #[arg(long, default_value_t = 10)]
        duration_sec: u64,
        #[arg(long, default_value_t = 250)]
        interval_ms: u64,
        #[arg(long)]
        out_file: PathBuf,
    },
    /// Build release binaries and optionally install them into bin.
    Build {
        #[arg(short, long)]
        package: Option<String>,
        #[arg(long)]
        install: bool,
    },
    /// Run the locked Rust tests.
    Test {
        #[arg(short, long)]
        package: Option<String>,
    },
    /// Run Clippy with warnings treated as errors.
    Check {
        #[arg(short, long)]
        package: Option<String>,
    },
    /// Format Rust sources.
    Fmt {
        #[arg(short, long)]
        package: Option<String>,
        #[arg(long)]
        check: bool,
    },
    /// Build a release ZIP. With --skip-compile, use the installed binaries.
    Package {
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        skip_compile: bool,
        /// Keep the legacy engine manifests for controllers that require Cygwin.
        #[arg(long)]
        compatibility: bool,
        /// Package a verified build candidate without publishing to the checkout.
        #[arg(long)]
        candidate: Option<PathBuf>,
    },
    /// Collect notices from the locked Windows Cargo graph and Rust sysroot.
    Licenses {
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        target: Option<String>,
    },
    /// Convert the supported Flowseal batch profiles into zapret2 strategies.
    ImportFlowseal {
        source: PathBuf,
        output: PathBuf,
        #[arg(long)]
        check: bool,
        #[arg(long)]
        allow_known_differences: bool,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("zapret-dev: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(action: Action) -> Result<()> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .parent()
        .and_then(Path::parent)
        .context("Cannot locate the zapret-rust checkout")?;
    let build = Build {
        root,
        target: root.join("dist/native"),
    };
    match action {
        Action::BuildRing {
            queue,
            native_windows,
            compatibility,
            conformance,
        } => {
            if native_windows {
                engine_native::run(&build, queue, compatibility, conformance)
            } else {
                ring_build::run(&build, queue)
            }
        }
        Action::CheckEngine {
            pkg,
            output,
            fixture,
        } => ring::engine(
            root,
            pkg.as_deref()
                .unwrap_or(&root.join("dist/native/ring-candidate")),
            output
                .as_deref()
                .unwrap_or(&root.join("dist/native/ring-engine-check.json")),
            fixture.as_deref(),
        ),
        Action::CheckRing { output } => ring::run(
            root,
            output
                .as_deref()
                .unwrap_or(&root.join("dist/native/ring-check.json")),
        ),
        Action::CheckLive {
            allow_live_changes,
            network,
            validate_only,
            output,
        } => checks::live(
            root,
            allow_live_changes,
            network,
            validate_only,
            output.as_deref(),
        ),
        Action::MenuPreview {
            out_dir,
            width,
            binary,
        } => {
            ensure!((24..=200).contains(&width), "Preview width must be 24..200");
            let output =
                std::path::absolute(out_dir.unwrap_or_else(|| root.join("dist/ui-preview")))?;
            fs::create_dir_all(&output)?;
            let binary =
                std::path::absolute(binary.unwrap_or_else(|| root.join("bin/zapret-rust.exe")))?;
            for screen in ["main", "settings", "tools", "notifications", "test"] {
                checked(
                    Command::new(&binary)
                        .args([
                            "menu-preview",
                            "--screen",
                            screen,
                            "--width",
                            &width.to_string(),
                            "--png",
                        ])
                        .arg(output.join(format!("{screen}.png"))),
                )?;
            }
            Ok(())
        }
        Action::PerfBench {
            plan_file,
            journal_file,
            out_file,
        } => {
            let result =
                zapret_core::legacy_comparison::replay(&plan_file, &journal_file, Some(&out_file))?;
            println!("{}", result["Status"].as_str().unwrap_or("Invalid"));
            Ok(())
        }
        Action::CheckInstall { output } => {
            let _lock = build.lock_release()?;
            checks::install(
                &build,
                output
                    .as_deref()
                    .unwrap_or(&root.join("dist/native/native-install.json")),
            )
        }
        Action::CheckPackage { archive, output } => checks::package(&archive, &output),
        Action::CheckMenu { archive, output } => checks::menu(&archive, &output),
        Action::CheckProbe {
            binary,
            subcommand,
            output,
            benchmark_rounds,
            compare_legacy,
        } => checks::probe(
            root,
            &binary,
            subcommand.as_deref(),
            &output,
            benchmark_rounds,
            compare_legacy,
        ),
        Action::MemoryBench {
            pkg,
            baseline,
            baseline_ref,
            out,
            hosts,
            rounds,
            warm,
        } => memory::run(
            pkg.as_deref().unwrap_or(root),
            &baseline,
            baseline_ref.as_deref(),
            &std::path::absolute(out)?,
            hosts,
            rounds,
            warm,
        ),
        Action::PerfProbe {
            process_id,
            duration_sec,
            interval_ms,
            out_file,
        } => perf::run(process_id, duration_sec, interval_ms, &out_file),
        Action::Build { package, install } => {
            ensure!(
                !install || matches!(package.as_deref(), None | Some("zapret")),
                "--install requires a build containing zapret and zapret-worker"
            );
            let _lock = build.lock_release()?;
            build.release(package.as_deref(), install)
        }
        Action::Test { package } => {
            let mut cargo = build.cargo("test", package.as_deref());
            cargo.arg("--locked").arg("--target-dir").arg(&build.target);
            checked(&mut cargo)
        }
        Action::Check { package } => {
            let mut cargo = build.cargo("clippy", package.as_deref());
            cargo
                .args(["--locked", "--all-targets", "--target-dir"])
                .arg(&build.target)
                .args(["--", "-D", "warnings"]);
            checked(&mut cargo)
        }
        Action::Fmt { package, check } => {
            let mut cargo = build.cargo("fmt", package.as_deref());
            if check {
                cargo.args(["--", "--check"]);
            }
            checked(&mut cargo)
        }
        Action::Package {
            output,
            skip_compile,
            compatibility,
            candidate,
        } => {
            let _lock = build.lock_release()?;
            let output = match output {
                Some(path) => std::path::absolute(path)?,
                None => root.join("dist"),
            };
            if let Some(candidate) = candidate {
                return release_package::from_candidate(
                    &build,
                    &candidate,
                    &output,
                    skip_compile,
                    compatibility,
                );
            }
            if !skip_compile {
                build.release(Some("zapret"), true)?;
            }
            let exe = root.join("bin/zapret-rust.exe");
            ensure!(
                exe.is_file(),
                "Build and install the native application first"
            );
            let mut command = Command::new(exe);
            command
                .arg("--root")
                .arg(root)
                .args(["package", "--output"])
                .arg(output);
            if compatibility {
                command.arg("--compatibility");
            }
            checked(&mut command)
        }
        Action::Licenses { output, target } => {
            let target = match target {
                Some(target) => target,
                None => Build::host()?,
            };
            let mut cargo = build.cargo("metadata", None);
            cargo.args([
                "--locked",
                "--format-version",
                "1",
                "--filter-platform",
                &target,
            ]);
            let metadata = output_of(&mut cargo)?;
            let sysroot = Build::sysroot()?;
            let output = output.unwrap_or_else(|| root.join("licenses/LICENSE-rust.txt"));
            licenses::generate(&metadata, &sysroot, &std::path::absolute(output)?)
        }
        Action::ImportFlowseal {
            source,
            output,
            check,
            allow_known_differences,
        } => flowseal::run(&source, &output, check, allow_known_differences),
    }
}

struct Build<'a> {
    root: &'a Path,
    target: PathBuf,
}

impl Build<'_> {
    fn host() -> Result<String> {
        let version = output_of(Self::rustc().arg("-vV"))?;
        std::str::from_utf8(&version)?
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .map(str::to_owned)
            .context("Cannot determine the Rust host target")
    }

    fn rustc() -> Command {
        Command::new(env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
    }

    fn sysroot() -> Result<PathBuf> {
        let output = output_of(Self::rustc().args(["--print", "sysroot"]))?;
        Ok(PathBuf::from(std::str::from_utf8(&output)?.trim()))
    }

    fn cargo(&self, action: &str, package: Option<&str>) -> Command {
        let mut cargo = Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
        cargo
            .current_dir(self.root)
            .args([action, "--manifest-path"])
            .arg(self.root.join("native/Cargo.toml"));
        match package {
            Some(package) => {
                cargo.args(["-p", package]);
                if package == "zapret" && action == "build" {
                    cargo.args(["-p", "zapret-worker"]);
                }
            }
            None if action == "fmt" => {
                cargo.arg("--all");
            }
            None if action != "metadata" => {
                cargo.arg("--workspace");
            }
            None => {}
        }
        cargo
    }

    fn lock_release(&self) -> Result<File> {
        fs::create_dir_all(&self.target)?;
        let path = self.target.join("release.lock");
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(&path)
            .with_context(|| format!("Could not lock {} for the release build", path.display()))
    }

    fn release(&self, package: Option<&str>, install: bool) -> Result<()> {
        let mut cargo = self.cargo("build", package);
        checked(
            cargo
                .args(["--locked", "--release", "--target-dir"])
                .arg(&self.target),
        )?;
        if install {
            install::publish(self.root, &self.target)?;
        }
        Ok(())
    }
}

fn checked(command: &mut Command) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("Run {}", command.get_program().to_string_lossy()))?;
    ensure!(
        status.success(),
        "{} exited with {status}",
        command.get_program().to_string_lossy()
    );
    Ok(())
}

fn output_of(command: &mut Command) -> Result<Vec<u8>> {
    let output = command
        .output()
        .with_context(|| format!("Run {}", command.get_program().to_string_lossy()))?;
    ensure!(
        output.status.success(),
        "{command:?} exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}
