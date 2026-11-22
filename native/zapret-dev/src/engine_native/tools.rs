mod compile;
use anyhow::{Context, Result, ensure};
pub(super) use compile::Compilation;
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use zapret_platform::{RunOptions, run_owned};

pub(super) struct Tools<'a> {
    pub llvm: &'a Path,
    pub compiler: &'a Path,
    system: PathBuf,
    path: OsString,
    log: PathBuf,
}

impl<'a> Tools<'a> {
    pub fn new(llvm: &'a Path, compiler: &'a Path, log: &Path) -> Result<Self> {
        let system = PathBuf::from(std::env::var_os("SystemRoot").context("Missing SystemRoot")?)
            .join("System32");
        let path = std::env::join_paths([llvm, system.as_path()])?;
        File::create(log)?;
        Ok(Self {
            llvm,
            compiler,
            system,
            path,
            log: log.into(),
        })
    }

    pub fn compile(&self, cwd: &Path, step: &str, args: &[OsString]) -> Result<()> {
        self.run(self.compiler, cwd, step, args).map(|_| ())
    }

    pub fn run(&self, exe: &Path, cwd: &Path, step: &str, args: &[OsString]) -> Result<String> {
        let mut log = File::options().append(true).open(&self.log)?;
        writeln!(log, "{step}: {}", exe.display())?;
        let result = run_owned(
            exe,
            args,
            &RunOptions {
                cwd: Some(cwd.into()),
                timeout: Duration::from_secs(180),
                max_output_bytes: 4 * 1024 * 1024,
                env: BTreeMap::from([(OsString::from("PATH"), self.path.clone())]),
                ..Default::default()
            },
        )
        .with_context(|| format!("Run {step}; see {}", self.log.display()))?;
        log.write_all(&result.stdout)?;
        log.write_all(&result.stderr)?;
        ensure!(
            result.exit_code == 0 && !result.timed_out && !result.output_truncated,
            "{step} failed (exit {}, timeout {}, truncated {}); see {}",
            result.exit_code,
            result.timed_out,
            result.output_truncated,
            self.log.display()
        );
        Ok(String::from_utf8_lossy(&result.stdout).into_owned())
    }

    pub fn extract(&self, archive: &Path, destination: &Path) -> Result<()> {
        self.extract_members(archive, destination, &[])
    }

    pub fn extract_members(
        &self,
        archive: &Path,
        destination: &Path,
        members: &[String],
    ) -> Result<()> {
        let mut args = vec!["-xzf".into(), archive.as_os_str().into()];
        args.extend(members.iter().map(OsString::from));
        self.run(
            &self.system.join("tar.exe"),
            destination,
            "Extract pinned sources",
            &args,
        )?;
        Ok(())
    }

    pub fn run_command(
        &self,
        command: &std::process::Command,
        cwd: &Path,
        step: &str,
    ) -> Result<String> {
        self.run(
            Path::new(command.get_program()),
            cwd,
            step,
            &command
                .get_args()
                .map(OsStr::to_os_string)
                .collect::<Vec<_>>(),
        )
    }
}
