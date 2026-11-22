//! Bounded compilation of independent translation units, with ordered diagnostics.
use super::Tools;
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    thread,
    time::Instant,
};

pub(in super::super) struct Compilation {
    pub input: PathBuf,
    pub output: PathBuf,
    pub extra: Vec<OsString>,
}

fn parallel<T: Send>(
    count: usize,
    workers: usize,
    run: impl Fn(usize) -> Result<T> + Sync,
) -> Result<Vec<(usize, Result<T>)>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let next = AtomicUsize::new(0);
    let cancelled = AtomicBool::new(false);
    struct PanicGuard<'a>(&'a AtomicBool);
    impl Drop for PanicGuard<'_> {
        fn drop(&mut self) {
            if thread::panicking() {
                self.0.store(true, Ordering::Release);
            }
        }
    }
    let mut results = thread::scope(|scope| {
        let handles: Vec<_> = (0..workers.max(1).min(count))
            .map(|_| {
                scope.spawn(|| {
                    let _panic_guard = PanicGuard(&cancelled);
                    let mut finished = Vec::new();
                    while !cancelled.load(Ordering::Acquire) {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        if index >= count || cancelled.load(Ordering::Acquire) {
                            break;
                        }
                        let result = run(index);
                        if result.is_err() {
                            cancelled.store(true, Ordering::Release);
                        }
                        finished.push((index, result));
                    }
                    finished
                })
            })
            .collect();
        let mut results = Vec::new();
        let mut panicked = false;
        // Join every worker before returning, including when one panics. Each
        // command retains the existing finite, kill-on-close process owner.
        for handle in handles {
            match handle.join() {
                Ok(finished) => results.extend(finished),
                Err(_) => {
                    cancelled.store(true, Ordering::Release);
                    panicked = true;
                }
            }
        }
        ensure!(
            !panicked,
            "Native compiler worker panicked; all workers joined"
        );
        Ok(results)
    })?;
    results.sort_unstable_by_key(|(index, _)| *index);
    Ok(results)
}

impl Tools<'_> {
    pub(in super::super) fn compile_objects(
        &self,
        cwd: &Path,
        label: &str,
        flags: &[OsString],
        jobs: &[Compilation],
    ) -> Result<()> {
        if jobs.is_empty() {
            return Ok(());
        }
        let mut outputs = BTreeSet::new();
        for job in jobs {
            let output = if job.output.is_absolute() {
                job.output.clone()
            } else {
                cwd.join(&job.output)
            };
            ensure!(
                outputs.insert(output.as_os_str().to_ascii_lowercase()),
                "Duplicate compiler object: {}",
                output.display()
            );
        }
        let available = thread::available_parallelism().map_or(1, |count| count.get());
        let requested = match std::env::var_os("ZAPRET_NATIVE_BUILD_JOBS") {
            None => available,
            Some(value) => value
                .to_str()
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|value| *value > 0)
                .context("ZAPRET_NATIVE_BUILD_JOBS must be a positive integer")?,
        };
        let workers = requested.min(available).min(jobs.len());
        let directory = tempfile::Builder::new()
            .prefix("compile-")
            .tempdir_in(self.log.parent().context("Compiler diagnostic directory")?)?;
        let start = Instant::now();
        let result = parallel(jobs.len(), workers, |index| {
            let job = &jobs[index];
            let log = directory.path().join(format!("{index:04}.log"));
            File::create(&log)?;
            let tools = Tools {
                llvm: self.llvm,
                compiler: self.compiler,
                system: self.system.clone(),
                path: self.path.clone(),
                log,
            };
            let mut args = flags.to_vec();
            // LLD uses a full link. COFF incremental-link timestamps otherwise
            // make identical parallel and sequential object files differ.
            args.push("-mno-incremental-linker-compatible".into());
            args.extend_from_slice(&job.extra);
            args.extend([
                "-c".into(),
                job.input.as_os_str().into(),
                "-o".into(),
                job.output.as_os_str().into(),
            ]);
            tools.compile(cwd, &format!("{label}: {}", job.input.display()), &args)?;
            let output = if job.output.is_absolute() {
                job.output.clone()
            } else {
                cwd.join(&job.output)
            };
            ensure!(
                fs::metadata(&output).is_ok_and(|file| file.is_file() && file.len() != 0),
                "Compiler produced no object for {}",
                job.input.display()
            );
            Ok(())
        });
        let mut log = File::options().append(true).open(&self.log)?;
        // A worker never writes this shared log. Preserve source order even if
        // completion order changes, and retain partial diagnostics on failure.
        for index in 0..jobs.len() {
            let unit = directory.path().join(format!("{index:04}.log"));
            if unit.try_exists()? {
                log.write_all(&fs::read(unit)?)?;
            }
        }
        let complete = result.and_then(|results| {
            let count = results.len();
            for (index, result) in results {
                result.with_context(|| format!("{label}: {}", jobs[index].input.display()))?;
            }
            ensure!(
                count == jobs.len(),
                "Native compilation incomplete: {count}/{}",
                jobs.len()
            );
            Ok(())
        });
        let elapsed = start.elapsed().as_millis();
        writeln!(
            log,
            "Compilation batch {label}: units={} workers={workers} elapsed_ms={elapsed} success={}",
            jobs.len(),
            complete.is_ok()
        )?;
        if let Err(error) = complete {
            let retained = directory.keep();
            return Err(error).with_context(|| {
                format!("Compiler diagnostics retained in {}", retained.display())
            });
        }
        println!(
            "PASS parallel_compile {label} units={} workers={workers} elapsed_ms={elapsed}",
            jobs.len()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn independent_compiles_overlap_but_results_retain_source_order() {
        let gate = Barrier::new(4);
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let results = parallel(32, 4, |index| {
            let count = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(count, Ordering::SeqCst);
            if index < 4 {
                gate.wait();
            }
            thread::yield_now();
            active.fetch_sub(1, Ordering::SeqCst);
            Ok(index * 7)
        })
        .unwrap();
        assert_eq!(peak.load(Ordering::SeqCst), 4);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(
            results
                .into_iter()
                .map(|(index, result)| (index, result.unwrap()))
                .collect::<Vec<_>>(),
            (0..32).map(|index| (index, index * 7)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_failed_compile_prevents_later_jobs_from_starting() {
        let started = AtomicUsize::new(0);
        let result = parallel::<()>(16, 1, |_| {
            started.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("intentional compile failure");
        })
        .unwrap();
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(result.len(), 1);
        assert!(result[0].1.is_err());
    }

    #[test]
    fn compiler_worker_panic_is_joined_and_rejects_the_batch() {
        let finished = AtomicUsize::new(0);
        let result = parallel(16, 4, |index| {
            if index == 0 {
                panic!("intentional compiler worker panic");
            }
            finished.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("all workers joined")
        );
        let after = finished.load(Ordering::SeqCst);
        thread::yield_now();
        assert_eq!(finished.load(Ordering::SeqCst), after);
    }

    #[test]
    fn duplicate_windows_object_names_are_rejected_before_launch() {
        let temporary = tempfile::tempdir().unwrap();
        let compiler = temporary.path().join("missing-compiler.exe");
        let tools = Tools::new(
            temporary.path(),
            &compiler,
            &temporary.path().join("commands.log"),
        )
        .unwrap();
        let jobs: Vec<_> = ["one.o", "ONE.o"]
            .into_iter()
            .map(|output| Compilation {
                input: "source.c".into(),
                output: output.into(),
                extra: Vec::new(),
            })
            .collect();
        assert!(
            tools
                .compile_objects(temporary.path(), "duplicate", &[], &jobs)
                .unwrap_err()
                .to_string()
                .contains("Duplicate compiler object")
        );
        assert!(
            fs::read(temporary.path().join("commands.log"))
                .unwrap()
                .is_empty()
        );
    }
}
