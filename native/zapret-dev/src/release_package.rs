use crate::{Build, checked, install};
use anyhow::{Context, Result, ensure};
use std::{fs, os::windows::fs::MetadataExt, path::Path, process::Command};
use zapret_core::{RING_UPDATE_FILES, omits_engine_file, read_core_manifest, verify_ring};

pub(super) fn from_candidate(
    build: &Build<'_>,
    candidate: &Path,
    output: &Path,
    skip_compile: bool,
    compatibility: bool,
) -> Result<()> {
    let candidate = std::path::absolute(candidate)?;
    let ring = verify_ring(&candidate)?.context("Candidate is missing its ring manifest")?;
    let core = read_core_manifest(&candidate.join("tools/upstream.txt"))?;
    ensure!(
        ring.schema == core.schema,
        "Candidate manifest schemas differ"
    );
    ensure!(
        !compatibility || core.schema == 1,
        "Build a compatibility candidate before requesting a transition ZIP"
    );
    let temporary = tempfile::Builder::new()
        .prefix("zapret-release-")
        .tempdir()?;
    let stage = temporary.path();
    let controller = "bin/zapret-rust.exe";
    let worker = "bin/zapret-rust-worker.exe";
    for name in include_str!("../../../dev/native-package-files.txt")
        .lines()
        .map(str::trim)
        .filter(|name| !name.is_empty() && !name.starts_with('#'))
    {
        if omits_engine_file(core.schema, name) {
            continue;
        }
        // The controller generates its recovery image and the default user lists.
        if name == "zapret-rust.exe"
            || name == controller
            || name == worker
            || matches!(
                name,
                "bin/zapret-rust-recovery.exe"
                    | "lists/list-general-user.txt"
                    | "lists/list-exclude-user.txt"
                    | "lists/ipset-user.txt"
                    | "lists/ipset-exclude-user.txt"
            )
        {
            continue;
        }
        let copied = if RING_UPDATE_FILES.contains(&name) {
            &candidate
        } else {
            build.root
        };
        copy(copied, stage, name)?;
    }
    if skip_compile {
        copy(build.root, stage, "zapret-rust.exe")?;
        copy(build.root, stage, controller)?;
        copy(build.root, stage, worker)?;
    } else {
        build.release(Some("zapret"), false)?;
        install::publish(stage, &build.target)?;
    }
    let mut command = Command::new(stage.join(controller));
    command
        .arg("--root")
        .arg(stage)
        .args(["package", "--output"])
        .arg(output);
    if compatibility {
        command.arg("--compatibility");
    }
    checked(&mut command)
}

fn copy(root: &Path, stage: &Path, name: &str) -> Result<()> {
    let source = root.join(name);
    for path in source.ancestors() {
        ensure!(
            fs::symlink_metadata(path)?.file_attributes() & 0x400 == 0,
            "Reparse release input: {}",
            source.display()
        );
    }
    let target = stage.join(name);
    fs::create_dir_all(target.parent().context("Release input directory")?)?;
    fs::copy(source, target).with_context(|| format!("Copy release input: {name}"))?;
    Ok(())
}
