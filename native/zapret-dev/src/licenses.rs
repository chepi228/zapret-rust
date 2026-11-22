use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    fmt::Write,
    fs,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
    resolve: Resolve,
}

#[derive(Deserialize)]
struct Package {
    id: String,
    source: Option<String>,
    name: String,
    version: String,
    license: Option<String>,
    license_file: Option<PathBuf>,
    manifest_path: PathBuf,
}

#[derive(Deserialize)]
struct Resolve {
    nodes: Vec<Node>,
}

#[derive(Deserialize)]
struct Node {
    id: String,
    deps: Vec<Dependency>,
}

#[derive(Deserialize)]
struct Dependency {
    pkg: String,
    dep_kinds: Vec<DependencyKind>,
}

#[derive(Deserialize)]
struct DependencyKind {
    kind: Option<String>,
}

pub(crate) fn generate(metadata: &[u8], sysroot: &Path, output: &Path) -> Result<()> {
    let Metadata {
        mut packages,
        resolve,
    } = serde_json::from_slice(metadata).context("Read Cargo dependency graph")?;
    let selected = release_dependencies(&packages, &resolve)?;
    packages.retain(|package| package.source.is_some() && selected.contains(package.id.as_str()));
    packages.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));

    let mut index = String::from(concat!(
        "Rust dependencies for the Windows native application\n\n",
        "Source expressions are listed as declared by each crate. All license\n",
        "alternatives supplied in its published source are retained below.\n\n",
    ));
    let separator = "=".repeat(72);
    let mut seen_notices = HashSet::new();
    let mut notices = String::new();
    for package in &packages {
        let files = notice_files(package)?;
        ensure!(
            !files.is_empty(),
            "No notices found for {} {}",
            package.name,
            package.version
        );
        writeln!(
            index,
            "{} {} | {}",
            package.name,
            package.version,
            package.license.as_deref().unwrap_or_default()
        )?;
        writeln!(
            index,
            "  https://crates.io/crates/{}/{}",
            package.name, package.version
        )?;
        for path in files {
            let text = read_notice(&path)?;
            let content = format!("{}\n", text.trim_start_matches('\u{feff}').trim());
            let digest = zapret_core::sha256(content.as_bytes()).to_ascii_lowercase();
            let short = &digest[..16];
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .context("Invalid notice name")?;
            writeln!(index, "  {name}: {short}")?;
            if seen_notices.insert(digest.clone()) {
                writeln!(
                    notices,
                    "{separator}\nNotice {short}\n{separator}\n{content}"
                )?;
            }
        }
    }

    let library = sysroot.join("share/doc/rust/COPYRIGHT-library.html");
    let std_notices = read_notice(&library).context("Install the rust-docs toolchain component")?;
    let output_text = format!(
        "{index}\n{notices}\n{separator}\nRust standard library distribution notices (original HTML)\n{separator}\n{std_notices}"
    );
    zapret_core::atomic_write(output, output_text.as_bytes())?;
    println!(
        "Collected {} locked crate notices and Rust standard library notices",
        packages.len()
    );
    Ok(())
}

fn release_dependencies(packages: &[Package], resolve: &Resolve) -> Result<HashSet<String>> {
    let nodes: HashMap<_, _> = resolve
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();
    let mut pending: Vec<_> = packages
        .iter()
        .filter(|package| {
            package.source.is_none()
                && matches!(
                    package.name.as_str(),
                    "zapret" | "zapret-worker" | "zapret-ring-ffi" | "zapret-wincompat"
                )
        })
        .map(|package| package.id.as_str())
        .collect();
    ensure!(
        pending.len() == 4,
        "Missing release crates in Cargo metadata"
    );
    let mut selected = HashSet::new();
    while let Some(id) = pending.pop() {
        if selected.insert(id.to_owned()) {
            let node = nodes
                .get(id)
                .context("Dependency missing from Cargo metadata")?;
            pending.extend(
                node.deps
                    .iter()
                    .filter(|dependency| {
                        dependency
                            .dep_kinds
                            .iter()
                            .any(|kind| kind.kind.as_deref() != Some("dev"))
                    })
                    .map(|dependency| dependency.pkg.as_str()),
            );
        }
    }
    Ok(selected)
}

fn notice_files(package: &Package) -> Result<Vec<PathBuf>> {
    let directory = package
        .manifest_path
        .parent()
        .context("Crate directory missing")?;
    let mut files = Vec::new();
    for entry in fs::read_dir(directory).with_context(|| format!("Read {}", directory.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_ascii_uppercase();
        let prefix = name.split(['.', '-', '_']).next().unwrap_or_default();
        if matches!(
            prefix,
            "LICENSE" | "LICENCE" | "COPYING" | "NOTICE" | "COPYRIGHT" | "UNLICENSE"
        ) && entry.path().is_file()
        {
            files.push(entry.path());
        }
    }
    files.sort();
    if let Some(path) = &package.license_file {
        let path = directory.join(path);
        if !files.contains(&path) {
            files.push(path);
        }
    }
    Ok(files)
}

fn read_notice(path: &Path) -> Result<String> {
    Ok(fs::read_to_string(path)
        .with_context(|| format!("Read {}", path.display()))?
        .replace("\r\n", "\n")
        .replace('\r', "\n"))
}
