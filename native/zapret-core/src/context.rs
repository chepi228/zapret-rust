use crate::{Settings, io::hex, sha256, sha256_file};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

/// Digests belong to one composition. During Windows startup the open file
/// handles deny writes and renames until that launch has finished.
pub(crate) enum InputHashes<'a> {
    Live(BTreeMap<PathBuf, String>),
    Pinned(&'a BTreeMap<PathBuf, &'a str>),
}
impl InputHashes<'_> {
    pub(crate) fn live() -> Self {
        Self::Live(BTreeMap::new())
    }
    pub(crate) fn get(&mut self, path: &Path) -> Result<&str> {
        match self {
            Self::Pinned(files) => files.get(path).copied().with_context(|| {
                format!(
                    "File is absent from the pinned launch inputs: {}",
                    path.display()
                )
            }),
            Self::Live(files) => Ok(match files.entry(path.to_owned()) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(sha256_file(path)?),
            }),
        }
    }
}

pub const PACKAGE_VERSION: &str = "1.2";
// Frozen PowerShell signatures retain their historical release identity.
const LEGACY_PACKAGE_VERSION: &str = "2.2";
const SCORE_CODE: [&str; 20] = [
    "tools/test.ps1",
    "tools/lib.ps1",
    "tools/netstate.ps1",
    "tools/netwatch.ps1",
    "tools/watchcode.ps1",
    "tools/capture.ps1",
    "tools/filtercheck.cs",
    "tools/linkguard.ps1",
    "tools/recovery.ps1",
    "tools/selection.ps1",
    "tools/webprobe.ps1",
    "tools/comparison.ps1",
    "tools/processmetrics.ps1",
    "tools/recipe.ps1",
    "tools/launch.ps1",
    "tools/tgws.ps1",
    "tools/tgwsrunner.cs",
    "tools/integrity.ps1",
    "tools/upstream.txt",
    "CHECKSUMS.txt",
];
pub(crate) fn sorted_files(root: &Path, dir: &str) -> Result<Vec<String>> {
    sorted_file_names(fs::read_dir(root.join(dir))?)
}

fn sorted_file_names(entries: fs::ReadDir) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    names.sort_by(|a, b| crate::io::legacy_compare(a, b));
    Ok(names)
}
pub fn score_input_files(root: &Path) -> Result<Vec<String>> {
    let legacy = root.join("tools/lib.ps1").is_file();
    let mut result: Vec<String> = if legacy {
        SCORE_CODE.iter().map(|s| s.to_string()).collect()
    } else {
        [
            "bin/zapret-rust.exe",
            "tools/upstream.txt",
            "CHECKSUMS.txt",
            "tools/targets.txt",
            "tools/dpi-suite.json",
        ]
        .map(str::to_owned)
        .to_vec()
    };
    let lua = root.join("lua");
    let scripts = match fs::read_dir(&lua) {
        Ok(entries) => sorted_file_names(entries)?,
        Err(error) if error.kind() == ErrorKind::NotFound && crate::uses_builtin_rules(root) => {
            Vec::new()
        }
        Err(error) => {
            return Err(error).with_context(|| format!("Read Lua inputs in {}", lua.display()));
        }
    };
    for file in scripts {
        if file.to_ascii_lowercase().ends_with(".lua") {
            result.push(format!("lua/{file}"));
        }
    }
    for name in ["tools/rust-ring.json", "bin/zapret-ring.dll"] {
        if root.join(name).is_file() {
            result.push(name.to_owned());
        }
    }
    for dir in ["lists", "fake"] {
        for file in sorted_files(root, dir)? {
            if !file.eq_ignore_ascii_case("autohostlist.txt")
                && !file.to_ascii_lowercase().ends_with(".bak")
            {
                result.push(format!("{dir}/{file}"));
            }
        }
    }
    if legacy {
        result.extend(
            [
                "tools/connectionprobe.ps1",
                "tools/connectionprobe.cs",
                "tools/voiceprobe.ps1",
                "tools/voiceprobe.cs",
            ]
            .map(str::to_owned),
        );
    }
    Ok(result)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScoreTarget {
    pub group: String,
    pub name: String,
    pub url: String,
}

/// Legacy v2 input signature. Callers may add native worker identity to parameters.
pub fn score_inputs_hash(
    root: &Path,
    targets: &[ScoreTarget],
    parameters: &BTreeMap<String, String>,
) -> Result<String> {
    score_hash(root, targets, parameters, &mut InputHashes::live())
}
fn score_hash(
    root: &Path,
    targets: &[ScoreTarget],
    parameters: &BTreeMap<String, String>,
    hashes: &mut InputHashes<'_>,
) -> Result<String> {
    ensure!(!targets.is_empty(), "No score targets");
    let (schema, version) = if root.join("tools/lib.ps1").is_file() {
        ("score-inputs-v2", LEGACY_PACKAGE_VERSION)
    } else {
        ("score-inputs-native-v1", PACKAGE_VERSION)
    };
    let mut parts = vec![schema.to_owned(), version.to_owned()];
    let mut target_keys: Vec<String> = targets
        .iter()
        .map(|t| serde_json::to_string(&[&t.group, &t.name, &t.url]))
        .collect::<std::result::Result<_, _>>()?;
    target_keys.sort_by(|a, b| crate::io::legacy_compare(a, b));
    parts.extend(target_keys);
    let mut parameters: Vec<_> = parameters.iter().collect();
    parameters.sort_by(|(a, _), (b, _)| crate::io::legacy_compare(a, b));
    parts.extend(parameters.into_iter().map(|(k, v)| format!("{k}={v}")));
    for file in score_input_files(root)? {
        parts.push(hashes.get(&root.join(file))?.to_owned());
    }
    Ok(sha256(parts.join("\n").as_bytes()))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestResultContext {
    #[serde(rename = "Schema", alias = "schema")]
    pub schema: u32,
    #[serde(rename = "NetworkKey", alias = "network_key")]
    pub network_key: String,
    #[serde(rename = "InputsHash", alias = "inputs_hash")]
    pub inputs_hash: String,
    #[serde(rename = "RunId", alias = "run_id")]
    pub run_id: String,
}
impl TestResultContext {
    pub fn valid(&self) -> bool {
        self.schema == 2
            && hex(&self.network_key, 64)
            && hex(&self.inputs_hash, 64)
            && self.run_id.len() == 32
            && self
                .run_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    pub fn compatible(&self, other: &Self) -> bool {
        self.valid()
            && other.valid()
            && self.network_key == other.network_key
            && self.inputs_hash == other.inputs_hash
    }
}
fn new_run_id() -> String {
    // tempfile supplies OS randomness and create_new, without exposing machine identity.
    let random = tempfile::Builder::new()
        .prefix("zapret-rust-context-")
        .tempfile();
    let material = format!(
        "{:?}|{:?}|{}",
        std::time::SystemTime::now(),
        random.as_ref().ok().map(|p| p.path()),
        std::process::id()
    );
    sha256(material.as_bytes())[..32].to_ascii_lowercase()
}
pub fn test_result_context(
    root: &Path,
    settings: &Settings,
    network_key: &str,
) -> Result<TestResultContext> {
    rank_context(root, settings, network_key, None, &mut InputHashes::live())
}
pub(crate) fn rank_context(
    root: &Path,
    settings: &Settings,
    network_key: &str,
    native_identity: Option<&str>,
    hashes: &mut InputHashes<'_>,
) -> Result<TestResultContext> {
    ensure!(
        native_identity.is_none_or(|id| hex(id, 64)),
        "Native identity must be a SHA256"
    );
    ensure!(hex(network_key, 64), "Unknown network context");
    let settings_key = settings_signature(settings, &["alt", "auto", "notify"]);
    let inputs = score_hash(
        root,
        &[ScoreTarget {
            group: "rank".into(),
            name: "configuration".into(),
            url: "local".into(),
        }],
        &BTreeMap::from([("Settings".into(), settings_key)]),
        hashes,
    )?;
    let mut parts = vec!["rank-context-v2".to_owned(), inputs];
    for dir in ["strategies", "bin", "windivert"] {
        for file in sorted_files(root, dir)? {
            let relative = format!("{dir}/{file}");
            if crate::is_native_build_artifact(&relative) {
                continue;
            }
            parts.push(format!("{relative}={}", hashes.get(&root.join(&relative))?));
        }
    }
    let inputs_hash = sha256(parts.join("\n").as_bytes());
    let inputs_hash = match native_identity {
        Some(identity) => {
            sha256(format!("native-rank-context-v1\n{inputs_hash}\n{identity}").as_bytes())
        }
        None => inputs_hash,
    };
    Ok(TestResultContext {
        schema: 2,
        network_key: network_key.to_owned(),
        inputs_hash,
        run_id: new_run_id(),
    })
}
pub fn test_result_context_with_identity(
    root: &Path,
    settings: &Settings,
    network_key: &str,
    native_identity: &str,
) -> Result<TestResultContext> {
    rank_context(
        root,
        settings,
        network_key,
        Some(native_identity),
        &mut InputHashes::live(),
    )
}
pub fn ring_composition_key(root: &Path, settings: &Settings) -> Result<String> {
    ring_key(root, settings, None, &mut InputHashes::live())
}
pub(crate) fn ring_key(
    root: &Path,
    settings: &Settings,
    native_identity: Option<&str>,
    hashes: &mut InputHashes<'_>,
) -> Result<String> {
    ensure!(
        native_identity.is_none_or(|id| hex(id, 64)),
        "Native identity must be a SHA256"
    );
    let settings_key = settings_signature(settings, &[]);
    let key = score_hash(
        root,
        &[ScoreTarget {
            group: "ring".into(),
            name: "composition".into(),
            url: "local".into(),
        }],
        &BTreeMap::from([("Settings".into(), settings_key)]),
        hashes,
    )?;
    Ok(match native_identity {
        Some(identity) => {
            sha256(format!("native-ring-composition-v1\n{key}\n{identity}").as_bytes())
        }
        None => key,
    })
}
pub fn ring_composition_key_with_identity(
    root: &Path,
    settings: &Settings,
    native_identity: &str,
) -> Result<String> {
    ring_key(
        root,
        settings,
        Some(native_identity),
        &mut InputHashes::live(),
    )
}
pub fn result_header(text: &str) -> Option<TestResultContext> {
    let headers: Vec<_> = text
        .lines()
        .filter_map(|l| l.strip_prefix("# context: "))
        .collect();
    if headers.len() != 1 {
        return None;
    }
    let context: TestResultContext = serde_json::from_str(headers[0]).ok()?;
    context.valid().then_some(context)
}
fn settings_signature(settings: &Settings, exclude: &[&str]) -> String {
    let mut entries: Vec<_> = settings
        .values
        .iter()
        .filter(|(k, _)| !exclude.contains(&k.as_str()))
        .filter(|(k, _)| {
            !k.eq_ignore_ascii_case("gameapps")
                || settings.get("game").eq_ignore_ascii_case("selected")
        })
        .collect();
    entries.sort_by(|(a, _), (b, _)| crate::io::legacy_compare(a, b));
    entries
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("|")
}
