use std::{
    fs,
    io::Read,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};
use zapret_core::*;

#[test]
fn atomic_replace_supports_every_utf16_filename_alignment() {
    let root = tempfile::tempdir().unwrap();
    for count in 1..=8 {
        let path = root.path().join(format!("{}.exe", "a".repeat(count)));
        atomic_write(&path, b"complete").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"complete");
    }
}

#[cfg(windows)]
#[test]
fn denied_atomic_replacement_preserves_target_and_cleans_only_owned_temp() {
    use std::os::windows::fs::OpenOptionsExt;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("settings.ini");
    fs::write(&path, b"old complete settings").unwrap();
    let unrelated = root.path().join("unrelated.tmp");
    fs::write(&unrelated, b"keep").unwrap();
    let _lock = fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&path)
        .unwrap();
    assert!(atomic_write(&path, b"new settings").is_err());
    assert_eq!(fs::read(&path).unwrap(), b"old complete settings");
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
}

#[test]
fn concurrent_readers_see_only_complete_atomic_versions() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("state.txt");
    let old = vec![b'a'; 100_000];
    let new = vec![b'b'; 100_000];
    atomic_write(&path, &old).unwrap();
    let complete = Arc::new(AtomicBool::new(false));
    let signal = complete.clone();
    let worker_path = path.clone();
    let worker = thread::spawn(move || {
        let result = (|| -> anyhow::Result<()> {
            for i in 0..30 {
                atomic_write(
                    &worker_path,
                    &vec![if i % 2 == 0 { b'b' } else { b'a' }; 100_000],
                )?;
            }
            Ok(())
        })();
        signal.store(true, Ordering::Release);
        result
    });
    let mut reads = 0;
    let started = std::time::Instant::now();
    while !complete.load(Ordering::Acquire)
        && started.elapsed() < std::time::Duration::from_secs(15)
    {
        let mut file = fs::File::open(&path).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert!(bytes == old || bytes == new);
        reads += 1;
    }
    assert!(
        complete.load(Ordering::Acquire),
        "Atomic writer did not finish in 15 seconds"
    );
    worker.join().unwrap().unwrap();
    assert!(reads > 0);
}

#[test]
fn manifest_requires_exact_unique_printable_authority_and_detects_tampering() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("tools")).unwrap();
    let mut manifest = "schema=1\ntag=v1.0.6\ncommit=".to_owned()
        + &"a".repeat(40)
        + "\narchive-sha256="
        + &"b".repeat(64)
        + "\n";
    for file in CORE_FILES {
        let path = root.path().join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"fixture").unwrap();
        manifest.push_str(&format!("{file}={}\n", sha256(b"fixture")));
    }
    let path = root.path().join("tools/upstream.txt");
    fs::write(&path, &manifest).unwrap();
    let captured = read_core_manifest(&path).unwrap();
    assert!(verify_integrity(root.path(), &captured).unwrap().is_empty());
    let native = manifest
        .replace("schema=1", "schema=2")
        .replace(&format!("{CYGWIN_DLL}={}\n", sha256(b"fixture")), "");
    let parsed = parse_core_manifest(native.as_bytes()).unwrap();
    assert_eq!(parsed.schema, NATIVE_ONLY_SCHEMA);
    assert_eq!(parsed.hashes.len(), CORE_FILES.len() - 1);
    assert!(!parsed.hashes.contains_key(CYGWIN_DLL));
    assert!(parse_core_manifest(manifest.replace("schema=1", "schema=2").as_bytes()).is_err());
    assert!(parse_core_manifest(native.replace("schema=2", "schema=1").as_bytes()).is_err());
    fs::write(root.path().join("bin/winws2.exe"), b"modified").unwrap();
    assert_eq!(verify_integrity(root.path(), &captured).unwrap().len(), 1);
    for invalid in [
        format!("{manifest}schema=1\n"),
        manifest.replace("schema=1", "sche\u{ad}ma=1"),
        manifest.replace("tag=v1.0.6", "tag=v01.0.6"),
        format!("{manifest}extra=value\n"),
    ] {
        fs::write(&path, invalid).unwrap();
        assert!(read_core_manifest(&path).is_err());
        assert!(!core_manifest_current(&captured, &path));
    }
}
