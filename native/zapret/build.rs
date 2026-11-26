use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    if env::var("TARGET").as_deref() != Ok("x86_64-pc-windows-gnu") {
        return;
    }

    println!("cargo:rerun-if-changed=windows-version.rc");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo provides OUT_DIR"));
    let version = env!("CARGO_PKG_VERSION");
    let version_fields = version
        .split('-')
        .next()
        .expect("Cargo version")
        .replace('.', ",");
    let source = include_str!("windows-version.rc")
        .replace("@VERSION@", version)
        .replace("@VERSION_FIELDS@", &version_fields);
    let script = out.join("zapret-version.rc");
    let object = out.join("zapret-version.o");
    fs::write(&script, source).expect("write Windows version resource");

    let status = Command::new("x86_64-w64-mingw32-windres")
        .args(["-O", "coff", "-i"])
        .arg(script)
        .arg("-o")
        .arg(&object)
        .status()
        .expect("run windres from the Windows LLVM MinGW toolchain");
    assert!(
        status.success(),
        "Windows version resource compilation failed"
    );
    println!("cargo:rustc-link-arg-bins={}", object.display());
}
