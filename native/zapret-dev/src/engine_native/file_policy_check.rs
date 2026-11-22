//! Compare complete facade traces and verify the Rust exports with UCRT.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("File facade parent")?
        .join("file-policy-check");
    fs::create_dir(&directory)?;
    let reference = shim.join("file_policy_reference.c");
    let original = fs::read_to_string(&reference)?;
    ensure!(
        original.contains("static char *wf_resolve(")
            && original.contains("canonical_mode[4]")
            && original.contains("static wf_environment *environment;"),
        "Pinned complete file facade changed"
    );
    let candidate =
        "#define WIN_FILES_IMPLEMENTATION\n#include \"file_policy_candidate_fixture.inc\"\n";
    let actual = directory.join("file_policy_actual.c");
    fs::write(&actual, candidate)?;
    let command = || {
        let mut c = Command::new(tools.compiler);
        c.args([
            "-O2",
            "-std=gnu99",
            "-ffunction-sections",
            "-fdata-sections",
            "-DZAPRET_WINDOWS=1",
            "-DZAPRET_NATIVE_WINDOWS=1",
            "-D_FILE_OFFSET_BITS=64",
        ]);
        for p in [&directory, shim, &shim.join("include"), nfq] {
            c.arg(format!("-I{}", p.display()));
        }
        c.arg("-include").arg(shim.join("win_platform.h"));
        c
    };
    let fixture = |c: &mut Command| {
        c.arg("-include").arg(shim.join("file_policy_fixture.h"));
        for (from, to) in [
            ("path", "path"),
            ("utf8", "utf8"),
            ("realpath", "realpath"),
            ("stat", "stat"),
            ("exedir", "exedir"),
            ("getenv", "getenv"),
            ("setenv", "setenv"),
            ("open", "open"),
            ("getcwd", "getcwd"),
            ("mkdir", "mkdir"),
            ("unlink", "unlink"),
            ("remove", "remove"),
            ("rename", "rename"),
        ] {
            c.arg(format!("-Dzapret_wf_{from}=file_fixture_{to}"));
        }
    };
    let names = [
        "error",
        "path_utf16",
        "wide_to_utf8",
        "realpath",
        "realpath_any",
        "file_stat",
        "set_exedir",
        "getenv",
        "setenv",
        "fopen",
        "open",
        "chdir",
        "getcwd",
        "mkdir",
        "unlink",
        "remove",
        "rename",
    ];
    let object = directory.join("reference.o");
    let mut c = command();
    fixture(&mut c);
    for name in &names {
        c.arg(format!("-Dwf_{name}=reference_wf_{name}"));
    }
    tools.run_command(
        c.arg("-c").arg(&reference).arg("-o").arg(&object),
        &directory,
        "Compile complete old file facade",
    )?;
    let actual_object = directory.join("actual.o");
    let mut c = command();
    fixture(&mut c);
    for name in names.into_iter().chain(["state_result"]) {
        c.arg(format!("-Dwf_{name}=selected_wf_{name}"));
    }
    tools.run_command(
        c.arg("-c").arg(actual).arg("-o").arg(&actual_object),
        &directory,
        "Compile Rust-policy file facade",
    )?;
    let exe = directory.join("file-policy-check.exe");
    let mut c = command();
    c.arg(shim.join("file_policy_oracle.c"))
        .arg(shim.join("win_files.c"))
        .arg(&object)
        .arg(&actual_object)
        .arg(library)
        .args([
            "-Wl,--gc-sections",
            "-static",
            "-lws2_32",
            "-lbcrypt",
            "-lntdll",
            "-luserenv",
            "-ladvapi32",
            "-lwinpthread",
            "-o",
        ])
        .arg(&exe);
    tools.run_command(&c, &directory, "Link whole-entry file facade comparison")?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare file facade traces, ownership, errno and native failures",
    )?;
    ensure!(
        result.starts_with("PASS file_policy entries=17 ")
            && result.contains("PASS file_policy_native "),
        "Incomplete file facade comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    let state = shim.join("file_state_windows.inc");
    let text = fs::read_to_string(&state)?;
    let start = text
        .find("static bool native_file_state_result(")
        .context("Pinned file state result")?;
    let end = start
        + text[start..]
            .find("\n}\n")
            .context("Pinned file state result end")?
        + 3;
    fs::write(
        state,
        format!(
            "{}static bool native_file_state_result(uint32_t error) {{return wf_state_result(error);}}\n{}",
            &text[..start],
            &text[end..]
        ),
    )?;
    Ok(())
}
