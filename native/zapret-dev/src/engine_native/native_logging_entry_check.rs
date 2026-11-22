//! Gate complete native logging entries before replacing any selected source.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

const PARAMS: &[(&str, &str)] = &[
    ("int DLOG_FILE_VA(", "DLOG_FILE_VA"),
    ("int DLOG_CON_VA(", "DLOG_CON_VA"),
    ("int DLOG_FILENAME_VA(", "DLOG_FILENAME_VA"),
    ("static void syslog_log_function(", "syslog_log_function"),
    ("static int DLOG_FILENAME(", "DLOG_FILENAME"),
    ("static void file_log_function(", "file_log_function"),
    ("static int DLOG_VA(", "DLOG_VA"),
    ("int DLOG(", "DLOG"),
    ("int DLOG_CONDUP(", "DLOG_CONDUP"),
    ("int DLOG_ERR(", "DLOG_ERR"),
    ("int DLOG_PERROR(", "DLOG_PERROR"),
    ("int LOG_APPEND(", "LOG_APPEND"),
    ("int HOSTLIST_DEBUGLOG_APPEND(", "HOSTLIST_DEBUGLOG_APPEND"),
];
fn function(source: &str, signature: &str) -> Result<std::ops::Range<usize>> {
    let start = source
        .find(signature)
        .with_context(|| format!("Missing original logging {signature}"))?;
    let end = start + source[start..].find("\n}\n").context("Logging entry end")? + 3;
    ensure!(
        source[end..].find(signature).is_none(),
        "Duplicate logging signature"
    );
    Ok(start..end)
}
pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    object: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Logging entry parent")?
        .join("native-logging-entry-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("params.c");
    let original = fs::read_to_string(&path)?;
    let helper_path = nfq.join("helpers.c");
    let helpers = fs::read_to_string(&helper_path)?;
    let mut reference = String::from("typedef void (*f_log_function)(int,const char *);\n");
    reference.push_str(&helpers[function(&helpers, "int fprint_localtime(")?]);
    for &(signature, _) in PARAMS {
        reference.push_str(&original[function(&original, signature)?]);
    }
    fs::write(directory.join("native_logging_reference.inc"), &reference)?;
    let mut selected = original.clone();
    for (signature, include) in [
        ("int DLOG_FILENAME_VA(", "native_log_append_windows.inc"),
        ("static int DLOG_VA(", "native_logging_entry_windows.inc"),
    ] {
        let span = function(&selected, signature)?;
        selected.replace_range(span, &format!("#include \"{include}\"\n"));
    }
    let append = function(&selected, "int LOG_APPEND(")?;
    selected.replace_range(append, "");
    for (from, to) in [
        (
            "syslog(priority,\"%s\",line);",
            "zapret_system_syslog(priority,line);",
        ),
        (
            "syslog_priority==LOG_ERR ? stderr : stdout",
            "zapret_log_console_error(syslog_priority) ? stderr : stdout",
        ),
        (
            "if (*params.hostlist_auto_debuglog)",
            "if (zapret_log_path_enabled(params.hostlist_auto_debuglog))",
        ),
        (
            "return DLOG_ERR(\"%s: %s\\n\", s, strerror(errno));",
            "return zapret_log_perror(s, strerror(errno), DLOG_ERR);",
        ),
    ] {
        ensure!(
            selected.matches(from).count() == 1,
            "Original logging condition changed: {from}"
        );
        selected = selected.replace(from, to);
    }
    let mut actual = String::new();
    actual.push_str(&helpers[function(&helpers, "int fprint_localtime(")?]);
    let span = function(&actual, "int fprint_localtime(")?;
    actual.replace_range(span, "#include \"native_log_time_windows.inc\"\n");
    actual.push_str("#include \"native_logging_stdio_fixture.inc\"\n");
    for &(signature, name) in PARAMS {
        if matches!(
            name,
            "DLOG_FILENAME"
                | "DLOG"
                | "DLOG_CONDUP"
                | "DLOG_ERR"
                | "DLOG_PERROR"
                | "HOSTLIST_DEBUGLOG_APPEND"
        ) {
            actual.push_str(&selected[function(&selected, signature)?]);
        }
    }
    fs::write(directory.join("native_logging_selected.inc"), actual)?;
    let exe = directory.join("native-logging-entry-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu11",
        "-ffunction-sections",
        "-fdata-sections",
        "-D_POSIX_C_SOURCE=200809L",
    ]);
    for include in [&directory, shim] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg(shim.join("native_logging_entry_oracle.c"))
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
    tools.run_command(
        &command,
        &directory,
        "Compile complete DLOG/append/timestamp oracle",
    )?;
    let result = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare complete logging entries and deferred native observations",
    )?;
    ensure!(
        result.starts_with("PASS native_logging_entry ")
            && result.contains("PASS native_logging_stdio "),
        "Incomplete native logging comparison"
    );
    let direct = directory.join("native-logging-stdio-direct.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu99",
        "-ffunction-sections",
        "-fdata-sections",
        "-fexceptions",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-DZAPRET_WINDOWS=1",
        "-D_FILE_OFFSET_BITS=64",
        "-D_POSIX_C_SOURCE=200809L",
        "-DLUAJIT",
        "-Wno-macro-redefined",
    ]);
    for include in [shim, &shim.join("include"), &nfq.join("windows"), lua, nfq] {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(shim.join("engine_logging_stdio_oracle.c"))
        .arg(object)
        .arg(library)
        .args([
            "-Wl,--gc-sections,--wrap=wf_fopen,--wrap=fclose,--wrap=__mingw_vfprintf,--wrap=zapret_crt_fprint_localtime,--wrap=zapret_system_syslog",
            "-static",
            "-lws2_32",
            "-lbcrypt",
            "-lntdll",
            "-luserenv",
            "-ladvapi32",
            "-luser32",
            "-lwinpthread",
            "-o",
        ])
        .arg(&direct);
    tools.run_command(
        &command,
        &directory,
        "Compile the linked Rust logging entry",
    )?;
    let private = directory.join("direct-run");
    fs::create_dir(&private)?;
    let native = tools.run_command(
        &Command::new(direct),
        &private,
        "Compare actual log files, variadic inputs and output ownership",
    )?;
    ensure!(
        native.starts_with("PASS engine_logging_stdio_direct "),
        "Incomplete Rust UCRT log comparison"
    );
    fs::write(output, format!("{result}{native}"))?;
    print!("{result}{native}");
    // The source files are unchanged until the complete comparison succeeds.
    selected.insert_str(0, "#include \"native_logging_entry_abi.h\"\n");
    // Fixed-width C names must be declared before the ABI include.
    selected=selected.replacen("#include \"native_logging_entry_abi.h\"\n","#include <stdbool.h>\n#include <stdint.h>\n#include <stddef.h>\n#include \"native_logging_entry_abi.h\"\n",1);
    fs::write(path, selected)?;
    Ok(())
}
