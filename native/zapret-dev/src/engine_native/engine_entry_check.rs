//! Compare final Windows main routing/order before replacing its control flow.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn select_adapter(shim: &Path) -> Result<String> {
    let mut source = fs::read_to_string(shim.join("engine_entry_windows.inc"))?;
    let first = source
        .find("static int32_t native_engine_option_category(")
        .context("Main option category binding")?;
    let outcome = source[first..]
        .find("static bool native_engine_apply_option_result(")
        .context("Main option outcome binding")?
        + first;
    source.replace_range(
        first..outcome,
        "#include \"engine_cli_bindings_windows.inc\"\n",
    );
    let result = source
        .find("zapret_engine_route_result result = zapret_engine_route_effect(")
        .context("Main route result")?;
    let end = source[result..]
        .find(';')
        .context("Main route result end")?
        + result
        + 1;
    source.replace_range(
        result..end,
        "zapret_engine_route_result result = zapret_native_cli_route_effect(state, route);",
    );
    let finish = source
        .find("static int native_engine_finish(")
        .context("Main finish binding")?;
    let end = finish + source[finish..].find("\n}\n").context("Main finish end")? + 3;
    source.replace_range(finish..end, "#include \"engine_main_finish_windows.inc\"\n");
    Ok(source)
}

fn reference_arguments(shim: &Path) -> Result<String> {
    let mut arguments = fs::read_to_string(shim.join("engine_arguments_windows.inc"))?;
    let first = arguments
        .find("static void native_engine_arguments(")
        .context("Main argument loop")?;
    let end = arguments[first..]
        .find("\n}\n")
        .context("Main argument loop end")?
        + first
        + 3;
    arguments.replace_range(first..end, "");
    let begin = arguments
        .find("    zapret_capture_cli capture = {")
        .context("Main capture storage")?;
    let end = begin
        + arguments[begin..]
            .find("    native_engine_arguments(&route")
            .context("Main dispatch call")?;
    arguments.replace_range(
        begin..end,
        concat!(
            "    zapret_capture_cli capture;\n",
            "    native_engine_cli route;\n",
            "    zapret_native_main_bind(&options, hashes, &profile_flow, &entry, &profile, &capture, &route);\n"
        ),
    );
    let scan = "    native_engine_arguments(&route, argc, argv);";
    ensure!(
        arguments.matches(scan).count() == 1,
        "Pinned main argument call"
    );
    Ok(arguments.replacen(
        scan,
        concat!(
            "    const zapret_native_argument_ops ops = {long_options, zapret_native_cli_count(),\n",
            "        getenv, native_cli_stderr, zapret_native_cli_read_blob};\n",
            "    zapret_native_argument_result arguments = zapret_native_cli_run(argc, argv, &route, &ops);\n",
            "    if (arguments.action == NATIVE_ARGUMENT_HELP) exithelp_clean();\n",
            "    else if (arguments.action == NATIVE_ARGUMENT_EXIT) exit_clean(arguments.exit_code);",
        ),
        1,
    ))
}

pub(super) fn select(nfq: &Path, shim: &Path) -> Result<()> {
    let mut adapter = select_adapter(shim)?;
    let first = adapter
        .find("static bool native_engine_apply_option_result(")
        .context("Main argument result wrapper")?;
    let end = first
        + adapter[first..]
            .find("\n}\n")
            .context("Argument result end")?
        + 3;
    adapter.replace_range(first..end, "");
    let fixture_bindings = "#include \"engine_cli_bindings_windows.inc\"\n";
    ensure!(
        adapter.matches(fixture_bindings).count() == 1,
        "Pinned CLI binding fixture include"
    );
    adapter = adapter.replace(fixture_bindings, "#include \"engine_cli_dispatch_abi.h\"\n");
    let finish = "#include \"engine_main_finish_windows.inc\"\n";
    ensure!(
        adapter.matches(finish).count() == 1,
        "Pinned main finish include"
    );
    adapter = adapter.replace(finish, "");
    fs::write(shim.join("engine_entry_windows.inc"), adapter)?;
    let engine = nfq.join("nfqws.c");
    let source = fs::read_to_string(&engine)?;
    let entry = concat!(
        "#include \"engine_main_prefix_windows.inc\"\n",
        "#include \"engine_arguments_windows.inc\"\n\n",
        "int main(int argc, char **argv)\n{\n\treturn native_engine_main(argc, argv);\n}\n"
    );
    ensure!(
        source.matches(entry).count() == 1,
        "Pinned Windows main entry adapter"
    );
    fs::write(
        engine,
        source.replace(entry, "#include \"engine_host_layout_windows.inc\"\n"),
    )?;
    Ok(())
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
        .context("Engine entry parent")?
        .join("engine-entry-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&path)?;
    let main = source
        .find("int main(int argc, char **argv)\n")
        .context("Windows main entry")?;
    let last = main + source[main..].find("\n}\n").context("Windows main end")? + 3;
    let route = main
        + source[main..]
            .find("\t\tif (option_index != IDX_SSID_FILTER_NEG")
            .context("Main option routing")?;
    let route_end = route
        + source[route..]
            .find("\t\tswitch (option_index)")
            .context("Main residual options")?;
    let finish = main
        + source[main..]
            .find("\t{\n\t\tuint32_t status = native_profile_finish(")
            .context("Main final profile phase")?;
    let reference_route = format!(
        "static bool reference_engine_option(native_engine_cli *input)\n{{\n    native_engine_reference storage={{.cli=*input}};native_engine_reference *state=&storage;bool handled=true;\n    do{{\n{}\n        handled=false;\n    }}while(0);return handled;\n}}\n",
        &source[route..route_end]
    );
    let reference_finish = format!(
        "static int reference_engine_finish(native_profile_flow *profiles,struct desync_profile *profile,zapret_capture_cli *capture,bool *dry,int *argc_pointer,char ***argv_pointer)\n{{\n    native_engine_reference storage={{.cli={{.flow=profiles,.profile=&profile,.capture=capture,.dry=dry}},.argc_pointer=argc_pointer,.argv_pointer=argv_pointer}};native_engine_reference *state=&storage;int result;\n{}",
        &source[finish..last]
    );
    fs::write(
        directory.join("engine_entry_reference.inc"),
        format!("{reference_route}\n{reference_finish}"),
    )?;
    let capture = fs::read_to_string(shim.join("cli_capture_options_windows.inc"))?;
    let declaration = capture
        .lines()
        .find(|line| line.starts_with("typedef struct{char *save;"))
        .context("Capture CLI type")?;
    fs::write(
        directory.join("engine_entry_capture_type.inc"),
        format!("{declaration}\n"),
    )?;
    fs::write(
        directory.join("engine_entry_rust.inc"),
        select_adapter(shim)?,
    )?;
    fs::write(
        directory.join("engine_arguments_reference.inc"),
        reference_arguments(shim)?,
    )?;
    let mut results = String::new();
    for (fixture, executable, direct) in [
        ("engine_entry_oracle.c", "engine-entry-check.exe", false),
        ("engine_entry_oracle.c", "engine-entry-rust-check.exe", true),
        (
            "engine_host_main_oracle.c",
            "engine-host-main-check.exe",
            true,
        ),
    ] {
        let host = fixture == "engine_host_main_oracle.c";
        let exe = directory.join(executable);
        let mut command = Command::new(tools.compiler);
        command.args([
            "-O2",
            "-std=gnu99",
            "-ffunction-sections",
            "-fdata-sections",
            "-DZAPRET_WINDOWS=1",
            "-DZAPRET_NATIVE_WINDOWS=1",
            "-DLUAJIT",
            "-Wno-macro-redefined",
        ]);
        if host {
            command.args([
                "-D_FILE_OFFSET_BITS=64",
                "-D_POSIX_C_SOURCE=200809L",
                "-Wl,--wrap=zapret_native_main_advance",
            ]);
        } else if direct {
            command.arg("-DZAPRET_DIRECT_NATIVE_ENTRY=1");
        }
        for include in [
            &directory,
            shim,
            &shim.join("include"),
            &nfq.join("windows"),
            lua,
            nfq,
        ] {
            command.arg(format!("-I{}", include.display()));
        }
        command
            .arg("-include")
            .arg(shim.join("win_platform.h"))
            .arg(shim.join(fixture));
        if direct {
            command.arg(object);
        }
        command
            .arg(library)
            .args([
                "-Wl,--gc-sections",
                "-static",
                "-lws2_32",
                "-lbcrypt",
                "-lntdll",
                "-luserenv",
                "-ladvapi32",
                "-lole32",
                "-lshell32",
                "-luser32",
                "-lwinpthread",
                "-o",
            ])
            .arg(&exe);
        tools.run_command(
            &command,
            &directory,
            "Compile main option routing and final startup comparison",
        )?;
        let result = tools.run_command(
            &Command::new(&exe),
            &directory,
            "Compare parser order, mutable storage, early exits and exact final cleanup order",
        )?;
        let prefix = if host {
            "PASS engine_host_main "
        } else {
            "PASS engine_entry "
        };
        ensure!(
            result.starts_with(prefix),
            "Incomplete main entry comparison"
        );
        if direct && !host {
            ensure!(
                result.contains("rust_dispatch=1")
                    && result.contains("rust_main_storage=1")
                    && result.contains("rust_argument_runs=6"),
                "Rust routing, main storage or complete argument loop not exercised"
            );
        }
        print!("{result}");
        results.push_str(&result);
    }
    fs::write(output, results)?;
    source.replace_range(
        finish..last,
        "\treturn native_engine_finish(&profile_flow,dp,&capture_cli,&bDry,&argc,&argv);\n}\n",
    );
    source.replace_range(route..route_end,concat!("\t\tnative_engine_cli route={option_index,optarg,&profile_flow,&dpl,&dp,{&anon_hl,&anon_hl_exclude,&anon_ips,&anon_ips_exclude},&payload_type,&range_in,&range_out,&bDry,&capture_cli};\n","\t\tif(native_engine_option(&route))continue;\n"));
    let main = source
        .find("int main(int argc, char **argv)\n")
        .context("Patched main entry")?;
    source.insert_str(main, "#include \"engine_entry_windows.inc\"\n\n");
    ensure!(
        source.matches("\tint result, v;\n").count() == 1,
        "Pinned main result storage"
    );
    source = source.replace("\tint result, v;\n", "\tint v;\n");
    fs::write(path, source)?;
    Ok(())
}
