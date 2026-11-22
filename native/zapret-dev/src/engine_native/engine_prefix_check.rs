//! Compare startup through the first parser call and the capture activation entry.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, ops::Range, path::Path, process::Command};

fn body(source: &str, signature: &str) -> Result<Range<usize>> {
    let start = source
        .find(signature)
        .with_context(|| format!("Pinned startup {signature}"))?;
    let end = start + source[start..].find("\n}\n").context("Startup body end")? + 3;
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
        .context("Startup parent")?
        .join("engine-prefix-check");
    fs::create_dir(&directory)?;
    let path = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&path)?;
    let defaults = body(&source, "static void ApplyDefaultBlobs(")?;
    let main = body(&source, "int main(int argc, char **argv)")?;
    let version_start = source
        .find("#define STRINGIFY(x) #x\n")
        .context("Pinned version macros")?;
    let version_end = version_start
        + source[version_start..]
            .find("enum {WF_TCP_IN,")
            .context("Pinned version block end")?;
    ensure!(defaults.end < version_start && version_end < main.start);
    let entry = &source[main.clone()];
    let begin = entry.find("{\n").context("Main startup opening")? + 2;
    let locals = entry.find("\n\tint v;").context("Main storage start")?;
    let prepare = entry
        .find("\n\tif (argc < 2) exithelp();")
        .context("Main startup arguments")?;
    let capture = entry
        .find("\n\tzapret_capture_cli capture_cli")
        .context("Main parser setup")?;
    let parse_error = entry
        .find("\n\t\tif (v)\n")
        .context("Main parse-error dispatch")?;
    let route = entry
        .find("\n\t\tnative_engine_cli route=")
        .context("Main option routing")?;
    let residual = entry
        .find("\n\t\tswitch (option_index)")
        .context("Main residual switch")?;
    let finish = entry
        .find("\n\treturn native_engine_finish(")
        .context("Main final dispatch")?;
    ensure!(
        begin < locals
            && locals < prepare
            && prepare < capture
            && capture < parse_error
            && parse_error < route
            && route < residual
            && residual < finish,
        "Startup anchors out of order"
    );
    let mut reference = source[version_start..version_end].to_owned();
    reference.push_str(&source[defaults.clone()]);
    reference.push_str(&format!(
        "\nstatic bool reference_prefix(int *argc_out, char ***argv_out, unsigned *hash_wf,\n\
            native_profile_flow *profile_out, struct desync_profile_list **entry_out,\n\
            struct desync_profile **dp_out)\n{{\n\
            int argc=*argc_out; char **argv=*argv_out;\n{}{}\n\
            *argc_out=argc;*argv_out=argv;*profile_out=profile_flow;*entry_out=dpl;*dp_out=dp;return true;\n}}\n",
        &entry[begin..locals],
        entry[prepare..capture].replace("sizeof(hash_wf)", "WF_COUNT * sizeof(*hash_wf)")
    ));
    let parse_reference = &entry[parse_error..route];
    reference.push_str(&format!(
        "\nstatic void reference_parse_error(bool bDry){{int v=1;{parse_reference}\n}}\n"
    ));
    let residual_reference = entry[residual..finish]
        .strip_suffix("\n\t}")
        .context("Main option loop end")?;
    reference.push_str(&format!(
        "\nstatic void reference_residual(int option_index,char *optarg){{{}\n}}\n",
        residual_reference
    ));
    let loop_path = shim.join("engine_loop_windows.inc");
    let mut loop_source = fs::read_to_string(&loop_path)?;
    let activation = body(&loop_source, "static bool loop_activate(")?;
    reference.push_str(&loop_source[activation.clone()]);
    let storage = entry[locals..prepare]
        .strip_prefix("\n\tint v;\n\tint option_index = 0;")
        .context("Pinned main cursor locals")?;
    reference.push_str(&format!(
        "\nstatic zapret_engine_main_options reference_main_defaults(void)\n{{{storage}\n\
        \tzapret_engine_main_options options={{\n\
        \t\t.anonymous={{anon_hl,anon_hl_exclude,anon_ips,anon_ips_exclude}}, .payload=payload_type,\n\
        \t\t.incoming=range_in, .outgoing=range_out, .index=IfIdx, .sub_index=SubIfIdx,\n\
        \t\t.dry=bDry, .duplicate=bDupCheck, .ipv4=wf_ipv4, .ipv6=wf_ipv6,\n\
        \t\t.lan=wf_filter_lan, .loopback=wf_filter_loopback, .empty=wf_tcp_empty,\n\
        \t}};\n\
        \t(void)hash_wf;\n\
        \tmemcpy(options.save,wf_save_file,sizeof(options.save));\n\
        \treturn options;\n}}\n"
    ));
    fs::write(directory.join("engine_prefix_reference.inc"), reference)?;
    let replacement = format!(
        "#include \"engine_prefix_windows.inc\"\n#include \"engine_arguments_windows.inc\"\n\n{}\treturn native_engine_main(argc, argv);\n}}\n",
        &entry[..begin]
    );
    source.replace_range(main, &replacement);
    source.replace_range(version_start..version_end, "");
    source.replace_range(defaults, "#include \"engine_default_blobs_windows.inc\"\n");
    loop_source.replace_range(activation, "#include \"engine_activate_windows.inc\"\n");

    let mut results = String::new();
    for direct in [false, true] {
        let (fixture, exe_name, marker) = if direct {
            (
                "engine_main_prefix_oracle.c",
                "engine-main-prefix-check.exe",
                "PASS main_prefix_direct ",
            )
        } else {
            (
                "engine_prefix_oracle.c",
                "engine-prefix-check.exe",
                "PASS engine_prefix ",
            )
        };
        let exe = directory.join(exe_name);
        let mut command = Command::new(tools.compiler);
        command.args([
            "-O2",
            "-std=gnu11",
            "-ffunction-sections",
            "-fdata-sections",
            "-DZAPRET_WINDOWS=1",
            "-DZAPRET_NATIVE_WINDOWS=1",
            "-DLUAJIT",
            "-D_FILE_OFFSET_BITS=64",
            "-D_POSIX_C_SOURCE=200809L",
            "-Wno-macro-redefined",
        ]);
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
            command.arg("-fexceptions").arg(object).arg(
                "-Wl,--wrap=zapret_native_main_prefix_step,--wrap=_time64,--wrap=zapret_srandom,--wrap=zapret_crt_set_console_io_buffering,--wrap=zapret_prefix_prepare6,--wrap=calloc",
            );
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
                "-luser32",
                "-lwinpthread",
                "-o",
            ])
            .arg(&exe);
        tools.run_command(
            &command,
            &directory,
            "Compile native startup and activation comparison",
        )?;
        let text = tools.run_command(
            &Command::new(&exe),
            &directory,
            "Compare startup order, default blobs, early exits and activation",
        )?;
        ensure!(text.starts_with(marker), "Incomplete startup comparison");
        print!("{text}");
        results.push_str(&text);
    }
    fs::write(output, results)?;
    fs::write(path, source)?;
    fs::write(loop_path, loop_source)?;
    Ok(())
}
