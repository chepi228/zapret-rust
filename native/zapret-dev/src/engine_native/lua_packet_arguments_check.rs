//! Compare the exact packet argument block before replacing its metadata policy.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

fn function(source: &str, anchor: &str) -> Result<std::ops::Range<usize>> {
    let first = source
        .find(anchor)
        .context("Pinned Lua packet argument helper")?;
    let last = first
        + source[first..]
            .find("\n}\n")
            .context("Packet argument helper end")?
        + 3;
    Ok(first..last)
}

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    lua: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Packet argument parent")?
        .join("lua-packet-arguments-check");
    fs::create_dir(&directory)?;
    fs::copy(nfq.join("lua.h"), directory.join("engine_lua.h"))?;
    let path = nfq.join("desync.c");
    let mut source = fs::read_to_string(&path)?;
    let start = source
        .find("\t\t\t// create arg table that persists across multiple desync function calls")
        .context("Packet argument block")?;
    let end = start
        + source[start..]
            .find("\t\t\tref_arg = luaL_ref(")
            .context("Packet argument publication end")?;
    let original = &source[start..end];
    let replacement = "\t\t\tzapret_lua_packet_argument_input arguments={\n\t\t\t\t.profile=dp,.packet=dis,.current=pos,.opposite=rpos,.interface_in=ifin,.interface_out=ifout,\n\t\t\t\t.target4=(const uint8_t *)sdp4,.target6=(const uint8_t *)sdp6,.port=sdport,.incoming=bIncoming,\n\t\t\t\t.mark=fwmark,.piece=replay_piece,.pieces=replay_piece_count,.payload=l7payload,.protocol=l7proto,\n\t\t\t\t.reassembly_offset=reasm_offset,.reassembly=rdata_payload,.reassembly_length=rlen_payload,\n\t\t\t\t.decryption=data_decrypt,.decryption_length=len_decrypt\n\t\t\t};\n\t\t\tnative_lua_packet_arguments(&arguments,ctrack,tpos);\n";
    fs::write(
        directory.join("lua_packet_arguments_candidate.inc"),
        format!(
            "#define reference_packet_arguments candidate_packet_arguments\n#include \"lua_packet_arguments_locals.inc\"\n#undef reference_packet_arguments\n{replacement}\n}}\n"
        ),
    )?;
    fs::write(
        directory.join("lua_packet_arguments_reference.inc"),
        format!("#include \"lua_packet_arguments_locals.inc\"\n{original}\n}}\n"),
    )?;
    let lua_source = fs::read_to_string(nfq.join("lua.c"))?;
    let mut common = String::new();
    for anchor in [
        "int lua_absindex(",
        "void lua_pushf_int(",
        "void lua_pushf_lint(",
        "void lua_pushf_bool(",
        "void lua_pushf_str(",
        "void lua_pushf_lstr(",
        "void lua_push_raw(",
        "void lua_pushf_raw(",
        "void lua_pushf_table(",
        "void lua_pushf_global(",
    ] {
        let mut body = lua_source[function(&lua_source, anchor)?].to_owned();
        if anchor.starts_with("void lua_pushf_") {
            let at = body.rfind('}').context("Packet helper brace")?;
            body.insert_str(at, "    observe(L,field);\n");
        }
        common.push_str(&body);
        common.push('\n');
    }
    fs::write(directory.join("lua_packet_arguments_common.inc"), common)?;
    let exe = directory.join("lua-packet-arguments-check.exe");
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
        .arg(shim.join("lua_packet_arguments_oracle.c"))
        .arg(shim.join("win_files.c"))
        .arg(lua.join("libluajit.a"))
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
        "Compile packet-to-Lua argument comparison",
    )?;
    let result=tools.run_command(&Command::new(&exe),&directory,"Compare packet field values, nesting, lazy MSS lookup, callback mutations and VM error cleanup")?;
    ensure!(
        result.starts_with("PASS lua_packet_arguments "),
        "Incomplete packet argument comparison"
    );
    fs::write(output, &result)?;
    print!("{result}");
    source.replace_range(start..end, replacement);
    let at = source
        .find("static uint8_t desync(\n")
        .context("Packet invocation anchor")?;
    source.insert_str(at, "#include \"lua_packet_arguments_windows.inc\"\n\n");
    // rpos is consumed by the new borrowed input rather than copied early.
    fs::write(path, source)?;
    Ok(())
}
