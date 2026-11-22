//! Native Windows build of the pinned LuaJIT static library.
use anyhow::{Context, Result, ensure};
use std::{ffi::OsString, fs, path::Path};

use super::tools::{Compilation, Tools};

pub(super) fn luajit(tools: &Tools<'_>, source: &Path, file_shim: &Path) -> Result<()> {
    const LIBS: &str = "lib_base lib_math lib_bit lib_string lib_table lib_io lib_os \
        lib_package lib_debug lib_jit lib_ffi lib_buffer";
    const CORE: &str = "lj_assert lj_gc lj_err lj_char lj_bc lj_obj lj_buf lj_str lj_tab lj_func \
        lj_udata lj_meta lj_debug lj_prng lj_state lj_dispatch lj_vmevent lj_vmmath lj_strscan \
        lj_strfmt lj_strfmt_num lj_serialize lj_api lj_profile lj_lex lj_parse lj_bcread \
        lj_bcwrite lj_load lj_ir lj_opt_mem lj_opt_fold lj_opt_narrow lj_opt_dce lj_opt_loop \
        lj_opt_split lj_opt_sink lj_mcode lj_snap lj_record lj_crecord lj_ffrecord lj_asm \
        lj_trace lj_gdbjit lj_ctype lj_cdata lj_cconv lj_ccall lj_ccallback lj_carith \
        lj_clib lj_cparse lj_lib lj_alloc lib_aux";
    const BUILDVM: &[&str] = &[
        "host/buildvm.c",
        "host/buildvm_asm.c",
        "host/buildvm_peobj.c",
        "host/buildvm_lib.c",
        "host/buildvm_fold.c",
    ];
    const BASE: &[&str] = &[
        "-O2",
        "-fomit-frame-pointer",
        "-Wall",
        "-DLUAJIT_DISABLE_FFI",
    ];
    const ARCH: &[&str] = &[
        "-DLUAJIT_TARGET=LUAJIT_ARCH_x64",
        "-DLJ_ARCH_HASFPU=1",
        "-DLJ_ABI_SOFTFP=0",
        "-DLUAJIT_NO_UNWIND",
    ];
    const TARGET: &[&str] = &[
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-U_FORTIFY_SOURCE",
        "-fno-strict-float-cast-overflow",
    ];

    // Keep DynASM, version generation and VM tables tied to the same source
    // archive and flags as the library. LuaJIT's FFI remains disabled throughout.
    let minilua = source.join("host/minilua.exe");
    let mut arguments: Vec<OsString> = BASE.iter().chain(ARCH).map(OsString::from).collect();
    arguments.extend([
        "-I.".into(),
        "host/minilua.c".into(),
        "-o".into(),
        "host/minilua.exe".into(),
        "-lm".into(),
    ]);
    tools.compile(source, "LuaJIT minilua", &arguments)?;
    let version = source
        .parent()
        .context("Missing LuaJIT source directory")?
        .join(".relver");
    fs::copy(version, source.join("luajit_relver.txt"))?;
    tools.run(
        &minilua,
        source,
        "LuaJIT version header",
        &["host/genversion.lua".into()],
    )?;
    tools.run(
        &minilua,
        source,
        "LuaJIT DynASM",
        &os(&[
            "../dynasm/dynasm.lua",
            "-D",
            "ENDIAN_LE",
            "-D",
            "P64",
            "-D",
            "JIT",
            "-D",
            "FPU",
            "-D",
            "HFABI",
            "-D",
            "NO_UNWIND",
            "-D",
            "VER=",
            "-D",
            "WIN",
            "-o",
            "host/buildvm_arch.h",
            "vm_x64.dasc",
        ]),
    )?;
    let buildvm = source.join("host/buildvm.exe");
    let mut arguments: Vec<OsString> = BASE.iter().chain(ARCH).map(OsString::from).collect();
    arguments.extend(os(&["-I.", "-I../dynasm"]));
    arguments.extend(os(BUILDVM));
    arguments.extend(os(&["-o", "host/buildvm.exe"]));
    tools.compile(source, "LuaJIT buildvm", &arguments)?;
    tools.run(
        &buildvm,
        source,
        "LuaJIT VM object",
        &os(&["-m", "peobj", "-o", "lj_vm.o"]),
    )?;
    for (mode, output) in [
        ("bcdef", "lj_bcdef.h"),
        ("ffdef", "lj_ffdef.h"),
        ("libdef", "lj_libdef.h"),
        ("recdef", "lj_recdef.h"),
        ("folddef", "lj_folddef.h"),
    ] {
        let mut arguments = os(&["-m", mode, "-o", output]);
        if mode == "folddef" {
            arguments.push("lj_opt_fold.c".into());
        } else {
            arguments.extend(
                LIBS.split_whitespace()
                    .map(|name| format!("{name}.c").into()),
            );
        }
        tools.run(&buildvm, source, output, &arguments)?;
    }
    let files = format!("{CORE} {LIBS} lib_init lj_str_hash");
    let flags: Vec<_> = BASE.iter().chain(TARGET).copied().collect();
    let mut extra = os(&["-include"]);
    extra.push(file_shim.as_os_str().into());
    compile_archive(
        tools,
        source,
        "libluajit.a",
        &files,
        &flags,
        &extra,
        Some("lj_vm.o"),
    )?;

    let symbols = tools.run(
        &tools.llvm.join("llvm-nm.exe"),
        source,
        "LuaJIT filesystem imports",
        &os(&["--undefined-only", "libluajit.a"]),
    )?;
    for symbol in ["wf_fopen", "wf_rename", "wf_remove", "wf_getenv"] {
        ensure!(
            symbols
                .lines()
                .any(|line| line.split_whitespace().last() == Some(symbol)),
            "LuaJIT lacks the native filesystem binding: {symbol}"
        );
    }
    Ok(())
}

fn os(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn compile_archive(
    tools: &Tools<'_>,
    source: &Path,
    archive: &str,
    files: &str,
    flags: &[&str],
    extra: &[OsString],
    generated_object: Option<&str>,
) -> Result<()> {
    let mut objects = os(&["rcsD", archive]);
    if let Some(object) = generated_object {
        objects.push(object.into());
    }
    let mut jobs = Vec::new();
    for name in files.split_whitespace() {
        let input = format!("{name}.c");
        let object = format!("{name}.o");
        jobs.push(Compilation {
            input: input.into(),
            output: object.clone().into(),
            extra: if name == "lj_str_hash" {
                os(&["-msse4.2"])
            } else {
                Vec::new()
            },
        });
        objects.push(object.into());
    }
    let mut arguments = os(flags);
    arguments.extend_from_slice(extra);
    tools.compile_objects(source, archive, &arguments, &jobs)?;
    tools.run(&tools.llvm.join("llvm-ar.exe"), source, archive, &objects)?;
    Ok(())
}
