//! Compare legacy blob inputs and check atomic insertion and file replacement.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

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
        .context("Blob source parent")?
        .join("blob-check");
    fs::create_dir(&directory)?;
    let pools = nfq.join("pools.c");
    let mut collections = fs::read_to_string(&pools)?;
    let start = collections
        .find("struct blob_item *blob_collection_add(")
        .context("Pinned blob collection")?;
    let last = collections[start..]
        .find("struct blob_item *blob_collection_search_name(")
        .context("Pinned blob search")?
        + start;
    let end = collections[last..]
        .find("\n}\n")
        .context("Pinned blob collection end")?
        + last
        + 3;

    let options = nfq.join("nfqws.c");
    let mut cli = fs::read_to_string(&options)?;
    let input = cli
        .find("static bool is_hexstring(")
        .context("Pinned blob input")?;
    let end_input = cli[input..]
        .find("#ifndef ZAPRET_NATIVE_WINDOWS\nstatic bool parse_uid(")
        .context("Pinned blob input end")?
        + input;

    let mut reference = String::new();
    let names = [
        "blob_collection_add",
        "blob_collection_add_blob",
        "blob_destroy",
        "blob_collection_destroy",
        "blob_collection_empty",
        "blob_collection_search_name",
        "load_file_or_exit",
        "item_name",
        "load_blob_to_collection",
        "load_const_blob_to_collection",
    ];
    for name in names {
        reference.push_str(&format!("#define {name} reference_{name}\n"));
    }
    reference.push_str(&collections[start..end]);
    reference.push_str(&cli[input..end_input]);
    for name in names {
        reference.push_str(&format!("#undef {name}\n"));
    }
    fs::write(directory.join("blob_reference.inc"), reference)?;

    let mut results = String::new();
    for direct in [false, true] {
        let exe = directory.join(if direct {
            "blob-rust-check.exe"
        } else {
            "blob-check.exe"
        });
        let mut command = Command::new(tools.compiler);
        command.args([
            "-Dzapret_localtime_r=fixture_localtime_r",
            "-O2",
            "-std=gnu99",
            "-ffunction-sections",
            "-fdata-sections",
            "-DZAPRET_WINDOWS=1",
            "-DZAPRET_NATIVE_WINDOWS=1",
            "-D_FILE_OFFSET_BITS=64",
            "-D_POSIX_C_SOURCE=200809L",
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
            .arg(shim.join("blob_oracle.c"))
            .arg(nfq.join("helpers.c"))
            .arg(shim.join("win_files.c"));
        if direct {
            command
                .args([
                    "-DZAPRET_BLOB_INPUT_DIRECT=1",
                    "-Wl,--wrap=malloc,--wrap=free",
                ])
                .arg(object);
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
                "-lwinpthread",
                "-o",
            ])
            .arg(&exe);
        tools.run_command(&command, &directory, "Compile engine blob comparison")?;
        let private = directory.join(if direct { "rust-run" } else { "legacy-run" });
        fs::create_dir(&private)?;
        let result =
            tools.run_command(&Command::new(exe), &private, "Compare engine blob input")?;
        ensure!(
            result.starts_with("PASS engine_blobs ")
                && (!direct || result.contains("nonterminating_cli=1")),
            "Incomplete blob comparison"
        );
        print!("{result}");
        results.push_str(&result);
    }
    fs::write(output, results)?;

    collections.replace_range(start..end, "#include \"blob_collection_windows.inc\"\n");
    cli.replace_range(input..end_input, "#include \"blob_input_windows.inc\"\n\n");
    fs::write(pools, collections)?;
    fs::write(options, cli)?;
    let path = nfq.join("lua.c");
    let source = fs::read_to_string(&path)?;
    let start = source
        .find("static void lua_init_blobs(void)")
        .context("Pinned Lua blob transfer")?;
    let end = source[start..]
        .find("\n}\n")
        .context("Pinned Lua blob transfer end")?
        + start
        + 3;
    let original = &source[start..end];
    let unlink = "\t\tLIST_REMOVE(blob, next);\n";
    let finish = "\t\tblob_destroy(blob);\n";
    ensure!(
        original.matches(unlink).count() == 1 && original.matches(finish).count() == 1,
        "Pinned Lua blob transfer changed"
    );
    let updated = original.replace(unlink, "").replace(
        finish,
        "\t\tzapret_blob_destroy(zapret_blob_pop(&params.blobs), &native_blob_allocator);\n",
    );
    let mut source = source;
    source.replace_range(
        start..end,
        &format!("#include \"blob_windows.h\"\n{updated}"),
    );
    fs::write(path, source)?;
    Ok(())
}
