//! Independently compare catalog/schema and all existing complete category oracles.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const CATEGORIES: &[(u32, &str, &str)] = &[
    (1, "startup_options", "startup-options"),
    (2, "list_options", "list-options"),
    (3, "profile_filters", "profile-filters"),
    (4, "capture_options", "capture-options"),
    (5, "control", "control"),
];
fn function(source: &str, signature: &str) -> Result<std::ops::Range<usize>> {
    let start = source
        .find(signature)
        .with_context(|| format!("CLI function {signature}"))?;
    let end = start + source[start..].find("\n}\n").context("CLI function end")? + 3;
    Ok(start..end)
}
fn kinds(source: &str) -> Result<Vec<(String, u32)>> {
    let mut rest = source;
    let mut found = Vec::new();
    while let Some(offset) = rest.find("case IDX_") {
        rest = &rest[offset + 5..];
        let colon = rest.find(':').context("CLI case colon")?;
        let name = rest[..colon].trim();
        let after = rest[colon + 1..].trim_start();
        if let Some(value) = after.strip_prefix("kind=") {
            let end = value.find(';').context("CLI kind end")?;
            found.push((name.into(), value[..end].parse()?));
        }
        rest = &rest[colon + 1..];
    }
    ensure!(!found.is_empty(), "CLI kinds absent");
    Ok(found)
}
fn metadata(source: &str, category: u32) -> Result<String> {
    let pairs = kinds(source)?;
    let mut selected = source.to_owned();
    for (name, kind) in &pairs {
        let entry = format!("case {name}:");
        let assignment = format!("{entry}kind={kind};");
        ensure!(
            selected.matches(&assignment).count() == 1,
            "Unexpected CLI kind assignment: {name}"
        );
        selected = selected.replace(&assignment, &entry);
    }
    ensure!(
        selected.matches("uint32_t kind;").count() == 1,
        "CLI kind storage"
    );
    selected=selected.replacen("uint32_t kind;",&format!("int32_t selected=zapret_native_cli_kind(index,{category});if(selected<0)return 0;uint32_t kind=(uint32_t)selected;"),1);
    if category == 5 {
        let start = selected
            .find("switch(index){")
            .context("Control kind switch")?;
        let end = start
            + selected[start..]
                .find('}')
                .context("Control kind switch end")?
            + 1;
        selected.replace_range(start..end, "");
    } else {
        for (name, _) in &pairs {
            selected = selected.replace(&format!("\n        case {name}:break;"), "");
        }
        selected = selected.replace("default:return 0;", "default:break;");
    }
    if category == 4 {
        selected = selected.replace(
            "const char *name;",
            "const char *name=zapret_native_cli_option_name(index);",
        );
        while let Some(start) = selected.find("name=\"") {
            let end = start
                + selected[start..]
                    .find("\";")
                    .context("Capture option name")?
                + 2;
            selected.replace_range(start..end, "");
        }
        selected = selected
            .replace(
                "target.capacity=WINDIVERT_PORTFILTER_MAX;",
                "target.capacity=zapret_native_cli_capacity(index);",
            )
            .replace("target.capacity=WINDIVERT_MAX;", "");
    }
    Ok(format!("#include \"native_cli_catalog_abi.h\"\n{selected}"))
}
fn compile(
    tools: &Tools<'_>,
    directory: &Path,
    source: &Path,
    includes: &[&Path],
    shim: &Path,
    library: &Path,
    exe: &Path,
) -> Result<()> {
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-std=gnu11",
        "-ffunction-sections",
        "-fdata-sections",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-Wno-macro-redefined",
        "-DSTARTUP_INTEGRATED_CHECK",
        "-DCAPTURE_INTEGRATED_CHECK",
    ]);
    for include in includes {
        command.arg(format!("-I{}", include.display()));
    }
    command
        .arg("-include")
        .arg(shim.join("win_platform.h"))
        .arg(source)
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
        .arg(exe);
    tools.run_command(&command, directory, "Compile CLI ownership oracle")?;
    Ok(())
}
pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    output: &Path,
) -> Result<()> {
    let parent = nfq.parent().context("CLI catalog parent")?;
    let directory = parent.join("native-cli-catalog-check");
    fs::create_dir(&directory)?;
    let stage = directory.join("selected");
    fs::create_dir(&stage)?;
    let path = nfq.join("nfqws.c");
    let original = fs::read_to_string(&path)?;
    let first = original
        .find("enum opt_indices {")
        .context("CLI native enum")?;
    let table = original
        .find("static const struct option long_options[] = {")
        .context("CLI original table")?;
    let end = table + original[table..].find("\n};").context("CLI table end")? + 3;
    let enumeration = &original[first..table];
    let mut reference = original[first..end].to_owned();
    reference
        .push_str("\nstatic int reference_kind(int index,unsigned category){switch(category){\n");
    let mut changes = Vec::<(PathBuf, String)>::new();
    let mut total = 0;
    for &(category, base, _) in CATEGORIES {
        let name = format!("cli_{base}_windows.inc");
        let old = fs::read_to_string(shim.join(&name))?;
        let pairs = kinds(&old)?;
        total += pairs.len();
        reference.push_str(&format!("case {category}:switch(index){{"));
        for (name, kind) in &pairs {
            reference.push_str(&format!("case {name}:return {kind};"));
        }
        reference.push_str("default:return -1;}\n");
        let selected = metadata(&old, category)?;
        fs::write(stage.join(&name), &selected)?;
        changes.push((shim.join(name), selected));
    }
    ensure!(total == 59, "Incomplete Windows CLI kind schema");
    reference.push_str("default:return -1;}}\n");
    fs::write(directory.join("native_cli_reference.inc"), reference)?;
    let numeric_path = shim.join("cli_numeric_windows.inc");
    let numeric = fs::read_to_string(&numeric_path)?;
    let span = function(&numeric, "static int engine_numeric_option(")?;
    fs::write(
        directory.join("native_cli_numeric_reference.inc"),
        &numeric[span.clone()],
    )?;
    let mut selected_numeric = numeric.clone();
    selected_numeric.replace_range(span, "#include \"native_cli_numeric_windows.inc\"\n");
    changes.push((numeric_path, selected_numeric));
    let exe = directory.join("native-cli-catalog-check.exe");
    compile(
        tools,
        &directory,
        &shim.join("native_cli_catalog_oracle.c"),
        &[&directory, shim, &shim.join("include"), nfq],
        shim,
        library,
        &exe,
    )?;
    let mut results = tools.run_command(
        &Command::new(&exe),
        &directory,
        "Compare pinned option catalog and complete scalar target schema",
    )?;
    ensure!(
        results.starts_with("PASS native_cli_catalog "),
        "Incomplete native CLI catalog comparison"
    );
    // Reuse every original full-entry oracle. Its compact fixture enum is mapped
    // to independently captured native indices only at the new metadata ABI.
    for &(category, base, folder) in CATEGORIES {
        let mut oracle = fs::read_to_string(shim.join(format!("cli_{base}_oracle.c")))?;
        let enum_start = oracle.find("IDX_").context("Fixture option indices")?;
        let enum_end = enum_start
            + oracle[enum_start..]
                .find('}')
                .context("Fixture option enum end")?;
        let names = oracle[enum_start..enum_end]
            .split(',')
            .map(str::trim)
            .collect::<Vec<_>>();
        ensure!(
            names.iter().all(|name| name.starts_with("IDX_")
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')),
            "Unexpected fixture option enum"
        );
        let mapping = names
            .iter()
            .map(|name| name.replace("IDX_", "NATIVE_IDX_"))
            .collect::<Vec<_>>()
            .join(",");
        let injected = format!(
            "\n{}\nstatic int fixture_native_index(int index){{static const int map[]={{ {mapping} }};return index>=0&&(size_t)index<sizeof(map)/sizeof(*map)?map[index]:index+1000;}}\nstatic int fixture_catalog_kind(int index,unsigned category){{return zapret_native_cli_kind(fixture_native_index(index),category);}}\nstatic size_t fixture_catalog_capacity(int index){{return zapret_native_cli_capacity(fixture_native_index(index));}}\nstatic const char *fixture_catalog_name(int index){{return zapret_native_cli_option_name(fixture_native_index(index));}}\n#define zapret_native_cli_kind fixture_catalog_kind\n#define zapret_native_cli_capacity fixture_catalog_capacity\n#define zapret_native_cli_option_name fixture_catalog_name\n",
            enumeration.replace("IDX_", "NATIVE_IDX_")
        );
        let include = format!("#include \"cli_{base}_windows.inc\"");
        ensure!(
            oracle.matches(&include).count() == 1,
            "CLI fixture selected adapter"
        );
        oracle=oracle.replace(&include,&format!("#include \"native_cli_catalog_abi.h\"\n{injected}\n{include}\n#undef zapret_native_cli_kind\n#undef zapret_native_cli_capacity\n"));
        let source = stage.join(format!("cli_{base}_oracle.c"));
        fs::write(&source, oracle)?;
        let old_reference = parent.join(format!("cli-{folder}-check"));
        ensure!(
            old_reference.is_dir(),
            "Run existing CLI checks before catalog ownership"
        );
        let exe = directory.join(format!("category-{category}.exe"));
        compile(
            tools,
            &directory,
            &source,
            &[&stage, &old_reference, shim, &shim.join("include"), nfq],
            shim,
            library,
            &exe,
        )?;
        let result = tools.run_command(
            &Command::new(&exe),
            &directory,
            "Recompare complete original/new CLI category with Rust catalog",
        )?;
        ensure!(
            result.starts_with(&format!("PASS cli_{base} ")),
            "Incomplete complete CLI category comparison"
        );
        results.push_str(&result);
    }
    let mut selected = original.clone();
    selected.replace_range(table..end, "#include \"native_cli_catalog_windows.inc\"\n");
    fs::write(output, &results)?;
    print!("{results}");
    // Only now publish all selected source changes together.
    for (path, contents) in changes {
        fs::write(path, contents)?;
    }
    fs::write(path, selected)?;
    Ok(())
}
