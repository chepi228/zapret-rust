//! Bind Luna's standard I/O to the existing Win64 path and mode policy.
use crate::ring_build::patch;
use anyhow::{Context, Result};
use std::{fs, path::Path};

fn replace_section(path: &Path, start: &str, end: &str, replacement: &str) -> Result<()> {
    let mut source = fs::read_to_string(path)?;
    let begin = source
        .find(start)
        .with_context(|| format!("Missing {start} in {}", path.display()))?;
    let end = begin
        + source[begin..]
            .find(end)
            .with_context(|| format!("Missing {end} in {}", path.display()))?;
    source.replace_range(begin..end, replacement);
    fs::write(path, source)?;
    Ok(())
}

pub(super) fn adapt(source: &Path) -> Result<()> {
    let vm = source.join("vm");
    fs::write(
        vm.join("zapret_io.rs"),
        include_str!("windows_rust_lua_io.rs"),
    )?;
    patch(
        &vm.join("mod.rs"),
        "pub(crate) mod lib_io;",
        "pub(crate) mod lib_io;\npub(crate) mod zapret_io;",
    )?;
    patch(
        &source.join("runtime/userdata.rs"),
        "        std::fs::File,",
        "        crate::vm::zapret_io::File,",
    )?;
    let io = vm.join("lib_io.rs");
    patch(
        &io,
        "fn posix_error(code: i32)",
        "pub(crate) fn posix_error(code: i32)",
    )?;
    replace_section(
        &io,
        "/// How `fopen` opens a mode;",
        "fn io_open(",
        r#"fn open_file(name: &[u8], mode: &[u8]) -> std::io::Result<(crate::vm::zapret_io::File, bool)> {
    let mode = c_str(mode);
    let writable = mode.first().is_some_and(|&first| first != b'r') || mode.contains(&b'+');
    Ok((crate::vm::zapret_io::open(name, mode)?, writable))
}

"#,
    )?;
    patch(
        &io,
        "    if vm.version() >= LuaVersion::Lua52 && !mode_ok(vm.version(), &mode) {\n        return Err(arg_error(vm, 2, \"invalid mode\"));\n    }\n",
        "",
    )?;
    patch(
        &io,
        "new_file(vm, FileHandle::File(file), true)",
        "new_file(vm, FileHandle::File(file.into()), true)",
    )?;
    patch(
        &io,
        "new_file(vm, FileHandle::File(file), !read)",
        "new_file(vm, FileHandle::File(file.into()), !read)",
    )?;
    replace_section(
        &io,
        "/// ≤5.2's ",
        "/// A string read from a file.",
        r#"/// The Windows Lua line interface ends each result at its first NUL.
fn read_line_fgets(vm: &mut Vm, file: Gc<Userdata>, keep_nl: bool) -> std::io::Result<Value> {
    let mut line = Vec::with_capacity(BUFSIZ);
    let mut read_any = false;
    let mut terminated = false;
    while let Some(byte) = getc(file)? {
        read_any = true;
        if byte == b'\n' {
            if keep_nl && !terminated { line.push(byte); }
            break;
        }
        terminated |= byte == 0;
        if !terminated { line.push(byte); }
    }
    if read_any { read_str(vm, &line) } else { Ok(Value::Nil) }
}

"#,
    )?;

    let os = vm.join("lib_os_io.rs");
    replace_section(&os, "/// C `remove`:", "fn os_remove(", "")?;
    patch(
        &os,
        "remove_path(&lib_io::os_path(&name))",
        "crate::vm::zapret_io::remove(&name)",
    )?;
    patch(
        &os,
        "std::fs::rename(lib_io::os_path(&from), lib_io::os_path(&to))",
        "crate::vm::zapret_io::rename(&from, &to)",
    )?;
    patch(
        &os,
        "std::fs::read(String::from_utf8_lossy(n).as_ref())",
        "crate::vm::zapret_io::read_source(n, vm.loader_input_budget())",
    )?;

    let package = vm.join("lib_package.rs");
    patch(
        &package,
        "use crate::vm::lib_io::{c_str, os_path};",
        "use crate::vm::lib_io::c_str;",
    )?;
    patch(
        &package,
        "std::fs::File::open(os_path(name)).is_ok()",
        "crate::vm::zapret_io::open(name, b\"rb\").is_ok()",
    )?;
    Ok(())
}
