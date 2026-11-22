//! Build the pinned Rust interpreter with the engine's Win64 embedding ABI.
use super::tools::Tools;
use crate::{Build, checked, ring_build::patch};
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use zapret_core::sha256_file;

#[path = "luna_io.rs"]
mod luna_io;

const CRATE: &str = "luna-core-4.0.2";
const ABI: &str = include_str!("windows_rust_lua_abi.rs");

pub(super) fn build(root: &Path, stage: &Path, tools: &Tools<'_>) -> Result<PathBuf> {
    let source = root
        .join("dist/upstream/rust-ring-build")
        .join(format!("{CRATE}.crate"));
    ensure!(
        sha256_file(&source)
            .with_context(|| format!(
                "Missing pinned Rust interpreter source {}",
                source.display()
            ))?
            .eq_ignore_ascii_case(zapret_core::RUST_LUA_SOURCE_SHA256),
        "Rust interpreter source hash mismatch"
    );
    tools.extract(&source, stage)?;
    let source = stage.join(CRATE).join("src");
    luna_io::adapt(&source)?;
    patch(
        &source.join("compiler/mod.rs"),
        "                TableField::Keyed(k, v) => {\n                    let saved = self.lr().freereg;\n                    let ke = self.expr(*k)?;\n                    let kr = self.exp_to_anyreg(ke)?;",
        "                TableField::Keyed(k, v) => {\n                    let saved = self.lr().freereg;\n                    let ke = self.expr(*k)?;\n                    // Keep the computed key live while emitting its value.\n                    let kr = self.exp_to_nextreg(ke)?;",
    )?;
    patch(
        &source.join("vm/builtins.rs"),
        "        // `newproxy` remembers the metatables it created in a weak-keyed",
        "    }\n    {\n        // `newproxy` remembers the metatables it created in a weak-keyed",
    )?;
    let vm = source.join("vm/exec.rs");
    patch(
        &vm,
        "        let resumer = self.current;\n        // save the resumer's live context away",
        "        let resumer = self.current;\n        let resumer_nny = std::mem::replace(&mut self.nny, 0);\n        // save the resumer's live context away",
    )?;
    patch(
        &vm,
        "        // save the coroutine's context back and restore the resumer\n        self.natives_base = resumer_natives_base;",
        "        // save the coroutine's context back and restore the resumer\n        self.nny = resumer_nny;\n        self.natives_base = resumer_natives_base;",
    )?;
    patch(
        &vm,
        "    pub capi_stack: Vec<crate::runtime::Value>,",
        r#"    pub capi_stack: Vec<crate::runtime::Value>,
    capi_base: usize,
    capi_depth: usize,
    capi_panic: Option<unsafe extern "C-unwind" fn(*mut Self) -> i32>,"#,
    )?;
    patch(
        &vm,
        "            capi_stack: Vec::new(),",
        r#"            capi_stack: Vec::new(),
            capi_base: 0,
            capi_depth: 0,
            capi_panic: None,"#,
    )?;
    patch(
        &vm,
        "        // debug.getregistry() and io library state",
        "        roots.extend_from_slice(&self.capi_stack);\n        // debug.getregistry() and io library state",
    )?;
    patch(
        &vm,
        "            self.heap.gc_finish_atomic();",
        "            self.heap.gc_finish_atomic_with_roots(&self.capi_stack);",
    )?;
    patch(
        &vm,
        "            if self.instr_budget.is_some() || self.heap.mem_cap.is_some() {",
        r#"            if zapret_capi::take_interrupt(self) {
                return Err(self.plain_err("INTERRUPT"));
            }
            if self.instr_budget.is_some() || self.heap.mem_cap.is_some() {"#,
    )?;
    let heap = source.join("runtime/heap.rs");
    patch(
        &heap,
        "            self.gc_finish_atomic();",
        "            self.gc_finish_atomic_with_roots(roots);",
    )?;
    patch(
        &heap,
        "    pub(crate) fn gc_finish_atomic(&mut self) {\n        debug_assert!(self.phase == GcPhase::Propagate);\n        let mut m = self.loan_marker();",
        r#"    #[cfg(test)]
    pub(crate) fn gc_finish_atomic(&mut self) {
        self.gc_finish_atomic_with_roots(&[]);
    }

    pub(crate) fn gc_finish_atomic_with_roots(&mut self, roots: &[Value]) {
        debug_assert!(self.phase == GcPhase::Propagate);
        let mut m = self.loan_marker();
        for &root in roots {
            m.value(root);
        }"#,
    )?;
    let strings = source.join("runtime/string.rs");
    patch(
        &strings,
        "Layout::array::<u8>(len).expect",
        "Layout::array::<u8>(len + 1).expect",
    )?;
    patch(
        &strings,
        "        ptr::copy_nonoverlapping(bytes.as_ptr(), p.add(1) as *mut u8, bytes.len());",
        "        ptr::copy_nonoverlapping(bytes.as_ptr(), p.add(1) as *mut u8, bytes.len());\n        p.add(1).cast::<u8>().add(bytes.len()).write(0);",
    )?;
    let mut interpreter = fs::read_to_string(&vm)?;
    interpreter.push_str(
        r#"
#[path = "exec/zapret_capi.rs"]
mod zapret_capi;

impl Vm {
    fn capi_concat(&mut self, left: Value, right: Value) -> Result<Value, LuaError> {
        if let Some(value) = self.concat_pair(left, right)? {
            return Ok(value);
        }
        let mut method = self.get_mm(left, Mm::Concat);
        if method.is_nil() {
            method = self.get_mm(right, Mm::Concat);
        }
        if method.is_nil() {
            return Err(self.type_err("concatenate", left));
        }
        self.call_mm1(method, &[left, right])
    }
}

"#,
    );
    fs::write(vm, interpreter)?;
    fs::write(source.join("vm/exec/zapret_capi.rs"), ABI)?;

    // This pinned crate has no dependencies or build script. Compile it from
    // a stable source prefix so scratch paths do not change the engine bytes.
    let archive = stage.join("libzapret_rust_lua_runtime.a");
    checked(
        Build::rustc()
            .current_dir(stage)
            .args([
                "--edition=2024",
                "--crate-name=luna_core",
                "--crate-type=staticlib",
                "-O",
                "-C",
                "codegen-units=16",
                "--check-cfg=cfg(feature, values(\"gc-verify\", \"send\"))",
                "--check-cfg=cfg(luna_aot_runtime_stub)",
                "--check-cfg=cfg(test)",
            ])
            .arg(format!(
                "--remap-path-prefix={}=/zapret-rust/runtime",
                stage.display()
            ))
            .arg(source.join("lib.rs"))
            .arg("-o")
            .arg(&archive),
    )?;

    Ok(archive)
}

pub(super) fn check(
    root: &Path,
    stage: &Path,
    tools: &Tools<'_>,
    headers: &Path,
    runtime: &Path,
    wincompat: &Path,
    log: &Path,
) -> Result<()> {
    let sources = root.join("native/zapret-dev/src/engine_native");
    let executable = stage.join("rust-lua-guard-oracle.exe");
    let mut compile = Command::new(tools.compiler);
    compile
        .args(["-O2", "-fexceptions", "-static"])
        .arg(format!("-I{}", headers.display()))
        .arg(sources.join("rust_lua_guard_oracle.c"))
        .arg(runtime)
        .arg(wincompat)
        .args([
            "-lws2_32",
            "-lntdll",
            "-lbcrypt",
            "-luserenv",
            "-ladvapi32",
            "-ldbghelp",
            "-lwinpthread",
            "-o",
        ])
        .arg(&executable);
    tools.run_command(&compile, stage, "Compile Rust Lua and Win64 unwind check")?;
    let result = tools.run_command(
        &Command::new(&executable),
        stage,
        "Check Rust Lua error unwinding, binary roots and interrupt",
    )?;
    ensure!(
        result.starts_with("PASS Rust Lua ABI "),
        "Missing Rust Lua ABI evidence"
    );
    print!("{result}");
    fs::write(log, result)?;
    Ok(())
}
