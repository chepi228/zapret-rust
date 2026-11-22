//! Developer Lua binding to the same versioned ABI used by the engine bridge.
mod capture_preflight_cases;
mod cli_capture_cases;
mod cli_control_cases;
mod cli_list_cases;
mod cli_profile_cases;
mod cli_startup_cases;
mod config_cases;
mod engine_entry_cases;
mod engine_lifecycle_cases;
mod gzip_file_cases;
mod lua_packet_dispatch_cases;
mod lua_startup_cases;
mod startup_cases;
mod startup_validation_cases;
mod writable_cases;
use anyhow::{Context, Result, ensure};
use mlua::{Lua, MultiValue, UserData, Value, Variadic};
use ring_backend::{Request, Response};
use std::{
    collections::BTreeMap,
    ffi::{OsString, c_void},
    path::Path,
    time::{Duration, Instant},
};

struct Handle(*mut c_void);
impl UserData for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { ((*ring_backend::zapret_ring_api_v1()).drop_object)(self.0) };
            self.0 = std::ptr::null_mut();
        }
    }
}

pub(crate) fn register(lua: &Lua) -> mlua::Result<()> {
    let table = lua.create_table()?;
    for (index, name) in ring_backend::OPERATIONS.iter().enumerate() {
        let op = index as u32 + 1;
        table.set(
            *name,
            lua.create_function(move |lua, args: Variadic<Value>| {
                if args.len() > 16 {
                    return Err(mlua::Error::external("Too many native ring arguments"));
                }
                let mut request = Request {
                    numbers: [0.; 16],
                    present: 0,
                    strings: [std::ptr::null(); 16],
                    lengths: [0; 16],
                    text_present: 0,
                };
                let mut object = std::ptr::null_mut();
                for (i, value) in args.iter().enumerate() {
                    match value {
                        Value::Boolean(value) => {
                            request.numbers[i] = f64::from(*value);
                            request.present |= 1 << i;
                        }
                        Value::Integer(value) => {
                            request.numbers[i] = *value as f64;
                            request.present |= 1 << i;
                        }
                        Value::Number(value) => {
                            if !value.is_finite() {
                                return Err(mlua::Error::external(
                                    "Nonfinite native ring argument",
                                ));
                            }
                            request.numbers[i] = *value;
                            request.present |= 1 << i;
                        }
                        // args retains the Lua strings and no Lua allocation/GC runs
                        // during the native call. Only the borrowed bytes cross ABI.
                        Value::String(text) => {
                            let bytes = text.as_bytes();
                            request.strings[i] = bytes.as_ptr();
                            request.lengths[i] = bytes.len();
                            request.text_present |= 1 << i;
                        }
                        Value::UserData(handle) if i == 0 => {
                            object = handle.borrow::<Handle>()?.0;
                        }
                        Value::UserData(handle)
                            if op == ring_backend::STORE_SCHEDULER
                                && i == ring_backend::STORE_HANDLE_SLOT =>
                        {
                            request.strings[i] = handle.borrow::<Handle>()?.0.cast();
                            request.text_present |= ring_backend::STORE_HANDLE_PRESENT;
                        }
                        Value::Nil => {}
                        _ => return Err(mlua::Error::external("Unsupported native ring argument")),
                    }
                }
                let mut small = [0; 512];
                let mut large = Vec::new();
                let buffer = if op == 4 || op == 15 || op == 29 {
                    large.resize(if op == 4 { 262144 } else { 32768 }, 0);
                    large.as_mut_slice()
                } else {
                    &mut small
                };
                let mut response = Response::default();
                let result = unsafe {
                    ((*ring_backend::zapret_ring_api_v1()).invoke)(
                        op,
                        object,
                        &request,
                        &mut response,
                        buffer.as_mut_ptr(),
                        buffer.len(),
                    )
                };
                if result != 0 {
                    return Err(mlua::Error::external(format!(
                        "Native ring operation {op} failed: {result}"
                    )));
                }
                let mut values = MultiValue::new();
                if !response.object.is_null() {
                    values.push_back(Value::UserData(
                        lua.create_userdata(Handle(response.object))?,
                    ));
                }
                for value in &response.values[..response.count as usize] {
                    values.push_back(match value.kind {
                        0 => Value::Nil,
                        1 => Value::Number(value.number),
                        2 => Value::Boolean(value.number != 0.),
                        3 => Value::String(
                            lua.create_string(&buffer[value.offset..value.offset + value.length])?,
                        ),
                        _ => return Err(mlua::Error::external("Invalid native ring result")),
                    });
                }
                Ok(values)
            })?,
        )?;
    }
    table.set("api_version", 1)?;
    table.set("backend", "Rust")?;
    lua.globals().set("zapret_ring_native", table)
}

pub(crate) fn run(root: &Path, output: &Path) -> Result<()> {
    let bridge = root.join("native/zapret-ring/lua");
    let mut passed = Vec::new();
    for name in [
        "storetest.lua",
        "watchtest.lua",
        "linkguardtest.lua",
        "hostcachetest.lua",
        "foolingtest.lua",
    ] {
        let lua = Lua::new();
        register(&lua)?;
        lua.load("os.exit=function(code) TEST_EXIT=code end")
            .exec()?;
        if name == "hostcachetest.lua" {
            lua.load(&zapret_core::read_text(
                &root.join("lua/zapret-auto.lua"),
                1024 * 1024,
            )?)
            .set_name("zapret-auto.lua")
            .exec()?;
            lua.load(&zapret_core::read_text(
                &bridge.join("host-cache.lua"),
                1024 * 1024,
            )?)
            .set_name("native host-cache.lua")
            .exec()?;
        }
        lua.load(&zapret_core::read_text(
            &bridge.join("ring-store.lua"),
            1024 * 1024,
        )?)
        .set_name("native ring-store.lua")
        .exec()?;
        lua.load(&zapret_core::read_text(
            &bridge.join("autoring.lua"),
            1024 * 1024,
        )?)
        .set_name("native autoring.lua")
        .exec()?;
        if name == "foolingtest.lua" {
            let adapter = zapret_core::read_text(&root.join("lua/fooling.lua"), 64 * 1024)?;
            lua.globals().set(
                "FOOLING_ADAPTER",
                lua.load(&adapter).set_name("fooling.lua").into_function()?,
            )?;
        }
        lua.load(&zapret_core::read_text(
            &root.join("dev/tests").join(name),
            1024 * 1024,
        )?)
        .set_name(name)
        .exec()
        .with_context(|| format!("Ring fixture {name}"))?;
        ensure!(
            lua.globals().get::<i32>("TEST_EXIT")? == 0,
            "Ring fixture failed: {name}"
        );
        passed.push(name);
    }
    let report = serde_json::json!({"schema":1,"backend":"Rust","tests":passed,"status":"Passed","live_changes":false,"driver_loaded":false,"lua_runtime":"embedded Lua 5.4; same native ABI as LuaJIT engine bridge"});
    zapret_core::atomic_write(
        &std::path::absolute(output)?,
        &serde_json::to_vec_pretty(&report)?,
    )?;
    println!("PASS native ring fixtures; {}", output.display());
    Ok(())
}

/// Exercise the actual sandboxed engine and its C/LuaJIT/Rust boundary. Every
/// process is a private owned job in normal TEMP; no driver is opened.
pub(crate) fn engine(root: &Path, pkg: &Path, output: &Path, fixture: Option<&str>) -> Result<()> {
    let started = Instant::now();
    let package = std::path::absolute(pkg)?;
    let pkg = package.as_path();
    let manifest = zapret_core::verify_ring(pkg)?
        .context("Engine tests require the pinned Rust ring candidate")?;
    let temp = tempfile::Builder::new()
        .prefix("zapret-rust-ring-engine-")
        .tempdir()?;
    let bin = temp.path().join("bin");
    std::fs::create_dir(&bin)?;
    let engine_bytes = std::fs::read(pkg.join("bin/winws2.exe"))?;
    let uses_cygwin = engine_bytes
        .windows(b"cygwin1.dll".len())
        .any(|bytes| bytes.eq_ignore_ascii_case(b"cygwin1.dll"));
    ensure!(
        !(uses_cygwin
            && matches!(
                fixture,
                Some("native-platform.lua" | "native-lua-modules.lua" | "zstreamtest.lua")
            )),
        "This fixture requires the native Windows engine"
    );
    for name in ["winws2.exe", "zapret-ring.dll"] {
        std::fs::copy(pkg.join("bin").join(name), bin.join(name))?;
    }
    if uses_cygwin {
        std::fs::copy(pkg.join("bin/cygwin1.dll"), bin.join("cygwin1.dll"))?;
    }
    let stock = if pkg.join("lua/zapret-lib.lua").is_file() {
        pkg
    } else {
        root
    };
    // Build candidates inherit the project adapter from the checkout. A full
    // package provides its own adapter, which must be tested as shipped.
    let fooling = stock.join("lua/fooling.lua");
    let builtin = manifest.schema >= zapret_core::BUILTIN_RULES_SCHEMA;
    let rust_lua = manifest.schema == zapret_core::RUST_LUA_SCHEMA;
    let ring_scripts = if builtin {
        root.join("native/zapret-ring/lua")
    } else {
        pkg.join("lua")
    };
    std::fs::copy(stock.join("bin/WinDivert.dll"), bin.join("WinDivert.dll"))?;
    let logs = root.join("dist/native/ring-engine-logs");
    std::fs::create_dir_all(&logs)?;
    let mut passed = Vec::new();
    let mut checks = 0;
    let result = (|| {
        if fixture.is_none() {
            // --wf-save exits before WinDivertOpen. Exercise the default
            // intercept=true filter builder as well as the no-capture branch.
            for (name, option, exact) in [
                ("generated-filter-export", "--wf-tcp-out=443", None),
                (
                    "raw-filter-export",
                    "--wf-raw=tcp.DstPort == 443",
                    Some("tcp.DstPort == 443"),
                ),
                ("disabled-filter-export", "--intercept=0", Some("false")),
            ] {
                let export = temp.path().join(format!("{name}.txt"));
                let text = engine_case(
                    &bin,
                    &[
                        "--dry-run".into(),
                        option.into(),
                        format!("--wf-save={}", export.display()).into(),
                        "--wf-dup-check=0".into(),
                    ],
                    0,
                    &[],
                )?;
                let bytes = std::fs::read(&export)?;
                let filter = std::str::from_utf8(&bytes)
                    .with_context(|| format!("{name}: filter export is not UTF-8"))?;
                ensure!(
                    exact.map_or_else(
                        || filter.starts_with("!impostor") && filter.contains("tcp.DstPort == 443"),
                        |expected| filter == expected,
                    ),
                    "{name}: exported filter differs"
                );
                zapret_platform::validate_capture_filter(stock, &bytes)?;
                zapret_core::atomic_write(&logs.join(format!("{name}.log")), text.as_bytes())?;
                checks += 1;
                passed.push(name.to_owned());
                println!("ok real engine: {name}");
            }
            checks += check_list_readers(&bin, temp.path(), &logs)?;
            passed.push("list-readers".into());
            checks += check_list_registration(&bin, temp.path(), &logs)?;
            passed.push("list-registration".into());
            if !uses_cygwin {
                checks += config_cases::check(&bin, temp.path(), &logs)?;
                passed.push("native-config-ownership".into());
                checks += writable_cases::check(&bin, temp.path(), &logs)?;
                passed.push("native-writable-setup".into());
                checks += startup_cases::check(&bin, temp.path(), &logs)?;
                passed.push("native-startup-pid".into());
                checks += cli_startup_cases::check(&bin, temp.path(), &logs)?;
                passed.push("native-startup-options".into());
                checks += cli_list_cases::check(&bin, temp.path(), &logs)?;
                passed.push("native-list-options".into());
                checks += cli_profile_cases::check(&bin, &logs)?;
                passed.push("native-profile-filter-options".into());
                checks += cli_capture_cases::check(&bin, stock, temp.path(), &logs)?;
                passed.push("native-capture-options".into());
                checks += cli_control_cases::check(&bin, &logs)?;
                passed.push("native-cli-control".into());
                checks += startup_validation_cases::check(&bin, temp.path(), &logs)?;
                passed.push("native-startup-validation".into());
                checks += capture_preflight_cases::check(&bin, stock, temp.path(), &logs)?;
                passed.push("native-capture-preflight".into());
                checks += engine_lifecycle_cases::check(&bin, &logs)?;
                passed.push("native-engine-lifecycle".into());
                checks += gzip_file_cases::check(&bin, temp.path(), &logs)?;
                passed.push("native-gzip-file".into());
                checks += lua_startup_cases::check(&bin, temp.path(), &logs)?;
                passed.push("native-lua-startup".into());
                checks += engine_entry_cases::check(&bin, temp.path(), &logs)?;
                checks += lua_packet_dispatch_cases::check(&bin, &logs)?;
                println!(
                    "ok real engine: disabled/enabled conntrack shortcut and packet API arity"
                );
                passed.push("native-engine-entry".into());
            }
        }
        for name in [
            "storetest.lua",
            "watchtest.lua",
            "linkguardtest.lua",
            "hostcachetest.lua",
            "luatest.lua",
            "storeiotest.lua",
            "foolingtest.lua",
            "timertest.lua",
            "conntracktest.lua",
            "packetwritetest.lua",
            "protocoltest.lua",
            "registrytest.lua",
            "zstreamtest.lua",
            "native-platform.lua",
            "native-lua-modules.lua",
        ] {
            if matches!(
                name,
                "native-platform.lua" | "native-lua-modules.lua" | "zstreamtest.lua"
            ) && uses_cygwin
            {
                continue;
            }
            if fixture.is_some_and(|selected| selected != name) {
                continue;
            }
            let writable = temp.path().join(format!("data-{}", passed.len()));
            std::fs::create_dir(&writable)?;
            let mut args: Vec<OsString> = vec![
                "--intercept=0".into(),
                format!("--writable={}", writable.display()).into(),
            ];
            for name in ["zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"] {
                args.push(format!("--lua-init=@{}", stock.join("lua").join(name).display()).into());
            }
            for path in [
                ring_scripts.join("host-cache.lua"),
                fooling.clone(),
                ring_scripts.join("ring-store.lua"),
                ring_scripts.join("autoring.lua"),
            ] {
                args.push(format!("--lua-init=@{}", path.display()).into());
            }
            let fixture_path = root.join("dev/tests").join(name);
            let mut extra_env = Vec::new();
            let init_file = if name == "foolingtest.lua" {
                let fixture = zapret_core::read_text(&fixture_path, 64 * 1024)?;
                let adapter = zapret_core::read_text(&fooling, 64 * 1024)?;
                let path = temp.path().join(name);
                std::fs::write(
                    &path,
                    format!("FOOLING_ADAPTER = function()\n{adapter}\nend\n{fixture}"),
                )?;
                path
            } else if name == "native-platform.lua" {
                let denied = temp.path().join("medium-sentinel.txt");
                std::fs::write(&denied, b"native-platform-medium-sentinel\n")?;
                let compressed_init = temp.path().join("fixture-init.lua.gz");
                // A gzip member produced by the C zlib reference.
                std::fs::write(
                    &compressed_init,
                    b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x0a\x8b\x72\x0c\x08\x72\x0d\x89\x77\x8f\xf2\x0c\x88\x77\xf3\x8c\x08\x09\x0d\x72\x55\xb0\x55\x30\x31\xe2\x02\x00\xe5\xa3\x52\xa3\x19\x00\x00\x00",
                )?;
                args.push(format!("--lua-init=@{}", compressed_init.display()).into());
                let mut long_directory = writable.clone();
                for _ in 0..4 {
                    long_directory =
                        long_directory.join("длинный-путь-данные-0123456789-abcdefghijklmnop");
                    std::fs::create_dir(&long_directory)?;
                    lower_fixture_directory(&long_directory)?;
                }
                let path = long_directory.join("проверка-платформы.lua");
                std::fs::copy(&fixture_path, &path)?;
                extra_env.push((
                    "ZAPRET_NATIVE_LONG_DIR".into(),
                    long_directory.into_os_string(),
                ));
                extra_env.push(("ZAPRET_NATIVE_DENIED_FILE".into(), denied.into_os_string()));
                path
            } else {
                fixture_path
            };
            args.push(format!("--lua-init=@{}", init_file.display()).into());
            let text = engine_case(&bin, &args, 0, &extra_env)?;
            if name == "native-platform.lua" {
                ensure!(
                    std::fs::read(temp.path().join("medium-sentinel.txt"))?
                        == b"native-platform-medium-sentinel\n",
                    "Restricted engine changed the medium-integrity sentinel"
                );
                ensure!(
                    text.contains("ok native timer runs in the restricted event loop"),
                    "Native platform fixture did not finish"
                );
            }
            zapret_core::atomic_write(&logs.join(format!("{name}.log")), text.as_bytes())?;
            ensure!(
                !text.lines().any(|line| line.starts_with("FAIL")),
                "Engine fixture failed: {name}"
            );
            if name == "luatest.lua" {
                ensure!(
                    text.contains("all ok"),
                    "Full engine fixture did not finish"
                );
            }
            if name == "storeiotest.lua" {
                ensure!(
                    text.contains("ok native timer atomically replaces"),
                    "Real timer/file snapshot was not confirmed"
                );
            }
            if name == "timertest.lua" {
                ensure!(
                    text.contains("ok all completed timer references are removed"),
                    "Timer mutation fixture did not finish"
                );
            }
            if name == "conntracktest.lua" {
                ensure!(
                    text.contains("ok conntrack fixture completed"),
                    "Conntrack fixture did not finish"
                );
            }
            if name == "packetwritetest.lua" {
                ensure!(
                    text.contains("ok packet writer fixture completed"),
                    "Packet writer fixture did not finish"
                );
                // Captured from the pinned C engine's Lua API. Exclude the
                // non-deterministic checksum perturbation and log messages.
                let records: Vec<_> = text
                    .lines()
                    .filter(|line| line.starts_with("wire "))
                    .collect();
                ensure!(
                    records.len() == 300
                        && zapret_core::sha256(records.join("\n").as_bytes()).eq_ignore_ascii_case(
                            "70228D3B02CB66D74CBA0E18714BACBCC99C00A4E6BCB8BB18CA1B740F3F6E52"
                        ),
                    "Packet writer bytes differ from the pinned C engine"
                );
                checks += records.len();
            }
            if name == "protocoltest.lua" {
                ensure!(
                    text.contains("ok protocol fixture completed"),
                    "Protocol marker fixture did not finish"
                );
            }
            if name == "native-lua-modules.lua" {
                ensure!(
                    text.contains("ok native Lua module fixture completed"),
                    "Native Lua module fixture did not finish"
                );
            }
            if name == "foolingtest.lua" {
                ensure!(
                    text.contains("ok fooling adapter uses Rust")
                        && text.contains("ok older bridge retains the same result"),
                    "Fooling test did not finish both backend checks"
                );
            }
            checks += text.lines().filter(|line| line.starts_with("ok ")).count();
            passed.push(name.to_owned());
            println!("ok real engine with Lua bindings: {name}");
        }
        if builtin && fixture.is_none() {
            for name in [
                "luatest.lua",
                "watchtest.lua",
                "linkguardtest.lua",
                "storeiotest.lua",
                "timertest.lua",
                "conntracktest.lua",
                "packetwritetest.lua",
                "protocoltest.lua",
                "registrytest.lua",
                "zstreamtest.lua",
            ] {
                let writable = temp.path().join(format!("builtin-{name}"));
                std::fs::create_dir(&writable)?;
                let init = root.join("dev/tests").join(name);
                let output = engine_case(
                    &bin,
                    &[
                        "--intercept=0".into(),
                        format!("--writable={}", writable.display()).into(),
                        "--builtin-rules".into(),
                        "--builtin-rules".into(),
                        format!("--lua-init=@{}", init.display()).into(),
                    ],
                    0,
                    &[],
                )?;
                zapret_core::atomic_write(
                    &logs.join(format!("builtin-{name}.log")),
                    output.as_bytes(),
                )?;
                ensure!(
                    !output.lines().any(|line| line.starts_with("FAIL")),
                    "Built-in rule fixture failed: {name}"
                );
                let count = output
                    .lines()
                    .filter(|line| line.starts_with("ok "))
                    .count();
                ensure!(count > 0, "Built-in rule fixture did not finish: {name}");
                checks += count;
                passed.push(format!("builtin-{name}"));
                println!("ok built-in Rust rules: {name}");
            }
        }
        ensure!(!passed.is_empty(), "Unknown engine fixture");
        if !uses_cygwin && fixture.is_none_or(|name| name == "native-platform.lua") {
            checks += crate::engine_native::check_lifecycle(&bin, temp.path())?;
            passed.push("native-lifecycle".into());
        }
        if fixture.is_some() {
            return Ok(());
        }
        let abi = "assert(zapret_ring_native.api_version==1 and zapret_ring_native.backend=='Rust');assert(package.loadlib==nil);assert(not pcall(require,'ffi'));assert(not pcall(zapret_ring_native.host_access,{},'a','b'));assert(not pcall(zapret_ring_native.host_new,0));local s=zapret_ring_native.store_new(2,64,60,false,nil,100);assert(not pcall(zapret_ring_native.host_touch,s,1));assert(not pcall(zapret_ring_native.store_get,s,'a',100,0/0));print('ok pinned ABI and restricted Lua sandbox');os.exit(0)";
        let text = engine_case(
            &bin,
            &["--intercept=0".into(), format!("--lua-init={abi}").into()],
            0,
            &[],
        )?;
        ensure!(text.contains("ok pinned ABI"), "ABI fixture incomplete");
        passed.push("abi-and-sandbox".into());
        checks += 1;
        let text=engine_case(&bin,&["--intercept=0".into(),"--lua-init=timer_set('native_guard',function() print('ok no-driver lifetime guard');io.stdout:flush();os.exit(23) end,100,true)".into()],23,&[])?;
        ensure!(
            text.contains("ok no-driver lifetime guard"),
            "Real timer guard did not execute"
        );
        passed.push("no-driver-timer".into());
        checks += 1;
        let path = bin.join("zapret-ring.dll");
        let mut corrupted = std::fs::read(&path)?;
        corrupted[0] ^= 1;
        std::fs::write(&path, corrupted)?;
        let text = engine_case(
            &bin,
            &[
                "--intercept=0".into(),
                "--lua-init=error('untrusted module was loaded')".into(),
            ],
            87,
            &[],
        )?;
        ensure!(
            text.contains("failed its pinned hash/ABI/load checks")
                && !text.contains("untrusted module was loaded"),
            "Engine accepted a modified module"
        );
        passed.push("modified-module-rejected-before-Lua".into());
        checks += 1;
        Ok(())
    })();
    let runtime = if rust_lua {
        "actual native Windows engine + Luna Rust Lua 5.2 + pinned Rust ABI"
    } else if uses_cygwin {
        "actual Cygwin engine + LuaJIT 2.1 + pinned Rust ABI"
    } else {
        "actual native Windows engine + LuaJIT 2.1 + pinned Rust ABI"
    };
    let report = serde_json::json!({"schema":1,"status":if result.is_ok(){"Passed"}else{"Failed"},"error":result.as_ref().err().map(|error:&anyhow::Error|format!("{error:#}")),"backend":"Rust","cases":passed,"checks":checks,"elapsed_ms":started.elapsed().as_millis(),"files":manifest.hashes,"driver_loaded":false,"network_used":false,"live_changes":false,"cygwin_runtime_present":uses_cygwin,"runtime":runtime});
    zapret_core::atomic_write(
        &std::path::absolute(output)?,
        &serde_json::to_vec_pretty(&report)?,
    )?;
    result?;
    println!("PASS {checks} actual engine checks; {}", output.display());
    Ok(())
}
fn lower_fixture_directory(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            LABEL_SECURITY_INFORMATION, SetFileSecurityW,
        },
    };
    let path = std::fs::canonicalize(path)?;
    let path: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let sddl: Vec<_> = "S:(ML;OICI;NW;;;LW)"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = std::ptr::null_mut();
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } != 0,
        "Create private fixture integrity descriptor: {}",
        std::io::Error::last_os_error()
    );
    let result = unsafe { SetFileSecurityW(path.as_ptr(), LABEL_SECURITY_INFORMATION, descriptor) };
    let error = std::io::Error::last_os_error();
    unsafe { LocalFree(descriptor) };
    ensure!(result != 0, "Label private fixture directory: {error}");
    Ok(())
}

fn check_list_readers(bin: &Path, temporary: &Path, logs: &Path) -> Result<usize> {
    use std::io::Write;

    let hosts =
        b" #comment\r\n^EXAMPLE.COM trailing\r\nA.Example\nthird.example\tcomment\n".to_vec();
    let addresses = b";comment\n192.0.2.1/24\n2001:db8::/32\ninvalid\n198.51.100.7\n".to_vec();
    let mut count = 0;
    for (name, option, data, expected) in [
        ("hosts", "--hostlist", hosts.clone(), 3),
        ("addresses", "--ipset", addresses, 3),
        ("host-long-line", "--hostlist", vec![b'A'; 4096], 2),
        (
            "host-nul",
            "--hostlist",
            b"first\0second\n\0third\n".to_vec(),
            1,
        ),
        ("empty-hosts", "--hostlist", Vec::new(), 0),
    ] {
        for gzip in [false, true] {
            let expected = match (name, gzip) {
                ("host-long-line", true) => 1,
                ("host-nul", true) => 3,
                _ => expected,
            };
            let file = temporary.join(format!("list-{name}-{}.txt", u8::from(gzip)));
            let bytes = if gzip {
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(&data)?;
                encoder.finish()?
            } else {
                data.clone()
            };
            std::fs::write(&file, &bytes)?;
            let text = engine_case(
                bin,
                &[
                    "--dry-run".into(),
                    "--intercept=0".into(),
                    format!("{option}={}", file.display()).into(),
                ],
                0,
                &[],
            )?;
            ensure!(
                text.contains(&format!("Loaded {expected} ")),
                "List result differs for {name}, gzip {gzip}"
            );
            zapret_core::atomic_write(
                &logs.join(format!("list-{name}-{gzip}.log")),
                text.as_bytes(),
            )?;
            count += 1;
        }
    }
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&hosts)?;
    let mut damaged = encoder.finish()?;
    let crc = damaged.len() - 8;
    damaged[crc] ^= 1;
    let file = temporary.join("corrupt-hosts.txt.gz");
    std::fs::write(&file, &damaged)?;
    let text = engine_case(
        bin,
        &[
            "--dry-run".into(),
            "--intercept=0".into(),
            format!("--hostlist={}", file.display()).into(),
        ],
        1,
        &[],
    )?;
    ensure!(
        text.contains("zlib decompression failed"),
        "Damaged list was accepted"
    );
    zapret_core::atomic_write(&logs.join("list-corrupt-gzip.log"), text.as_bytes())?;
    println!("ok real engine: plain and gzip list readers");
    Ok(count + 1)
}

fn check_list_registration(bin: &Path, temporary: &Path, logs: &Path) -> Result<usize> {
    let shared = temporary.join("shared-hosts.txt");
    let blocked = temporary.join("excluded-hosts.txt");
    let addresses = temporary.join("shared-addresses.txt");
    std::fs::write(&shared, b"example.test\n")?;
    std::fs::write(&blocked, b"excluded.test\n")?;
    std::fs::write(&addresses, b"192.0.2.0/24\n")?;
    let output = engine_case(
        bin,
        &[
            "--dry-run".into(),
            "--intercept=0".into(),
            "--debug".into(),
            "--template=lists".into(),
            format!("--hostlist={}", shared.display()).into(),
            format!("--hostlist-exclude={}", blocked.display()).into(),
            format!("--ipset={}", addresses.display()).into(),
            "--hostlist-domains=fixed.example".into(),
            "--ipset-ip=2001:db8::/32".into(),
            "--new=consumer".into(),
            "--hostlist-domains=local.example".into(),
            "--import=lists".into(),
            format!(
                "--hostlist={}",
                temporary.join("./shared-hosts.txt").display()
            )
            .into(),
            format!("--ipset={}", addresses.display()).into(),
            "--new=sibling".into(),
            format!("--hostlist={}", shared.display()).into(),
            format!("--ipset={}", addresses.display()).into(),
        ],
        0,
        &[],
    )?;
    zapret_core::atomic_write(&logs.join("list-registration.log"), output.as_bytes())?;
    let loaded: Vec<_> = output
        .lines()
        .filter(|line| line.starts_with("Loading hostlist ") || line.starts_with("Loading ipset "))
        .filter_map(|line| line.rsplit(['/', '\\']).next())
        .collect();
    ensure!(
        loaded
            == [
                "excluded-hosts.txt",
                "shared-hosts.txt",
                "shared-addresses.txt"
            ],
        "Shared list files loaded more than once or out of registration order"
    );
    let consumer: Vec<_> = output
        .lines()
        .filter_map(|line| line.strip_prefix("profile 1 (consumer) "))
        .collect();
    ensure!(
        consumer.len() == 6
            && consumer[..2] == ["include fixed hostlist", "include fixed hostlist"]
            && consumer[2].starts_with("include hostlist ")
            && consumer[2].ends_with("shared-hosts.txt")
            && consumer[3].starts_with("exclude hostlist ")
            && consumer[3].ends_with("excluded-hosts.txt")
            && consumer[4] == "include fixed ipset (ipv6)"
            && consumer[5].starts_with("include ipset ")
            && consumer[5].ends_with("shared-addresses.txt (ipv4)"),
        "The importing profile did not retain its local and template list order"
    );
    let sibling: Vec<_> = output
        .lines()
        .filter_map(|line| line.strip_prefix("profile 2 (sibling) "))
        .collect();
    ensure!(
        sibling.len() == 2
            && sibling[0].starts_with("include hostlist ")
            && sibling[0].ends_with("shared-hosts.txt")
            && sibling[1].starts_with("include ipset ")
            && sibling[1].ends_with("shared-addresses.txt (ipv4)"),
        "The second profile did not reuse the shared files"
    );
    println!("ok real engine: shared list registration and template order");
    Ok(3)
}

pub(crate) fn engine_case(
    bin: &Path,
    args: &[OsString],
    expected: u32,
    extra_env: &[(OsString, OsString)],
) -> Result<String> {
    let mut env = BTreeMap::from([
        ("__COMPAT_LAYER".into(), "RunAsInvoker".into()),
        ("ZAPRET_RING_SELFTEST".into(), "1".into()),
    ]);
    env.extend(extra_env.iter().cloned());
    let result = zapret_platform::run_owned(
        &bin.join("winws2.exe"),
        args,
        &zapret_platform::RunOptions {
            cwd: Some(bin.into()),
            timeout: Duration::from_secs(30),
            env,
            ..Default::default()
        },
    )?;
    let text = String::from_utf8_lossy(&result.stdout).to_string()
        + &String::from_utf8_lossy(&result.stderr);
    let diagnostic = || {
        if text.chars().count() <= 3000 {
            return text.clone();
        }
        let head = text.chars().take(1500).collect::<String>();
        let tail = text.chars().rev().take(1500).collect::<Vec<_>>();
        format!("{head}\n…\n{}", tail.into_iter().rev().collect::<String>())
    };
    ensure!(
        !result.timed_out && !result.output_truncated && result.exit_code == expected,
        "Engine exit {} (expected {expected}, timed_out={}, output_truncated={}): {}",
        result.exit_code,
        result.timed_out,
        result.output_truncated,
        diagnostic()
    );
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::{Lua, Value, register};

    #[test]
    fn store_requires_the_paired_bridge_before_publishing_its_api() {
        for missing in ["store_scheduler", "store_effect", "store_stat"] {
            let lua = Lua::new();
            register(&lua).unwrap();
            let native: mlua::Table = lua.globals().get("zapret_ring_native").unwrap();
            native.set(missing, Value::Nil).unwrap();
            let error = lua
                .load(include_str!("../../zapret-ring/lua/ring-store.lua"))
                .exec()
                .unwrap_err();
            assert!(error.to_string().contains("unsupported ring store bridge"));
            assert!(matches!(
                lua.globals().get::<Value>("ring_store").unwrap(),
                Value::Nil
            ));
        }
    }

    #[test]
    fn bridge_projects_single_store_fields_and_validates_host_capacity() {
        let lua = Lua::new();
        register(&lua).unwrap();
        lua.load(
            r#"
            local n=zapret_ring_native
            local s=n.store_new(4,64,60,true,nil,100)
            n.store_put(s,'local',3,100,0)
            local values={n.store_stats(s)}
            assert(#values==4)
            for i=1,4 do
                assert(n.store_stat(s,i)==values[i])
                assert(select('#',n.store_stat(s,i))==1)
            end
            assert(not pcall(n.store_stat,n.host_new(2),1))
            assert(not pcall(n.store_stat,s,5))
            local names={n.store_effect('schema')}
            assert(#names==7 and names[1]=='maxrecords' and names[7]=='serial')
            assert(n.host_capacity(true)==4096 and n.host_capacity(false,4096)==4096)
            assert(n.host_capacity(false,4097)==nil and n.host_capacity(false,1.5)==nil)
            "#,
        )
        .exec()
        .unwrap();
    }
}
