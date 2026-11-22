mod address_check;
mod address_prefix_check;
mod auto_hostlist;
mod blob_check;
mod cache_check;
mod cache_lifecycle_check;
mod cache_patch;
mod capture_packet_check;
mod capture_preflight_check;
mod checksum_wire_check;
mod cli_capture_options_check;
mod cli_check;
mod cli_control_check;
mod cli_list_options_check;
mod cli_numeric_patch;
mod cli_profile_filters_check;
mod cli_startup_options_check;
mod collections_check;
mod config_lists_check;
mod config_ownership_check;
mod conntrack_check;
mod conntrack_lifecycle_check;
mod conntrack_patch;
mod console_check;
mod engine_bootstrap_check;
mod engine_config_check;
mod engine_entry_check;
mod engine_fuzz_check;
mod engine_lifecycle_check;
mod engine_loop_check;
mod engine_loop_patch;
mod engine_prefix_check;
mod file_helpers_check;
mod file_policy_check;
mod file_state_check;
mod files_patch;
mod filter_collections_check;
mod filter_config_check;
mod gzip_file_check;
mod helpers_check;
mod libraries;
mod lifecycle;
mod list_lifecycle_check;
mod list_policy_check;
mod list_registry_check;
mod list_registry_patch;
mod list_startup_check;
mod logging_check;
mod lua_aes_check;
mod lua_arguments_check;
mod lua_aux_check;
mod lua_buffer_check;
mod lua_checksum_check;
mod lua_connection_publication_check;
mod lua_conntrack_view_check;
mod lua_context_check;
mod lua_entry_check;
mod lua_execution_view_check;
mod lua_gcm_check;
mod lua_hash_check;
mod lua_hash_ip_entry_check;
mod lua_header_entry_check;
mod lua_header_fields_check;
mod lua_header_list_check;
mod lua_instance_check;
mod lua_interfaces_check;
mod lua_invocation_check;
mod lua_ip_check;
mod lua_numeric_check;
mod lua_numeric_entry_check;
mod lua_packet_arguments_check;
mod lua_packet_assembly_check;
mod lua_packet_dispatch_check;
mod lua_packet_dissection_check;
mod lua_packet_options_check;
mod lua_registry_check;
mod lua_rules_patch;
mod lua_runtime_check;
mod lua_scalar_check;
mod lua_startup_check;
mod lua_system_tables_check;
mod lua_table_policy_check;
mod lua_timer_check;
mod lua_tls_workspace_check;
mod lua_zstream_check;
mod luna;
mod native_cli_catalog_check;
mod native_diagnostic_views_check;
mod native_help_entry_check;
mod native_logging_entry_check;
mod network_diagnostics_check;
mod network_environment_check;
mod packet_describe_check;
mod packet_diagnostics_check;
mod packet_final_check;
mod packet_helpers_check;
mod packet_input_check;
mod packet_play_check;
mod packet_queue_check;
mod packet_write_patch;
mod play_prolog;
mod pools_check;
mod pools_patch;
mod profile_config_check;
mod profile_flow_patch;
mod profile_rediscovery;
mod profile_selection;
mod protocol_check;
mod prune_residue;
mod reassembly_patch;
mod ring_bridge_check;
mod ring_loader_check;
mod route_source_check;
mod runtime_diagnostics_check;
mod security_label_check;
mod security_sandbox_check;
mod security_token_check;
mod service_check;
mod startup_io_check;
mod startup_validation_check;
mod stdio_check;
mod system_diagnostics_check;
mod system_patch;
mod timer_lifecycle_check;
mod tls_debug_policy_check;
mod tools;
mod windivert_send_check;
mod writable_check;

pub(super) use lifecycle::run as check_lifecycle;

use crate::{Build, checked, ring_build};
use anyhow::{Context, Result, ensure};
use ring_build::{BASE_HASH, COMMIT, LUA_HASH};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tools::{Compilation, Tools};
use zapret_core::{CYGWIN_DLL, atomic_write, sha256, sha256_file};

const ENGINE_VERSION: &str = "v1.0.6-rust-native.1";

pub(super) fn rust_engine_object(root: &Path, source: &str, output: &Path, panic: &str) -> Command {
    let mut command = Build::rustc();
    command
        .current_dir(root)
        .args([
            "--edition=2024",
            "--crate-type=lib",
            "--emit=obj",
            "-C",
            panic,
            "-O",
            "-D",
            "warnings",
            "-o",
        ])
        .arg(output)
        .arg(format!(
            "--remap-path-prefix={}=/zapret-rust",
            root.display()
        ))
        .arg(
            root.join("native/zapret-dev/src/engine_native")
                .join(source),
        );
    command
}

pub(super) fn run(
    build: &Build<'_>,
    queue: bool,
    compatibility: bool,
    conformance: bool,
) -> Result<()> {
    let _lock = build.lock_release()?;
    let compatibility = queue || compatibility;
    let conformance = conformance || compatibility;
    ensure!(
        Build::host()? == "x86_64-pc-windows-gnu",
        "The native engine builder requires x86_64-pc-windows-gnu Rust"
    );
    checked(
        build
            .cargo("build", Some("zapret-ring-ffi"))
            .args(["--locked", "--release", "--target-dir"])
            .arg(&build.target),
    )?;
    checked(
        build
            .cargo("build", Some("zapret-wincompat"))
            .args(["--locked", "--release", "--target-dir"])
            .arg(&build.target),
    )?;
    let root = build.root;
    let work = build.target.join("native-engine-build");
    fs::create_dir_all(&work)?;
    let temporary = tempfile::Builder::new()
        .prefix("sources-")
        .tempdir_in(&work)?;
    let sources = temporary.path();
    let llvm = root.join("dist/rust-tools/llvm-mingw-20261104-ucrt-x86_64/bin");
    let compiler = llvm.join("x86_64-w64-mingw32-clang.exe");
    ensure!(
        compiler.is_file(),
        "Missing pinned LLVM MinGW compiler: {}",
        compiler.display()
    );
    let tools = Tools::new(&llvm, &compiler, &work.join("commands.log"))?;
    let cli_object = sources.join("windows_cli_dispatch.o");
    let blob_object = sources.join("windows_blob_input.o");
    let capture_object = sources.join("windows_cli_capture.o");
    let bootstrap_object = sources.join("windows_engine_bootstrap.o");
    let idle_object = sources.join("windows_engine_idle.o");
    let logging_object = sources.join("windows_engine_logging.o");
    let lifecycle_object = sources.join("windows_main_lifecycle.o");
    let prefix_object = sources.join("windows_main_prefix.o");
    let network_report_object = sources.join("windows_network_report.o");
    let packet_diagnostics_object = sources.join("windows_packet_diagnostics.o");
    let reports_object = sources.join("windows_engine_reports.o");
    let main_objects = [
        ("windows_blob_input", &blob_object),
        ("windows_cli_capture", &capture_object),
        ("windows_engine_logging", &logging_object),
        ("windows_engine_reports", &reports_object),
        ("windows_main_lifecycle", &lifecycle_object),
        ("windows_main_prefix", &prefix_object),
        ("windows_network_report", &network_report_object),
        ("windows_packet_diagnostics", &packet_diagnostics_object),
    ];
    for (name, object) in main_objects {
        checked(&mut rust_engine_object(
            root,
            &format!("{name}.rs"),
            object,
            "panic=abort",
        ))?;
    }
    let entry_bindings = [
        ("windows_cli_dispatch", &cli_object),
        ("windows_engine_bootstrap", &bootstrap_object),
        ("windows_engine_idle", &idle_object),
    ];
    for (name, object) in entry_bindings {
        checked(
            rust_engine_object(root, &format!("{name}.rs"), object, "panic=unwind")
                .args(["-C", "force-unwind-tables=yes"]),
        )?;
    }
    let vm_objects = [
        "windows_buffer_vm",
        "windows_capture_host",
        "windows_codec_vm",
        "windows_crypto_vm",
        "windows_divert_host",
        "windows_interfaces_vm",
        "windows_local_lifecycle",
        "windows_lua_checksums",
        "windows_lua_connection_view",
        "windows_lua_context",
        "windows_lua_cutoff",
        "windows_lua_execution_view",
        "windows_lua_fields",
        "windows_lua_file_vm",
        "windows_lua_guards",
        "windows_lua_header_decode",
        "windows_lua_header_views",
        "windows_lua_ipaddr",
        "windows_lua_lifetime",
        "windows_lua_packet_positions",
        "windows_lua_packet_projection",
        "windows_lua_packet_run",
        "windows_lua_packet_write",
        "windows_lua_sandbox",
        "windows_lua_scripts",
        "windows_lua_startup",
        "windows_lua_tables_vm",
        "windows_lua_timer_vm",
        "windows_lua_vm",
        "windows_network_gate",
        "windows_numeric_vm",
        "windows_packet_engine",
        "windows_registry_vm",
        "windows_ring_vm",
        "windows_scalar_vm",
        "windows_system_tables_vm",
        "windows_timer_host_vm",
        "windows_timer_vm",
        "windows_zstream_vm",
    ]
    .map(|name| (name, sources.join(format!("{name}.o"))));
    for (name, object) in &vm_objects {
        // VM errors can unwind through these entries.
        checked(
            rust_engine_object(root, &format!("{name}.rs"), object, "panic=unwind")
                .args(["-C", "force-unwind-tables=yes"]),
        )?;
    }
    let upstream = root.join("dist/upstream/rust-ring-build");
    let upstream_archive = upstream.join("zapret2-221d7dff.tar.gz");
    ensure!(
        sha256_file(&upstream_archive)?.eq_ignore_ascii_case(BASE_HASH),
        "Native engine source hash differs: zapret2-221d7dff.tar.gz"
    );
    let upstream_dir = format!("zapret2-{COMMIT}/nfq2");
    let nfq = sources.join(&upstream_dir);
    let resource = "windows/res/winws_res64.o";
    let windivert = "windows/windivert/libwindivert64.a";
    let luajit = sources.join("luajit2-2.1-20250826/src");
    let shim = sources.join("windows-support");
    let include = shim.join("include");
    if conformance {
        let archive = upstream.join("luajit2-2.1-20250826.tar.gz");
        ensure!(
            sha256_file(&archive)?.eq_ignore_ascii_case(LUA_HASH),
            "Native engine source hash differs: luajit2-2.1-20250826.tar.gz"
        );
        tools.extract(&archive, sources)?;
        tools.extract(&upstream_archive, sources)?;
        let originals = root.join("native/zapret-dev/src/engine_native");
        copy_tree(&originals, &shim)?;
        // Keep the upstream IPv4 and TCP bitfields in one byte on Windows.
        let ip = include.join("netinet/ip.h");
        ring_build::patch(&ip, "unsigned int ip_hl:4", "unsigned char ip_hl:4")?;
        ring_build::patch(&ip, "unsigned int ip_v:4", "unsigned char ip_v:4")?;
        let tcp = include.join("netinet/tcp.h");
        ring_build::patch(&tcp, "unsigned int  th_x2:4", "unsigned char th_x2:4")?;
        ring_build::patch(&tcp, "unsigned int  th_off:4", "unsigned char th_off:4")?;
    } else {
        tools.extract_members(
            &upstream_archive,
            sources,
            &[
                format!("{upstream_dir}/{resource}"),
                format!("{upstream_dir}/{windivert}"),
            ],
        )?;
    }
    let library = build.target.join("release/libzapret_wincompat.a");
    let mut provenance = Vec::new();
    for (name, digest) in [
        (
            resource,
            "08d0a1fb79f01c9c76975023ff4c111947c5d9d6a034d3c28ec4c87a5db6595a",
        ),
        (
            windivert,
            "8f992a067455aeea5cc5f828f124034b0c897cd8fec5cff614f0f90884f01ecd",
        ),
    ] {
        let bytes = fs::read(nfq.join(name))?;
        ensure!(
            sha256(&bytes).eq_ignore_ascii_case(digest),
            "Native link input hash differs: {name}"
        );
        record(name, &bytes, &mut provenance);
    }
    let dll = fs::read(build.target.join("release/zapret_ring_ffi.dll"))?;
    let ring_digest = sha256(&dll).to_ascii_uppercase();
    let luajit_guard = sources.join("windows_luajit_file_guard.o");
    if conformance {
        let bridge = root.join("native/zapret-ring-ffi/bridge");
        for name in ["rust_ring.c", "rust_ring.h"] {
            atomic_write(&nfq.join(name), &fs::read(bridge.join(name))?)?;
        }
        checked(
            rust_engine_object(
                root,
                "windows_luajit_file_guard.rs",
                &luajit_guard,
                "panic=unwind",
            )
            .args(["-C", "force-unwind-tables=yes"]),
        )?;
        check_conformance(Conformance {
            build,
            sources,
            tools: &tools,
            ring_digest: &ring_digest,
            dll: &dll,
            blob_object: &blob_object,
            bootstrap_object: &bootstrap_object,
            capture_object: &capture_object,
            cli_object: &cli_object,
            idle_object: &idle_object,
            include: &include,
            library: &library,
            lifecycle_object: &lifecycle_object,
            logging_object: &logging_object,
            luajit: &luajit,
            luajit_guard: &luajit_guard,
            network_report_object: &network_report_object,
            nfq: &nfq,
            packet_diagnostics_object: &packet_diagnostics_object,
            prefix_object: &prefix_object,
            reports_object: &reports_object,
            shim: &shim,
            work: &work,
        })?;
    }
    // The stand-alone oracles link individual ABI entries to their own
    // settings, VM and capture effects. Only the engine binds the live host.
    for name in [
        "windows_cli_capture",
        "windows_cli_dispatch",
        "windows_lua_context",
        "windows_lua_scripts",
        "windows_lua_vm",
        "windows_ring_vm",
    ] {
        checked(
            rust_engine_object(
                root,
                &format!("{name}.rs"),
                &sources.join(format!("{name}.o")),
                "panic=unwind",
            )
            .args([
                "--cfg",
                "zapret_engine_production",
                "-C",
                "force-unwind-tables=yes",
            ]),
        )?;
    }
    let entry_object = sources.join("windows_entry.o");
    checked(
        rust_engine_object(root, "windows_entry.rs", &entry_object, "panic=unwind")
            .args(["-C", "force-unwind-tables=yes"])
            .env("ZAPRET_RING_DLL_SHA256", ring_digest),
    )?;
    record(
        "windows_entry.o",
        &fs::read(&entry_object)?,
        &mut provenance,
    );
    let bindings = sources.join("windows_engine_bindings.o");
    let mut compile_bindings =
        rust_engine_object(root, "windows_engine_bindings.rs", &bindings, "panic=abort");
    if compatibility {
        compile_bindings.args(["--cfg", "zapret_luajit_compatibility"]);
    }
    checked(
        compile_bindings
            .env("ZAPRET_ENGINE_VERSION", ENGINE_VERSION)
            .env("ZAPRET_ENGINE_REVISION", COMMIT),
    )?;
    record(
        "windows_engine_bindings.o",
        &fs::read(&bindings)?,
        &mut provenance,
    );
    for (name, object) in main_objects.into_iter().chain(entry_bindings) {
        record(&format!("{name}.o"), &fs::read(object)?, &mut provenance);
    }
    for (name, object) in &vm_objects {
        record(&format!("{name}.o"), &fs::read(object)?, &mut provenance);
    }
    let runtime = if compatibility {
        record(
            "windows_luajit_file_guard.o",
            &fs::read(&luajit_guard)?,
            &mut provenance,
        );
        luajit.join("libluajit.a")
    } else {
        let library = luna::build(root, sources, &tools)?;
        if conformance {
            luna::check(
                root,
                sources,
                &tools,
                &luajit,
                &library,
                &build.target.join("release/libzapret_wincompat.a"),
                &work.join("rust-lua-abi.log"),
            )?;
        }
        record(
            "libzapret_rust_lua_runtime.a",
            &fs::read(&library)?,
            &mut provenance,
        );
        library
    };
    let engine = work.join("winws2.exe");
    let map = work.join("engine-link.map");
    let mut link = Command::new(&compiler);
    link.args([
        "-municode",
        "-s",
        "-Wl,--gc-sections,--no-insert-timestamp",
        "-o",
    ])
    .arg(&engine)
    .arg(format!("-Wl,-Map,{}", map.display()));
    let wincompat = build.target.join("release/libzapret_wincompat.a");
    record(
        "libzapret_wincompat.a",
        &fs::read(&wincompat)?,
        &mut provenance,
    );
    link.arg(&entry_object)
        .arg(&bindings)
        .args(main_objects.iter().map(|(_, object)| object))
        .args(entry_bindings.iter().map(|(_, object)| object))
        .args(vm_objects.iter().map(|(_, object)| object));
    if compatibility {
        link.arg(&luajit_guard);
    }
    link.arg(&runtime)
        .arg(&wincompat)
        .arg(nfq.join(resource))
        .arg(nfq.join(windivert))
        .args([
            "-lole32",
            "-loleaut32",
            "-liphlpapi",
            "-lntdll",
            "-lbcrypt",
            "-ladvapi32",
            "-lws2_32",
            "-luserenv",
            "-lcrypt32",
            "-luuid",
            "-ldbghelp",
            "-static",
            "-lwinpthread",
        ]);
    tools.run_command(&link, sources, "Link native winws2")?;
    let linked = fs::read_to_string(&map)?;
    ensure!(
        !linked
            .lines()
            .any(|line| line.contains("nfqws.o:(") || line.contains("lua.o:(")),
        "Unexpected upstream C translation unit in the native engine link map"
    );
    let cli_sections: Vec<_> = linked
        .lines()
        .filter(|line| line.ends_with(":(.rdata$zapret_native_cli_bindings)"))
        .collect();
    ensure!(
        cli_sections.len() == 1
            && cli_sections[0]
                .ends_with("windows_cli_dispatch.o:(.rdata$zapret_native_cli_bindings)")
            && cli_sections[0].split_whitespace().nth(1) == Some("00000038"),
        "Native CLI bindings must be a 56-byte table linked from Rust: {cli_sections:?}"
    );
    ensure!(
        linked.contains("windows_luajit_file_guard.o:(.text)") == compatibility,
        "Only the LuaJIT compatibility engine may link the LuaJIT buffer owner"
    );
    if !compatibility {
        // The COFF map names extracted object files rather than their archives.
        ensure!(
            linked.contains("libzapret_rust_lua_runtime.luna_core.")
                && !linked.contains("lj_vm_asm_begin")
                && !linked.contains("luaJIT_setmode"),
            "Unexpected Lua runtime in the native engine link map"
        );
    }
    let imports = tools.run_command(
        Command::new(llvm.join("llvm-readobj.exe"))
            .arg("--coff-imports")
            .arg(&engine),
        sources,
        "Read winws2 import table",
    )?;
    ensure!(
        !zapret_core::mentions_posix_runtime(imports.as_bytes()),
        "Native engine retains a POSIX runtime import"
    );
    atomic_write(&work.join("imports.log"), imports.as_bytes())?;
    if conformance {
        logging_check::snapshot_sources(&nfq, &shim, &luajit, &work.join("native-c-snapshot"))?;
    }
    let candidate = build.target.join(if compatibility {
        "native-engine-compatibility-candidate"
    } else {
        "native-engine-candidate"
    });
    atomic_write(&candidate.join("bin/winws2.exe"), &fs::read(&engine)?)?;
    atomic_write(&candidate.join("bin/zapret-ring.dll"), &dll)?;
    if compatibility {
        // Old installed controllers read the nine-file queue. Reuse the pinned
        // checkout DLL for that format without needing the Cygwin toolchain.
        let base = zapret_core::read_core_manifest(&root.join("tools/upstream.txt"))?;
        let bytes = fs::read(root.join(CYGWIN_DLL))?;
        ensure!(
            base.hashes
                .get(CYGWIN_DLL)
                .is_some_and(|expected| sha256(&bytes).eq_ignore_ascii_case(expected)),
            "Compatibility queue requires the pinned checkout Cygwin DLL"
        );
        atomic_write(&candidate.join(CYGWIN_DLL), &bytes)?;
    } else {
        let leftover = candidate.join(CYGWIN_DLL);
        if leftover.try_exists()? {
            fs::remove_file(leftover).context("Remove obsolete DLL from the owned build output")?;
        }
    }
    for name in ["autoring.lua", "ring-store.lua", "host-cache.lua"] {
        let output = candidate.join("lua").join(name);
        if compatibility {
            atomic_write(
                &output,
                &fs::read(root.join("native/zapret-ring/lua").join(name))?,
            )?;
        } else if output.try_exists()? {
            fs::remove_file(output)
                .context("Remove obsolete script from the owned build output")?;
        }
    }
    ring_build::finish(
        build,
        &candidate,
        &provenance,
        if compatibility {
            1
        } else {
            zapret_core::RUST_LUA_SCHEMA
        },
        queue,
        if compatibility {
            "native-engine-compatibility-check.json"
        } else {
            "native-engine-check.json"
        },
    )
}

struct Conformance<'a> {
    build: &'a Build<'a>,
    sources: &'a Path,
    tools: &'a Tools<'a>,
    ring_digest: &'a str,
    dll: &'a [u8],
    blob_object: &'a PathBuf,
    bootstrap_object: &'a PathBuf,
    capture_object: &'a PathBuf,
    cli_object: &'a PathBuf,
    idle_object: &'a PathBuf,
    include: &'a PathBuf,
    library: &'a PathBuf,
    lifecycle_object: &'a PathBuf,
    logging_object: &'a PathBuf,
    luajit: &'a PathBuf,
    luajit_guard: &'a PathBuf,
    network_report_object: &'a PathBuf,
    nfq: &'a PathBuf,
    packet_diagnostics_object: &'a PathBuf,
    prefix_object: &'a PathBuf,
    reports_object: &'a PathBuf,
    shim: &'a PathBuf,
    work: &'a PathBuf,
}

fn check_conformance(input: Conformance<'_>) -> Result<()> {
    let Conformance {
        build,
        sources,
        tools,
        ring_digest,
        dll,
        blob_object,
        bootstrap_object,
        capture_object,
        cli_object,
        idle_object,
        include,
        library,
        lifecycle_object,
        logging_object,
        luajit,
        luajit_guard,
        network_report_object,
        nfq,
        packet_diagnostics_object,
        prefix_object,
        reports_object,
        shim,
        work,
    } = input;
    let pin = format!("#define RUST_RING_DLL_SHA256 \"{ring_digest}\"\n");
    atomic_write(&nfq.join("rust_ring_pin.h"), pin.as_bytes())?;
    for entry in fs::read_dir(nfq)? {
        let file = entry?.path();
        if matches!(
            file.extension().and_then(|extension| extension.to_str()),
            Some("c" | "h")
        ) {
            let text = fs::read_to_string(&file)?;
            fs::write(&file, text.replace("__CYGWIN__", "ZAPRET_WINDOWS"))?;
        }
    }
    lua_checksum_check::capture(nfq)?;
    files_patch::apply(nfq)?;
    system_patch::apply(nfq)?;
    file_policy_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("file-policy-check.log"),
    )?;
    engine_loop_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("engine-loop-check.log"),
    )?;
    engine_loop_patch::apply(nfq)?;
    protocol_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("protocol-check.log"),
    )?;
    replace_packet_parser(nfq)?;
    replace_checksum_core(nfq)?;
    packet_write_patch::apply(nfq)?;
    replace_timer_pool(nfq)?;
    replace_list_loaders(nfq)?;
    pools_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("pools-check.log"),
    )?;
    pools_patch::apply(nfq)?;
    cache_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("caches-check.log"),
    )?;
    cache_lifecycle_check::run(
        tools,
        nfq,
        shim,
        library,
        &work.join("cache-lifecycle-check.log"),
    )?;
    list_registry_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("list-registry-check.log"),
    )?;
    profile_selection::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("profile-selection-check.log"),
    )?;
    auto_hostlist::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("auto-hostlist-check.log"),
    )?;
    packet_input_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("packet-input-check.log"),
    )?;
    packet_queue_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("packet-queue-check.log"),
    )?;
    conntrack_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("conntrack-check.log"),
    )?;
    conntrack_lifecycle_check::run(
        tools,
        nfq,
        shim,
        library,
        &work.join("conntrack-lifecycle-check.log"),
    )?;
    packet_play_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("packet-play-check.log"),
    )?;
    lua_rules_patch::apply(nfq)?;
    filter_config_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("filter-config-check.log"),
    )?;
    windivert_send_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("windivert-send-check.log"),
    )?;
    cli_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("engine-cli-check.log"),
    )?;
    profile_config_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("profile-config-check.log"),
    )?;
    network_environment_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        network_report_object,
        &work.join("network-environment-check.log"),
    )?;
    libraries::luajit(tools, luajit, &shim.join("win_files.h"))?;
    lua_aes_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-aes-check.log"),
    )?;
    lua_gcm_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-gcm-check.log"),
    )?;
    lua_ip_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-ip-check.log"),
    )?;
    lua_hash_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-hash-check.log"),
    )?;
    lua_numeric_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-numeric-check.log"),
    )?;
    helpers_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("helpers-check.log"),
    )?;
    address_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("address-check.log"),
    )?;
    lua_arguments_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-arguments-check.log"),
    )?;
    blob_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        blob_object,
        &work.join("blob-check.log"),
    )?;
    service_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("service-check.log"),
    )?;
    console_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("console-check.log"),
    )?;
    system_diagnostics_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("system-diagnostics-check.log"),
    )?;
    collections_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("collections-check.log"),
    )?;
    filter_collections_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("filter-collections-check.log"),
    )?;
    address_prefix_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("address-prefix-check.log"),
    )?;
    engine_config_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("engine-config-check.log"),
    )?;
    config_lists_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("config-lists-check.log"),
    )?;
    list_policy_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("list-policy-check.log"),
    )?;
    stdio_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("stdio-check.log"),
    )?;
    file_helpers_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("file-helpers-check.log"),
    )?;
    config_ownership_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("config-ownership-check.log"),
    )?;
    packet_helpers_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("packet-helpers-check.log"),
    )?;
    checksum_wire_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("checksum-wire-check.log"),
    )?;
    packet_describe_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("packet-describe-check.log"),
    )?;
    file_state_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("file-state-check.log"),
    )?;
    security_token_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("security-token-check.log"),
    )?;
    security_label_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("security-label-check.log"),
    )?;
    security_sandbox_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("security-sandbox-check.log"),
    )?;
    writable_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("writable-check.log"),
    )?;
    startup_io_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("startup-io-check.log"),
    )?;
    engine_bootstrap_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        bootstrap_object,
        &work.join("engine-bootstrap-check.log"),
    )?;
    lua_instance_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("lua-instance-check.log"),
    )?;
    lua_zstream_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &sources.join("windows_zstream_vm.o"),
        &work.join("lua-zstream-check.log"),
    )?;
    cli_startup_options_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("cli-startup-options-check.log"),
    )?;
    cli_list_options_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("cli-list-options-check.log"),
    )?;
    cli_profile_filters_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("cli-profile-filters-check.log"),
    )?;
    cli_capture_options_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        capture_object,
        &work.join("cli-capture-options-check.log"),
    )?;
    cli_control_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("cli-control-check.log"),
    )?;
    startup_validation_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("startup-validation-check.log"),
    )?;
    capture_preflight_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("capture-preflight-check.log"),
    )?;
    engine_lifecycle_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        lifecycle_object,
        &work.join("engine-lifecycle-check.log"),
    )?;
    lua_packet_assembly_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-packet-assembly-check.log"),
    )?;
    lua_packet_dissection_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-packet-dissection-check.log"),
    )?;
    gzip_file_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("gzip-file-check.log"),
    )?;
    lua_execution_view_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &sources.join("windows_lua_execution_view.o"),
        &work.join("lua-execution-view-check.log"),
    )?;
    lua_conntrack_view_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-conntrack-view-check.log"),
    )?;
    lua_context_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        [
            &sources.join("windows_lua_context.o"),
            &sources.join("windows_lua_cutoff.o"),
        ],
        &work.join("lua-context-check.log"),
    )?;
    lua_checksum_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-checksum-check.log"),
    )?;
    lua_startup_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        [
            &sources.join("windows_lua_scripts.o"),
            &sources.join("windows_lua_sandbox.o"),
            &sources.join("windows_lua_startup.o"),
        ],
        &work.join("lua-startup-check.log"),
    )?;
    lua_registry_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &sources.join("windows_registry_vm.o"),
        &work.join("lua-registry-check.log"),
    )?;
    lua_packet_arguments_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-packet-arguments-check.log"),
    )?;
    lua_invocation_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-invocation-check.log"),
    )?;
    engine_entry_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        cli_object,
        &work.join("engine-entry-check.log"),
    )?;
    lua_header_fields_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-header-fields-check.log"),
    )?;
    lua_header_list_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-header-list-check.log"),
    )?;
    lua_packet_options_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &sources.join("windows_lua_packet_positions.o"),
        &work.join("lua-packet-options-check.log"),
    )?;
    lua_interfaces_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-interfaces-check.log"),
    )?;
    route_source_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("route-source-check.log"),
    )?;
    lua_tls_workspace_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-tls-workspace-check.log"),
    )?;
    lua_packet_dispatch_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-packet-dispatch-check.log"),
    )?;
    lua_system_tables_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-system-tables-check.log"),
    )?;
    lua_runtime_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        [
            &sources.join("windows_lua_file_vm.o"),
            luajit_guard,
            &sources.join("windows_lua_vm.o"),
        ],
        &work.join("lua-runtime-check.log"),
    )?;
    lua_entry_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-entry-check.log"),
    )?;
    lua_buffer_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &sources.join("windows_buffer_vm.o"),
        &work.join("lua-buffer-check.log"),
    )?;
    lua_header_entry_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        [
            &sources.join("windows_lua_header_views.o"),
            &sources.join("windows_lua_ipaddr.o"),
            &sources.join("windows_lua_header_decode.o"),
            &sources.join("windows_lua_guards.o"),
        ],
        &work.join("lua-header-entry-check.log"),
    )?;
    lua_table_policy_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        [
            &sources.join("windows_lua_tables_vm.o"),
            &sources.join("windows_lua_packet_projection.o"),
        ],
        &work.join("lua-table-policy-check.log"),
    )?;
    lua_connection_publication_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &sources.join("windows_lua_connection_view.o"),
        &work.join("lua-connection-publication-check.log"),
    )?;
    lua_timer_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-timer-check.log"),
    )?;
    timer_lifecycle_check::run(
        tools,
        nfq,
        shim,
        library,
        &work.join("timer-lifecycle-check.log"),
    )?;
    lua_numeric_entry_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-numeric-entry-check.log"),
    )?;
    lua_hash_ip_entry_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-hash-ip-entry-check.log"),
    )?;
    lua_scalar_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        &work.join("lua-scalar-check.log"),
    )?;
    logging_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        &work.join("logging-check.log"),
    )?;
    native_logging_entry_check::run(
        tools,
        nfq,
        shim,
        &build.target.join("release/libzapret_wincompat.a"),
        luajit,
        logging_object,
        &work.join("native-logging-entry-check.log"),
    )?;
    list_lifecycle_check::run(
        tools,
        nfq,
        shim,
        library,
        &work.join("list-lifecycle-check.log"),
    )?;
    list_startup_check::run(
        tools,
        nfq,
        shim,
        library,
        luajit,
        &work.join("list-startup-check.log"),
    )?;
    native_cli_catalog_check::run(
        tools,
        nfq,
        shim,
        library,
        &work.join("native-cli-catalog-check.log"),
    )?;
    native_diagnostic_views_check::run(
        tools,
        nfq,
        shim,
        library,
        luajit,
        &work.join("native-diagnostic-views-check.log"),
    )?;
    native_help_entry_check::run(
        tools,
        nfq,
        shim,
        library,
        luajit,
        &work.join("native-help-entry-check.log"),
    )?;
    packet_final_check::run(
        tools,
        nfq,
        shim,
        library,
        luajit,
        &work.join("packet-final-check.log"),
    )?;
    tls_debug_policy_check::run(
        tools,
        nfq,
        shim,
        library,
        packet_diagnostics_object,
        luajit,
        &work.join("tls-debug-policy-check.log"),
    )?;
    packet_diagnostics_check::run(
        tools,
        nfq,
        shim,
        library,
        packet_diagnostics_object,
        luajit,
        &work.join("packet-diagnostics-check.log"),
    )?;
    capture_packet_check::run(
        tools,
        nfq,
        shim,
        library,
        luajit,
        &sources.join("windows_capture_host.o"),
        &work.join("capture-packet-check.log"),
    )?;
    ring_bridge_check::run(
        tools,
        nfq,
        shim,
        library,
        luajit,
        &sources.join("windows_ring_vm.o"),
        &work.join("ring-bridge-check.log"),
    )?;
    ring_loader_check::run(
        tools,
        nfq,
        shim,
        library,
        luajit,
        dll,
        &work.join("ring-loader-check.log"),
    )?;
    lua_aux_check::run(
        tools,
        nfq,
        shim,
        library,
        luajit,
        [
            &sources.join("windows_lua_guards.o"),
            &sources.join("windows_timer_vm.o"),
            &sources.join("windows_lua_fields.o"),
            &sources.join("windows_lua_lifetime.o"),
            &sources.join("windows_timer_host_vm.o"),
        ],
        &work.join("lua-aux-check.log"),
    )?;
    engine_prefix_check::run(
        tools,
        nfq,
        shim,
        library,
        luajit,
        prefix_object,
        &work.join("engine-prefix-check.log"),
    )?;
    engine_fuzz_check::run(
        tools,
        nfq,
        shim,
        library,
        &work.join("engine-fuzz-check.log"),
    )?;
    runtime_diagnostics_check::run(
        tools,
        nfq,
        shim,
        library,
        luajit,
        [idle_object, reports_object],
        &work.join("runtime-diagnostics-check.log"),
    )?;
    prune_residue::apply(nfq, shim)?;
    let mut flags = vec![
        "-O2".into(),
        "-ffunction-sections".into(),
        "-fdata-sections".into(),
        "-fexceptions".into(),
        "-std=gnu99".into(),
        "-DZAPRET_WINDOWS=1".into(),
        "-DZAPRET_NATIVE_WINDOWS=1".into(),
        "-D_FILE_OFFSET_BITS=64".into(),
        "-D_POSIX_C_SOURCE=200809L".into(),
        "-DLUAJIT".into(),
        "-Wno-macro-redefined".into(),
        format!("-DZAPRET_GH_VER={ENGINE_VERSION}"),
        format!("-DZAPRET_GH_HASH={COMMIT}"),
    ];
    for path in [shim, include, &nfq.join("windows"), luajit, nfq] {
        flags.push(format!("-I{}", path.display()));
    }
    flags.extend([
        "-include".into(),
        shim.join("win_platform.h").display().to_string(),
    ]);
    let mut compilations = Vec::new();
    // Compile the pinned C ABI assertions for conformance without linking the objects.
    for directory in [nfq] {
        let mut files = fs::read_dir(directory)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        files.sort();
        for file in files
            .into_iter()
            .filter(|file| file.extension().is_some_and(|extension| extension == "c"))
        {
            let output = file.with_extension("o");
            compilations.push(Compilation {
                input: file,
                output,
                extra: Vec::new(),
            });
        }
    }
    tools.compile_objects(
        sources,
        "winws2-abi",
        &flags
            .iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>(),
        &compilations,
    )?;
    Ok(())
}

fn replace_packet_parser(nfq: &Path) -> Result<()> {
    let path = nfq.join("darkmagic.c");
    let text = fs::read_to_string(&path)?;
    let first = "bool proto_check_ipv4(const uint8_t *data, size_t len)\n{";
    let next = "void reverse_ip(struct ip *ip, struct ip6_hdr *ip6)\n{";
    let start = text
        .find(first)
        .context("Missing pinned packet parser start")?;
    let end = text
        .find(next)
        .context("Missing pinned packet parser end")?;
    ensure!(start < end, "Pinned packet parser boundaries changed");
    // Compile the adapter in the same translation unit as the removed code.
    fs::write(
        &path,
        format!(
            "{}#include \"packet.c\"\n\n{}",
            &text[..start],
            &text[end..]
        ),
    )?;
    Ok(())
}

fn replace_checksum_core(nfq: &Path) -> Result<()> {
    let path = nfq.join("checksum.c");
    let text = fs::read_to_string(&path)?;
    let (_, body) = text
        .split_once("static uint16_t from64to16(uint64_t x)\n{")
        .context("Missing pinned checksum start")?;
    let (_, wrappers) = body
        .split_once("void ip4_fix_checksum(struct ip *ip)\n{")
        .context("Missing pinned IPv4 checksum wrapper")?;
    let (ipv4, rest) = wrappers
        .split_once("uint16_t csum_ipv6_magic(")
        .context("Missing pinned IPv6 checksum start")?;
    let (_, transport) = rest
        .split_once("void tcp4_fix_checksum(")
        .context("Missing pinned transport checksum wrappers")?;
    fs::write(
        &path,
        format!(
            "#include \"checksum.h\"\n\n\
             uint16_t zapret_internet_sum(const void *, size_t);\n\
             #define csum_partial zapret_internet_sum\n\n\
             void ip4_fix_checksum(struct ip *ip)\n{{{ipv4}void tcp4_fix_checksum({transport}"
        ),
    )?;
    Ok(())
}

fn replace_timer_pool(nfq: &Path) -> Result<()> {
    let header = nfq.join("timer.h");
    let text = fs::read_to_string(&header)?;
    ensure!(
        text.contains("typedef struct timer_pool {"),
        "Pinned timer header changed"
    );
    fs::write(&header, "#pragma once\n#include \"timer_windows.h\"\n")?;
    fs::write(
        nfq.join("timer.c"),
        "#include \"timer.h\"\n#include \"params.h\"\n#include \"helpers.h\"\n#include \"lua.h\"\n#include \"timer_windows.c\"\n",
    )?;

    let path = nfq.join("lua.c");
    let text = fs::read_to_string(&path)?;
    let first = "static int luacall_timer_set(lua_State *L)\n{";
    let last = "void lua_cleanup(lua_State *L)\n{";
    let start = text.find(first).context("Missing pinned Lua timer start")?;
    let end = text.find(last).context("Missing pinned Lua timer end")?;
    ensure!(start < end, "Pinned Lua timer boundaries changed");
    fs::write(
        &path,
        format!(
            "{}#include \"timer_lua.c\"\n\n{}",
            &text[..start],
            &text[end..]
        ),
    )?;
    Ok(())
}

fn replace_list_loaders(nfq: &Path) -> Result<()> {
    for (name, next, adapter) in [
        (
            "hostlist.c",
            "// bChanged is set to true",
            "hostlist_windows.c",
        ),
        (
            "ipset.c",
            "static bool LoadIpset(struct ipset_file *hfile)",
            "ipset_windows.c",
        ),
    ] {
        let path = nfq.join(name);
        let text = fs::read_to_string(&path)?;
        let start = text
            .find("static bool addpool(")
            .context("Missing pinned list parser")?;
        let end = text.find(next).context("Missing pinned list reload code")?;
        ensure!(start < end, "Pinned list loader boundaries changed");
        fs::write(
            &path,
            format!(
                "{}#include \"{adapter}\"\n\n{}",
                &text[..start],
                &text[end..]
            ),
        )?;
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn record(name: &str, bytes: &[u8], output: &mut Vec<u8>) {
    output.extend_from_slice(name.as_bytes());
    output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    output.extend_from_slice(bytes);
}
