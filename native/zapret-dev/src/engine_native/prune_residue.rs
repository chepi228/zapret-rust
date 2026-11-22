//! Drop unreachable native Windows bodies after all pinned C comparisons.
use super::{engine_entry_check, lua_aux_check};
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

fn body_range(source: &str, signature: &str) -> Result<std::ops::Range<usize>> {
    let start = source
        .find(signature)
        .with_context(|| format!("Pinned unused body {signature}"))?;
    let end = start + source[start..].find("\n}\n").context("Unused body end")? + 3;
    Ok(start..end)
}

fn remove_body(source: &mut String, signature: &str) -> Result<()> {
    let range = body_range(source, signature)?;
    source.replace_range(range, "");
    Ok(())
}

fn remove_before(source: &mut String, signature: &str, next: &str) -> Result<()> {
    let start = source
        .find(signature)
        .with_context(|| format!("Pinned unused block {signature}"))?;
    let end = start
        + source[start..]
            .find(next)
            .with_context(|| format!("Unused block boundary {next}"))?;
    ensure!(start < end, "Empty unused block");
    source.replace_range(start..end, "");
    Ok(())
}

fn replace_include(source: &mut String, filename: &str, replacement: &str) -> Result<()> {
    let include = format!("#include \"{filename}\"");
    ensure!(
        source.matches(&include).count() == 1,
        "Engine adapter changed after verification: {filename}"
    );
    *source = source.replacen(&include, replacement, 1);
    Ok(())
}

fn direct_timer_lifecycle(nfq: &Path) -> Result<()> {
    let header = nfq.join("timer.h");
    let source = fs::read_to_string(&header)?;
    fs::write(
        header,
        format!(
            "{source}\nuint64_t zapret_timer_next_dirty(const timer_pool *, bool *);\n#define TimerPoolNext zapret_timer_next_dirty\n"
        ),
    )?;
    Ok(())
}

fn direct_lua_boundaries(nfq: &Path, shim: &Path) -> Result<()> {
    let lua = nfq.join("lua.c");
    let mut source = fs::read_to_string(&lua)?;
    for (previous, rust) in [
        ("lua_aux_arity_windows.inc", "windows_lua_guards_abi.h"),
        ("lua_aux_context_windows.inc", "windows_lua_lifetime_abi.h"),
        ("lua_buffer_windows.inc", "windows_buffer_vm_abi.h"),
        ("lua_checksum_windows.inc", "windows_lua_checksums_abi.h"),
        ("lua_codec_windows.inc", "lua_codec_vm_windows.h"),
        (
            "lua_conntrack_view_windows.inc",
            "windows_lua_connection_view_abi.h",
        ),
        (
            "lua_execution_view_windows.inc",
            "windows_lua_execution_view_abi.h",
        ),
        ("lua_file_windows.inc", "windows_lua_file_vm_abi.h"),
        ("lua_hash_ip_entry_windows.inc", "windows_crypto_vm_abi.h"),
        (
            "lua_header_entry_windows.inc",
            "windows_lua_packet_write_abi.h",
        ),
        ("lua_interfaces_windows.inc", "windows_interfaces_vm_abi.h"),
        ("lua_numeric_entry_windows.inc", "lua_numeric_vm_windows.h"),
        ("lua_packet_address_windows.inc", "windows_lua_ipaddr_abi.h"),
        (
            "lua_packet_dissection_windows.inc",
            "windows_lua_packet_projection_abi.h",
        ),
        ("lua_registry_windows.inc", "lua_registry_vm_sources.inc"),
        ("lua_scalar_windows.inc", "windows_scalar_vm_abi.h"),
        ("lua_startup_order_windows.inc", "windows_lua_startup_abi.h"),
        (
            "lua_system_tables_windows.inc",
            "windows_system_tables_vm_abi.h",
        ),
        ("lua_timer_windows.inc", "windows_lua_timer_vm_abi.h"),
        ("lua_table_policy_windows.inc", "lua_table_policy_abi.h"),
        ("lua_vm_windows.inc", "windows_lua_vm_sources.inc"),
        ("lua_zstream_windows.inc", "windows_zstream_vm_abi.h"),
    ] {
        replace_include(&mut source, previous, &format!("#include \"{rust}\""))?;
    }
    for include in [
        "lua_instance_windows.inc",
        "lua_packet_options_windows.inc",
        "packet_lua_windows.c",
        "lua_packet_assembly_windows.inc",
        "lua_packet_dispatch_windows.inc",
        "lua_tls_workspace_windows.inc",
    ] {
        replace_include(&mut source, include, "")?;
    }
    replace_include(
        &mut source,
        "lua_context_windows.inc",
        concat!(
            "#include \"lua_context_windows.h\"\n",
            "#include \"windows_lua_context_abi.h\"\n",
            "#include \"windows_lua_cutoff_abi.h\"\n",
            "_Static_assert(offsetof(struct desync_profile, n) == 0 && ",
            "offsetof(struct desync_profile, lua_desync) == 160, \"Rust Lua context profile ABI\");"
        ),
    )?;
    replace_include(
        &mut source,
        "lua_startup_windows.inc",
        concat!(
            "#include \"blob_windows.h\"\n",
            "#include \"runtime_log_windows.h\"\n",
            "#include \"windows_lua_scripts_abi.h\"\n",
            "#include \"windows_lua_sandbox_sources.inc\""
        ),
    )?;
    for include in [
        "lua_aux_error_windows.inc",
        "lua_crypto_windows.inc",
        "lua_lifetime_windows.inc",
        "lua_registry_windows.h",
    ] {
        replace_include(&mut source, include, "")?;
    }
    let helpers = lua_aux_check::field_helpers(&source)?;
    source.replace_range(helpers, "#include \"windows_lua_fields_abi.h\"\n");
    for signature in [
        "int lua_absindex(",
        "const char *lua_reqlstring(",
        "const char *lua_reqstring(",
        "static void lua_mt_init_desync_ctx(",
        "static void lua_mt_init_zstream(",
        "static void *z_alloc(",
        "static void z_free(",
    ] {
        ensure!(
            source.matches(signature).count() == 1,
            "Lua boundary definition changed: {signature}"
        );
        remove_body(&mut source, signature)?;
    }
    for header in [
        "engine_config_exports_abi.h",
        "engine_profile_exports_abi.h",
        "engine_params_boundary_windows.inc",
        "windows_timer_host_vm_abi.h",
    ] {
        source.push_str(&format!("\n#include \"{header}\"\n"));
    }
    fs::write(lua, source)?;

    let lifecycle = shim.join("lua_lifetime_windows.h");
    let source = fs::read_to_string(&lifecycle)?;
    let interrupt = "static void native_lua_install_interrupt(void *);";
    ensure!(
        source.matches(interrupt).count() == 1,
        "Pinned Lua interrupt declaration"
    );
    fs::write(lifecycle, source.replacen(interrupt, "", 1))?;

    let logging = shim.join("engine_params_boundary_windows.inc");
    let mut source = fs::read_to_string(&logging)?;
    let cleanup = "#include \"engine_cleanup_native_windows.inc\"";
    remove_before(
        &mut source,
        "#include \"native_logging_entry_abi.h\"",
        cleanup,
    )?;
    let position = source.find(cleanup).context("Native cleanup boundary")?;
    source.insert_str(position, "#include \"engine_logging_stdio_abi.h\"\n\n");
    replace_include(
        &mut source,
        "engine_cleanup_native_windows.inc",
        "#include \"engine_cleanup_exports_abi.h\"",
    )?;
    fs::write(logging, source)?;
    Ok(())
}

fn direct_windows_platform(nfq: &Path, shim: &Path) -> Result<()> {
    let main = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&main)?;
    for definition in [
        "struct params_s params;",
        "_Atomic(sig_atomic_t) bQuit = false;",
    ] {
        ensure!(
            source.matches(definition).count() == 1,
            "Engine global definition changed: {definition}"
        );
        source = source.replacen(definition, "", 1);
    }
    let exit = body_range(&source, "static void exit_clean(int code)\n")?;
    source.replace_range(exit, "#include \"windows_local_lifecycle_abi.h\"\n");
    remove_body(&mut source, "static void exithelp_clean(void)\n")?;
    replace_include(
        &mut source,
        "console_windows.inc",
        "void catch_signals(void);",
    )?;
    replace_include(
        &mut source,
        "list_startup_probe_windows.inc",
        "#include \"engine_application_exports_abi.h\"",
    )?;
    for include in [
        "cli_control_windows.inc",
        "native_collection_diagnostics_windows.inc",
        "native_help_entry_windows.inc",
        "profile_defaults_windows.inc",
        "engine_default_blobs_windows.inc",
        "capture_preflight_windows.inc",
    ] {
        replace_include(&mut source, include, "")?;
    }
    replace_include(
        &mut source,
        "startup_icon_windows.inc",
        "void WinSetIcon(void);",
    )?;
    for (previous, rust) in [
        ("blob_input_windows.inc", "engine_blob_input_abi.h"),
        (
            "cli_capture_options_windows.inc",
            "engine_cli_capture_abi.h",
        ),
        ("config_file_windows.inc", "engine_config_file_abi.h"),
        ("config_lists_windows.inc", "engine_config_lists_abi.h"),
        ("filter_lists_windows.inc", "engine_profile_options_abi.h"),
        (
            "cli_list_options_windows.inc",
            "engine_cli_list_options_abi.h",
        ),
        (
            "cli_startup_options_windows.inc",
            "engine_cli_options_abi.h",
        ),
        (
            "cli_profile_filters_windows.inc",
            "engine_profile_filters_abi.h",
        ),
        (
            "engine_lifecycle_windows.inc",
            "engine_main_lifecycle_abi.h",
        ),
        (
            "engine_prefix_windows.inc",
            "engine_main_prefix_windows.inc",
        ),
        ("lua_arguments_windows.inc", "engine_lua_arguments_abi.h"),
        ("profile_flow_windows.inc", "profile_flow_windows.h"),
        (
            "startup_validation_windows.inc",
            "engine_startup_validation_abi.h",
        ),
    ] {
        replace_include(&mut source, previous, &format!("#include \"{rust}\""))?;
    }
    fs::write(main, source)?;

    let numeric = shim.join("cli_numeric_windows.inc");
    let mut source = fs::read_to_string(&numeric)?;
    replace_include(
        &mut source,
        "native_cli_numeric_windows.inc",
        "#include \"engine_cli_options_abi.h\"",
    )?;
    fs::write(numeric, source)?;

    Ok(())
}

pub(super) fn apply(nfq: &Path, shim: &Path) -> Result<()> {
    direct_timer_lifecycle(nfq)?;
    direct_lua_boundaries(nfq, shim)?;
    direct_windows_platform(nfq, shim)?;
    engine_entry_check::select(nfq, shim)?;
    // The comparisons above retain their separate pinned C inputs.
    for unit in [
        "random.c",
        "conntrack.c",
        "darkmagic.c",
        "desync.c",
        "sec.c",
        "win.c",
        "gzip.c",
        "checksum.c",
        "helpers.c",
        "pools.c",
        "protocol.c",
        "filter.c",
        "hostlist.c",
        "ipset.c",
        "params.c",
        "rust_ring.c",
        "timer.c",
    ] {
        fs::remove_file(nfq.join(unit))?;
    }
    let checksum = nfq.join("checksum.h");
    let source = fs::read_to_string(&checksum)?;
    fs::write(
        checksum,
        format!("{source}\n#include \"checksum_windows.h\"\n"),
    )?;
    let packet = nfq.join("darkmagic.h");
    let source = fs::read_to_string(&packet)?;
    fs::write(
        packet,
        format!(
            "{source}\n#include \"packet_read_views_abi.h\"\n#include \"windows_packet_host_abi.h\"\n"
        ),
    )?;
    let filter = nfq.join("filter.h");
    let mut source = fs::read_to_string(&filter)?;
    source.push_str("\n#include \"filters_windows.h\"\n");
    for name in [
        "pf_parse",
        "pf_match",
        "icf_parse",
        "icf_match",
        "ipp_parse",
        "ipp_match",
        "packet_range_parse",
        "parse_cidr4",
        "parse_cidr6",
        "str_cidr4",
        "str_cidr6",
    ] {
        source.push_str(&format!("#define {name} zapret_{name}\n"));
    }
    fs::write(filter, source)?;
    let gzip = nfq.join("gzip.h");
    let source = fs::read_to_string(&gzip)?.replacen(
        "#pragma once\n",
        concat!(
            "#pragma once\n",
            "#define z_readfile zapret_crt_z_readfile\n",
            "#define is_gzip zapret_crt_is_gzip\n",
        ),
        1,
    );
    fs::write(gzip, source)?;
    let engine = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&engine)?;
    replace_include(
        &mut source,
        "engine_bootstrap_windows.inc",
        "#include \"windows_engine_bootstrap_abi.h\"",
    )?;
    for (previous, replacement) in [
        (
            "engine_loop_windows.inc",
            "#include \"engine_loop_windows.h\"",
        ),
        ("engine_fuzz_windows.inc", ""),
        ("windivert_filter_windows.inc", ""),
    ] {
        replace_include(&mut source, previous, replacement)?;
    }
    for name in ["onhup", "onusr1", "onusr2", "hash_jen"] {
        ensure!(
            source.matches(name).count() == 1,
            "Unexpected native call site: {name}"
        );
    }
    ensure!(
        source.matches("bReload").count() == 4,
        "Unexpected reload writer"
    );
    for signature in [
        "static void onhup(",
        "static void ReloadCheck(",
        "static void onusr1(",
        "static void onusr2(",
        "static int write_pidfile(",
        "static unsigned int hash_jen(",
        "static uint8_t processPacketData(",
    ] {
        remove_body(&mut source, signature)?;
    }
    source = source.replace("static _Atomic(sig_atomic_t) bReload = false;\n", "");
    fs::write(engine, source)?;
    // The removed Unix diagnostic signals were the only consumers of the
    // connection dump. Preserve the pre-removal sources in the oracles.
    let conntrack_header = nfq.join("conntrack.h");
    let mut source = fs::read_to_string(&conntrack_header)?;
    let declaration = "void ConntrackPoolDump(const t_conntrack *p);\n";
    ensure!(
        source.matches(declaration).count() == 1,
        "Unused connection dump declaration changed"
    );
    source = source.replace(declaration, "");
    for predicate in ["ReasmIsEmpty", "ReasmIsFull"] {
        let signature = format!("inline static bool {predicate}(");
        let start = source
            .find(&signature)
            .context("Unused reassembly predicate")?;
        let end = start
            + source[start..]
                .find("}\n")
                .context("Reassembly predicate end")?
            + 2;
        source.replace_range(start..end, "");
    }
    fs::write(conntrack_header, source)?;

    let helpers_header = nfq.join("helpers.h");
    let source = fs::read_to_string(&helpers_header)?.replacen(
        "#pragma once\n",
        concat!(
            "#pragma once\n",
            "#define set_console_io_buffering zapret_crt_set_console_io_buffering\n",
            "#define close_std zapret_crt_close_std\n",
            "#define close_std_and_exit zapret_crt_close_std_and_exit\n",
            "#define fprint_localtime zapret_crt_fprint_localtime\n",
        ),
        1,
    );
    let declaration = "bool parse_int16(const char *p, int16_t *v);\n";
    ensure!(
        source.matches(declaration).count() == 1,
        "Unused int16 declaration changed"
    );
    fs::write(helpers_header, source.replace(declaration, ""))?;

    let pools_header = nfq.join("pools.h");
    let mut source = fs::read_to_string(&pools_header)?;
    remove_before(
        &mut source,
        "struct kavl_bit_elem\n{",
        "struct zapret_ip_pool;",
    )?;
    for declaration in [
        "void ipset4Print(struct zapret_ip_pool *ipset);\n",
        "void ipset6Print(struct zapret_ip_pool *ipset);\n",
        "void ipsetPrint(ipset *ipset);\n",
        "void HostFailPoolDump(hostfail_index *p);\n",
        "void ipcachePrint(ip_cache *ipcache);\n",
    ] {
        ensure!(
            source.matches(declaration).count() == 1,
            "Unused pool dump declaration changed: {declaration}"
        );
        source = source.replace(declaration, "");
    }
    for (name, cidr) in [("ipset4AddCidr", "cidr4"), ("ipset6AddCidr", "cidr6")] {
        let range = body_range(&source, &format!("static inline bool {name}("))?;
        source.replace_range(
            range,
            &format!("bool {name}(struct zapret_ip_pool **, const struct {cidr} *);\n"),
        );
    }
    source.push_str("\n#include \"engine_exports_abi.h\"\n");
    fs::write(pools_header, source)?;
    let params_header = nfq.join("params.h");
    let source = fs::read_to_string(&params_header)?;
    fs::write(
        params_header,
        format!("{source}\n#include \"engine_list_exports_abi.h\"\n"),
    )?;
    Ok(())
}
