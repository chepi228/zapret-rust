//! Route scalar engine parameters through one checked Rust implementation.
use anyhow::{Context, Result, ensure};

pub(super) fn reference(source: &str, directory: &std::path::Path) -> Result<()> {
    let mut cases = String::new();
    for (start, end) in [
        ("IDX_INTERCEPT", "IDX_VERSION"),
        ("IDX_DAEMON", "IDX_CHDIR"),
        ("IDX_CTRACK_TIMEOUTS", "IDX_PAYLOAD_DISABLE"),
        ("IDX_LUA_GC", "IDX_HOSTLIST"),
        (
            "IDX_HOSTLIST_AUTO_FAIL_THRESHOLD",
            "IDX_HOSTLIST_AUTO_DEBUG",
        ),
    ] {
        let start = source
            .find(&format!("\t\tcase {start}:"))
            .context("Numeric option start")?;
        let end = start
            + source[start..]
                .find(&format!("\t\tcase {end}:"))
                .context("Numeric option end")?;
        cases.push_str(&source[start..end]);
    }
    std::fs::write(directory.join("cli_numeric_reference.inc"), cases)?;
    Ok(())
}

pub(super) fn apply(source: &mut String) -> Result<()> {
    for (start, end) in [
        ("IDX_INTERCEPT", "IDX_VERSION"),
        ("IDX_DAEMON", "IDX_CHDIR"),
        ("IDX_CTRACK_TIMEOUTS", "IDX_PAYLOAD_DISABLE"),
        ("IDX_LUA_GC", "IDX_HOSTLIST"),
        (
            "IDX_HOSTLIST_AUTO_FAIL_THRESHOLD",
            "IDX_HOSTLIST_AUTO_DEBUG",
        ),
    ] {
        let first = source
            .find(&format!("\t\tcase {start}:"))
            .context("Numeric option start")?;
        let last = first
            + source[first..]
                .find(&format!("\t\tcase {end}:"))
                .context("Numeric option end")?;
        source.replace_range(first..last, "");
    }
    for id in ["SSID", "NLM"] {
        let old = format!(
            "\t\t\thash_wf[GLOBAL_{id}_FILTER_NEG] = params.{}_filter_neg = !optarg || atoi(optarg);",
            id.to_ascii_lowercase()
        );
        ensure!(
            source.matches(&old).count() == 1,
            "Pinned network negation changed"
        );
        let field = format!("{}_filter_neg", id.to_ascii_lowercase());
        let new = format!(
            "\t\t\tif (engine_numeric_option(option_index, optarg, dp) < 0) {{ DLOG_ERR(\"invalid numeric value for --%s\\n\", long_options[option_index].name); exit_clean(1); }}\n\t\t\thash_wf[GLOBAL_{id}_FILTER_NEG] = params.{field};"
        );
        *source = source.replacen(&old, &new, 1);
    }
    let include = "#include \"cli_windows.inc\"";
    ensure!(
        source.matches(include).count() == 1,
        "Pinned CLI adapter include changed"
    );
    *source = source.replace(
        include,
        &format!("{include}\n#include \"cli_numeric_windows.inc\""),
    );
    let anchor = "\t\tswitch (option_index)";
    ensure!(
        source.matches(anchor).count() == 1,
        "Pinned CLI dispatch changed"
    );
    *source = source.replace(anchor, concat!(
        "\t\tif (option_index != IDX_SSID_FILTER_NEG && option_index != IDX_NLM_FILTER_NEG)\n",
        "\t\t{\n\t\t\tint parsed = engine_numeric_option(option_index, optarg, dp);\n",
        "\t\t\tif (parsed < 0) { DLOG_ERR(\"invalid numeric value for --%s\\n\", long_options[option_index].name); exit_clean(1); }\n",
        "\t\t\tif (parsed > 0) continue;\n\t\t}\n",
        "\t\tswitch (option_index)",
    ));
    Ok(())
}
