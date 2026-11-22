//! Keep option-specific side effects in C and profile transitions in Rust.
use anyhow::{Context, Result, ensure};

pub(super) fn apply(source: &mut String) -> Result<()> {
    let main = source
        .find("\nint main(int argc, char **argv)\n")
        .context("Pinned profile argument entry")?;
    let mut options = source[main..].to_owned();
    replace_once(
        &mut options,
        "bool bSkip = false, bDry = false, bDupCheck = true, bTemplate;",
        "bool bDry = false, bDupCheck = true;",
    )?;
    replace_range(
        &mut options,
        "\tstruct desync_profile_list *dpl;\n",
        "\n#if !defined( __OpenBSD__) && !defined(__ANDROID__)",
        concat!(
            "\tnative_profile_flow profile_flow = {.profiles = &params.desync_profiles, .templates = &params.desync_templates};\n",
            "\tnative_profile_exit(native_profile_next(&profile_flow, NULL), NULL);\n",
            "\tstruct desync_profile_list *dpl = profile_flow.current;\n",
            "\tstruct desync_profile *dp = &dpl->dp;\n",
        ),
    )?;
    replace_range(
        &mut options,
        "\t\tcase IDX_NEW:\n",
        "\t\tcase IDX_FILTER_L3:\n",
        concat!(
            "\t\tcase IDX_NEW:\n",
            "\t\t{\n",
            "\t\t\tuint32_t status = native_profile_next(&profile_flow, optarg);\n",
            "\t\t\tif (status) native_profile_exit(status, dp->name);\n",
            "\t\t\tdpl = profile_flow.current;\n",
            "\t\t\tdp = &dpl->dp;\n",
            "\t\t\tanon_hl = anon_hl_exclude = NULL;\n",
            "\t\t\tanon_ips = anon_ips_exclude = NULL;\n",
            "\t\t\tpayload_type = 0;\n",
            "\t\t\trange_in = PACKET_RANGE_NEVER;\n",
            "\t\t\trange_out = PACKET_RANGE_ALWAYS;\n",
            "\t\t\tbreak;\n",
            "\t\t}\n",
            "\t\tcase IDX_SKIP:\n\t\t\tprofile_flow.skip = true;\n\t\t\tbreak;\n",
            "\t\tcase IDX_TEMPLATE:\n\t\t\tprofile_flow.template = true;\n",
            "\t\t\t/* fall through */\n",
            "\t\tcase IDX_NAME:\n\t\t\tnative_profile_exit(native_profile_label(dp, false, optarg), optarg);\n\t\t\tbreak;\n",
            "\t\tcase IDX_COOKIE:\n\t\t\tnative_profile_exit(native_profile_label(dp, true, optarg), optarg);\n\t\t\tbreak;\n",
            "\t\tcase IDX_IMPORT:\n\t\t\tnative_profile_exit(native_profile_import(&profile_flow, optarg), optarg);\n\t\t\tbreak;\n\n",
        ),
    )?;
    replace_range(
        &mut options,
        "\n\tif (bSkip)\n\t{\n\t\tLIST_REMOVE(dpl, next);",
        "\n\t// do not need args from file anymore",
        concat!(
            "\n\t{\n",
            "\t\tuint32_t status = native_profile_finish(&profile_flow);\n",
            "\t\tif (status) native_profile_exit(status, dp->name);\n",
            "\t}\n",
        ),
    )?;
    options = options
        .replace("if (bSkip)", "if (profile_flow.skip)")
        .replace("desync_profile_count", "profile_flow.count")
        .replace("desync_template_count", "profile_flow.template_count");
    ensure!(
        !options.contains("bSkip") && !options.contains("bTemplate"),
        "Unconverted profile state"
    );
    source.replace_range(
        main..,
        &format!("\n#include \"profile_flow_windows.inc\"\n{options}"),
    );
    Ok(())
}

fn replace_once(source: &mut String, old: &str, new: &str) -> Result<()> {
    ensure!(
        source.matches(old).count() == 1,
        "Pinned profile option changed: {old}"
    );
    *source = source.replacen(old, new, 1);
    Ok(())
}

fn replace_range(source: &mut String, first: &str, last: &str, new: &str) -> Result<()> {
    let start = source
        .find(first)
        .with_context(|| format!("Missing profile option start: {first}"))?;
    let end = start
        + source[start..]
            .find(last)
            .with_context(|| format!("Missing profile option end: {last}"))?;
    source.replace_range(start..end, new);
    Ok(())
}
