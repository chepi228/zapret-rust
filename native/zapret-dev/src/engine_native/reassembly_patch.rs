//! Bind the client reassembly calls in the pinned packet handlers to Rust.
use anyhow::{Context, Result, ensure};
use std::{fs, ops::Range, path::Path};

pub(super) fn lifecycle(source: &str) -> Result<Range<usize>> {
    let start = source
        .find("static bool send_delayed(")
        .context("Pinned delayed send helper")?;
    let end = source
        .find("static uint8_t ct_new_postnat_fix(")
        .context("Pinned reassembly lifecycle end")?;
    ensure!(
        start < end,
        "Pinned reassembly lifecycle boundaries changed"
    );
    Ok(start..end)
}

fn replace_block(source: &mut String, first: &str, next: &str, replacement: &str) -> Result<()> {
    let start = source
        .find(first)
        .with_context(|| format!("Missing reassembly anchor {first:?}"))?;
    let end = source[start..]
        .find(next)
        .with_context(|| format!("Missing reassembly boundary {next:?}"))?;
    ensure!(end != 0, "Empty pinned reassembly block");
    source.replace_range(start..start + end, replacement);
    Ok(())
}

pub(super) fn apply(path: &Path) -> Result<()> {
    let mut source = fs::read_to_string(path)?;
    let range = lifecycle(&source)?;
    source.replace_range(range, "#include \"reassembly_windows.inc\"\n\n");
    replace_block(
        &mut source,
        "\n\t\t\t\t\tif (rawpacket_queue(&ps.ctrack->delayed,",
        "\n\t\t\t\t\treturn VERDICT_DROP;",
        "\n\t\t\t\t\tif (!reasm_client_defer(ps.ctrack, &ps.dst, fwmark, desync_fwmark, ifin, ifout, dis,\n\
         \t\t\t\t\t\tReasmIsFull(&ps.ctrack->reasm_client)))\n\
         \t\t\t\t\t{\n\
         \t\t\t\t\t\trdata_payload = dis->data_payload;\n\
         \t\t\t\t\t\trlen_payload = dis->len_payload;\n\
         \t\t\t\t\t\tps.l7payload = L7P_UNKNOWN;\n\
         \t\t\t\t\t\tgoto rediscover;\n\
         \t\t\t\t\t}",
    )?;
    replace_block(
        &mut source,
        "\n\t\t\treasm_client_cancel(ps.ctrack);\n\t\t\tif (ps.l7payload==L7P_HTTP_REQ)",
        "\n\t\t\tif (ps.l7payload==L7P_HTTP_REQ)",
        "\n\t\t\tif (ps.ctrack)\n\
         \t\t\t{\n\
         \t\t\t\treasm_client_cancel(ps.ctrack);\n\
         \t\t\t\trdata_payload = dis->data_payload;\n\
         \t\t\t\trlen_payload = dis->len_payload;\n\
         \t\t\t}",
    )?;
    replace_block(
        &mut source,
        "\n\t\t\t\t\t\tif (ReasmHasSpace(&ps.ctrack->reasm_client, clean_len))",
        "\n\t\t\t\t\t}\n\t\t\t\t\tsize_t hello_offset",
        "\n\t\t\t\t\t\tif (!reasm_client_feed(ps.ctrack, IPPROTO_UDP, clean, clean_len))\n\
         \t\t\t\t\t\t\tgoto rediscover_cancel;\n\
         \t\t\t\t\t\tpclean = ps.ctrack->reasm_client.packet;\n\
         \t\t\t\t\t\tclean_len = ps.ctrack->reasm_client.size_present;",
    )?;
    for (indent, complete) in [(9, "bReqFull"), (8, "false")] {
        let tabs = "\t".repeat(indent);
        replace_block(
            &mut source,
            &format!("\n{tabs}if (rawpacket_queue(&ps.ctrack->delayed,"),
            &format!("\n{tabs}return ct_new_postnat_fix("),
            &format!(
                "\n{tabs}if (!reasm_client_defer(ps.ctrack, &ps.dst, fwmark, desync_fwmark, ifin, ifout, dis, {complete}))\n{tabs}\tgoto rediscover_cancel;"
            ),
        )?;
    }
    ensure!(
        !source.contains("reasm_client_fin(")
            && !source.contains("rawpacket_queue(&ps.ctrack->delayed,"),
        "A pinned deferred-packet call still needs the Rust lifecycle"
    );
    fs::write(path, source)?;
    Ok(())
}
