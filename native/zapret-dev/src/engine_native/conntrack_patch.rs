//! Native connection tracking uses Rust indexing, transitions and expiry rules.
use crate::ring_build;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

pub(super) fn apply(nfq: &Path) -> Result<()> {
    let header = nfq.join("conntrack.h");
    ring_build::patch(
        &header,
        "\tUT_hash_handle hh;\t// makes this structure hashable\n",
        "",
    )?;
    ring_build::patch(
        &header,
        "\tt_conntrack_pool *pool;",
        "\tstruct zapret_conntrack_index *pool;",
    )?;
    let text = fs::read_to_string(&header)?;
    fs::write(
        &header,
        format!("{text}\n#include \"conntrack_windows.h\"\n"),
    )?;

    let source = nfq.join("conntrack.c");
    let text = fs::read_to_string(&source)?;
    let start = text
        .find("static void taddr2str(")
        .context("Missing pinned conntrack formatter")?;
    let end = text
        .find("void ReasmClear(")
        .context("Missing pinned reassembly start")?;
    ensure!(start < end, "Pinned conntrack dump boundaries changed");
    let dump = text[start..end]
        .replace("t_conntrack_pool *t, *tmp;", "t_conntrack_pool *t;")
        .replace(
            "HASH_ITER(hh, p->pool, t, tmp) {",
            "uint64_t cursor = 0;\n\twhile ((t = zapret_conntrack_after(p->pool, &cursor))) {",
        );
    ensure!(
        !dump.contains("HASH_ITER"),
        "Pinned conntrack iterator changed"
    );
    fs::write(
        &source,
        format!(
            "#include \"conntrack.h\"\n#include \"params.h\"\n#include \"helpers.h\"\n\
             #include \"lua.h\"\n#include <arpa/inet.h>\n#include \"conntrack_windows.c\"\n\n{dump}"
        ),
    )?;
    Ok(())
}
