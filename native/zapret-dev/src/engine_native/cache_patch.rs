//! Replace auxiliary hash tables while preserving their C-facing payloads.
use crate::ring_build;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

pub(super) fn apply(nfq: &Path) -> Result<()> {
    let header = nfq.join("pools.h");
    let text = fs::read_to_string(&header)?;
    let first = text
        .find("typedef struct hostfail_pool {")
        .context("Pinned host failure record")?;
    let last = text
        .find("struct hostlist_file {")
        .context("Pinned host failure boundary")?;
    ensure!(first < last, "Pinned host failure layout changed");
    let failure = text[first..last]
        .replace(
            "\tUT_hash_handle hh;\t/* makes this structure hashable */\n",
            "",
        )
        .replace("hostfail_pool **", "hostfail_index **")
        .replace(
            "HostFailPoolFind(hostfail_pool *",
            "HostFailPoolFind(hostfail_index *",
        )
        .replace(
            "HostFailPoolDump(hostfail_pool *",
            "HostFailPoolDump(hostfail_index *",
        );
    ensure!(
        !failure.contains("UT_hash_handle"),
        "Host failure hash handle changed"
    );
    fs::write(
        &header,
        format!(
            "{}typedef struct zapret_hostfail_index hostfail_index;\n{failure}{}",
            &text[..first],
            &text[last..]
        ),
    )?;

    let text = fs::read_to_string(&header)?;
    let first = text
        .find("typedef struct ip_cache4\n")
        .context("Pinned IP cache records")?;
    let last = text
        .find("typedef struct ip_cache\n")
        .context("Pinned IP cache root")?;
    ensure!(first < last, "Pinned IP cache layout changed");
    fs::write(
        &header,
        format!(
            "{}typedef struct zapret_ipcache_index ip_cache4, ip_cache6;\n{}\n#include \"cache_windows.h\"\n",
            &text[..first],
            &text[last..]
        ),
    )?;
    ring_build::patch(
        &nfq.join("params.h"),
        "hostfail_pool *hostlist_auto_fail_counters;",
        "hostfail_index *hostlist_auto_fail_counters;",
    )?;
    ring_build::patch(
        &nfq.join("desync.c"),
        "\tfail_counter->counter++;",
        "\tzapret_hostfail_increment(fail_counter);",
    )?;

    let source = nfq.join("pools.c");
    let text = fs::read_to_string(&source)?;
    let first = text
        .find("void HostFailPoolDestroy(")
        .context("Pinned host failure functions")?;
    let last = text
        .find("static struct str_list *strlist_entry_alloc(")
        .context("Pinned string list functions")?;
    let cache = text
        .find("static void ipcache_item_touch(")
        .context("Pinned IP cache functions")?;
    ensure!(
        first < last && last < cache,
        "Pinned cache function boundaries changed"
    );
    fs::write(
        &source,
        format!(
            "{}#include \"cache_windows.c\"\n\n{}",
            &text[..first],
            &text[last..cache]
        ),
    )?;
    Ok(())
}
