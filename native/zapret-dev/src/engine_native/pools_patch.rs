//! Native bindings to Rust-owned domain and IP prefix stores.
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

pub(super) fn apply(nfq: &Path) -> Result<()> {
    let header = nfq.join("pools.h");
    let text = fs::read_to_string(&header)?;
    let first = text
        .find("typedef struct hostlist_pool {")
        .context("Missing pinned host pool")?;
    let last = text
        .find("struct str_list {")
        .context("Missing pinned string list")?;
    ensure!(first < last, "Pinned host pool boundaries changed");
    fs::write(
        &header,
        format!(
            "{}typedef struct hostlist_pool hostlist_pool;\n\
             void HostlistPoolDestroy(hostlist_pool **);\n\
             bool HostlistPoolAddStr(hostlist_pool **, const char *, uint32_t);\n\
             bool HostlistPoolAddStrLen(hostlist_pool **, const char *, size_t, uint32_t);\n\
             bool HostlistPoolCheckStr(hostlist_pool *, const char *);\n\n{}",
            &text[..first],
            &text[last..]
        ),
    )?;

    let text = fs::read_to_string(&header)?;
    let start = text
        .find("// combined ipset ipv4 and ipv6")
        .context("Missing pinned IP pool")?;
    let end = text
        .find("struct ipset_file {")
        .context("Missing pinned IP list file")?;
    ensure!(start < end, "Pinned IP pool boundaries changed");
    let declarations = text[start..end].replace("struct kavl_bit_elem", "struct zapret_ip_pool");
    fs::write(
        &header,
        format!(
            "{}struct zapret_ip_pool;\n{declarations}{}",
            &text[..start],
            &text[end..]
        ),
    )?;

    replace(
        &nfq.join("pools.c"),
        "// for not zero terminated strings",
        "void HostFailPoolDestroy(",
        "#include \"host_pool_windows.c\"\n\n",
    )?;
    replace(
        &nfq.join("pools.c"),
        "static bool ipset_kavl_add(",
        "struct ipset_file *ipset_files_add(",
        "#include \"ip_pool_windows.c\"\n\n",
    )?;
    replace(
        &nfq.join("hostlist.c"),
        "static bool SearchHostList(",
        "static bool HostlistsReloadCheck(",
        "#include \"host_search_windows.c\"\n\n",
    )?;
    Ok(())
}

fn replace(path: &Path, first: &str, last: &str, code: &str) -> Result<()> {
    let text = fs::read_to_string(path)?;
    let start = text
        .find(first)
        .with_context(|| format!("Missing {first}"))?;
    let end = text.find(last).with_context(|| format!("Missing {last}"))?;
    ensure!(start < end, "Pinned pool function boundaries changed");
    fs::write(path, format!("{}{code}{}", &text[..start], &text[end..]))?;
    Ok(())
}
