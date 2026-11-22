//! Use stable Rust list files and ordered profile references in the native engine.
use crate::ring_build::patch;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

pub(super) fn apply(nfq: &Path) -> Result<()> {
    let header = nfq.join("pools.h");
    replace_section(
        &header,
        "struct hostlist_file {",
        "struct kavl_bit_elem",
        "",
    )?;
    replace_section(
        &header,
        "struct ipset_file {",
        "struct port_filter_item {",
        "#include \"list_registry_windows.h\"\n\n",
    )?;
    let pools = nfq.join("pools.c");
    replace_section(
        &pools,
        "struct hostlist_file *hostlist_files_add(",
        "static int kavl_bit_cmp(",
        "#include \"params.h\"\n#include \"list_registry_windows.c\"\n\n",
    )?;
    replace_section(
        &pools,
        "struct ipset_file *ipset_files_add(",
        "static struct port_filter_item *port_filter_entry_alloc(",
        "",
    )?;
    let host = nfq.join("hostlist.c");
    replace_section(
        &host,
        "// bChanged is set to true",
        "static bool LoadHostLists(",
        "#define ZAPRET_RELOAD_HOSTS 1\n#include \"list_reload_windows.inc\"\n\n",
    )?;
    replace_section(
        &host,
        "static struct hostlist_file *RegisterHostlist_(",
        "struct hostlist_file *RegisterHostlist(",
        "",
    )?;
    let ip = nfq.join("ipset.c");
    replace_section(
        &ip,
        "static bool LoadIpset(struct ipset_file *hfile)",
        "static bool LoadIpsets(",
        "#define ZAPRET_RELOAD_HOSTS 0\n#include \"list_reload_windows.inc\"\n\n",
    )?;
    replace_section(
        &ip,
        "static struct ipset_file *RegisterIpset_(",
        "struct ipset_file *RegisterIpset(",
        "",
    )?;
    for (path, replacements) in [
        (
            &host,
            &[
                ("struct hostlist_file ", "struct zapret_list_file "),
                ("struct hostlist_files_head ", "struct zapret_list_files "),
                (
                    "struct hostlist_collection_head ",
                    "struct zapret_list_collection ",
                ),
                ("struct hostlist_item ", "struct zapret_list_file "),
                ("item->hfile", "item"),
                (
                    "LIST_FOREACH(hfile, list, next)",
                    "ZAPRET_FOR_LIST_FILE(hfile, list)",
                ),
                (
                    "LIST_FOREACH(hfile, &params.hostlists, next)",
                    "ZAPRET_FOR_LIST_FILE(hfile, params.hostlists)",
                ),
                (
                    "LIST_FOREACH(item, hostlists, next)",
                    "ZAPRET_FOR_LIST_REFERENCE(item, hostlists)",
                ),
                (
                    "LIST_FOREACH(item, hostlists_exclude, next)",
                    "ZAPRET_FOR_LIST_REFERENCE(item, hostlists_exclude)",
                ),
                (
                    "LIST_FOREACH(hl_item, &dp->hl_collection, next)",
                    "ZAPRET_FOR_LIST_REFERENCE(hl_item, dp->hl_collection)",
                ),
                (
                    "LIST_FOREACH(hl_item, &dp->hl_collection_exclude, next)",
                    "ZAPRET_FOR_LIST_REFERENCE(hl_item, dp->hl_collection_exclude)",
                ),
                (
                    "LoadHostLists(&params.hostlists",
                    "LoadHostLists(params.hostlists",
                ),
                ("HostlistsReloadCheck(&dp->", "HostlistsReloadCheck(dp->"),
                (
                    "HostlistCheck_(&dp->hl_collection, &dp->hl_collection_exclude,",
                    "HostlistCheck_(dp->hl_collection, dp->hl_collection_exclude,",
                ),
                (
                    "hostlist_collection_is_empty(",
                    "zapret_list_collection_empty(",
                ),
                (
                    "return RegisterHostlist_(\n",
                    "return zapret_list_register_path(\n",
                ),
            ][..],
        ),
        (
            &ip,
            &[
                ("struct ipset_file ", "struct zapret_list_file "),
                ("struct ipset_files_head ", "struct zapret_list_files "),
                (
                    "struct ipset_collection_head ",
                    "struct zapret_list_collection ",
                ),
                ("struct ipset_item ", "struct zapret_list_file "),
                ("item->hfile", "item"),
                (
                    "LIST_FOREACH(hfile, list, next)",
                    "ZAPRET_FOR_LIST_FILE(hfile, list)",
                ),
                (
                    "LIST_FOREACH(hfile, &params.ipsets, next)",
                    "ZAPRET_FOR_LIST_FILE(hfile, params.ipsets)",
                ),
                (
                    "LIST_FOREACH(item, ipsets, next)",
                    "ZAPRET_FOR_LIST_REFERENCE(item, ipsets)",
                ),
                (
                    "LIST_FOREACH(item, ips_exclude, next)",
                    "ZAPRET_FOR_LIST_REFERENCE(item, ips_exclude)",
                ),
                (
                    "LIST_FOREACH(item, ips, next)",
                    "ZAPRET_FOR_LIST_REFERENCE(item, ips)",
                ),
                (
                    "LIST_FOREACH(ips_item, &dp->ips_collection, next)",
                    "ZAPRET_FOR_LIST_REFERENCE(ips_item, dp->ips_collection)",
                ),
                (
                    "LIST_FOREACH(ips_item, &dp->ips_collection_exclude, next)",
                    "ZAPRET_FOR_LIST_REFERENCE(ips_item, dp->ips_collection_exclude)",
                ),
                ("LoadIpsets(&params.ipsets", "LoadIpsets(params.ipsets"),
                ("IpsetsReloadCheck(&dp->", "IpsetsReloadCheck(dp->"),
                (
                    "IpsetCheck_(&dp->ips_collection,&dp->ips_collection_exclude,",
                    "IpsetCheck_(dp->ips_collection,dp->ips_collection_exclude,",
                ),
                (
                    "ipset_collection_is_empty(",
                    "zapret_list_collection_empty(",
                ),
                (
                    "return RegisterIpset_(\n",
                    "return zapret_list_register_path(\n",
                ),
            ][..],
        ),
    ] {
        replace_all(path, replacements)?;
    }

    let params = nfq.join("params.h");
    replace_all(
        &params,
        &[
            ("struct hostlist_file ", "struct zapret_list_file "),
            (
                "struct hostlist_files_head hostlists;",
                "struct zapret_list_files *hostlists;",
            ),
            (
                "struct ipset_files_head ipsets;",
                "struct zapret_list_files *ipsets;",
            ),
            (
                "struct hostlist_collection_head hl_collection, hl_collection_exclude;",
                "struct zapret_list_collection *hl_collection, *hl_collection_exclude;",
            ),
            (
                "struct ipset_collection_head ips_collection, ips_collection_exclude;",
                "struct zapret_list_collection *ips_collection, *ips_collection_exclude;",
            ),
            (
                "LIST_FIRST(&(dp)->ips_collection)",
                "zapret_list_collection_at((dp)->ips_collection, 0)",
            ),
            (
                "LIST_FIRST(&(dp)->ips_collection_exclude)",
                "zapret_list_collection_at((dp)->ips_collection_exclude, 0)",
            ),
            (
                "ipset_collection_is_empty(&(dp)->",
                "zapret_list_collection_empty((dp)->",
            ),
            (
                "hostlist_collection_is_empty(&(dp)->",
                "zapret_list_collection_empty((dp)->",
            ),
        ],
    )?;
    let params = nfq.join("params.c");
    for name in [
        "hl_collection",
        "hl_collection_exclude",
        "ips_collection",
        "ips_collection_exclude",
    ] {
        patch(
            &params,
            &format!("LIST_INIT(&dp->{name});"),
            &format!("dp->{name} = NULL;"),
        )?;
        let prefix = if name.starts_with("hl_") {
            "hostlist"
        } else {
            "ipset"
        };
        patch(
            &params,
            &format!("{prefix}_collection_copy(&to->{name}, &from->{name})"),
            &format!("zapret_list_collection_copy(&to->{name}, from->{name})"),
        )?;
    }
    for name in ["hostlists", "ipsets"] {
        patch(
            &params,
            &format!("LIST_INIT(&params->{name});"),
            &format!("params->{name} = NULL;"),
        )?;
    }
    replace_all(
        &params,
        &[
            (
                "hostlist_collection_destroy",
                "zapret_list_collection_destroy",
            ),
            ("ipset_collection_destroy", "zapret_list_collection_destroy"),
            ("hostlist_files_destroy", "zapret_list_files_destroy"),
            ("ipset_files_destroy", "zapret_list_files_destroy"),
        ],
    )?;
    replace_all(
        &nfq.join("nfqws.c"),
        &[
            ("struct hostlist_file ", "struct zapret_list_file "),
            ("struct ipset_file ", "struct zapret_list_file "),
            (
                "LIST_FOREACH(hfile, &params.hostlists, next)",
                "ZAPRET_FOR_LIST_FILE(hfile, params.hostlists)",
            ),
            (
                "LIST_FOREACH(ifile, &params.ipsets, next)",
                "ZAPRET_FOR_LIST_FILE(ifile, params.ipsets)",
            ),
        ],
    )?;
    replace_all(
        &nfq.join("hostlist.h"),
        &[
            ("struct hostlist_file ", "struct zapret_list_file "),
            (
                "hostlist_files_reset_modtime(&params.hostlists)",
                "zapret_list_files_reset(params.hostlists)",
            ),
        ],
    )?;
    replace_all(
        &nfq.join("ipset.h"),
        &[
            ("struct ipset_file ", "struct zapret_list_file "),
            (
                "ipset_files_reset_modtime(&params.ipsets)",
                "zapret_list_files_reset(params.ipsets)",
            ),
        ],
    )?;
    Ok(())
}

fn replace_all(path: &Path, replacements: &[(&str, &str)]) -> Result<()> {
    let mut source = fs::read_to_string(path)?;
    for (from, to) in replacements {
        ensure!(
            source.contains(from),
            "Missing list registry anchor {from:?} in {}",
            path.display()
        );
        source = source.replace(from, to);
    }
    fs::write(path, source)?;
    Ok(())
}

fn replace_section(path: &Path, first: &str, last: &str, replacement: &str) -> Result<()> {
    let source = fs::read_to_string(path)?;
    let start = source
        .find(first)
        .with_context(|| format!("Missing list source anchor {first}"))?;
    let end = source[start..]
        .find(last)
        .with_context(|| format!("Missing list source anchor {last}"))?
        + start;
    ensure!(start < end, "Pinned list source boundaries changed");
    fs::write(
        path,
        format!("{}{replacement}{}", &source[..start], &source[end..]),
    )?;
    Ok(())
}
