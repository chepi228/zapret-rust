//! Keep the pinned Lua API and replace its wire-format operations.
use crate::ring_build::patch;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

pub(super) fn apply(nfq: &Path) -> Result<()> {
    let lua = nfq.join("lua.c");
    let mut source = fs::read_to_string(&lua)?;
    for (first, last, replacement) in [
        (
            "static bool lua_reconstruct_ip6exthdr(",
            "static int luacall_reconstruct_ip6hdr(",
            "#include \"packet_lua_windows.c\"\n\n",
        ),
        (
            "bool lua_reconstruct_iphdr(",
            "static int luacall_reconstruct_iphdr(",
            "",
        ),
        (
            "static bool lua_reconstruct_tcphdr_options(",
            "static int luacall_reconstruct_tcphdr(",
            "",
        ),
        (
            "bool lua_reconstruct_udphdr(",
            "static int luacall_reconstruct_udphdr(",
            "",
        ),
        (
            "bool lua_reconstruct_icmphdr(",
            "static int luacall_reconstruct_icmphdr(",
            "",
        ),
    ] {
        replace_section(&mut source, first, last, replacement)?;
    }
    replace_section(
        &mut source,
        "\t\tif (!keepsum)\n",
        "\n\t}\n\n\t*len = l;\n",
        "\t\tuint8_t transport = tcp ? IPPROTO_TCP : udp ? IPPROTO_UDP : icmp ? IPPROTO_ICMP : 0;\n\
         \t\tif (!finish_packet(buf, &l, l3, ip ? 4 : 6, transport, keepsum, badsum)) goto err;",
    )?;
    fs::write(&lua, source)?;
    patch(
        &lua,
        "size_t sz,l,lpayload,l3,left = *len;",
        "size_t l,lpayload,l3,left = *len;",
    )?;
    patch(
        &lua,
        "\t\tip4_fix_checksum(ip);\n\t}\n\telse\n\t{\n\t\tlua_pop(L, 1);\n\t\tlua_getfield(L,idx,\"ip6\");",
        "\t}\n\telse\n\t{\n\t\tlua_pop(L, 1);\n\t\tlua_getfield(L,idx,\"ip6\");",
    )?;
    Ok(())
}

fn replace_section(text: &mut String, first: &str, last: &str, replacement: &str) -> Result<()> {
    let start = text
        .find(first)
        .with_context(|| format!("Missing packet writer anchor {first:?}"))?;
    let length = text[start..]
        .find(last)
        .with_context(|| format!("Missing packet writer boundary {last:?}"))?;
    ensure!(length > 0, "Pinned packet writer boundaries changed");
    text.replace_range(start..start + length, replacement);
    Ok(())
}
