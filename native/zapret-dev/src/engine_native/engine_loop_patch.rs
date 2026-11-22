use crate::ring_build::patch;
use anyhow::{Context, Result};
use std::{fs, path::Path};

pub(super) fn apply(nfq: &Path) -> Result<()> {
    let main = nfq.join("nfqws.c");
    let mut source = fs::read_to_string(&main)?;
    replace_section(
        &mut source,
        "void NoInterceptLoop(void)\n{",
        "#ifdef __linux__\n\nstruct nfq_cb_data",
        "#include \"engine_loop_windows.inc\"\n\n",
    )?;
    replace_section(
        &mut source,
        "#define WINDIVERT_BULK_MAX",
        "\t// windows emulated fork logic",
        "static int win_main(void)\n{\n\tint res = 0;\n",
    )?;
    replace_section(
        &mut source,
        "\tif (!(packets = malloc(WINDIVERT_PACKET_BUF_SIZE))",
        "\twin_dark_deinit();",
        "\tWINDIVERT_ADDRESS addresses[ZAPRET_CAPTURE_ADDRESS_COUNT];\n\
         \tres = zapret_capture_loop(&capture_ops, addresses, params.intercept);\n\
         ex:\n",
    )?;
    fs::write(main, source)?;

    let dark = nfq.join("darkmagic.c");
    let mut source = fs::read_to_string(&dark)?;
    replace_section(
        &mut source,
        "static bool windivert_recv_exit(void)",
        "static bool windivert_send_filter(",
        "#include \"windivert_receive_windows.inc\"\n\n",
    )?;
    fs::write(&dark, source)?;
    patch(
        &dark,
        "static OVERLAPPED ovl = { .hEvent = NULL };",
        "static HANDLE w_receive_event = NULL;",
    )?;
    patch(
        &dark,
        "ovl.hEvent = CreateEventW(NULL,FALSE,FALSE,NULL);",
        "ovl.hEvent = CreateEventW(NULL,TRUE,FALSE,NULL);",
    )?;
    let source = fs::read_to_string(&dark)?;
    fs::write(dark, source.replace("ovl.hEvent", "w_receive_event"))?;
    patch(
        &nfq.join("darkmagic.h"),
        "bool windivert_recv(uint8_t *packet, size_t *len, WINDIVERT_ADDRESS *wa, unsigned int *wa_count, uint64_t *bt_next);\n",
        "",
    )
}

fn replace_section(source: &mut String, first: &str, next: &str, new: &str) -> Result<()> {
    let start = source
        .find(first)
        .with_context(|| format!("Missing engine loop anchor {first:?}"))?;
    let length = source[start..]
        .find(next)
        .with_context(|| format!("Missing engine loop boundary {next:?}"))?;
    source.replace_range(start..start + length, new);
    Ok(())
}
