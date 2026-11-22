use crate::ring_build::patch;
use anyhow::Result;
use std::path::Path;

const REFERENCE_SELFTEST: &str = "\t/* Explicit developer mode: no WinDivert open, no interception. */\n\tconst char *ring_selftest=getenv(\"ZAPRET_RING_SELFTEST\");\n\tif (!params.intercept && ring_selftest && !strcmp(ring_selftest,\"1\"))\n\t{\n\t\tif (!win_sandbox()) return ERROR_ACCESS_DENIED;\n\t\tif (!lua_init()) return ERROR_INVALID_PARAMETER;\n\t\tNoInterceptLoop();\n\t\treturn 0;\n\t}\n\n";

pub(super) fn apply(root: &Path) -> Result<()> {
    patch(
        &root.join("darkmagic.h"),
        "#define TCP_KIND_END",
        r#"#ifdef ZAPRET_NATIVE_WINDOWS
_Static_assert(sizeof(struct ip)==20,"IPv4 wire header layout");
_Static_assert(sizeof(struct ip6_hdr)==40,"IPv6 wire header layout");
_Static_assert(sizeof(struct tcphdr)==20,"TCP wire header layout");
_Static_assert(sizeof(struct udphdr)==8,"UDP wire header layout");
_Static_assert(sizeof(WINDIVERT_ADDRESS)==80,"WinDivert address ABI");
_Static_assert(offsetof(struct ip,ip_tos)==1,"IPv4 TOS offset");
_Static_assert(offsetof(struct ip,ip_src)==12,"IPv4 source offset");
_Static_assert(offsetof(struct tcphdr,th_seq)==4,"TCP sequence offset");
_Static_assert(offsetof(struct tcphdr,th_flags)==13,"TCP flags offset");
_Static_assert(offsetof(struct tcphdr,th_win)==14,"TCP window offset");
#endif

#define TCP_KIND_END"#,
    )?;
    let service = root.join("win.c");
    patch(
        &service,
        "SERVICE_TABLE_ENTRY ServiceTable[]",
        "SERVICE_TABLE_ENTRYA ServiceTable[]",
    )?;
    patch(
        &service,
        "(LPSERVICE_MAIN_FUNCTION)service_main",
        "(LPSERVICE_MAIN_FUNCTIONA)service_main",
    )?;
    for file in ["nfqws.c", "sec.c"] {
        for header in ["pwd.h", "grp.h"] {
            let path = root.join(file);
            let anchor = format!("#include <{header}>");
            if std::fs::read_to_string(&path)?.contains(&anchor) {
                patch(
                    &path,
                    &anchor,
                    &format!("#ifndef ZAPRET_NATIVE_WINDOWS\n{anchor}\n#endif"),
                )?;
            }
        }
    }
    let main = root.join("nfqws.c");
    // The upstream builder tests the first byte before generating a filter.
    // A fresh heap allocation is not guaranteed to contain an empty string.
    patch(
        &main,
        "params.windivert_filter = malloc(WINDIVERT_MAX);",
        "params.windivert_filter = calloc(1,WINDIVERT_MAX);",
    )?;
    patch(
        &main,
        "static bool parse_uid(",
        "#ifndef ZAPRET_NATIVE_WINDOWS\nstatic bool parse_uid(",
    )?;
    patch(
        &main,
        "static bool parse_l7_list(",
        "#endif\nstatic bool parse_l7_list(",
    )?;
    patch(
        &main,
        "static void catch_signals(void)\n{",
        r#"#ifdef ZAPRET_NATIVE_WINDOWS
static BOOL WINAPI native_console_handler(DWORD event)
{
    switch(event) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            onint(SIGINT);
            return TRUE;
        default:
            return FALSE;
    }
}
#endif
static void catch_signals(void)
{
#ifdef ZAPRET_NATIVE_WINDOWS
    signal(SIGINT,onint);
    signal(SIGTERM,onterm);
    SetConsoleCtrlHandler(native_console_handler,TRUE);
#else"#,
    )?;
    patch(
        &main,
        "sigaction(SIGTERM, &sa, NULL);\n}",
        "sigaction(SIGTERM, &sa, NULL);\n#endif\n}",
    )?;
    let anchor = "\tif (!win_dark_init(";
    patch(&main, anchor, &format!("{REFERENCE_SELFTEST}{anchor}"))?;
    let lua = root.join("lua.c");
    let text = std::fs::read(&lua)?;
    let mut source = b"#include \"rust_ring.h\"\n".to_vec();
    source.extend_from_slice(&text);
    std::fs::write(&lua, source)?;
    patch(
        &lua,
        "luaL_openlibs(params.L);",
        "luaL_openlibs(params.L);\n\tif (!rust_ring_register(params.L)) { lua_close(params.L); params.L=NULL; return false; }",
    )?;
    Ok(())
}
