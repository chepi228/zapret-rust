//! Compare the protocol API with the original pinned source before replacing it.
use super::tools::Tools;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

pub(super) fn run(
    tools: &Tools<'_>,
    nfq: &Path,
    shim: &Path,
    library: &Path,
    output: &Path,
) -> Result<()> {
    let directory = nfq
        .parent()
        .context("Protocol source parent")?
        .join("protocol-check");
    fs::create_dir(&directory)?;
    let source = fs::read_to_string(nfq.join("protocol.c"))?;
    let header = fs::read_to_string(nfq.join("protocol.h"))?;
    let mut aliases = String::new();
    let mut ordinary = String::new();
    for line in header.lines().filter(|line| !line.starts_with("//")) {
        let Some((declaration, _)) = line.split_once('(') else {
            continue;
        };
        if !line.ends_with(';') {
            continue;
        }
        let name = declaration
            .split_whitespace()
            .last()
            .context("Protocol API name")?
            .trim_start_matches('*');
        aliases.push_str(&format!("#define {name} reference_{name}\n"));
        ordinary.push_str(&format!("#undef {name}\n{line}\n"));
    }
    fs::write(directory.join("protocol_reference.h"), &aliases)?;
    fs::write(directory.join("protocol_ordinary.h"), &ordinary)?;
    fs::write(directory.join("protocol_reference.c"), &source)?;
    let mut vectors = String::from("/* Public RFC 9001/9369 numeric test vectors. */\n");
    for (name, text) in [
        (
            "quic_v1",
            include_str!("../../../zapret-wincompat/fixtures/quic/rfc9001-client.hex"),
        ),
        (
            "quic_v2",
            include_str!("../../../zapret-wincompat/fixtures/quic/rfc9369-client.hex"),
        ),
        (
            "quic_crypto",
            include_str!("../../../zapret-wincompat/fixtures/quic/client-crypto.hex"),
        ),
    ] {
        let digits: String = text
            .chars()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        ensure!(digits.len() % 2 == 0, "QUIC vector hex length");
        let bytes = (0..digits.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&digits[at..at + 2], 16))
            .collect::<Result<Vec<_>, _>>()?;
        vectors.push_str(&format!("static const uint8_t {name}[] = {{"));
        for byte in bytes {
            vectors.push_str(&format!("0x{byte:02x},"));
        }
        vectors.push_str("};\n");
    }
    fs::write(directory.join("quic_vectors.h"), vectors)?;
    let helpers = fs::read_to_string(nfq.join("helpers.c"))?;
    let mut helper_reference = String::new();
    for (first, next) in [
        ("#define UNIQ_SORT", "static inline bool is_letter("),
        ("uint16_t pntoh16(", "uint16_t bswap16("),
        ("bool parse_int16(", "time_t boottime("),
        ("void fill_random_bytes(", "#if defined(__FreeBSD__)"),
    ] {
        let start = helpers.find(first).context("Protocol helper start")?;
        let end = helpers[start..].find(next).context("Protocol helper end")?;
        helper_reference.push_str(&helpers[start..start + end]);
    }
    fs::write(
        directory.join("protocol_helper_reference.inc"),
        helper_reference,
    )?;
    let executable = directory.join("protocol-check.exe");
    let mut command = Command::new(tools.compiler);
    command.args([
        "-O2",
        "-ffunction-sections",
        "-fdata-sections",
        "-std=gnu99",
        "-DZAPRET_WINDOWS=1",
        "-DZAPRET_NATIVE_WINDOWS=1",
        "-D_FILE_OFFSET_BITS=64",
        "-D_POSIX_C_SOURCE=200809L",
        "-Wno-macro-redefined",
    ]);
    for path in [
        &directory,
        shim,
        &shim.join("include"),
        nfq,
        &nfq.join("windows"),
        &nfq.join("../../luajit2-2.1-20250826/src"),
    ] {
        command.arg(format!("-I{}", path.display()));
    }
    tools.run_command(
        command
            .arg("-include")
            .arg(shim.join("win_platform.h"))
            .arg(shim.join("protocol_oracle.c"))
            .arg(nfq.join("crypto/aes.c"))
            .arg(nfq.join("crypto/aes-ctr.c"))
            .arg(nfq.join("crypto/aes-gcm.c"))
            .arg(nfq.join("crypto/gcm.c"))
            .arg(nfq.join("crypto/hkdf.c"))
            .arg(nfq.join("crypto/hmac.c"))
            .arg(nfq.join("crypto/sha224-256.c"))
            .arg(nfq.join("crypto/usha.c"))
            .arg(library)
            .args([
                "-Wl,--gc-sections",
                "-static",
                "-lws2_32",
                "-lbcrypt",
                "-lntdll",
                "-luserenv",
                "-ladvapi32",
                "-o",
            ])
            .arg(&executable),
        &directory,
        "Compile pinned C and Rust protocol conformance",
    )?;
    let result = tools.run_command(
        &Command::new(&executable),
        &directory,
        "Compare C and Rust protocol APIs",
    )?;
    ensure!(
        result.starts_with("PASS "),
        "Protocol conformance did not finish"
    );
    fs::write(output, &result)?;
    print!("{result}");
    let mut benchmark = Command::new(&executable);
    benchmark.arg("--benchmark");
    let measurements = tools.run_command(
        &benchmark,
        &directory,
        "Measure pinned C and Rust TLS transforms",
    )?;
    let _: serde_json::Value =
        serde_json::from_str(&measurements).context("TLS transform benchmark JSON")?;
    fs::write(output.with_extension("benchmark.json"), measurements)?;
    let mut benchmark = Command::new(&executable);
    benchmark.arg("--quic-benchmark");
    let measurements = tools.run_command(
        &benchmark,
        &directory,
        "Measure pinned C and Rust QUIC Initial decryption",
    )?;
    let _: serde_json::Value =
        serde_json::from_str(&measurements).context("QUIC Initial benchmark JSON")?;
    fs::write(output.with_extension("quic-benchmark.json"), measurements)?;

    // All protocol operations now use Rust. Keep only the ordinary TLS entry
    // point and the C logger callback; LuaJIT never runs through a Rust frame.
    fs::write(
        nfq.join("protocol.c"),
        "#include \"protocol.h\"\n#include \"params.h\"\n#include \"tls_mod_windows.inc\"\n",
    )?;
    let assertion = "\n_Static_assert(sizeof(struct proto_pos)==8 && offsetof(struct proto_pos, marker)==4, \"Rust protocol position ABI\");\n_Static_assert(sizeof(struct fake_tls_mod)==260 && offsetof(struct fake_tls_mod, mod)==256, \"Rust TLS modifier ABI\");\n";
    fs::write(nfq.join("protocol.h"), format!("{header}{assertion}"))?;
    Ok(())
}
