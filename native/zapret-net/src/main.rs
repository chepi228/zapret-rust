use anyhow::{Context, Result, bail};
use zapret_net::BatchOptions;
fn main() {
    if let Err(e) = run() {
        eprintln!("zapret-net-probe: {e:#}");
        std::process::exit(2);
    }
}
fn run() -> Result<()> {
    let mut options = BatchOptions::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                println!(
                    "zapret-net-probe {}\nVersion-1 JSONL probe. --parallel 1..64 --deadline-ms 1..1800000 --ca-file PATH --post-file PATH\n--post-file requires exactly 65536 bytes and preserves the captured POST payload.\n--diagnostics KIND ROOT JSON runs a network diagnostic.",
                    env!("CARGO_PKG_VERSION")
                );
                return Ok(());
            }
            "--version" => {
                println!("zapret-net-probe {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--diagnostics" => {
                let kind = args.next().context("missing kind")?;
                let root = args.next().context("missing root")?;
                let input = args.next().context("missing diagnostic JSON")?;
                if args.next().is_some() {
                    bail!("unexpected argument")
                }
                println!(
                    "{}",
                    zapret_net::diagnostics(
                        std::path::Path::new(&root),
                        &kind,
                        &serde_json::from_str(&input)?
                    )?
                );
                return Ok(());
            }
            _ => {
                let value = args
                    .next()
                    .with_context(|| format!("missing value for {arg}"))?;
                match arg.as_str() {
                    "--parallel" => options.parallel = value.parse()?,
                    "--deadline-ms" => options.deadline_ms = value.parse()?,
                    "--ca-file" => options.ca_file = Some(value.into()),
                    "--post-file" => {
                        let mut file = std::fs::File::open(value)?;
                        let mut body = Vec::new();
                        use std::io::Read;
                        file.by_ref().take(65537).read_to_end(&mut body)?;
                        options.post_body = Some(body);
                    }
                    _ => bail!("unknown option {arg}"),
                }
            }
        }
    }
    zapret_net::run_stdio(options)
}
