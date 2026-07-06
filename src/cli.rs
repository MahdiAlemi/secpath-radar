//! Command-line arguments and parsing.

use crate::prelude::*;

#[derive(Debug)]
pub(crate) struct Args {
    pub(crate) input: PathBuf,
    pub(crate) template: PathBuf,
    pub(crate) out: PathBuf,
    pub(crate) config: PathBuf,
    pub(crate) fetch: bool,
    pub(crate) cves: bool,
    pub(crate) offline: bool,
    pub(crate) refresh_cache: bool,
    pub(crate) ai: bool,
    pub(crate) refresh_ai: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            input: PathBuf::from("samples/sample_brief.json"),
            template: PathBuf::from("templates/index.html.j2"),
            out: PathBuf::from("site/index.html"),
            config: PathBuf::from("config.yaml"),
            fetch: false,
            cves: false,
            offline: false,
            refresh_cache: false,
            ai: false,
            refresh_ai: false,
        }
    }
}

pub(crate) fn parse_args() -> Result<Args> {
    let mut args = Args::default();
    let mut iter = env::args().skip(1);

    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--fetch" => args.fetch = true,
            "--cves" => args.cves = true,
            "--offline" => args.offline = true,
            "--refresh-cache" => args.refresh_cache = true,
            "--ai" => args.ai = true,
            "--refresh-ai" => args.refresh_ai = true,
            "--no-ai" => args.ai = false,
            "--full" => {
                args.fetch = true;
                args.cves = true;
            }
            "--input" => {
                args.input = PathBuf::from(
                    iter.next()
                        .context("--input needs a path, e.g. --input samples/sample_brief.json")?,
                );
            }
            "--template" => {
                args.template =
                    PathBuf::from(iter.next().context(
                        "--template needs a path, e.g. --template templates/index.html.j2",
                    )?);
            }
            "--out" => {
                args.out = PathBuf::from(
                    iter.next()
                        .context("--out needs a path, e.g. --out site/index.html")?,
                );
            }
            "--config" => {
                args.config = PathBuf::from(
                    iter.next()
                        .context("--config needs a path, e.g. --config config.yaml")?,
                );
            }
            "--help" | "-h" => {
                println!(
                    "Usage: secpath-radar [--fetch] [--cves] [--full] [--offline] [--refresh-cache] [--ai] [--refresh-ai] [--config PATH] [--input PATH] [--template PATH] [--out PATH]"
                );
                println!("Default mode renders samples/sample_brief.json without network calls.");
                println!("Use --fetch for RSS, --cves for NVD/CISA KEV/EPSS, --full for both, or --offline --full to use cache only.");
                println!("Use --ai to polish the brief with Gemini. It is cached and limited to one call per run.");
                std::process::exit(0);
            }
            unknown => anyhow::bail!("unknown argument: {unknown}"),
        }
    }

    if args.offline && !args.fetch && !args.cves {
        args.fetch = true;
        args.cves = true;
    }

    Ok(args)
}
