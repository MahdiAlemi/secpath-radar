use anyhow::{Context, Result};
use chrono::{Datelike, Duration as ChronoDuration, Local, SecondsFormat, Utc};
use feed_rs::parser;
use minijinja::{context, Environment};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    env, fs,
    hash::{Hash, Hasher},
    path::PathBuf,
    thread,
    time::{Duration, SystemTime},
};

#[derive(Debug)]
struct Args {
    input: PathBuf,
    template: PathBuf,
    out: PathBuf,
    config: PathBuf,
    fetch: bool,
    cves: bool,
    offline: bool,
    refresh_cache: bool,
    ai: bool,
    refresh_ai: bool,
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

#[derive(Debug, Deserialize)]
struct Config {
    site: SiteConfig,
    fetch: FetchConfig,
    #[serde(default)]
    cache: CacheConfig,
    filters: FiltersConfig,
    limits: LimitsConfig,
    sources: Vec<SourceConfig>,
    #[serde(default)]
    cve: CveConfig,
    #[serde(default)]
    gemini: GeminiConfig,
}

#[derive(Debug, Deserialize)]
struct SiteConfig {
    title: String,
    #[allow(dead_code)]
    tagline: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FetchConfig {
    max_items_per_source: usize,
    max_total_items: usize,
    sleep_ms_between_sources: u64,
    user_agent: String,
}

#[derive(Debug, Deserialize, Clone)]
struct CacheConfig {
    #[serde(default = "default_cache_enabled")]
    enabled: bool,
    #[serde(default = "default_cache_dir")]
    dir: String,
    #[serde(default = "default_cache_ttl_minutes")]
    ttl_minutes: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_cache_enabled(),
            dir: default_cache_dir(),
            ttl_minutes: default_cache_ttl_minutes(),
        }
    }
}

fn default_cache_enabled() -> bool {
    true
}

fn default_cache_dir() -> String {
    "data/cache/http".to_string()
}

fn default_cache_ttl_minutes() -> u64 {
    720
}

#[derive(Debug, Deserialize)]
struct FiltersConfig {
    iran_keywords: Vec<String>,
    high_keywords: Vec<String>,
    low_keywords: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LimitsConfig {
    iran_radar: usize,
    global_news: usize,
    #[serde(default = "default_cve_limit")]
    cves: usize,
}

fn default_cve_limit() -> usize {
    8
}

#[derive(Debug, Deserialize)]
struct SourceConfig {
    name: String,
    url: String,
}

#[derive(Debug, Deserialize, Clone)]
struct CveConfig {
    #[serde(default = "default_max_cves")]
    max_cves: usize,
    #[serde(default = "default_lookback_days")]
    lookback_days: i64,
    #[serde(default = "default_sleep_ms")]
    sleep_ms_between_sources: u64,
    #[serde(default = "default_nvd_url")]
    nvd_url: String,
    #[serde(default = "default_kev_url")]
    kev_url: String,
    #[serde(default = "default_epss_url")]
    epss_url: String,
    #[serde(default)]
    include_epss: bool,
}

impl Default for CveConfig {
    fn default() -> Self {
        Self {
            max_cves: default_max_cves(),
            lookback_days: default_lookback_days(),
            sleep_ms_between_sources: default_sleep_ms(),
            nvd_url: default_nvd_url(),
            kev_url: default_kev_url(),
            epss_url: default_epss_url(),
            include_epss: true,
        }
    }
}

fn default_max_cves() -> usize {
    12
}

fn default_lookback_days() -> i64 {
    2
}

fn default_sleep_ms() -> u64 {
    1200
}

fn default_nvd_url() -> String {
    "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string()
}

fn default_kev_url() -> String {
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        .to_string()
}

fn default_epss_url() -> String {
    "https://api.first.org/data/v1/epss".to_string()
}

#[derive(Debug, Deserialize, Clone)]
struct GeminiConfig {
    #[serde(default = "default_gemini_model")]
    model: String,
    #[serde(default = "default_gemini_api_url")]
    api_url: String,
    #[serde(default = "default_gemini_cache_dir")]
    cache_dir: String,
    #[serde(default = "default_gemini_temperature")]
    temperature: f64,
    #[serde(default = "default_gemini_max_iran")]
    max_iran_items: usize,
    #[serde(default = "default_gemini_max_global")]
    max_global_news: usize,
    #[serde(default = "default_gemini_max_cves")]
    max_cves: usize,
}

impl Default for GeminiConfig {
    fn default() -> Self {
        Self {
            model: default_gemini_model(),
            api_url: default_gemini_api_url(),
            cache_dir: default_gemini_cache_dir(),
            temperature: default_gemini_temperature(),
            max_iran_items: default_gemini_max_iran(),
            max_global_news: default_gemini_max_global(),
            max_cves: default_gemini_max_cves(),
        }
    }
}

fn default_gemini_model() -> String {
    "gemini-2.5-flash".to_string()
}

fn default_gemini_api_url() -> String {
    "https://generativelanguage.googleapis.com/v1beta".to_string()
}

fn default_gemini_cache_dir() -> String {
    "data/cache/ai".to_string()
}

fn default_gemini_temperature() -> f64 {
    0.2
}

fn default_gemini_max_iran() -> usize {
    5
}

fn default_gemini_max_global() -> usize {
    7
}

fn default_gemini_max_cves() -> usize {
    8
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Tip {
    title: String,
    #[serde(rename = "type")]
    tip_type: String,
    body: String,
    command: String,
    takeaway: String,
}

#[derive(Debug, Clone, Serialize)]
struct FeedItem {
    title: String,
    summary: String,
    source: String,
    url: String,
    published: String,
    risk_score: i64,
    tags: Vec<String>,
    iran_related: bool,
    iran_context: String,
}

#[derive(Debug, Clone, Serialize)]
struct CveItem {
    cve_id: String,
    title: String,
    summary: String,
    severity: String,
    cvss: f64,
    epss: f64,
    kev: bool,
    published: String,
    url: String,
    recommended_action: String,
    risk_score: i64,
    tags: Vec<String>,
}

fn parse_args() -> Result<Args> {
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

fn main() -> Result<()> {
    let args = parse_args()?;

    let network_mode = args.fetch || args.cves;
    let config = load_config(&args.config)?;
    let mut gemini_calls_used = 0_u8;

    let mut brief = if network_mode {
        let items = if args.fetch {
            fetch_and_score(&config, args.offline, args.refresh_cache)?
        } else {
            Vec::new()
        };

        let cves = if args.cves {
            match fetch_cves(&config, args.offline, args.refresh_cache) {
                Ok(cves) => cves,
                Err(err) => {
                    eprintln!("⚠️  CVE engine skipped: {err:#}");
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        build_brief(&config, items, cves)?
    } else {
        let brief_raw = fs::read_to_string(&args.input)
            .with_context(|| format!("failed to read input JSON: {}", args.input.display()))?;
        serde_json::from_str(&brief_raw)
            .with_context(|| format!("invalid JSON in {}", args.input.display()))?
    };

    if args.ai {
        match enhance_brief_with_gemini(&config, &brief, args.refresh_ai) {
            Ok(result) => {
                brief = result.brief;
                gemini_calls_used = result.calls_used;
                if result.cache_hit {
                    eprintln!("↳ Gemini cache hit: {}", config.gemini.model);
                } else if result.calls_used > 0 {
                    eprintln!("✅ Gemini editor: {} call used", result.calls_used);
                }
            }
            Err(err) => {
                eprintln!("⚠️  Gemini editor skipped: {err:#}");
                brief["ai_status"] = json!({
                    "enabled": true,
                    "ok": false,
                    "model": config.gemini.model,
                    "calls_used": 0,
                    "error": err.to_string()
                });
            }
        }
    } else {
        brief["ai_status"] = json!({
            "enabled": false,
            "ok": true,
            "calls_used": 0,
            "model": "none"
        });
    }

    apply_local_polish(&mut brief);

    fs::create_dir_all("data").context("failed to create data directory")?;
    fs::write(
        "data/latest_brief.json",
        serde_json::to_string_pretty(&brief)?,
    )
    .context("failed to write data/latest_brief.json")?;

    render_html(&brief, &args.template, &args.out)?;
    println!("✅ rendered {}", args.out.display());
    println!("✅ wrote data/latest_brief.json");
    println!("ℹ️ Gemini calls used: {gemini_calls_used}");
    if args.offline {
        println!("ℹ️ offline mode: used cached HTTP responses only");
    }
    Ok(())
}

fn load_config(path: &PathBuf) -> Result<Config> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config: {}", path.display()))?;
    serde_yaml::from_str(&raw).with_context(|| format!("invalid YAML in {}", path.display()))
}

fn fetch_and_score(config: &Config, offline: bool, refresh_cache: bool) -> Result<Vec<FeedItem>> {
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(18))
        .build()
        .context("failed to build HTTP client")?;

    let mut seen = HashSet::new();
    let mut all = Vec::new();

    for source in &config.sources {
        eprintln!("→ fetching {}", source.name);

        match fetch_source(&client, source, config, offline, refresh_cache) {
            Ok(mut items) => all.append(&mut items),
            Err(err) => eprintln!("⚠️  skipped {}: {err:#}", source.name),
        }

        thread::sleep(Duration::from_millis(config.fetch.sleep_ms_between_sources));
    }

    let mut deduped = Vec::new();
    for item in all {
        let key = normalize_key(&item.title, &item.url);
        if seen.insert(key) {
            deduped.push(item);
        }
    }

    deduped.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));
    deduped.truncate(config.fetch.max_total_items);

    eprintln!("✅ fetched+deduped RSS: {} items", deduped.len());
    Ok(deduped)
}

fn fetch_source(
    client: &Client,
    source: &SourceConfig,
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<Vec<FeedItem>> {
    let bytes = get_bytes_cached(
        client,
        config,
        &source.url,
        &[],
        &format!("RSS {}", source.name),
        offline,
        refresh_cache,
    )?;

    let feed = parser::parse(&bytes[..]).context("failed to parse RSS/Atom feed")?;
    let mut out = Vec::new();

    for entry in feed.entries.iter().take(config.fetch.max_items_per_source) {
        let title = entry
            .title
            .as_ref()
            .map(|t| clean_text(&t.content))
            .unwrap_or_else(|| "بدون عنوان".to_string());

        let url = entry
            .links
            .first()
            .map(|l| l.href.clone())
            .unwrap_or_else(|| source.url.clone());

        let summary = entry
            .summary
            .as_ref()
            .map(|s| clean_text(&s.content))
            .or_else(|| {
                entry
                    .content
                    .as_ref()
                    .and_then(|c| c.body.as_ref())
                    .map(|s| clean_text(s))
            })
            .unwrap_or_default();

        let published = entry
            .published
            .or(entry.updated)
            .map(|d| d.to_rfc3339())
            .unwrap_or_default();

        let mut item = FeedItem {
            title,
            summary: truncate_chars(&summary, 260),
            source: source.name.clone(),
            url,
            published,
            risk_score: 1,
            tags: Vec::new(),
            iran_related: false,
            iran_context: "global".to_string(),
        };

        classify_and_score(&mut item, config);
        out.push(item);
    }

    Ok(out)
}

fn fetch_cves(config: &Config, offline: bool, refresh_cache: bool) -> Result<Vec<CveItem>> {
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(28))
        .build()
        .context("failed to build HTTP client for CVE engine")?;

    let cve_config = &config.cve;
    let now = Utc::now();
    let rounded_end =
        chrono::DateTime::<Utc>::from_timestamp((now.timestamp() / 3600) * 3600, 0).unwrap_or(now);
    let start = rounded_end - ChronoDuration::days(cve_config.lookback_days.max(1));
    let start_s = start.to_rfc3339_opts(SecondsFormat::Millis, true);
    let end_s = rounded_end.to_rfc3339_opts(SecondsFormat::Millis, true);
    let results_per_page = (cve_config.max_cves * 4).max(20).min(2000).to_string();

    eprintln!("→ fetching NVD CVEs from {start_s} to {end_s}");

    let nvd_bytes = get_bytes_cached(
        &client,
        config,
        &cve_config.nvd_url,
        &[
            ("pubStartDate", start_s.as_str()),
            ("pubEndDate", end_s.as_str()),
            ("resultsPerPage", results_per_page.as_str()),
        ],
        "NVD CVE API",
        offline,
        refresh_cache,
    )?;

    let nvd_json: Value = serde_json::from_slice(&nvd_bytes).context("invalid JSON from NVD")?;

    thread::sleep(Duration::from_millis(cve_config.sleep_ms_between_sources));

    let kev_set = match fetch_kev_set(&client, config, cve_config, offline, refresh_cache) {
        Ok(set) => set,
        Err(err) => {
            eprintln!("⚠️  skipped CISA KEV enrichment: {err:#}");
            HashSet::new()
        }
    };

    let mut cves = parse_nvd_cves(&nvd_json, &kev_set);

    if cve_config.include_epss && !cves.is_empty() {
        thread::sleep(Duration::from_millis(cve_config.sleep_ms_between_sources));
        let ids: Vec<String> = cves.iter().map(|c| c.cve_id.clone()).collect();
        match fetch_epss_map(&client, config, cve_config, &ids, offline, refresh_cache) {
            Ok(epss_map) => {
                for cve in &mut cves {
                    if let Some(epss) = epss_map.get(&cve.cve_id) {
                        cve.epss = *epss;
                    }
                    finalize_cve_score(cve);
                }
            }
            Err(err) => eprintln!("⚠️  skipped EPSS enrichment: {err:#}"),
        }
    }

    for cve in &mut cves {
        finalize_cve_score(cve);
    }

    cves.sort_by(|a, b| {
        b.risk_score.cmp(&a.risk_score).then_with(|| {
            b.cvss
                .partial_cmp(&a.cvss)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });
    cves.truncate(cve_config.max_cves);

    eprintln!("✅ CVE engine: {} CVEs selected", cves.len());
    Ok(cves)
}

fn fetch_kev_set(
    client: &Client,
    config: &Config,
    cve_config: &CveConfig,
    offline: bool,
    refresh_cache: bool,
) -> Result<HashSet<String>> {
    eprintln!("→ fetching CISA KEV catalog");
    let bytes = get_bytes_cached(
        client,
        config,
        &cve_config.kev_url,
        &[],
        "CISA KEV catalog",
        offline,
        refresh_cache,
    )?;

    let json: Value = serde_json::from_slice(&bytes).context("invalid JSON from CISA KEV")?;
    let mut out = HashSet::new();

    if let Some(vulns) = json.get("vulnerabilities").and_then(|v| v.as_array()) {
        for vuln in vulns {
            if let Some(id) = vuln.get("cveID").and_then(|v| v.as_str()) {
                out.insert(id.to_string());
            }
        }
    }

    Ok(out)
}

fn fetch_epss_map(
    client: &Client,
    config: &Config,
    cve_config: &CveConfig,
    cve_ids: &[String],
    offline: bool,
    refresh_cache: bool,
) -> Result<HashMap<String, f64>> {
    eprintln!("→ fetching EPSS for {} CVEs", cve_ids.len());
    let joined = cve_ids.join(",");
    let bytes = get_bytes_cached(
        client,
        config,
        &cve_config.epss_url,
        &[("cve", joined.as_str())],
        "EPSS API",
        offline,
        refresh_cache,
    )?;

    let json: Value = serde_json::from_slice(&bytes).context("invalid JSON from EPSS")?;
    let mut map = HashMap::new();

    if let Some(rows) = json.get("data").and_then(|v| v.as_array()) {
        for row in rows {
            let Some(cve) = row.get("cve").and_then(|v| v.as_str()) else {
                continue;
            };
            let epss = row
                .get("epss")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(0.0);
            map.insert(cve.to_string(), epss);
        }
    }

    Ok(map)
}

fn parse_nvd_cves(nvd_json: &Value, kev_set: &HashSet<String>) -> Vec<CveItem> {
    let mut out = Vec::new();
    let Some(vulns) = nvd_json.get("vulnerabilities").and_then(|v| v.as_array()) else {
        return out;
    };

    for vuln in vulns {
        let cve = &vuln["cve"];
        let Some(cve_id) = cve.get("id").and_then(|v| v.as_str()) else {
            continue;
        };

        let summary = extract_description(cve);
        let title = derive_cve_title(cve_id, &summary);
        let (severity, cvss) = extract_cvss(cve);
        let kev = kev_set.contains(cve_id);
        let published = cve
            .get("published")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let url = format!("https://nvd.nist.gov/vuln/detail/{cve_id}");

        let mut item = CveItem {
            cve_id: cve_id.to_string(),
            title,
            summary: truncate_chars(&summary, 310),
            severity,
            cvss,
            epss: 0.0,
            kev,
            published,
            url,
            recommended_action: String::new(),
            risk_score: 1,
            tags: Vec::new(),
        };

        finalize_cve_score(&mut item);
        out.push(item);
    }

    out
}

fn extract_description(cve: &Value) -> String {
    let Some(descriptions) = cve.get("descriptions").and_then(|v| v.as_array()) else {
        return "No description provided by NVD.".to_string();
    };

    descriptions
        .iter()
        .find(|d| d.get("lang").and_then(|v| v.as_str()) == Some("en"))
        .or_else(|| descriptions.first())
        .and_then(|d| d.get("value"))
        .and_then(|v| v.as_str())
        .map(clean_text)
        .unwrap_or_else(|| "No description provided by NVD.".to_string())
}

fn extract_cvss(cve: &Value) -> (String, f64) {
    let metrics = &cve["metrics"];
    let names = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ];

    for name in names {
        let Some(arr) = metrics.get(name).and_then(|v| v.as_array()) else {
            continue;
        };
        let Some(first) = arr.first() else {
            continue;
        };

        let cvss_data = &first["cvssData"];
        let score = cvss_data
            .get("baseScore")
            .and_then(|v| v.as_f64())
            .or_else(|| first.get("baseScore").and_then(|v| v.as_f64()))
            .unwrap_or(0.0);

        let severity = first
            .get("baseSeverity")
            .and_then(|v| v.as_str())
            .or_else(|| cvss_data.get("baseSeverity").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .unwrap_or_else(|| severity_from_score(score).to_string());

        return (severity.to_uppercase(), score);
    }

    ("UNKNOWN".to_string(), 0.0)
}

fn severity_from_score(score: f64) -> &'static str {
    if score >= 9.0 {
        "CRITICAL"
    } else if score >= 7.0 {
        "HIGH"
    } else if score >= 4.0 {
        "MEDIUM"
    } else if score > 0.0 {
        "LOW"
    } else {
        "UNKNOWN"
    }
}

fn derive_cve_title(cve_id: &str, summary: &str) -> String {
    let first_sentence = summary
        .split('.')
        .next()
        .unwrap_or(summary)
        .trim()
        .to_string();

    if first_sentence.is_empty() {
        cve_id.to_string()
    } else {
        concise_title(&first_sentence, 84)
    }
}

fn finalize_cve_score(cve: &mut CveItem) {
    let mut score = cve.cvss.round() as i64;
    let mut tags = Vec::new();

    if cve.severity == "CRITICAL" {
        score += 2;
        push_tag(&mut tags, "Critical".to_string());
    } else if cve.severity == "HIGH" {
        score += 1;
        push_tag(&mut tags, "High".to_string());
    }

    if cve.kev {
        score += 3;
        push_tag(&mut tags, "KEV".to_string());
    }

    if cve.epss >= 0.70 {
        score += 2;
        push_tag(&mut tags, "High EPSS".to_string());
    } else if cve.epss >= 0.30 {
        score += 1;
        push_tag(&mut tags, "Medium EPSS".to_string());
    }

    let text = format!("{} {}", cve.title, cve.summary).to_lowercase();
    for kw in [
        "vpn",
        "firewall",
        "router",
        "gateway",
        "exchange",
        "wordpress",
        "linux",
    ] {
        if text.contains(kw) {
            score += 1;
            push_tag(&mut tags, keyword_tag(kw));
        }
    }

    cve.risk_score = score.clamp(1, 10);
    cve.tags = tags.into_iter().take(5).collect();
    cve.recommended_action = recommended_action_for_cve(cve);
}

fn recommended_action_for_cve(cve: &CveItem) -> String {
    if cve.kev {
        "به‌دلیل حضور در KEV، فوراً exposure و patch/mitigation را بررسی کن.".to_string()
    } else if cve.severity == "CRITICAL" || cve.cvss >= 9.0 {
        "با asset inventory تطبیق بده و برای patch یا mitigation اولویت بالا بده.".to_string()
    } else if cve.epss >= 0.70 {
        "به‌خاطر احتمال exploit بالا، سرویس‌های public-facing مرتبط را سریع بررسی کن.".to_string()
    } else {
        "اثرگذاری روی محصولات محیط خودت را بررسی و در چرخه patch عادی پیگیری کن.".to_string()
    }
}

fn classify_and_score(item: &mut FeedItem, config: &Config) {
    let haystack = format!("{} {} {}", item.title, item.summary, item.url).to_lowercase();

    let mut score = 1_i64;
    let mut tags = Vec::new();

    for kw in &config.filters.high_keywords {
        if haystack.contains(&kw.to_lowercase()) {
            score += 2;
            push_tag(&mut tags, keyword_tag(kw));
        }
    }

    for kw in &config.filters.low_keywords {
        if haystack.contains(&kw.to_lowercase()) {
            score -= 1;
        }
    }

    if haystack.contains("cve-") {
        score += 2;
        push_tag(&mut tags, "CVE".to_string());
    }
    if haystack.contains("zero-day") || haystack.contains("zeroday") {
        score += 3;
        push_tag(&mut tags, "Zero-day".to_string());
    }
    if haystack.contains("ransomware") {
        score += 3;
        push_tag(&mut tags, "Ransomware".to_string());
    }
    if haystack.contains("actively exploited") || haystack.contains("exploited in the wild") {
        score += 3;
        push_tag(&mut tags, "Active Exploit".to_string());
    }

    let iran_hit = config
        .filters
        .iran_keywords
        .iter()
        .any(|kw| haystack.contains(&kw.to_lowercase()));

    if iran_hit {
        item.iran_related = true;
        item.iran_context = if haystack.contains("apt34")
            || haystack.contains("oilrig")
            || haystack.contains("charming kitten")
            || haystack.contains("muddywater")
        {
            "threat_actor".to_string()
        } else {
            "mentioned".to_string()
        };
        score += 2;
        push_tag(&mut tags, "Iran".to_string());
    }

    item.risk_score = score.clamp(1, 10);
    item.tags = tags.into_iter().take(4).collect();
}

fn build_brief(config: &Config, items: Vec<FeedItem>, mut cves: Vec<CveItem>) -> Result<Value> {
    let now = Local::now();
    let date_en = format!("{}-{:02}-{:02}", now.year(), now.month(), now.day());
    let generated_at = now.format("%Y-%m-%d %H:%M").to_string();

    let mut iran: Vec<_> = items.iter().filter(|i| i.iran_related).cloned().collect();
    let mut global: Vec<_> = items.iter().filter(|i| !i.iran_related).cloned().collect();
    iran.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));
    global.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));
    iran.truncate(config.limits.iran_radar);
    global.truncate(config.limits.global_news);

    cves.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));
    cves.truncate(config.limits.cves);

    let news_priority = items.iter().max_by_key(|i| i.risk_score);
    let cve_priority = cves.iter().max_by_key(|c| c.risk_score);

    let priority = match (news_priority, cve_priority) {
        (Some(news), Some(cve)) if cve.risk_score >= news.risk_score => priority_from_cve(cve),
        (Some(news), _) => priority_from_item(news),
        (None, Some(cve)) => priority_from_cve(cve),
        (None, None) => empty_priority(),
    };

    let risk_level = match priority["risk_score"].as_i64().unwrap_or(1) {
        8..=10 => "High",
        5..=7 => "Medium",
        _ => "Low",
    };

    let cve_count = cves.len();
    let critical_count = cves
        .iter()
        .filter(|c| c.severity == "CRITICAL" || c.cvss >= 9.0)
        .count();
    let kev_count = cves.iter().filter(|c| c.kev).count();

    Ok(json!({
        "site_title": config.site.title,
        "date_fa": "امروز",
        "date_en": date_en,
        "risk_level": risk_level,
        "generated_at": generated_at,
        "stats": {
            "total_items": items.len() + cve_count,
            "iran_items": iran.len(),
            "global_news": global.len(),
            "cves": cve_count,
            "critical_cves": critical_count,
            "kev": kev_count,
            "tools": 0
        },
        "source_health": {
            "rss_sources": config.sources.len(),
            "http_cache": config.cache.enabled,
            "cache_ttl_minutes": config.cache.ttl_minutes,
            "ai_cache_dir": config.gemini.cache_dir.clone()
        },
        "priority_alert": priority,
        "iran_radar": iran,
        "global_news": global,
        "cves": cves,
        "tools": [],
        "tip_of_the_day": pick_tip()?,
        "action_items": build_action_items(iran.len(), cve_count, critical_count, kev_count)
    }))
}

fn priority_from_item(item: &FeedItem) -> Value {
    json!({
        "title": item.title,
        "summary": item.summary,
        "source": item.source,
        "url": item.url,
        "risk_score": item.risk_score,
        "tags": item.tags
    })
}

fn priority_from_cve(cve: &CveItem) -> Value {
    json!({
        "title": format!("{} — {}", cve.cve_id, cve.title),
        "summary": cve.summary,
        "source": "NVD / CISA KEV / EPSS",
        "url": cve.url,
        "risk_score": cve.risk_score,
        "tags": cve.tags
    })
}

fn empty_priority() -> Value {
    json!({
        "title": "فعلاً آیتمی دریافت نشد",
        "summary": "RSSها یا اینترنت در دسترس نبودند. خروجی سایت ساخته شد، اما داده واقعی دریافت نشد.",
        "source": "SecPath Radar Local",
        "url": "#",
        "risk_score": 1,
        "tags": ["No Data"]
    })
}

fn pick_tip() -> Result<Value> {
    let raw = fs::read_to_string("data/tips.yaml").context("failed to read data/tips.yaml")?;
    let tips: Vec<Tip> = serde_yaml::from_str(&raw).context("invalid YAML in data/tips.yaml")?;
    let day = Local::now().ordinal() as usize;
    let tip = tips
        .get(day % tips.len().max(1))
        .context("data/tips.yaml has no tips")?;

    Ok(json!({
        "title": tip.title,
        "type": tip.tip_type,
        "body": tip.body,
        "command": tip.command,
        "takeaway": tip.takeaway
    }))
}

fn build_action_items(
    iran_count: usize,
    cve_count: usize,
    critical_count: usize,
    kev_count: usize,
) -> Vec<String> {
    let mut items = Vec::new();

    if kev_count > 0 {
        items.push("فوری: CVEهای KEV را با asset inventory تطبیق بده و برای patch/mitigation همان‌روز تصمیم بگیر.".to_string());
    }
    if critical_count > 0 {
        items.push("Critical: CVEهای CVSS 9+ را از چرخه patch عادی جدا کن و exposure اینترنتی آن‌ها را اول چک کن.".to_string());
    }
    if iran_count > 0 {
        items.push("Iran Radar: آیتم‌های مرتبط با ایران را برای دامنه، برند، vendor، زیرساخت و attribution جداگانه triage کن.".to_string());
    }
    if cve_count > 0 {
        items.push("Inventory: نام محصول‌ها و vendorهای CVE Watch را با CMDB، EDR inventory یا لیست سرویس‌های exposed مقایسه کن.".to_string());
    }

    items.push("Edge Review: VPN، firewall، gateway، mail و پنل‌های ادمین public-facing را با خبرهای High Risk امروز تطبیق بده.".to_string());
    items.push("Detection: برای vendorهای دیده‌شده، لاگ‌های authentication، EDR، WAF و edge device را در ۲۴ تا ۴۸ ساعت اخیر مرور کن.".to_string());
    items.push("Report: برای هر مورد مهم، وضعیت affected / not affected / unknown را در یک یادداشت کوتاه ثبت کن.".to_string());

    items.into_iter().take(7).collect()
}

struct GeminiEditResult {
    brief: Value,
    calls_used: u8,
    cache_hit: bool,
}

fn enhance_brief_with_gemini(
    config: &Config,
    brief: &Value,
    refresh_ai: bool,
) -> Result<GeminiEditResult> {
    let compact = compact_brief_for_ai(config, brief);
    let cache_key = ai_cache_key(&config.gemini.model, &compact);

    if !refresh_ai {
        if let Some(cached) = read_ai_cache(config, &cache_key)? {
            let edited = merge_ai_result(brief.clone(), &cached);
            return Ok(GeminiEditResult {
                brief: mark_ai_status(edited, true, true, &config.gemini.model, 0, None),
                calls_used: 0,
                cache_hit: true,
            });
        }
    }

    let api_key = get_env_or_dotenv("GEMINI_API_KEY")
        .context("GEMINI_API_KEY is not set. Put it in .env or export it before using --ai")?;

    let prompt = build_gemini_prompt(&compact)?;
    let request_body = json!({
        "contents": [{
            "role": "user",
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "temperature": config.gemini.temperature,
            "candidateCount": 1,
            "maxOutputTokens": 8192,
            "responseMimeType": "application/json",
            "responseSchema": gemini_response_schema()
        }
    });

    let url = format!(
        "{}/models/{}:generateContent",
        config.gemini.api_url.trim_end_matches('/'),
        config.gemini.model
    );

    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(60))
        .build()
        .context("failed to build HTTP client for Gemini")?;

    let response_json: Value = client
        .post(url)
        .header("x-goog-api-key", api_key.as_str())
        .json(&request_body)
        .send()
        .and_then(|response| response.error_for_status())
        .context("Gemini request failed")?
        .json()
        .context("Gemini response was not valid JSON")?;

    let text =
        extract_gemini_text(&response_json).context("Gemini response did not include text")?;
    let cleaned = clean_json_block(&text);
    let ai_json: Value = serde_json::from_str(&cleaned).with_context(|| {
        format!(
            "Gemini returned text, but it was not valid JSON: {}",
            json_parse_hint(&cleaned)
        )
    })?;
    let ai_json = validate_ai_result_shape(&ai_json)?;

    write_ai_cache(config, &cache_key, &ai_json)?;

    let edited = merge_ai_result(brief.clone(), &ai_json);
    Ok(GeminiEditResult {
        brief: mark_ai_status(edited, true, false, &config.gemini.model, 1, None),
        calls_used: 1,
        cache_hit: false,
    })
}

fn compact_brief_for_ai(config: &Config, brief: &Value) -> Value {
    let mut compact = json!({
        "site_title": brief.get("site_title").cloned().unwrap_or(Value::Null),
        "date_fa": brief.get("date_fa").cloned().unwrap_or(Value::Null),
        "date_en": brief.get("date_en").cloned().unwrap_or(Value::Null),
        "risk_level": brief.get("risk_level").cloned().unwrap_or(Value::Null),
        "stats": brief.get("stats").cloned().unwrap_or(Value::Null),
        "priority_alert": brief.get("priority_alert").cloned().unwrap_or(Value::Null),
        "iran_radar": take_array_items(brief.get("iran_radar"), config.gemini.max_iran_items),
        "global_news": take_array_items(brief.get("global_news"), config.gemini.max_global_news),
        "cves": take_array_items(brief.get("cves"), config.gemini.max_cves),
        "tip_of_the_day": brief.get("tip_of_the_day").cloned().unwrap_or(Value::Null),
        "action_items": brief.get("action_items").cloned().unwrap_or(Value::Null),
    });

    truncate_value_strings(&mut compact, 900);
    compact
}

fn take_array_items(value: Option<&Value>, limit: usize) -> Value {
    value
        .and_then(|v| v.as_array())
        .map(|items| Value::Array(items.iter().take(limit).cloned().collect()))
        .unwrap_or_else(|| Value::Array(Vec::new()))
}

fn truncate_value_strings(value: &mut Value, max_chars: usize) {
    match value {
        Value::String(s) => {
            if s.chars().count() > max_chars {
                *s = truncate_chars(s, max_chars);
            }
        }
        Value::Array(items) => {
            for item in items {
                truncate_value_strings(item, max_chars);
            }
        }
        Value::Object(map) => {
            for value in map.values_mut() {
                truncate_value_strings(value, max_chars);
            }
        }
        _ => {}
    }
}

fn gemini_response_schema() -> Value {
    json!({
        "type": "OBJECT",
        "properties": {
            "priority_alert": {
                "type": "OBJECT",
                "properties": {
                    "title_fa": {"type": "STRING"},
                    "summary_fa": {"type": "STRING"},
                    "why_it_matters": {"type": "STRING"},
                    "ops_note": {"type": "STRING"}
                }
            },
            "iran_radar": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "title_fa": {"type": "STRING"},
                        "summary_fa": {"type": "STRING"},
                        "why_it_matters": {"type": "STRING"},
                        "ops_note": {"type": "STRING"}
                    }
                }
            },
            "global_news": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "title_fa": {"type": "STRING"},
                        "summary_fa": {"type": "STRING"},
                        "why_it_matters": {"type": "STRING"},
                        "ops_note": {"type": "STRING"}
                    }
                }
            },
            "cves": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "title_fa": {"type": "STRING"},
                        "summary_fa": {"type": "STRING"},
                        "why_it_matters": {"type": "STRING"},
                        "recommended_action": {"type": "STRING"},
                        "ops_note": {"type": "STRING"}
                    }
                }
            },
            "action_items": {
                "type": "ARRAY",
                "items": {"type": "STRING"}
            }
        },
        "required": ["priority_alert", "iran_radar", "global_news", "cves", "action_items"]
    })
}

fn build_gemini_prompt(compact: &Value) -> Result<String> {
    Ok(format!(
        r#"You are the Persian editorial layer for SecPath Radar, a defensive daily cybersecurity intelligence brief.

Input is JSON generated from RSS, NVD, CISA KEV, and EPSS. Your job is to add a Persian display layer while preserving the original machine-generated/source fields.

Hard rules:
- Do not invent facts, CVEs, sources, URLs, exploitation status, affected products, victim geography, attribution, or exploit details.
- Do not rewrite or return immutable fields such as url, source, cve_id, risk_score, cvss, epss, kev, severity, published, iran_context, tags, title, or summary.
- Return editorial fields only: title_fa, summary_fa, why_it_matters, ops_note, recommended_action for CVEs, and action_items.
- Keep the same item order and approximate same item count for iran_radar, global_news, and cves.
- If an item is unclear, write a cautious Persian summary and say the original advisory should be checked.
- Do not move Iran-related items between sections. If Iran appears only as attribution, do not imply the target is inside Iran.
- Use defensive language only. No exploit chains, payloads, bypass steps, or unauthorized access guidance.
- summary_fa: 1 short Persian sentence, max 170 characters.
- why_it_matters: 1 Persian sentence about operational impact, max 150 characters.
- ops_note: 1 Persian action sentence for SOC/admin teams, max 160 characters.
- title_fa: concise Persian headline, max 70 characters. For CVEs, include product/impact, not a full NVD sentence.
- action_items: 5 to 7 concrete Persian checklist items for today's defensive work.
- Return valid JSON only. No markdown fences, comments, trailing commas, or explanatory text.

Return this exact top-level shape:
{{
  "priority_alert": {{"title_fa":"...", "summary_fa":"...", "why_it_matters":"...", "ops_note":"..."}},
  "iran_radar": [{{"title_fa":"...", "summary_fa":"...", "why_it_matters":"...", "ops_note":"..."}}],
  "global_news": [{{"title_fa":"...", "summary_fa":"...", "why_it_matters":"...", "ops_note":"..."}}],
  "cves": [{{"title_fa":"...", "summary_fa":"...", "why_it_matters":"...", "recommended_action":"...", "ops_note":"..."}}],
  "action_items": ["..."]
}}

Input JSON:
{}"#,
        serde_json::to_string_pretty(compact)?
    ))
}

fn extract_gemini_text(response: &Value) -> Option<String> {
    response
        .get("candidates")?
        .as_array()?
        .first()?
        .get("content")?
        .get("parts")?
        .as_array()?
        .first()?
        .get("text")?
        .as_str()
        .map(|s| s.to_string())
}

fn clean_json_block(text: &str) -> String {
    let mut out = text.trim().to_string();
    if out.starts_with("```json") {
        out = out.trim_start_matches("```json").trim().to_string();
    } else if out.starts_with("```") {
        out = out.trim_start_matches("```").trim().to_string();
    }
    if out.ends_with("```") {
        out = out.trim_end_matches("```").trim().to_string();
    }
    out
}

fn json_parse_hint(text: &str) -> String {
    let char_count = text.chars().count();
    let preview: String = text.chars().take(180).collect();
    format!("{} chars; starts with {:?}", char_count, preview)
}

fn validate_ai_result_shape(ai_json: &Value) -> Result<Value> {
    let obj = ai_json
        .as_object()
        .context("Gemini returned JSON, but the top-level value was not an object")?;

    let mut clean = serde_json::Map::new();

    if let Some(value) = obj.get("priority_alert") {
        if value.is_object() {
            clean.insert("priority_alert".to_string(), value.clone());
        }
    }

    for key in ["iran_radar", "global_news", "cves"] {
        if let Some(value) = obj.get(key) {
            if let Some(items) = value.as_array() {
                let safe_items = items
                    .iter()
                    .filter(|item| item.is_object())
                    .cloned()
                    .collect::<Vec<_>>();
                clean.insert(key.to_string(), Value::Array(safe_items));
            }
        }
    }

    if let Some(value) = obj.get("action_items") {
        if let Some(items) = value.as_array() {
            let safe_items = items
                .iter()
                .filter_map(|item| item.as_str().map(|s| Value::String(s.trim().to_string())))
                .filter(|item| item.as_str().is_some_and(|s| !s.is_empty()))
                .collect::<Vec<_>>();
            clean.insert("action_items".to_string(), Value::Array(safe_items));
        }
    }

    if clean.is_empty() {
        anyhow::bail!("Gemini returned JSON, but it did not contain any usable brief fields");
    }

    Ok(Value::Object(clean))
}

fn merge_ai_result(mut brief: Value, ai_json: &Value) -> Value {
    if let Some(value) = ai_json.get("priority_alert") {
        merge_object_preserve_existing(&mut brief["priority_alert"], value);
    }

    for key in ["iran_radar", "global_news", "cves"] {
        if let Some(value) = ai_json.get(key) {
            merge_array_items_by_index(&mut brief[key], value);
        }
    }

    if let Some(value) = ai_json.get("action_items") {
        if value.as_array().is_some_and(|items| !items.is_empty()) {
            brief["action_items"] = value.clone();
        }
    }

    brief
}

fn merge_array_items_by_index(base: &mut Value, edits: &Value) {
    let Some(base_items) = base.as_array_mut() else {
        return;
    };
    let Some(edit_items) = edits.as_array() else {
        return;
    };

    for (base_item, edit_item) in base_items.iter_mut().zip(edit_items.iter()) {
        merge_object_preserve_existing(base_item, edit_item);
    }
}

fn merge_object_preserve_existing(base: &mut Value, edit: &Value) {
    let Some(base_obj) = base.as_object_mut() else {
        return;
    };
    let Some(edit_obj) = edit.as_object() else {
        return;
    };

    for (key, value) in edit_obj {
        if protected_ai_field(key) && base_obj.contains_key(key) {
            continue;
        }

        let usable = match value {
            Value::Null => false,
            Value::String(s) => !s.trim().is_empty(),
            Value::Array(items) => !items.is_empty(),
            Value::Object(obj) => !obj.is_empty(),
            _ => true,
        };

        if usable {
            base_obj.insert(key.clone(), value.clone());
        }
    }
}

fn protected_ai_field(key: &str) -> bool {
    matches!(
        key,
        "url"
            | "source"
            | "cve_id"
            | "cvss"
            | "epss"
            | "kev"
            | "severity"
            | "risk_score"
            | "published"
            | "iran_context"
            | "summary"
            | "title"
            | "tags"
    )
}

fn mark_ai_status(
    mut brief: Value,
    ok: bool,
    cache_hit: bool,
    model: &str,
    calls_used: u8,
    error: Option<String>,
) -> Value {
    brief["ai_status"] = json!({
        "enabled": true,
        "ok": ok,
        "cache_hit": cache_hit,
        "model": model,
        "calls_used": calls_used,
        "error": error
    });
    brief
}

fn ai_cache_key(model: &str, compact: &Value) -> String {
    let raw = format!(
        "{}\n{}",
        model,
        serde_json::to_string(compact).unwrap_or_default()
    );
    let mut hasher = DefaultHasher::new();
    raw.hash(&mut hasher);
    format!("{:016x}.json", hasher.finish())
}

fn ai_cache_path(config: &Config, key: &str) -> PathBuf {
    PathBuf::from(&config.gemini.cache_dir).join(key)
}

fn read_ai_cache(config: &Config, key: &str) -> Result<Option<Value>> {
    let path = ai_cache_path(config, key);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read AI cache: {}", path.display()))?;
    serde_json::from_str(&raw)
        .map(Some)
        .with_context(|| format!("invalid AI cache JSON: {}", path.display()))
}

fn write_ai_cache(config: &Config, key: &str, value: &Value) -> Result<()> {
    let path = ai_cache_path(config, key);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("failed to create AI cache directory: {}", parent.display())
        })?;
    }
    fs::write(&path, serde_json::to_string_pretty(value)?)
        .with_context(|| format!("failed to write AI cache: {}", path.display()))?;
    Ok(())
}

fn get_env_or_dotenv(key: &str) -> Option<String> {
    if let Ok(value) = env::var(key) {
        if !value.trim().is_empty() {
            return Some(value);
        }
    }

    let raw = fs::read_to_string(".env").ok()?;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if k.trim() == key {
            let value = v.trim().trim_matches('"').trim_matches('\'').to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }

    None
}

fn apply_local_polish(brief: &mut Value) {
    brief["version"] = json!("v0.4.7-persian-quality");

    if brief.get("source_health").is_none() {
        brief["source_health"] = json!({
            "rss_sources": 0,
            "http_cache": true,
            "cache_ttl_minutes": 0,
            "ai_cache_dir": "data/cache/ai"
        });
    }

    polish_priority(brief);
    polish_array_items(brief, "iran_radar", 88, 240);
    polish_array_items(brief, "global_news", 88, 240);
    polish_cves(brief);
    add_editorial_display_fields(brief);
    brief["brief_notes"] = json!(build_brief_notes(brief));
}

fn polish_priority(brief: &mut Value) {
    let Some(priority) = brief
        .get_mut("priority_alert")
        .and_then(|v| v.as_object_mut())
    else {
        return;
    };

    if let Some(Value::String(title)) = priority.get_mut("title") {
        *title = concise_title(title, 92);
    }
    if let Some(Value::String(summary)) = priority.get_mut("summary") {
        *summary = non_empty_summary(summary, 260);
    }
}

fn polish_array_items(brief: &mut Value, key: &str, title_max: usize, summary_max: usize) {
    let Some(items) = brief.get_mut(key).and_then(|v| v.as_array_mut()) else {
        return;
    };

    for item in items {
        let Some(obj) = item.as_object_mut() else {
            continue;
        };
        if let Some(Value::String(title)) = obj.get_mut("title") {
            *title = concise_title(title, title_max);
        }
        if let Some(Value::String(summary)) = obj.get_mut("summary") {
            *summary = non_empty_summary(summary, summary_max);
        }
    }
}

fn polish_cves(brief: &mut Value) {
    let Some(items) = brief.get_mut("cves").and_then(|v| v.as_array_mut()) else {
        return;
    };

    for item in items {
        let Some(obj) = item.as_object_mut() else {
            continue;
        };
        if let Some(Value::String(title)) = obj.get_mut("title") {
            *title = concise_title(title, 84);
        }
        if let Some(Value::String(summary)) = obj.get_mut("summary") {
            *summary = non_empty_summary(summary, 260);
        }
        if let Some(Value::String(action)) = obj.get_mut("recommended_action") {
            *action = non_empty_summary(action, 170);
        }
    }
}

fn add_editorial_display_fields(brief: &mut Value) {
    enrich_priority_fields(brief);
    enrich_news_fields(brief, "iran_radar", true);
    enrich_news_fields(brief, "global_news", false);
    enrich_cve_fields(brief);
}

fn enrich_priority_fields(brief: &mut Value) {
    let Some(obj) = brief
        .get_mut("priority_alert")
        .and_then(|value| value.as_object_mut())
    else {
        return;
    };

    let title = obj
        .get("title")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    let summary = obj
        .get("summary")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    let risk_score = obj
        .get("risk_score")
        .and_then(|value| value.as_i64())
        .unwrap_or(1);

    insert_string_if_missing(obj, "title_fa", &fallback_persian_title(&title));
    insert_string_if_missing(
        obj,
        "summary_fa",
        &fallback_persian_summary(&summary, "این هشدار مهم‌ترین آیتم امروز است"),
    );
    insert_string_if_missing(
        obj,
        "why_it_matters",
        &fallback_why_it_matters(risk_score, &summary),
    );
    insert_string_if_missing(
        obj,
        "ops_note",
        "اول exposure و دارایی‌های مرتبط را مشخص کن، سپس وضعیت patch یا mitigation را ثبت کن.",
    );
}

fn enrich_news_fields(brief: &mut Value, key: &str, iran_section: bool) {
    let Some(items) = brief.get_mut(key).and_then(|value| value.as_array_mut()) else {
        return;
    };

    for item in items {
        let Some(obj) = item.as_object_mut() else {
            continue;
        };
        let title = obj
            .get("title")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let summary = obj
            .get("summary")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let risk_score = obj
            .get("risk_score")
            .and_then(|value| value.as_i64())
            .unwrap_or(1);

        insert_string_if_missing(obj, "title_fa", &fallback_persian_title(&title));
        insert_string_if_missing(
            obj,
            "summary_fa",
            &fallback_persian_summary(&summary, "این خبر برای پایش امروز قابل توجه است"),
        );
        insert_string_if_missing(
            obj,
            "why_it_matters",
            &fallback_why_it_matters(risk_score, &summary),
        );
        let note = if iran_section {
            "ارتباط این آیتم با ایران را با دامنه، برند، vendor و زیرساخت خودت جداگانه triage کن."
        } else if risk_score >= 8 {
            "برای دارایی‌های public-facing مرتبط، وضعیت exposure و لاگ‌های ۲۴ تا ۴۸ ساعت اخیر را بررسی کن."
        } else {
            "نام vendor یا محصول را با inventory و backlog patch مقایسه کن."
        };
        insert_string_if_missing(obj, "ops_note", note);
    }
}

fn enrich_cve_fields(brief: &mut Value) {
    let Some(items) = brief.get_mut("cves").and_then(|value| value.as_array_mut()) else {
        return;
    };

    for item in items {
        let Some(obj) = item.as_object_mut() else {
            continue;
        };
        let title = obj
            .get("title")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let summary = obj
            .get("summary")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let risk_score = obj
            .get("risk_score")
            .and_then(|value| value.as_i64())
            .unwrap_or(1);
        let kev = obj
            .get("kev")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let severity = obj
            .get("severity")
            .and_then(|value| value.as_str())
            .unwrap_or("UNKNOWN")
            .to_string();

        insert_string_if_missing(obj, "title_fa", &fallback_persian_title(&title));
        insert_string_if_missing(
            obj,
            "summary_fa",
            &fallback_persian_summary(&summary, "این CVE باید با موجودی دارایی‌ها تطبیق داده شود"),
        );
        insert_string_if_missing(
            obj,
            "why_it_matters",
            &fallback_why_it_matters(risk_score, &summary),
        );

        let note = if kev {
            "چون در KEV دیده شده، وضعیت affected/not affected را همان‌روز مشخص و mitigation را پیگیری کن."
        } else if severity == "CRITICAL" || risk_score >= 8 {
            "ابتدا assetهای اینترنتی و سرویس‌های حساس مرتبط را بررسی و برای patch اولویت بالا تعیین کن."
        } else {
            "با inventory تطبیق بده و در چرخه patch عادی یا accelerated پیگیری کن."
        };
        insert_string_if_missing(obj, "ops_note", note);
    }
}

fn insert_string_if_missing(obj: &mut serde_json::Map<String, Value>, key: &str, value: &str) {
    let has_good_value = obj
        .get(key)
        .and_then(|existing| existing.as_str())
        .is_some_and(|existing| !existing.trim().is_empty());

    if !has_good_value && !value.trim().is_empty() {
        obj.insert(key.to_string(), Value::String(value.to_string()));
    }
}

fn fallback_persian_title(title: &str) -> String {
    let cleaned = concise_title(title, 70);
    if cleaned.trim().is_empty() {
        "آیتم امنیتی قابل بررسی".to_string()
    } else {
        cleaned
    }
}

fn fallback_persian_summary(summary: &str, fallback_prefix: &str) -> String {
    let cleaned = non_empty_summary(summary, 190);
    if contains_persian(&cleaned) {
        cleaned
    } else {
        format!("{fallback_prefix}: {}", truncate_chars(&cleaned, 150))
    }
}

fn fallback_why_it_matters(risk_score: i64, text: &str) -> String {
    let lower = text.to_lowercase();
    if lower.contains("ransomware") {
        "احتمال اثر مستقیم روی تداوم کسب‌وکار و بازیابی سرویس‌ها وجود دارد.".to_string()
    } else if lower.contains("actively exploited") || lower.contains("exploited in the wild") {
        "نشانه بهره‌برداری فعال دیده شده و باید از backlog عادی جدا شود.".to_string()
    } else if lower.contains("cve-") || risk_score >= 8 {
        "اگر محصول مرتبط در محیط وجود داشته باشد، اولویت patch و کنترل exposure بالاست.".to_string()
    } else {
        "برای تصمیم روزانه SOC و تیم زیرساخت، ارزش triage و ثبت وضعیت دارد.".to_string()
    }
}

fn contains_persian(text: &str) -> bool {
    text.chars()
        .any(|ch| ('\u{0600}'..='\u{06FF}').contains(&ch))
}

fn build_brief_notes(brief: &Value) -> Vec<String> {
    let mut notes = Vec::new();
    let ai = brief.get("ai_status").unwrap_or(&Value::Null);
    let ai_enabled = ai.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let ai_ok = ai.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    let ai_cache = ai
        .get("cache_hit")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let calls = ai.get("calls_used").and_then(|v| v.as_u64()).unwrap_or(0);

    if ai_enabled && ai_ok && ai_cache {
        notes.push("AI polish از cache خوانده شد؛ برای این ورودی call جدید مصرف نشد.".to_string());
    } else if ai_enabled && ai_ok {
        notes.push(format!(
            "AI polish فعال بود و {calls} call مصرف شد؛ خروجی برای اجراهای بعدی cache شد."
        ));
    } else if ai_enabled {
        notes.push(
            "AI polish خطا داد؛ سایت با fallback محلی و داده‌های خام/کش‌شده ساخته شد.".to_string(),
        );
    } else {
        notes.push("AI خاموش است؛ خروجی فقط با ruleهای محلی ساخته شده است.".to_string());
    }

    if brief
        .get("source_health")
        .and_then(|v| v.get("http_cache"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        notes.push(
            "HTTP cache فعال است؛ حالت offline از پاسخ‌های ذخیره‌شده استفاده می‌کند.".to_string(),
        );
    }

    notes.into_iter().take(3).collect()
}

fn concise_title(input: &str, max_chars: usize) -> String {
    let mut title = clean_text(input);
    let replacements = [
        ("A vulnerability was found in ", ""),
        ("A vulnerability has been found in ", ""),
        ("A vulnerability in ", ""),
        ("A flaw was found in ", ""),
        ("An issue was discovered in ", ""),
        ("This vulnerability allows ", "Allows "),
        ("The vulnerability allows ", "Allows "),
        ("Multiple vulnerabilities in ", ""),
    ];

    for (from, to) in replacements {
        if title.starts_with(from) {
            title = title.replacen(from, to, 1);
        }
    }

    truncate_chars(title.trim(), max_chars)
}

fn non_empty_summary(input: &str, max_chars: usize) -> String {
    let cleaned = clean_text(input);
    if cleaned.trim().is_empty() {
        "جزئیات کافی در منبع وجود نداشت؛ برای تصمیم‌گیری، advisory اصلی را بررسی کن.".to_string()
    } else {
        truncate_chars(&cleaned, max_chars)
    }
}

fn render_html(brief: &Value, template_path: &PathBuf, out_path: &PathBuf) -> Result<()> {
    let template_raw = fs::read_to_string(template_path)
        .with_context(|| format!("failed to read template: {}", template_path.display()))?;

    let mut env = Environment::new();
    env.add_template("index.html", &template_raw)
        .context("failed to register template")?;

    let tmpl = env.get_template("index.html")?;
    let rendered = tmpl.render(context!(brief => brief))?;

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory: {}", parent.display()))?;
    }

    fs::write(out_path, rendered)
        .with_context(|| format!("failed to write output HTML: {}", out_path.display()))?;
    Ok(())
}

fn get_bytes_cached(
    client: &Client,
    config: &Config,
    url: &str,
    query: &[(&str, &str)],
    label: &str,
    offline: bool,
    refresh_cache: bool,
) -> Result<Vec<u8>> {
    let cache_key = cache_key(url, query);

    if !refresh_cache {
        if let Some(bytes) = read_cache(config, &cache_key, false)? {
            eprintln!("  ↳ cache hit: {label}");
            return Ok(bytes);
        }
    }

    if offline {
        return read_cache(config, &cache_key, true)?
            .with_context(|| format!("offline mode has no cached response for {label}"));
    }

    let mut request = client.get(url);
    if !query.is_empty() {
        request = request.query(query);
    }

    match request
        .send()
        .and_then(|response| response.error_for_status())
    {
        Ok(response) => {
            let bytes = response
                .bytes()
                .with_context(|| format!("failed to read response body for {label}"))?
                .to_vec();
            write_cache(config, &cache_key, &bytes)?;
            Ok(bytes)
        }
        Err(err) => {
            if let Some(bytes) = read_cache(config, &cache_key, true)? {
                eprintln!("⚠️  using stale cache for {label}: {err}");
                Ok(bytes)
            } else {
                Err(err).with_context(|| format!("request failed for {label}: {url}"))
            }
        }
    }
}

fn cache_key(url: &str, query: &[(&str, &str)]) -> String {
    let mut key = url.to_string();
    if !query.is_empty() {
        let parts = query
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        key.push('?');
        key.push_str(&parts);
    }
    key
}

fn cache_path(config: &Config, cache_key: &str) -> PathBuf {
    let mut hasher = DefaultHasher::new();
    cache_key.hash(&mut hasher);
    let hash = hasher.finish();
    PathBuf::from(&config.cache.dir).join(format!("{hash:016x}.bin"))
}

fn read_cache(config: &Config, cache_key: &str, allow_stale: bool) -> Result<Option<Vec<u8>>> {
    if !config.cache.enabled {
        return Ok(None);
    }

    let path = cache_path(config, cache_key);
    if !path.exists() {
        return Ok(None);
    }

    if !allow_stale {
        let metadata = fs::metadata(&path)
            .with_context(|| format!("failed to read cache metadata: {}", path.display()))?;
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or_else(|_| Duration::from_secs(0));
        let ttl = Duration::from_secs(config.cache.ttl_minutes.saturating_mul(60));

        if age > ttl {
            return Ok(None);
        }
    }

    fs::read(&path)
        .map(Some)
        .with_context(|| format!("failed to read cache file: {}", path.display()))
}

fn write_cache(config: &Config, cache_key: &str, bytes: &[u8]) -> Result<()> {
    if !config.cache.enabled {
        return Ok(());
    }

    let path = cache_path(config, cache_key);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create cache directory: {}", parent.display()))?;
    }

    fs::write(&path, bytes)
        .with_context(|| format!("failed to write cache file: {}", path.display()))?;
    Ok(())
}

fn normalize_key(title: &str, url: &str) -> String {
    let raw = if !url.is_empty() { url } else { title };
    raw.trim()
        .trim_end_matches('/')
        .to_lowercase()
        .replace("https://", "")
        .replace("http://", "")
}

fn clean_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_tag = false;

    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }

    out.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (idx, ch) in input.chars().enumerate() {
        if idx >= max_chars {
            out.push('…');
            return out;
        }
        out.push(ch);
    }
    out
}

fn keyword_tag(keyword: &str) -> String {
    match keyword.to_lowercase().as_str() {
        "zero-day" | "zeroday" => "Zero-day".to_string(),
        "actively exploited" | "exploited in the wild" => "Active Exploit".to_string(),
        "data breach" | "breach" => "Breach".to_string(),
        "vulnerability" | "critical" => "Vulnerability".to_string(),
        "cve-" => "CVE".to_string(),
        "vpn" => "VPN".to_string(),
        "firewall" => "Firewall".to_string(),
        "router" => "Router".to_string(),
        "gateway" => "Gateway".to_string(),
        "exchange" => "Exchange".to_string(),
        "wordpress" => "WordPress".to_string(),
        "linux" => "Linux".to_string(),
        other => {
            let mut chars = other.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => "Security".to_string(),
            }
        }
    }
}

fn push_tag(tags: &mut Vec<String>, tag: String) {
    if !tags.iter().any(|t| t == &tag) {
        tags.push(tag);
    }
}
