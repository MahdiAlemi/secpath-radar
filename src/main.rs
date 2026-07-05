use anyhow::{Context, Result};
use chrono::{Datelike, Duration as ChronoDuration, Local, SecondsFormat, Utc};
use feed_rs::parser;
use minijinja::{context, Environment};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::PathBuf,
    thread,
    time::Duration,
};

#[derive(Debug)]
struct Args {
    input: PathBuf,
    template: PathBuf,
    out: PathBuf,
    config: PathBuf,
    fetch: bool,
    cves: bool,
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
        }
    }
}

#[derive(Debug, Deserialize)]
struct Config {
    site: SiteConfig,
    fetch: FetchConfig,
    filters: FiltersConfig,
    limits: LimitsConfig,
    sources: Vec<SourceConfig>,
    #[serde(default)]
    cve: CveConfig,
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
                    "Usage: cyberbrief [--fetch] [--cves] [--full] [--config PATH] [--input PATH] [--template PATH] [--out PATH]"
                );
                println!("Default mode renders samples/sample_brief.json without network calls.");
                println!("Use --fetch for RSS, --cves for NVD/CISA KEV/EPSS, or --full for both.");
                std::process::exit(0);
            }
            unknown => anyhow::bail!("unknown argument: {unknown}"),
        }
    }

    Ok(args)
}

fn main() -> Result<()> {
    let args = parse_args()?;

    let network_mode = args.fetch || args.cves;

    let brief = if network_mode {
        let config = load_config(&args.config)?;

        let items = if args.fetch {
            fetch_and_score(&config)?
        } else {
            Vec::new()
        };

        let cves = if args.cves {
            match fetch_cves(&config) {
                Ok(cves) => cves,
                Err(err) => {
                    eprintln!("⚠️  CVE engine skipped: {err:#}");
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        let brief = build_brief(&config, items, cves)?;
        fs::create_dir_all("data").context("failed to create data directory")?;
        fs::write(
            "data/latest_brief.json",
            serde_json::to_string_pretty(&brief)?,
        )
        .context("failed to write data/latest_brief.json")?;
        brief
    } else {
        let brief_raw = fs::read_to_string(&args.input)
            .with_context(|| format!("failed to read input JSON: {}", args.input.display()))?;
        serde_json::from_str(&brief_raw)
            .with_context(|| format!("invalid JSON in {}", args.input.display()))?
    };

    render_html(&brief, &args.template, &args.out)?;
    println!("✅ rendered {}", args.out.display());
    if network_mode {
        println!("✅ wrote data/latest_brief.json");
        println!("ℹ️ Gemini calls used: 0");
    }
    Ok(())
}

fn load_config(path: &PathBuf) -> Result<Config> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config: {}", path.display()))?;
    serde_yaml::from_str(&raw).with_context(|| format!("invalid YAML in {}", path.display()))
}

fn fetch_and_score(config: &Config) -> Result<Vec<FeedItem>> {
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(18))
        .build()
        .context("failed to build HTTP client")?;

    let mut seen = HashSet::new();
    let mut all = Vec::new();

    for source in &config.sources {
        eprintln!("→ fetching {}", source.name);

        match fetch_source(&client, source, config) {
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

fn fetch_source(client: &Client, source: &SourceConfig, config: &Config) -> Result<Vec<FeedItem>> {
    let bytes = client
        .get(&source.url)
        .send()
        .with_context(|| format!("request failed: {}", source.url))?
        .error_for_status()
        .with_context(|| format!("bad HTTP status: {}", source.url))?
        .bytes()
        .context("failed to read response body")?;

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

fn fetch_cves(config: &Config) -> Result<Vec<CveItem>> {
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(28))
        .build()
        .context("failed to build HTTP client for CVE engine")?;

    let cve_config = &config.cve;
    let end = Utc::now();
    let start = end - ChronoDuration::days(cve_config.lookback_days.max(1));
    let start_s = start.to_rfc3339_opts(SecondsFormat::Millis, true);
    let end_s = end.to_rfc3339_opts(SecondsFormat::Millis, true);
    let results_per_page = (cve_config.max_cves * 4).max(20).min(2000).to_string();

    eprintln!("→ fetching NVD CVEs from {start_s} to {end_s}");

    let nvd_bytes = client
        .get(&cve_config.nvd_url)
        .query(&[
            ("pubStartDate", start_s.as_str()),
            ("pubEndDate", end_s.as_str()),
            ("resultsPerPage", results_per_page.as_str()),
        ])
        .send()
        .context("NVD request failed")?
        .error_for_status()
        .context("NVD returned bad HTTP status")?
        .bytes()
        .context("failed to read NVD response body")?;

    let nvd_json: Value = serde_json::from_slice(&nvd_bytes).context("invalid JSON from NVD")?;

    thread::sleep(Duration::from_millis(cve_config.sleep_ms_between_sources));

    let kev_set = match fetch_kev_set(&client, cve_config) {
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
        match fetch_epss_map(&client, cve_config, &ids) {
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

fn fetch_kev_set(client: &Client, cve_config: &CveConfig) -> Result<HashSet<String>> {
    eprintln!("→ fetching CISA KEV catalog");
    let bytes = client
        .get(&cve_config.kev_url)
        .send()
        .context("CISA KEV request failed")?
        .error_for_status()
        .context("CISA KEV returned bad HTTP status")?
        .bytes()
        .context("failed to read CISA KEV response body")?;

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
    cve_config: &CveConfig,
    cve_ids: &[String],
) -> Result<HashMap<String, f64>> {
    eprintln!("→ fetching EPSS for {} CVEs", cve_ids.len());
    let joined = cve_ids.join(",");
    let bytes = client
        .get(&cve_config.epss_url)
        .query(&[("cve", joined.as_str())])
        .send()
        .context("EPSS request failed")?
        .error_for_status()
        .context("EPSS returned bad HTTP status")?
        .bytes()
        .context("failed to read EPSS response body")?;

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
        truncate_chars(&first_sentence, 100)
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
    let mut items = vec![
        "خبرهای High Risk را با دارایی‌های exposed مثل VPN، firewall و سرویس‌های public مقایسه کن.".to_string(),
        "اگر نام vendor یا محصولی در محیط خودت دیده شد، changelog و advisory رسمی همان vendor را بررسی کن.".to_string(),
        "لاگ‌های edge deviceها و authentication را برای رفتار غیرعادی مرور کن.".to_string(),
    ];

    if iran_count > 0 {
        items.push(
            "آیتم‌های Iran Radar را جداگانه برای دامنه‌ها، برندها و زیرساخت‌های مرتبط بررسی کن."
                .to_string(),
        );
    }
    if cve_count > 0 {
        items.push(
            "CVEهای امروز را با asset inventory تطبیق بده و public-facing بودنشان را چک کن."
                .to_string(),
        );
    }
    if critical_count > 0 {
        items
            .push("CVEهای Critical را از چرخه patch عادی جدا کن و اولویت اضطراری بده.".to_string());
    }
    if kev_count > 0 {
        items.push(
            "CVEهای KEV را فوراً برای exploitation احتمالی، patch و mitigation بررسی کن."
                .to_string(),
        );
    }

    items
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
