use anyhow::{Context, Result};
use chrono::{Datelike, Duration as ChronoDuration, Local, NaiveDate, SecondsFormat, Utc};
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
    #[serde(default)]
    intel: IntelConfig,
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

#[derive(Debug, Deserialize, Clone)]
struct IntelConfig {
    #[serde(default = "default_intel_enabled")]
    enabled: bool,
    #[serde(default = "default_intel_cache_dir")]
    cache_dir: String,
    #[serde(default = "default_intel_refresh_hours")]
    refresh_hours: u64,
    #[serde(default = "default_intel_sleep_ms")]
    sleep_ms_between_sources: u64,
    #[serde(default)]
    attack_pressure: AttackPressureConfig,
    #[serde(default)]
    ioc_radar: IocRadarConfig,
    #[serde(default)]
    infrastructure: InfrastructureRadarConfig,
    #[serde(default)]
    supply_chain: SupplyChainConfig,
    #[serde(default)]
    ransomware: RansomwareConfig,
    #[serde(default)]
    botnet_c2: BotnetC2Config,
}

impl Default for IntelConfig {
    fn default() -> Self {
        Self {
            enabled: default_intel_enabled(),
            cache_dir: default_intel_cache_dir(),
            refresh_hours: default_intel_refresh_hours(),
            sleep_ms_between_sources: default_intel_sleep_ms(),
            attack_pressure: AttackPressureConfig::default(),
            ioc_radar: IocRadarConfig::default(),
            infrastructure: InfrastructureRadarConfig::default(),
            supply_chain: SupplyChainConfig::default(),
            ransomware: RansomwareConfig::default(),
            botnet_c2: BotnetC2Config::default(),
        }
    }
}

fn default_intel_enabled() -> bool {
    true
}

fn default_intel_cache_dir() -> String {
    "data/cache/intel".to_string()
}

fn default_intel_refresh_hours() -> u64 {
    1
}

fn default_intel_sleep_ms() -> u64 {
    350
}

#[derive(Debug, Deserialize, Clone)]
struct AttackPressureConfig {
    #[serde(default = "default_attack_pressure_enabled")]
    enabled: bool,
    #[serde(default = "default_attack_pressure_max_ports")]
    max_ports: usize,
    #[serde(default = "default_top_ports_url")]
    top_ports_url: String,
    #[serde(default = "default_top_ports_source_url")]
    top_ports_source_url: String,
    #[serde(default = "default_top_ports_reports_url")]
    top_ports_reports_url: String,
    #[serde(default = "default_top_ports_targets_url")]
    top_ports_targets_url: String,
}

impl Default for AttackPressureConfig {
    fn default() -> Self {
        Self {
            enabled: default_attack_pressure_enabled(),
            max_ports: default_attack_pressure_max_ports(),
            top_ports_url: default_top_ports_url(),
            top_ports_source_url: default_top_ports_source_url(),
            top_ports_reports_url: default_top_ports_reports_url(),
            top_ports_targets_url: default_top_ports_targets_url(),
        }
    }
}

fn default_attack_pressure_enabled() -> bool {
    true
}

fn default_attack_pressure_max_ports() -> usize {
    10
}

fn default_top_ports_url() -> String {
    "https://feeds.dshield.org/feeds//topports.txt".to_string()
}

fn default_top_ports_source_url() -> String {
    "https://feeds.dshield.org/feeds//topports_source.txt".to_string()
}

fn default_top_ports_reports_url() -> String {
    "https://feeds.dshield.org/feeds//topports_reports.txt".to_string()
}

fn default_top_ports_targets_url() -> String {
    "https://feeds.dshield.org/feeds//topports_targets.txt".to_string()
}

#[derive(Debug, Deserialize, Clone)]
struct IocRadarConfig {
    #[serde(default = "default_ioc_radar_enabled")]
    enabled: bool,
    #[serde(default = "default_ioc_max_urlhaus")]
    max_urlhaus: usize,
    #[serde(default = "default_ioc_max_threatfox")]
    max_threatfox: usize,
    #[serde(default = "default_urlhaus_recent_csv_url")]
    urlhaus_recent_csv_url: String,
    #[serde(default = "default_threatfox_recent_csv_url")]
    threatfox_recent_csv_url: String,
}

impl Default for IocRadarConfig {
    fn default() -> Self {
        Self {
            enabled: default_ioc_radar_enabled(),
            max_urlhaus: default_ioc_max_urlhaus(),
            max_threatfox: default_ioc_max_threatfox(),
            urlhaus_recent_csv_url: default_urlhaus_recent_csv_url(),
            threatfox_recent_csv_url: default_threatfox_recent_csv_url(),
        }
    }
}

fn default_ioc_radar_enabled() -> bool {
    true
}

fn default_ioc_max_urlhaus() -> usize {
    18
}

fn default_ioc_max_threatfox() -> usize {
    18
}

fn default_urlhaus_recent_csv_url() -> String {
    "https://urlhaus.abuse.ch/downloads/csv_recent/".to_string()
}

fn default_threatfox_recent_csv_url() -> String {
    "https://threatfox.abuse.ch/export/csv/recent/".to_string()
}

#[derive(Debug, Deserialize, Clone)]
struct InfrastructureRadarConfig {
    #[serde(default = "default_infrastructure_enabled")]
    enabled: bool,
    #[serde(default = "default_infrastructure_max_ips")]
    max_ips: usize,
    #[serde(default = "default_shodan_internetdb_base_url")]
    shodan_base_url: String,
    #[serde(default = "default_dshield_top_ips_url")]
    dshield_top_ips_url: String,
}

impl Default for InfrastructureRadarConfig {
    fn default() -> Self {
        Self {
            enabled: default_infrastructure_enabled(),
            max_ips: default_infrastructure_max_ips(),
            shodan_base_url: default_shodan_internetdb_base_url(),
            dshield_top_ips_url: default_dshield_top_ips_url(),
        }
    }
}

fn default_infrastructure_enabled() -> bool {
    true
}

fn default_infrastructure_max_ips() -> usize {
    12
}

fn default_shodan_internetdb_base_url() -> String {
    "https://internetdb.shodan.io".to_string()
}

fn default_dshield_top_ips_url() -> String {
    "https://feeds.dshield.org/feeds/topips.txt".to_string()
}

#[derive(Debug, Deserialize, Clone)]
struct SupplyChainConfig {
    #[serde(default = "default_supply_chain_enabled")]
    enabled: bool,
    #[serde(default = "default_supply_chain_max_advisories")]
    max_advisories: usize,
    #[serde(default = "default_github_advisories_url")]
    github_advisories_url: String,
    #[serde(default = "default_osv_base_url")]
    osv_base_url: String,
    #[serde(default = "default_supply_chain_ecosystems")]
    ecosystems: Vec<String>,
}

impl Default for SupplyChainConfig {
    fn default() -> Self {
        Self {
            enabled: default_supply_chain_enabled(),
            max_advisories: default_supply_chain_max_advisories(),
            github_advisories_url: default_github_advisories_url(),
            osv_base_url: default_osv_base_url(),
            ecosystems: default_supply_chain_ecosystems(),
        }
    }
}

fn default_supply_chain_enabled() -> bool {
    true
}

fn default_supply_chain_max_advisories() -> usize {
    24
}

fn default_github_advisories_url() -> String {
    "https://api.github.com/advisories".to_string()
}

fn default_osv_base_url() -> String {
    "https://osv.dev/vulnerability".to_string()
}

fn default_supply_chain_ecosystems() -> Vec<String> {
    vec![
        "npm".to_string(),
        "pip".to_string(),
        "maven".to_string(),
        "go".to_string(),
        "rust".to_string(),
        "composer".to_string(),
        "nuget".to_string(),
    ]
}

#[derive(Debug, Deserialize, Clone)]
struct RansomwareConfig {
    #[serde(default = "default_ransomware_enabled")]
    enabled: bool,
    #[serde(default = "default_ransomware_max_victims")]
    max_victims: usize,
    #[serde(default = "default_ransomware_recent_victims_url")]
    recent_victims_url: String,
}

impl Default for RansomwareConfig {
    fn default() -> Self {
        Self {
            enabled: default_ransomware_enabled(),
            max_victims: default_ransomware_max_victims(),
            recent_victims_url: default_ransomware_recent_victims_url(),
        }
    }
}

fn default_ransomware_enabled() -> bool {
    true
}

fn default_ransomware_max_victims() -> usize {
    30
}

fn default_ransomware_recent_victims_url() -> String {
    "https://api.ransomware.live/v2/recentvictims".to_string()
}

#[derive(Debug, Deserialize, Clone)]
struct BotnetC2Config {
    #[serde(default = "default_botnet_enabled")]
    enabled: bool,
    #[serde(default = "default_botnet_max_c2")]
    max_c2: usize,
    #[serde(default = "default_botnet_max_tls")]
    max_tls: usize,
    #[serde(default = "default_feodo_ipblocklist_url")]
    feodo_ipblocklist_csv_url: String,
    #[serde(default = "default_sslbl_ja3_url")]
    sslbl_ja3_csv_url: String,
    #[serde(default = "default_sslbl_cert_url")]
    sslbl_cert_csv_url: String,
}

impl Default for BotnetC2Config {
    fn default() -> Self {
        Self {
            enabled: default_botnet_enabled(),
            max_c2: default_botnet_max_c2(),
            max_tls: default_botnet_max_tls(),
            feodo_ipblocklist_csv_url: default_feodo_ipblocklist_url(),
            sslbl_ja3_csv_url: default_sslbl_ja3_url(),
            sslbl_cert_csv_url: default_sslbl_cert_url(),
        }
    }
}

fn default_botnet_enabled() -> bool {
    true
}

fn default_botnet_max_c2() -> usize {
    18
}

fn default_botnet_max_tls() -> usize {
    16
}

fn default_feodo_ipblocklist_url() -> String {
    "https://feodotracker.abuse.ch/downloads/ipblocklist.csv".to_string()
}

fn default_sslbl_ja3_url() -> String {
    "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv".to_string()
}

fn default_sslbl_cert_url() -> String {
    "https://sslbl.abuse.ch/blacklist/sslblacklist.csv".to_string()
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

#[derive(Debug, Clone, Serialize)]
struct SourceFailure {
    name: String,
    url: String,
    error: String,
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
    #[serde(default)]
    include_epss_momentum: bool,
    #[serde(default = "default_epss_momentum_days")]
    epss_momentum_days: Vec<i64>,
    #[serde(default)]
    include_vulnrichment: bool,
    #[serde(default = "default_vulnrichment_base_url")]
    vulnrichment_base_url: String,
    #[serde(default = "default_max_vulnrichment")]
    max_vulnrichment: usize,
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
            include_epss_momentum: true,
            epss_momentum_days: default_epss_momentum_days(),
            include_vulnrichment: true,
            vulnrichment_base_url: default_vulnrichment_base_url(),
            max_vulnrichment: default_max_vulnrichment(),
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

fn default_epss_momentum_days() -> Vec<i64> {
    vec![7, 30]
}

fn default_vulnrichment_base_url() -> String {
    "https://raw.githubusercontent.com/cisagov/vulnrichment/develop".to_string()
}

fn default_max_vulnrichment() -> usize {
    10
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

#[derive(Debug, Clone, Serialize)]
struct FeedItem {
    title: String,
    summary: String,
    source: String,
    url: String,
    published: String,
    risk_score: i64,
    category: String,
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
    epss_percentile: f64,
    epss_7d: f64,
    epss_30d: f64,
    epss_delta_7d: f64,
    epss_delta_30d: f64,
    epss_momentum: String,
    kev: bool,
    cisa_vulnrichment: bool,
    ssvc_exploitation: String,
    ssvc_automatable: String,
    ssvc_technical_impact: String,
    cisa_priority: String,
    published: String,
    url: String,
    recommended_action: String,
    risk_score: i64,
    tags: Vec<String>,
}

#[derive(Debug, Clone)]
struct EpssSnapshot {
    epss: f64,
    percentile: f64,
}

#[derive(Debug, Clone, Default)]
struct CisaVulnrichment {
    found: bool,
    exploitation: String,
    automatable: String,
    technical_impact: String,
    priority: String,
}

#[derive(Debug, Clone, Serialize)]
struct AttackPort {
    rank: usize,
    port: u16,
    service: String,
    description: String,
    risk: String,
    note_fa: String,
    pressure_score: usize,
    bar_width: usize,
}

#[derive(Debug, Clone, Serialize)]
struct IocIndicator {
    rank: usize,
    source: String,
    indicator_type: String,
    indicator: String,
    indicator_safe: String,
    threat_type: String,
    malware: String,
    first_seen: String,
    confidence: usize,
    risk: String,
    risk_score: usize,
    bar_width: usize,
    tags: Vec<String>,
    note_fa: String,
}

#[derive(Debug, Clone)]
struct InfraCandidate {
    ip: String,
    source: String,
    first_seen: String,
    reason: String,
}

#[derive(Debug, Clone, Serialize)]
struct InfrastructureHost {
    rank: usize,
    ip: String,
    source: String,
    first_seen: String,
    reason: String,
    ports: Vec<u16>,
    port_count: usize,
    hostnames: Vec<String>,
    tags: Vec<String>,
    vulns: Vec<String>,
    vuln_count: usize,
    exposure_score: usize,
    bar_width: usize,
    risk: String,
    note_fa: String,
}

#[derive(Debug, Clone, Serialize)]
struct RansomwareVictim {
    rank: usize,
    victim_safe: String,
    group: String,
    country: String,
    sector: String,
    claimed_date: String,
    recency_score: usize,
    risk: String,
    bar_width: usize,
    note_fa: String,
}

#[derive(Debug, Clone, Serialize)]
struct BotnetC2Indicator {
    rank: usize,
    ip: String,
    ip_safe: String,
    port: u16,
    status: String,
    malware: String,
    first_seen: String,
    source: String,
    risk: String,
    score: usize,
    bar_width: usize,
    note_fa: String,
}

#[derive(Debug, Clone, Serialize)]
struct TlsThreatIndicator {
    rank: usize,
    indicator_type: String,
    fingerprint: String,
    fingerprint_safe: String,
    first_seen: String,
    last_seen: String,
    reason: String,
    source: String,
    risk: String,
    score: usize,
    bar_width: usize,
    note_fa: String,
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
        let (items, rss_failures) = if args.fetch {
            fetch_and_score(&config, args.offline, args.refresh_cache)?
        } else {
            (Vec::new(), Vec::new())
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

        let mut brief = build_brief(&config, items, cves)?;
        brief["source_health"]["failed_rss_sources"] = json!(rss_failures.len());
        brief["source_health"]["rss_failures"] = json!(rss_failures);
        brief["stats"]["failed_rss_sources"] = brief["source_health"]["failed_rss_sources"].clone();
        let attack_pressure =
            fetch_attack_pressure_or_fallback(&config, args.offline, args.refresh_cache);
        brief["attack_pressure"] = attack_pressure;
        let ioc_radar = fetch_ioc_radar_or_fallback(&config, args.offline, args.refresh_cache);
        let ioc_total = ioc_radar
            .get("totals")
            .and_then(|totals| totals.get("total"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["iocs"] = json!(ioc_total);
        brief["ioc_radar"] = ioc_radar;

        let infrastructure_radar = fetch_infrastructure_radar_or_fallback(
            &config,
            &brief["ioc_radar"],
            args.offline,
            args.refresh_cache,
        );
        let infra_total = infrastructure_radar
            .get("totals")
            .and_then(|totals| totals.get("hosts"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["infrastructure_hosts"] = json!(infra_total);
        brief["infrastructure_radar"] = infrastructure_radar;

        let supply_chain =
            fetch_supply_chain_radar_or_fallback(&config, args.offline, args.refresh_cache);
        let supply_total = supply_chain
            .get("totals")
            .and_then(|totals| totals.get("advisories"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["supply_chain_advisories"] = json!(supply_total);
        brief["supply_chain_radar"] = supply_chain;

        let ransomware_pulse =
            fetch_ransomware_pulse_or_fallback(&config, args.offline, args.refresh_cache);
        let ransomware_total = ransomware_pulse
            .get("totals")
            .and_then(|totals| totals.get("victims"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["ransomware_victims"] = json!(ransomware_total);
        brief["ransomware_pulse"] = ransomware_pulse;

        let botnet_c2_pulse =
            fetch_botnet_c2_pulse_or_fallback(&config, args.offline, args.refresh_cache);
        let botnet_total = botnet_c2_pulse
            .get("totals")
            .and_then(|totals| totals.get("c2"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        let malicious_tls_total = botnet_c2_pulse
            .get("totals")
            .and_then(|totals| totals.get("tls"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["botnet_c2"] = json!(botnet_total);
        brief["stats"]["malicious_tls"] = json!(malicious_tls_total);
        brief["botnet_c2_pulse"] = botnet_c2_pulse;

        let executive_snapshot = build_executive_snapshot(&brief);
        brief["executive_snapshot"] = executive_snapshot;
        brief
    } else {
        let brief_raw = fs::read_to_string(&args.input)
            .with_context(|| format!("failed to read input JSON: {}", args.input.display()))?;
        serde_json::from_str(&brief_raw)
            .with_context(|| format!("invalid JSON in {}", args.input.display()))?
    };

    if args.ai {
        match enhance_brief_with_gemini(&config, &brief, args.refresh_ai, args.offline) {
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
    copy_static_assets(&args.out)?;
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

fn fetch_and_score(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<(Vec<FeedItem>, Vec<SourceFailure>)> {
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(18))
        .build()
        .context("failed to build HTTP client")?;

    let mut seen = HashSet::new();
    let mut all = Vec::new();
    let mut failures = Vec::new();

    for source in &config.sources {
        eprintln!("→ fetching {}", source.name);

        match fetch_source(&client, source, config, offline, refresh_cache) {
            Ok(mut items) => all.append(&mut items),
            Err(err) => {
                eprintln!("⚠️  skipped {}: {err:#}", source.name);
                failures.push(SourceFailure {
                    name: source.name.clone(),
                    url: source.url.clone(),
                    error: source_error_summary(&err.to_string()),
                });
            }
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
    Ok((deduped, failures))
}

fn source_error_summary(error: &str) -> String {
    let compact = clean_text(error);
    truncate_chars(&compact, 160)
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
            category: "general".to_string(),
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
        match fetch_epss_map(
            &client,
            config,
            cve_config,
            &ids,
            None,
            offline,
            refresh_cache,
        ) {
            Ok(epss_map) => {
                for cve in &mut cves {
                    if let Some(snapshot) = epss_map.get(&cve.cve_id) {
                        cve.epss = snapshot.epss;
                        cve.epss_percentile = snapshot.percentile;
                    }
                    finalize_cve_score(cve);
                }

                if cve_config.include_epss_momentum {
                    enrich_epss_momentum(
                        &client,
                        config,
                        cve_config,
                        &mut cves,
                        &ids,
                        rounded_end.date_naive(),
                        offline,
                        refresh_cache,
                    );
                }
            }
            Err(err) => eprintln!("⚠️  skipped EPSS enrichment: {err:#}"),
        }
    }

    if cve_config.include_vulnrichment && !cves.is_empty() {
        enrich_vulnrichment(
            &client,
            config,
            cve_config,
            &mut cves,
            offline,
            refresh_cache,
        );
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
    date: Option<NaiveDate>,
    offline: bool,
    refresh_cache: bool,
) -> Result<HashMap<String, EpssSnapshot>> {
    let label = match date {
        Some(day) => format!("EPSS API {day}"),
        None => "EPSS API".to_string(),
    };
    eprintln!("→ fetching {label} for {} CVEs", cve_ids.len());
    let joined = cve_ids.join(",");
    let mut query = vec![("cve", joined.as_str())];
    let date_s;
    if let Some(day) = date {
        date_s = day.format("%Y-%m-%d").to_string();
        query.push(("date", date_s.as_str()));
    }
    let bytes = get_bytes_cached(
        client,
        config,
        &cve_config.epss_url,
        &query,
        &label,
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
            let percentile = row
                .get("percentile")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(0.0);
            map.insert(cve.to_string(), EpssSnapshot { epss, percentile });
        }
    }

    Ok(map)
}

fn enrich_epss_momentum(
    client: &Client,
    config: &Config,
    cve_config: &CveConfig,
    cves: &mut [CveItem],
    ids: &[String],
    current_day: NaiveDate,
    offline: bool,
    refresh_cache: bool,
) {
    for days in &cve_config.epss_momentum_days {
        let day = current_day - ChronoDuration::days((*days).max(1));
        thread::sleep(Duration::from_millis(
            cve_config.sleep_ms_between_sources / 2,
        ));
        match fetch_epss_map(
            client,
            config,
            cve_config,
            ids,
            Some(day),
            offline,
            refresh_cache,
        ) {
            Ok(snapshot_map) => {
                for cve in cves.iter_mut() {
                    if let Some(snapshot) = snapshot_map.get(&cve.cve_id) {
                        match *days {
                            7 => {
                                cve.epss_7d = snapshot.epss;
                                cve.epss_delta_7d = cve.epss - snapshot.epss;
                            }
                            30 => {
                                cve.epss_30d = snapshot.epss;
                                cve.epss_delta_30d = cve.epss - snapshot.epss;
                            }
                            _ => {}
                        }
                    }
                    cve.epss_momentum = epss_momentum_label(cve.epss_delta_7d, cve.epss_delta_30d);
                }
            }
            Err(err) => eprintln!("⚠️  skipped EPSS momentum {days}d: {err:#}"),
        }
    }
}

fn epss_momentum_label(delta_7d: f64, delta_30d: f64) -> String {
    if delta_7d >= 0.10 || delta_30d >= 0.20 {
        "rising".to_string()
    } else if delta_7d <= -0.10 || delta_30d <= -0.20 {
        "falling".to_string()
    } else {
        "stable".to_string()
    }
}

fn enrich_vulnrichment(
    client: &Client,
    config: &Config,
    cve_config: &CveConfig,
    cves: &mut [CveItem],
    offline: bool,
    refresh_cache: bool,
) {
    eprintln!("→ fetching CISA Vulnrichment for selected CVEs");
    let mut checked = 0_usize;
    let mut hits = 0_usize;
    let mut missing = 0_usize;
    let mut errors = 0_usize;
    for cve in cves.iter_mut() {
        if checked >= cve_config.max_vulnrichment {
            break;
        }
        checked += 1;
        thread::sleep(Duration::from_millis(
            (cve_config.sleep_ms_between_sources / 3).max(150),
        ));
        match fetch_cisa_vulnrichment(
            client,
            config,
            cve_config,
            &cve.cve_id,
            offline,
            refresh_cache,
        ) {
            Ok(Some(enrichment)) => {
                hits += 1;
                apply_cisa_vulnrichment(cve, enrichment);
            }
            Ok(None) => {
                missing += 1;
            }
            Err(err) => {
                errors += 1;
                eprintln!(
                    "⚠️  CISA Vulnrichment transport error for {}: {err:#}",
                    cve.cve_id
                );
            }
        }
    }
    if checked > 0 {
        eprintln!(
            "  ↳ CISA Vulnrichment summary: {hits}/{checked} enriched, {missing} no-data, {errors} transport errors"
        );
    }
}

fn fetch_cisa_vulnrichment(
    client: &Client,
    config: &Config,
    cve_config: &CveConfig,
    cve_id: &str,
    offline: bool,
    refresh_cache: bool,
) -> Result<Option<CisaVulnrichment>> {
    let Some(url) = vulnrichment_url(&cve_config.vulnrichment_base_url, cve_id) else {
        return Ok(None);
    };

    let bytes = match get_bytes_cached(
        client,
        config,
        &url,
        &[],
        &format!("CISA Vulnrichment {cve_id}"),
        offline,
        refresh_cache,
    ) {
        Ok(bytes) => bytes,
        Err(err) => {
            let err_s = format!("{err:#}");
            if is_vulnrichment_no_data(&err_s) {
                return Ok(None);
            }
            return Err(err);
        }
    };
    let json: Value =
        serde_json::from_slice(&bytes).context("invalid JSON from CISA Vulnrichment")?;
    Ok(extract_cisa_vulnrichment(&json))
}

fn is_vulnrichment_no_data(error_text: &str) -> bool {
    let text = error_text.to_ascii_lowercase();
    text.contains("404")
        || text.contains("not found")
        || text.contains("no cached response")
        || text.contains("offline mode has no cached response")
}

fn vulnrichment_url(base_url: &str, cve_id: &str) -> Option<String> {
    let mut parts = cve_id.split('-');
    let _prefix = parts.next()?;
    let year = parts.next()?;
    let number_s = parts.next()?;
    let number = number_s.parse::<u64>().ok()?;
    let bucket = format!("{}xxx", number / 1000);
    Some(format!(
        "{}/{}/{}/{}.json",
        base_url.trim_end_matches('/'),
        year,
        bucket,
        cve_id
    ))
}

fn extract_cisa_vulnrichment(json: &Value) -> Option<CisaVulnrichment> {
    let mut out = CisaVulnrichment::default();
    let Some(adps) = json.pointer("/containers/adp").and_then(|v| v.as_array()) else {
        return None;
    };

    for adp in adps {
        let short_name = adp
            .pointer("/providerMetadata/shortName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        if !short_name.contains("cisa") {
            continue;
        }
        out.found = true;
        find_ssvc_options(adp, &mut out);
    }

    if out.found {
        out.priority = cisa_priority_from_ssvc(&out);
        Some(out)
    } else {
        None
    }
}

fn find_ssvc_options(value: &Value, out: &mut CisaVulnrichment) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "Exploitation" {
                    if let Some(s) = child.as_str() {
                        out.exploitation = s.to_string();
                    }
                } else if key == "Automatable" {
                    if let Some(s) = child.as_str() {
                        out.automatable = s.to_string();
                    }
                } else if key == "Technical Impact" {
                    if let Some(s) = child.as_str() {
                        out.technical_impact = s.to_string();
                    }
                }
                find_ssvc_options(child, out);
            }
        }
        Value::Array(items) => {
            for child in items {
                find_ssvc_options(child, out);
            }
        }
        _ => {}
    }
}

fn cisa_priority_from_ssvc(enrichment: &CisaVulnrichment) -> String {
    let exploitation = enrichment.exploitation.to_lowercase();
    let automatable = enrichment.automatable.to_lowercase();
    let impact = enrichment.technical_impact.to_lowercase();
    if exploitation.contains("active")
        || exploitation == "poc"
        || (automatable == "yes" && impact == "total")
    {
        "immediate-watch".to_string()
    } else if automatable == "yes" || impact == "total" {
        "elevated".to_string()
    } else {
        "tracked".to_string()
    }
}

fn apply_cisa_vulnrichment(cve: &mut CveItem, enrichment: CisaVulnrichment) {
    cve.cisa_vulnrichment = enrichment.found;
    cve.ssvc_exploitation = enrichment.exploitation;
    cve.ssvc_automatable = enrichment.automatable;
    cve.ssvc_technical_impact = enrichment.technical_impact;
    cve.cisa_priority = enrichment.priority;
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
            epss_percentile: 0.0,
            epss_7d: 0.0,
            epss_30d: 0.0,
            epss_delta_7d: 0.0,
            epss_delta_30d: 0.0,
            epss_momentum: "stable".to_string(),
            kev,
            cisa_vulnrichment: false,
            ssvc_exploitation: String::new(),
            ssvc_automatable: String::new(),
            ssvc_technical_impact: String::new(),
            cisa_priority: "unscored".to_string(),
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

    if cve.epss_momentum == "rising" {
        score += 1;
        push_tag(&mut tags, "EPSS rising".to_string());
    }

    if cve.cisa_priority == "immediate-watch" {
        score += 2;
        push_tag(&mut tags, "CISA priority".to_string());
    } else if cve.cisa_priority == "elevated" {
        score += 1;
        push_tag(&mut tags, "CISA elevated".to_string());
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
    } else if cve.cisa_priority == "immediate-watch" {
        "با توجه به SSVC/Vulnrichment، این CVE باید در watch فوری تیم دفاعی باشد.".to_string()
    } else if cve.epss_momentum == "rising" {
        "EPSS این CVE رو به رشد است؛ اولویت پایش و تطبیق با assetها را بالاتر ببر.".to_string()
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

    item.category = classify_news_category(&haystack).to_string();
    if item.category != "general" {
        push_tag(&mut tags, category_label(&item.category).to_string());
    }
    item.risk_score = score.clamp(1, 10);
    item.tags = tags.into_iter().take(5).collect();
}

fn classify_news_category(haystack: &str) -> &'static str {
    if haystack.contains("actively exploited")
        || haystack.contains("exploited in the wild")
        || haystack.contains("zero-day")
        || haystack.contains("zeroday")
        || haystack.contains("exploit")
    {
        "active_exploitation"
    } else if haystack.contains("cve-")
        || haystack.contains("vulnerability")
        || haystack.contains("patch")
        || haystack.contains("advisory")
    {
        "vulnerability"
    } else if haystack.contains("ransomware")
        || haystack.contains("malware")
        || haystack.contains("botnet")
        || haystack.contains("phishing")
        || haystack.contains("stealer")
    {
        "malware_incident"
    } else if haystack.contains(" ai ")
        || haystack.contains("artificial intelligence")
        || haystack.contains("llm")
        || haystack.contains("agentic")
    {
        "ai_security"
    } else {
        "general"
    }
}

fn category_label(category: &str) -> &'static str {
    match category {
        "active_exploitation" => "Active Exploit",
        "vulnerability" => "Vulnerability",
        "malware_incident" => "Malware/Incident",
        "ai_security" => "AI Security",
        _ => "General",
    }
}

fn fetch_attack_pressure_or_fallback(config: &Config, offline: bool, refresh_cache: bool) -> Value {
    if !config.intel.enabled || !config.intel.attack_pressure.enabled {
        return empty_attack_pressure("disabled");
    }

    match fetch_attack_pressure(config, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  Attack Pressure Radar skipped: {err:#}");
            let mut fallback = empty_attack_pressure("error");
            fallback["error"] = json!(err.to_string());
            fallback
        }
    }
}

fn fetch_attack_pressure(config: &Config, offline: bool, refresh_cache: bool) -> Result<Value> {
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(18))
        .build()
        .context("failed to build HTTP client for Attack Pressure Radar")?;

    let ap = &config.intel.attack_pressure;
    eprintln!("→ fetching DShield Attack Pressure feeds");

    let headline = fetch_dshield_port_feed(
        &client,
        config,
        &ap.top_ports_url,
        "DShield top ports",
        offline,
        refresh_cache,
        ap.max_ports,
    )?;
    thread::sleep(Duration::from_millis(config.intel.sleep_ms_between_sources));

    let scanning = fetch_dshield_port_feed(
        &client,
        config,
        &ap.top_ports_source_url,
        "DShield top ports by source IPs",
        offline,
        refresh_cache,
        ap.max_ports,
    )?;
    thread::sleep(Duration::from_millis(config.intel.sleep_ms_between_sources));

    let reports = fetch_dshield_port_feed(
        &client,
        config,
        &ap.top_ports_reports_url,
        "DShield top ports by reports",
        offline,
        refresh_cache,
        ap.max_ports,
    )?;
    thread::sleep(Duration::from_millis(config.intel.sleep_ms_between_sources));

    let targets = fetch_dshield_port_feed(
        &client,
        config,
        &ap.top_ports_targets_url,
        "DShield top ports by targets",
        offline,
        refresh_cache,
        ap.max_ports,
    )?;

    let all_ports = headline
        .iter()
        .chain(scanning.iter())
        .chain(reports.iter())
        .chain(targets.iter())
        .collect::<Vec<_>>();
    let high_risk_count = all_ports.iter().filter(|port| port.risk == "high").count();
    let medium_risk_count = all_ports
        .iter()
        .filter(|port| port.risk == "medium")
        .count();
    let level = if high_risk_count >= 6 {
        "High"
    } else if high_risk_count >= 2 || medium_risk_count >= 8 {
        "Medium"
    } else {
        "Low"
    };

    let summary_fa = match level {
        "High" => "چندین پورت حساس در feedهای DShield تکرار شده‌اند؛ فشار اسکن اینترنتی بالا ارزیابی می‌شود.",
        "Medium" => "چند سرویس پرریسک در بین پورت‌های هدف دیده می‌شود؛ وضعیت برای پایش روزانه قابل توجه است.",
        _ => "داده‌های DShield فشار غیرعادی شدیدی را نشان نمی‌دهد، اما سرویس‌های رایج همچنان زیر اسکن هستند.",
    };

    Ok(json!({
        "enabled": true,
        "ok": true,
        "provider": "SANS ISC / DShield",
        "source_url": "https://www.dshield.org/feeds_doc.html",
        "level": level,
        "summary_fa": summary_fa,
        "last_updated": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "cache_dir": config.intel.cache_dir.clone(),
        "refresh_hours": config.intel.refresh_hours,
        "top_ports": headline,
        "scanning_ports": scanning,
        "reported_ports": reports,
        "targeted_ports": targets
    }))
}

fn fetch_dshield_port_feed(
    client: &Client,
    config: &Config,
    url: &str,
    label: &str,
    offline: bool,
    refresh_cache: bool,
    limit: usize,
) -> Result<Vec<AttackPort>> {
    let bytes = get_bytes_cached_intel(client, config, url, label, offline, refresh_cache)?;
    let text = String::from_utf8_lossy(&bytes);
    let mut ports = parse_dshield_ports(&text);
    ports.truncate(limit);
    annotate_attack_ports(&mut ports);
    Ok(ports)
}

fn annotate_attack_ports(ports: &mut [AttackPort]) {
    let total = ports.len().max(1);
    for (idx, port) in ports.iter_mut().enumerate() {
        let relative = (((total - idx) as f64 / total as f64) * 100.0).round() as usize;
        port.pressure_score = relative.max(10);
        port.bar_width = relative.clamp(10, 100);
    }
}

fn parse_dshield_ports(text: &str) -> Vec<AttackPort> {
    let tokens = text.split_whitespace().collect::<Vec<_>>();
    let mut out = Vec::new();
    let mut i = 0;

    while i < tokens.len() {
        let Some(port) = tokens[i].parse::<u16>().ok() else {
            i += 1;
            continue;
        };
        i += 1;

        let service = tokens
            .get(i)
            .filter(|token| token.parse::<u16>().is_err())
            .map(|token| (*token).to_string())
            .unwrap_or_else(|| "unknown".to_string());
        if i < tokens.len() && tokens[i].parse::<u16>().is_err() {
            i += 1;
        }

        let mut desc_parts = Vec::new();
        while i < tokens.len() && tokens[i].parse::<u16>().is_err() {
            desc_parts.push(tokens[i]);
            i += 1;
        }

        let description = if desc_parts.is_empty() {
            service.clone()
        } else {
            desc_parts.join(" ")
        };

        let rank = out.len() + 1;
        out.push(AttackPort {
            rank,
            port,
            service: normalize_port_service(&service),
            description: clean_text(&description),
            risk: attack_port_risk(port).to_string(),
            note_fa: attack_port_note(port),
            pressure_score: 0,
            bar_width: 0,
        });
    }

    out
}

fn normalize_port_service(service: &str) -> String {
    let cleaned = service.trim_matches('-').trim();
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned.to_string()
    }
}

fn attack_port_risk(port: u16) -> &'static str {
    match port {
        21 | 22 | 23 | 445 | 3389 | 5900 | 6379 | 9200 | 11211 | 27017 => "high",
        80 | 443 | 8080 | 8443 | 8000 | 2222 | 5060 | 53 | 853 => "medium",
        _ => "watch",
    }
}

fn attack_port_note(port: u16) -> String {
    match port {
        22 | 2222 => "اسکن SSH؛ کلیدها، MFA، rate-limit و دسترسی public را بررسی کن.".to_string(),
        23 => "Telnet روی اینترنت پرریسک است؛ وجود آن در assetها باید سریع حذف یا محدود شود.".to_string(),
        80 | 443 | 8080 | 8000 | 8443 | 8081 => "فشار روی سرویس‌های وب؛ exposure، WAF، patch و لاگ‌های edge را پایش کن.".to_string(),
        445 => "SMB نباید public-facing باشد؛ هر exposure اینترنتی را بحرانی فرض کن.".to_string(),
        3389 => "RDP اینترنتی هدف رایج brute-force و exploit است؛ دسترسی را محدود و مانیتور کن.".to_string(),
        53 | 853 => "فعالیت DNS دیده می‌شود؛ resolverهای باز و policyهای recursive را بررسی کن.".to_string(),
        5060 => "SIP/VoIP زیر اسکن است؛ brute-force و تنظیمات exposed PBX را بررسی کن.".to_string(),
        _ => "این پورت در داده‌های DShield دیده شده؛ در صورت وجود در سطح اینترنت، مالکیت و ضرورت آن را بررسی کن.".to_string(),
    }
}

fn fetch_ioc_radar_or_fallback(config: &Config, offline: bool, refresh_cache: bool) -> Value {
    if !config.intel.enabled || !config.intel.ioc_radar.enabled {
        return empty_ioc_radar("disabled");
    }

    match fetch_ioc_radar(config, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  IOC Radar skipped: {err:#}");
            let mut fallback = empty_ioc_radar("error");
            fallback["error"] = json!(err.to_string());
            fallback
        }
    }
}

fn fetch_ioc_radar(config: &Config, offline: bool, refresh_cache: bool) -> Result<Value> {
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(24))
        .build()
        .context("failed to build HTTP client for IOC Radar")?;

    let ioc = &config.intel.ioc_radar;
    eprintln!("→ fetching IOC Radar feeds");

    let urlhaus_bytes = get_bytes_cached_intel(
        &client,
        config,
        &ioc.urlhaus_recent_csv_url,
        "URLhaus recent URLs",
        offline,
        refresh_cache,
    )?;
    thread::sleep(Duration::from_millis(config.intel.sleep_ms_between_sources));

    let threatfox_bytes = get_bytes_cached_intel(
        &client,
        config,
        &ioc.threatfox_recent_csv_url,
        "ThreatFox recent IOCs",
        offline,
        refresh_cache,
    )?;

    let mut urlhaus = parse_urlhaus_recent_csv(&String::from_utf8_lossy(&urlhaus_bytes));
    let mut threatfox = parse_threatfox_recent_csv(&String::from_utf8_lossy(&threatfox_bytes));
    urlhaus.truncate(ioc.max_urlhaus);
    threatfox.truncate(ioc.max_threatfox);
    finalize_ioc_indicators(&mut urlhaus);
    finalize_ioc_indicators(&mut threatfox);

    let all = urlhaus
        .iter()
        .chain(threatfox.iter())
        .cloned()
        .collect::<Vec<_>>();
    let type_chart = ioc_count_chart(&all, |item| item.indicator_type.as_str(), 7);
    let malware_chart = ioc_count_chart(&all, |item| item.malware.as_str(), 8);
    let source_chart = ioc_count_chart(&all, |item| item.source.as_str(), 4);
    let high_count = all.iter().filter(|item| item.risk == "high").count();
    let watch_count = all.iter().filter(|item| item.risk == "watch").count();

    let level = if high_count >= 12 {
        "High"
    } else if high_count >= 5 || watch_count >= 18 {
        "Medium"
    } else {
        "Low"
    };

    let summary_fa = match level {
        "High" => "حجم IOCهای تازه و چند خانواده بدافزاری قابل توجه است؛ این بخش برای آگاهی موقعیتی و triage دفاعی است.",
        "Medium" => "IOCهای تازه از URLhaus و ThreatFox دریافت شده‌اند؛ چند نوع indicator و خانواده بدافزاری دیده می‌شود.",
        _ => "IOCهای تازه دریافت شد، اما شدت کلی در این اجرا پایین ارزیابی می‌شود.",
    };

    Ok(json!({
        "enabled": true,
        "ok": true,
        "provider": "abuse.ch URLhaus + ThreatFox",
        "source_urls": [
            "https://urlhaus.abuse.ch/api/",
            "https://threatfox.abuse.ch/api/"
        ],
        "level": level,
        "summary_fa": summary_fa,
        "last_updated": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "cache_dir": config.intel.cache_dir.clone(),
        "refresh_hours": config.intel.refresh_hours,
        "totals": {
            "urlhaus": urlhaus.len(),
            "threatfox": threatfox.len(),
            "total": all.len(),
            "high": high_count,
            "watch": watch_count
        },
        "urlhaus": urlhaus,
        "threatfox": threatfox,
        "type_chart": type_chart,
        "malware_chart": malware_chart,
        "source_chart": source_chart
    }))
}

fn parse_urlhaus_recent_csv(text: &str) -> Vec<IocIndicator> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = split_csv_line(line);
        if fields.len() < 4 || fields[0].eq_ignore_ascii_case("id") {
            continue;
        }

        let date_added = fields.get(1).cloned().unwrap_or_default();
        let url = fields.get(2).cloned().unwrap_or_default();
        if url.is_empty() || !url.contains('.') {
            continue;
        }
        let status = fields.get(3).cloned().unwrap_or_default();
        let threat = fields
            .get(5)
            .cloned()
            .unwrap_or_else(|| "malware_download".to_string());
        let tags = parse_tag_list(fields.get(6).map(String::as_str).unwrap_or(""));
        let malware = first_useful_tag(&tags).unwrap_or_else(|| normalize_family(&threat));

        out.push(IocIndicator {
            rank: out.len() + 1,
            source: "URLhaus".to_string(),
            indicator_type: "url".to_string(),
            indicator: url.clone(),
            indicator_safe: defang_indicator(&url),
            threat_type: non_empty_or(threat, "malware_url"),
            malware,
            first_seen: date_added,
            confidence: if status.eq_ignore_ascii_case("online") {
                85
            } else {
                65
            },
            risk: "watch".to_string(),
            risk_score: 0,
            bar_width: 0,
            tags,
            note_fa: String::new(),
        });
    }
    out
}

fn parse_threatfox_recent_csv(text: &str) -> Vec<IocIndicator> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = split_csv_line(line);
        if fields.len() < 5 || fields[0].to_lowercase().contains("first_seen") {
            continue;
        }

        let first_seen = fields.first().cloned().unwrap_or_default();
        let indicator = fields
            .get(2)
            .cloned()
            .or_else(|| fields.get(1).cloned())
            .unwrap_or_default();
        if indicator.trim().is_empty() || indicator.eq_ignore_ascii_case("ioc_value") {
            continue;
        }
        let indicator_type = fields
            .get(3)
            .cloned()
            .unwrap_or_else(|| infer_indicator_type(&indicator));
        let threat_type = fields
            .get(4)
            .cloned()
            .unwrap_or_else(|| "malware_ioc".to_string());
        let malware = fields
            .get(7)
            .filter(|value| {
                !value.trim().is_empty()
                    && value.trim() != "-"
                    && !value.contains("malware_printable")
            })
            .cloned()
            .or_else(|| fields.get(5).cloned())
            .unwrap_or_else(|| normalize_family(&threat_type));
        let confidence = fields
            .iter()
            .filter_map(|value| value.trim().parse::<usize>().ok())
            .find(|value| *value <= 100)
            .unwrap_or(70);
        let tags = fields
            .iter()
            .rev()
            .find(|value| value.contains(',') || value.contains('|'))
            .map(|value| parse_tag_list(value))
            .unwrap_or_default();

        out.push(IocIndicator {
            rank: out.len() + 1,
            source: "ThreatFox".to_string(),
            indicator_type: normalize_ioc_type(&indicator_type),
            indicator: indicator.clone(),
            indicator_safe: defang_indicator(&indicator),
            threat_type: non_empty_or(threat_type, "malware_ioc"),
            malware: normalize_family(&malware),
            first_seen,
            confidence,
            risk: "watch".to_string(),
            risk_score: 0,
            bar_width: 0,
            tags,
            note_fa: String::new(),
        });
    }
    out
}

fn finalize_ioc_indicators(items: &mut [IocIndicator]) {
    let total = items.len().max(1);
    for (idx, item) in items.iter_mut().enumerate() {
        item.rank = idx + 1;
        item.indicator_type = normalize_ioc_type(&item.indicator_type);
        item.threat_type = normalize_family(&item.threat_type);
        item.malware = normalize_family(&item.malware);
        item.indicator_safe = defang_indicator(&item.indicator);

        let mut score = 35 + ((total - idx) * 50 / total);
        let lower =
            format!("{} {} {}", item.indicator, item.threat_type, item.malware).to_lowercase();
        if lower.contains("botnet")
            || lower.contains("stealer")
            || lower.contains("ransom")
            || lower.contains("loader")
        {
            score += 10;
        }
        if matches!(item.indicator_type.as_str(), "url" | "domain" | "ip") {
            score += 5;
        }
        if item.confidence >= 80 {
            score += 6;
        }
        item.risk_score = score.clamp(10, 100);
        item.bar_width = item.risk_score.clamp(10, 100);
        item.risk = if item.risk_score >= 78 {
            "high".to_string()
        } else if item.risk_score >= 55 {
            "medium".to_string()
        } else {
            "watch".to_string()
        };
        item.note_fa = ioc_note(&item.indicator_type, &item.malware);
        item.tags = item
            .tags
            .iter()
            .filter(|tag| !tag.trim().is_empty())
            .take(4)
            .cloned()
            .collect();
    }
}

fn ioc_count_chart<F>(items: &[IocIndicator], key_fn: F, limit: usize) -> Vec<Value>
where
    F: Fn(&IocIndicator) -> &str,
{
    let mut counts: HashMap<String, usize> = HashMap::new();
    for item in items {
        let key = normalize_family(key_fn(item));
        if !key.trim().is_empty() && key != "unknown" && key != "-" {
            *counts.entry(key).or_insert(0) += 1;
        }
    }

    let mut rows = counts.into_iter().collect::<Vec<_>>();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let max = rows
        .iter()
        .map(|(_, count)| *count)
        .max()
        .unwrap_or(1)
        .max(1);
    rows.into_iter()
        .take(limit)
        .map(|(name, count)| {
            let width = ((count as f64 / max as f64) * 100.0).round() as usize;
            json!({
                "name": truncate_chars(&name, 38),
                "count": count,
                "bar_width": width.clamp(12, 100)
            })
        })
        .collect()
}

fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(current.trim().trim_matches('"').to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    fields.push(current.trim().trim_matches('"').to_string());
    fields
}

fn parse_tag_list(raw: &str) -> Vec<String> {
    raw.split(&[',', '|', ';'][..])
        .map(|tag| {
            tag.trim()
                .trim_matches('"')
                .trim_matches('[')
                .trim_matches(']')
        })
        .filter(|tag| !tag.is_empty() && *tag != "-" && !tag.eq_ignore_ascii_case("null"))
        .map(|tag| truncate_chars(tag, 28))
        .take(6)
        .collect()
}

fn first_useful_tag(tags: &[String]) -> Option<String> {
    tags.iter()
        .find(|tag| {
            !matches!(
                tag.to_lowercase().as_str(),
                "elf" | "exe" | "payload" | "malware" | "download"
            )
        })
        .map(|tag| normalize_family(tag))
}

fn normalize_ioc_type(value: &str) -> String {
    let lower = value
        .trim()
        .trim_matches('"')
        .to_lowercase()
        .replace('-', "_");
    if lower.contains("url") || lower.starts_with("http") {
        "url".to_string()
    } else if lower.contains("domain") || lower.contains("hostname") || lower == "fqdn" {
        "domain".to_string()
    } else if lower.contains("ip") || lower.contains("ipv4") || lower.contains("ipv6") {
        "ip".to_string()
    } else if lower.contains("sha") || lower.contains("md5") || lower.contains("hash") {
        "hash".to_string()
    } else if lower.is_empty() {
        "unknown".to_string()
    } else {
        truncate_chars(&lower, 24)
    }
}

fn infer_indicator_type(value: &str) -> String {
    let lower = value.to_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        "url".to_string()
    } else if lower.parse::<std::net::IpAddr>().is_ok() {
        "ip".to_string()
    } else if lower.len() >= 32 && lower.chars().all(|ch| ch.is_ascii_hexdigit()) {
        "hash".to_string()
    } else if lower.contains('.') {
        "domain".to_string()
    } else {
        "unknown".to_string()
    }
}

fn normalize_family(value: &str) -> String {
    let cleaned = value
        .trim()
        .trim_matches('"')
        .trim_matches('-')
        .replace('_', " ")
        .replace("malware ", "")
        .replace("Malware ", "");
    if cleaned.trim().is_empty() {
        "unknown".to_string()
    } else {
        truncate_chars(cleaned.trim(), 36)
    }
}

fn non_empty_or(value: String, fallback: &str) -> String {
    if value.trim().is_empty() || value.trim() == "-" {
        fallback.to_string()
    } else {
        value
    }
}

fn defang_indicator(value: &str) -> String {
    let mut out = value.trim().to_string();
    out = out
        .replace("https://", "hxxps://")
        .replace("http://", "hxxp://");
    out = out.replace('.', "[.]");
    truncate_chars(&out, 96)
}

fn ioc_note(indicator_type: &str, malware: &str) -> String {
    match indicator_type {
        "url" => "URL بدافزاری defanged نمایش داده شده؛ آن را مستقیم باز نکن و فقط برای correlation دفاعی استفاده کن.".to_string(),
        "domain" => "دامنه IOC برای correlation در DNS logs، proxy و EDR مناسب است؛ از کلیک مستقیم خودداری شود.".to_string(),
        "ip" => "IP IOC را با firewall/proxy/EDR logs تطبیق بده و قبل از block، مالکیت و false positive را بررسی کن.".to_string(),
        "hash" => format!("Hash مرتبط با {malware} برای hunting در EDR و فایل‌لاگ‌ها قابل استفاده است."),
        _ => "IOC تازه برای آگاهی موقعیتی نمایش داده شده؛ قبل از اقدام، با منبع و لاگ داخلی تطبیق بده.".to_string(),
    }
}

fn empty_ioc_radar(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "abuse.ch URLhaus + ThreatFox",
        "level": "Unknown",
        "summary_fa": "داده IOC Radar در این اجرا در دسترس نبود.",
        "last_updated": "",
        "refresh_hours": 1,
        "totals": {"urlhaus": 0, "threatfox": 0, "total": 0, "high": 0, "watch": 0},
        "urlhaus": [],
        "threatfox": [],
        "type_chart": [],
        "malware_chart": [],
        "source_chart": []
    })
}

fn fetch_infrastructure_radar_or_fallback(
    config: &Config,
    ioc_radar: &Value,
    offline: bool,
    refresh_cache: bool,
) -> Value {
    if !config.intel.enabled || !config.intel.infrastructure.enabled {
        return empty_infrastructure_radar("disabled");
    }

    match fetch_infrastructure_radar(config, ioc_radar, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  Suspicious Infrastructure Radar skipped: {err:#}");
            let mut fallback = empty_infrastructure_radar("error");
            fallback["error"] = json!(err.to_string());
            fallback
        }
    }
}

fn fetch_infrastructure_radar(
    config: &Config,
    ioc_radar: &Value,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
    let infra = &config.intel.infrastructure;
    eprintln!("→ fetching Suspicious Infrastructure radar");

    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(18))
        .build()
        .context("failed to build HTTP client for Suspicious Infrastructure Radar")?;

    let candidates = infrastructure_candidates_from_sources(
        &client,
        config,
        ioc_radar,
        offline,
        refresh_cache,
        infra.max_ips,
    );
    if candidates.is_empty() {
        return Ok(json!({
            "enabled": true,
            "ok": true,
            "provider": "Shodan InternetDB + DShield top IPs",
            "level": "Low",
            "summary_fa": "در IOCها یا DShield Top IPs این اجرا IP عمومی مناسبی برای رادار زیرساختی دیده نشد.",
            "last_updated": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            "source_url": "https://internetdb.shodan.io/",
            "cache_dir": config.intel.cache_dir.clone(),
            "refresh_hours": config.intel.refresh_hours,
            "totals": {"candidates": 0, "hosts": 0, "high": 0, "vulns": 0},
            "hosts": [],
            "port_chart": [],
            "risk_chart": []
        }));
    }

    let mut hosts = Vec::new();
    for (idx, candidate) in candidates.iter().enumerate() {
        if idx > 0 {
            thread::sleep(Duration::from_millis(config.intel.sleep_ms_between_sources));
        }
        match fetch_shodan_internetdb_host(&client, config, candidate, offline, refresh_cache) {
            Ok(Some(host)) => hosts.push(host),
            Ok(None) => hosts.push(candidate_only_infrastructure_host(candidate)),
            Err(err) => {
                eprintln!("⚠️  skipped Shodan InternetDB {}: {err:#}", candidate.ip);
                hosts.push(candidate_only_infrastructure_host(candidate));
            }
        }
    }

    finalize_infrastructure_hosts(&mut hosts);
    let high_count = hosts.iter().filter(|host| host.risk == "high").count();
    let vuln_count = hosts.iter().map(|host| host.vuln_count).sum::<usize>();
    let total_ports = hosts.iter().map(|host| host.port_count).sum::<usize>();

    let level = if high_count >= 4 || vuln_count >= 6 {
        "High"
    } else if high_count >= 1 || total_ports >= 20 {
        "Medium"
    } else {
        "Low"
    };

    let summary_fa = match level {
        "High" => "چند IP مشکوک دارای پورت‌های باز یا نشانه آسیب‌پذیری هستند؛ این بخش برای exposure awareness است.",
        "Medium" => "چند IP استخراج‌شده از IOCها سطح exposure قابل مشاهده دارند؛ برای correlation دفاعی مناسب است.",
        _ => "زیرساخت‌های استخراج‌شده از IOCها exposure محدودی در InternetDB نشان می‌دهند.",
    };

    let port_chart = infrastructure_port_chart(&hosts, 10);
    let risk_chart = infrastructure_risk_chart(&hosts);

    Ok(json!({
        "enabled": true,
        "ok": true,
        "provider": "Shodan InternetDB + DShield top IPs",
        "source_url": "https://internetdb.shodan.io/",
        "level": level,
        "summary_fa": summary_fa,
        "last_updated": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "cache_dir": config.intel.cache_dir.clone(),
        "refresh_hours": config.intel.refresh_hours,
        "totals": {
            "candidates": candidates.len(),
            "hosts": hosts.len(),
            "high": high_count,
            "vulns": vuln_count,
            "ports": total_ports
        },
        "hosts": hosts,
        "port_chart": port_chart,
        "risk_chart": risk_chart
    }))
}

fn fetch_shodan_internetdb_host(
    client: &Client,
    config: &Config,
    candidate: &InfraCandidate,
    offline: bool,
    refresh_cache: bool,
) -> Result<Option<InfrastructureHost>> {
    let url = format!(
        "{}/{}",
        config
            .intel
            .infrastructure
            .shodan_base_url
            .trim_end_matches('/'),
        candidate.ip
    );
    let label = format!("Shodan InternetDB {}", candidate.ip);
    let bytes = match get_bytes_cached_intel(client, config, &url, &label, offline, refresh_cache) {
        Ok(bytes) => bytes,
        Err(err) => {
            let msg = err.to_string();
            if msg.contains("404") || msg.contains("offline mode has no cached response") {
                return Ok(None);
            }
            return Err(err);
        }
    };

    let value: Value = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "Shodan InternetDB response was not JSON for {}",
            candidate.ip
        )
    })?;

    let ports = value
        .get("ports")
        .and_then(|v| v.as_array())
        .map(|items| {
            let mut ports = items
                .iter()
                .filter_map(|item| item.as_u64().and_then(|port| u16::try_from(port).ok()))
                .collect::<Vec<_>>();
            ports.sort_unstable();
            ports.dedup();
            ports
        })
        .unwrap_or_default();

    let hostnames = take_string_array(value.get("hostnames"), 4, 48);
    let tags = take_string_array(value.get("tags"), 6, 28);
    let vulns = take_vulns(value.get("vulns"), 5);
    let cpes = take_string_array(value.get("cpes"), 4, 60);

    if ports.is_empty()
        && hostnames.is_empty()
        && tags.is_empty()
        && vulns.is_empty()
        && cpes.is_empty()
    {
        return Ok(None);
    }

    let risky_ports = ports
        .iter()
        .filter(|port| is_risky_exposed_port(**port))
        .count();
    let mut exposure_score = ports.len().saturating_mul(8)
        + risky_ports.saturating_mul(18)
        + vulns.len().saturating_mul(26)
        + tags
            .iter()
            .filter(|tag| is_exposure_tag(tag))
            .count()
            .saturating_mul(12);
    exposure_score = exposure_score.clamp(8, 100);

    let risk = if !vulns.is_empty() || exposure_score >= 72 {
        "high"
    } else if exposure_score >= 36 || ports.len() >= 4 {
        "medium"
    } else {
        "watch"
    }
    .to_string();

    let note_fa = infrastructure_note(&ports, vulns.len(), &tags);

    Ok(Some(InfrastructureHost {
        rank: 0,
        ip: candidate.ip.clone(),
        source: candidate.source.clone(),
        first_seen: candidate.first_seen.clone(),
        reason: candidate.reason.clone(),
        ports,
        port_count: 0,
        hostnames,
        tags,
        vulns,
        vuln_count: 0,
        exposure_score,
        bar_width: 0,
        risk,
        note_fa,
    }))
}

fn infrastructure_candidates_from_sources(
    client: &Client,
    config: &Config,
    ioc_radar: &Value,
    offline: bool,
    refresh_cache: bool,
    limit: usize,
) -> Vec<InfraCandidate> {
    let mut out = infrastructure_candidates_from_iocs(ioc_radar, limit);
    if out.len() >= limit {
        return out;
    }

    let mut seen = out
        .iter()
        .map(|item| item.ip.clone())
        .collect::<HashSet<_>>();
    match fetch_dshield_top_ip_candidates(
        client,
        config,
        offline,
        refresh_cache,
        limit.saturating_sub(out.len()),
    ) {
        Ok(mut dshield_items) => {
            for item in dshield_items.drain(..) {
                if seen.insert(item.ip.clone()) {
                    out.push(item);
                    if out.len() >= limit {
                        break;
                    }
                }
            }
        }
        Err(err) => eprintln!("⚠️  skipped DShield top IP candidates: {err:#}"),
    }

    out
}

fn fetch_dshield_top_ip_candidates(
    client: &Client,
    config: &Config,
    offline: bool,
    refresh_cache: bool,
    limit: usize,
) -> Result<Vec<InfraCandidate>> {
    if limit == 0 {
        return Ok(Vec::new());
    }

    let bytes = get_bytes_cached_intel(
        client,
        config,
        &config.intel.infrastructure.dshield_top_ips_url,
        "DShield top source IPs",
        offline,
        refresh_cache,
    )?;
    let text = String::from_utf8_lossy(&bytes);
    Ok(parse_dshield_top_ip_candidates(&text, limit))
}

fn parse_dshield_top_ip_candidates(text: &str, limit: usize) -> Vec<InfraCandidate> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(ip) = line.split_whitespace().find_map(|token| {
            parse_public_ip(
                token.trim_matches(|ch: char| ch == ',' || ch == ';' || ch == '(' || ch == ')'),
            )
        }) else {
            continue;
        };
        if !seen.insert(ip.clone()) {
            continue;
        }

        let mut numeric = line
            .split_whitespace()
            .filter_map(|token| token.replace(',', "").parse::<usize>().ok())
            .collect::<Vec<_>>();
        numeric.sort_unstable_by(|a, b| b.cmp(a));
        let report_hint = numeric.first().copied().unwrap_or(0);
        let reason = if report_hint > 0 {
            format!("DShield top scanner · {} reports", report_hint)
        } else {
            "DShield top scanner".to_string()
        };

        out.push(InfraCandidate {
            ip,
            source: "DShield Top IPs".to_string(),
            first_seen: String::new(),
            reason,
        });
        if out.len() >= limit {
            break;
        }
    }

    out
}

fn candidate_only_infrastructure_host(candidate: &InfraCandidate) -> InfrastructureHost {
    InfrastructureHost {
        rank: 0,
        ip: candidate.ip.clone(),
        source: candidate.source.clone(),
        first_seen: candidate.first_seen.clone(),
        reason: candidate.reason.clone(),
        ports: Vec::new(),
        port_count: 0,
        hostnames: Vec::new(),
        tags: vec!["observed-scanner".to_string()],
        vulns: Vec::new(),
        vuln_count: 0,
        exposure_score: 32,
        bar_width: 0,
        risk: "watch".to_string(),
        note_fa: "این IP در feedهای IOC/DShield دیده شده، اما InternetDB برای آن exposure قابل مشاهده‌ای برنگرداند.".to_string(),
    }
}

fn infrastructure_candidates_from_iocs(ioc_radar: &Value, limit: usize) -> Vec<InfraCandidate> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for section in ["urlhaus", "threatfox"] {
        let Some(items) = ioc_radar.get(section).and_then(|v| v.as_array()) else {
            continue;
        };
        for item in items {
            let indicator = item
                .get("indicator")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let ips = extract_public_ips_from_indicator(indicator);
            if ips.is_empty() {
                continue;
            }
            let source = item
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or(section)
                .to_string();
            let malware = item
                .get("malware")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let indicator_type = item
                .get("indicator_type")
                .and_then(|v| v.as_str())
                .unwrap_or("ioc");
            let first_seen = item
                .get("first_seen")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            for ip in ips {
                if seen.insert(ip.clone()) {
                    out.push(InfraCandidate {
                        ip,
                        source: source.clone(),
                        first_seen: first_seen.clone(),
                        reason: format!("{} · {}", truncate_chars(malware, 28), indicator_type),
                    });
                    if out.len() >= limit {
                        return out;
                    }
                }
            }
        }
    }

    out
}

fn extract_public_ips_from_indicator(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let trimmed = value.trim().trim_matches('"');

    if let Some(ip) = parse_public_ip(trimmed) {
        out.push(ip);
    }

    if let Some(host) = extract_host_from_url(trimmed) {
        if let Some(ip) = parse_public_ip(&host) {
            out.push(ip);
        }
    }

    for candidate in trimmed.split(|ch: char| !(ch.is_ascii_digit() || ch == '.')) {
        if candidate.len() < 7 || candidate.matches('.').count() != 3 {
            continue;
        }
        if let Some(ip) = parse_public_ip(candidate) {
            out.push(ip);
        }
    }

    out.sort();
    out.dedup();
    out
}

fn extract_host_from_url(value: &str) -> Option<String> {
    let after_scheme = value
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(value);
    let authority = after_scheme.split('/').next()?.split('@').last()?.trim();
    if authority.is_empty() {
        return None;
    }
    let host = if authority.starts_with('[') {
        authority
            .trim_start_matches('[')
            .split(']')
            .next()?
            .to_string()
    } else {
        authority.split(':').next()?.to_string()
    };
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn parse_public_ip(value: &str) -> Option<String> {
    let ip = value.parse::<std::net::IpAddr>().ok()?;
    if is_public_ip(&ip) {
        Some(ip.to_string())
    } else {
        None
    }
}

fn is_public_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || v4.is_unspecified()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1])))
        }
        std::net::IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_multicast() || v6.is_unspecified()),
    }
}

fn take_string_array(value: Option<&Value>, limit: usize, max_chars: usize) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .map(|s| truncate_chars(s.trim(), max_chars))
                .filter(|s| !s.is_empty())
                .take(limit)
                .collect()
        })
        .unwrap_or_default()
}

fn take_vulns(value: Option<&Value>, limit: usize) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(|s| s.to_string()))
            .take(limit)
            .collect(),
        Some(Value::Object(map)) => map.keys().take(limit).cloned().collect(),
        _ => Vec::new(),
    }
}

fn finalize_infrastructure_hosts(hosts: &mut [InfrastructureHost]) {
    hosts.sort_by(|a, b| {
        b.exposure_score
            .cmp(&a.exposure_score)
            .then_with(|| a.ip.cmp(&b.ip))
    });
    let max_score = hosts
        .iter()
        .map(|host| host.exposure_score)
        .max()
        .unwrap_or(1)
        .max(1);
    for (idx, host) in hosts.iter_mut().enumerate() {
        host.rank = idx + 1;
        host.port_count = host.ports.len();
        host.vuln_count = host.vulns.len();
        host.bar_width = (((host.exposure_score as f64 / max_score as f64) * 100.0).round()
            as usize)
            .clamp(12, 100);
    }
}

fn infrastructure_port_chart(hosts: &[InfrastructureHost], limit: usize) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for host in hosts {
        for port in &host.ports {
            *counts.entry(port.to_string()).or_insert(0) += 1;
        }
    }
    count_chart_from_counts(counts, limit)
}

fn infrastructure_risk_chart(hosts: &[InfrastructureHost]) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for host in hosts {
        *counts.entry(host.risk.clone()).or_insert(0) += 1;
    }
    count_chart_from_counts(counts, 4)
}

fn count_chart_from_counts(mut counts: HashMap<String, usize>, limit: usize) -> Vec<Value> {
    let mut rows = counts.drain().collect::<Vec<_>>();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let max = rows
        .iter()
        .map(|(_, count)| *count)
        .max()
        .unwrap_or(1)
        .max(1);
    rows.into_iter()
        .take(limit)
        .map(|(name, count)| {
            let width = ((count as f64 / max as f64) * 100.0).round() as usize;
            json!({
                "name": truncate_chars(&name, 38),
                "count": count,
                "bar_width": width.clamp(12, 100)
            })
        })
        .collect()
}

fn is_risky_exposed_port(port: u16) -> bool {
    matches!(
        port,
        21 | 22
            | 23
            | 25
            | 110
            | 139
            | 143
            | 445
            | 1433
            | 1521
            | 3306
            | 3389
            | 5432
            | 5900
            | 6379
            | 9200
            | 11211
            | 27017
    )
}

fn is_exposure_tag(tag: &str) -> bool {
    let lower = tag.to_lowercase();
    lower.contains("vpn")
        || lower.contains("database")
        || lower.contains("ics")
        || lower.contains("industrial")
        || lower.contains("remote")
        || lower.contains("compromised")
}

fn infrastructure_note(ports: &[u16], vuln_count: usize, tags: &[String]) -> String {
    if vuln_count > 0 {
        return "InternetDB برای این IP نشانه CVE نشان می‌دهد؛ فقط برای آگاهی و correlation دفاعی استفاده شود.".to_string();
    }
    if ports
        .iter()
        .any(|port| matches!(port, 445 | 3389 | 23 | 5900))
    {
        return "پورت‌های مدیریت/شبکه پرریسک دیده می‌شود؛ exposure را در assetهای خودتان تطبیق بدهید.".to_string();
    }
    if tags.iter().any(|tag| is_exposure_tag(tag)) {
        return "Tagهای Shodan نشان‌دهنده سرویس حساس احتمالی است؛ برای surface awareness بررسی شود."
            .to_string();
    }
    "این IP از IOCها استخراج و با InternetDB enrich شده؛ خروجی فقط برای رادار مشاهده‌ای است."
        .to_string()
}

fn fetch_botnet_c2_pulse_or_fallback(config: &Config, offline: bool, refresh_cache: bool) -> Value {
    if !config.intel.enabled || !config.intel.botnet_c2.enabled {
        return empty_botnet_c2_pulse("disabled");
    }

    match fetch_botnet_c2_pulse(config, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  Botnet C2 Pulse skipped: {err:#}");
            let mut fallback = empty_botnet_c2_pulse("error");
            fallback["error"] = json!(err.to_string());
            fallback
        }
    }
}

fn fetch_botnet_c2_pulse(config: &Config, offline: bool, refresh_cache: bool) -> Result<Value> {
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(24))
        .build()
        .context("failed to build HTTP client for Botnet C2 Pulse")?;

    let cfg = &config.intel.botnet_c2;
    eprintln!("→ fetching Botnet C2 Pulse");

    let feodo_bytes = get_bytes_cached_intel(
        &client,
        config,
        &cfg.feodo_ipblocklist_csv_url,
        "Feodo Tracker C2 blocklist",
        offline,
        refresh_cache,
    )?;
    thread::sleep(Duration::from_millis(config.intel.sleep_ms_between_sources));

    let ja3_bytes = get_bytes_cached_intel(
        &client,
        config,
        &cfg.sslbl_ja3_csv_url,
        "SSLBL JA3 blacklist",
        offline,
        refresh_cache,
    )?;
    thread::sleep(Duration::from_millis(config.intel.sleep_ms_between_sources));

    let cert_bytes = get_bytes_cached_intel(
        &client,
        config,
        &cfg.sslbl_cert_csv_url,
        "SSLBL certificate blacklist",
        offline,
        refresh_cache,
    )?;

    let mut c2 = parse_feodo_c2_csv(&String::from_utf8_lossy(&feodo_bytes));
    let mut tls = parse_sslbl_ja3_csv(&String::from_utf8_lossy(&ja3_bytes));
    tls.extend(parse_sslbl_cert_csv(&String::from_utf8_lossy(&cert_bytes)));

    finalize_botnet_c2(&mut c2);
    finalize_tls_threats(&mut tls);
    c2.truncate(cfg.max_c2);
    tls.truncate(cfg.max_tls);

    let c2_high = c2.iter().filter(|item| item.risk == "high").count();
    let tls_high = tls.iter().filter(|item| item.risk == "high").count();
    let family_names = c2
        .iter()
        .map(|item| item.malware.clone())
        .collect::<Vec<_>>();
    let port_names = c2
        .iter()
        .map(|item| item.port.to_string())
        .collect::<Vec<_>>();
    let tls_reason_names = tls
        .iter()
        .map(|item| item.reason.clone())
        .collect::<Vec<_>>();
    let family_chart = count_chart_names(&family_names, 7);
    let port_chart = count_chart_names(&port_names, 6);
    let tls_chart = count_chart_names(&tls_reason_names, 6);

    let level = if c2_high >= 8 || tls_high >= 10 {
        "High"
    } else if c2.len() >= 8 || tls.len() >= 8 {
        "Medium"
    } else {
        "Low"
    };

    let summary_fa = match level {
        "High" => "چند C2 و fingerprint بدخواه تازه از Feodo و SSLBL دیده شده؛ این بخش فقط metadata دفاعی و defanged نمایش می‌دهد.",
        "Medium" => "چند سیگنال botnet C2 و TLS بدخواه دریافت شد؛ برای correlation با IOC و زیرساخت مشکوک مناسب است.",
        _ => "حجم سیگنال‌های botnet C2 و TLS در این اجرا پایین است.",
    };

    Ok(json!({
        "enabled": true,
        "ok": true,
        "provider": "Feodo Tracker + SSLBL",
        "source_urls": [
            "https://feodotracker.abuse.ch/blocklist/",
            "https://sslbl.abuse.ch/blacklist/"
        ],
        "level": level,
        "summary_fa": summary_fa,
        "last_updated": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "metadata_only": true,
        "totals": {
            "c2": c2.len(),
            "tls": tls.len(),
            "high": c2_high + tls_high,
            "families": family_chart.len(),
            "ports": port_chart.len()
        },
        "c2": c2,
        "tls": tls,
        "family_chart": family_chart,
        "port_chart": port_chart,
        "tls_chart": tls_chart
    }))
}

fn parse_feodo_c2_csv(text: &str) -> Vec<BotnetC2Indicator> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = split_csv_line(line);
        if fields.len() < 4 || fields[0].to_lowercase().contains("first_seen") {
            continue;
        }

        let Some(ip_index) = fields.iter().position(|value| looks_like_ipv4(value)) else {
            continue;
        };
        let first_seen = if ip_index > 0 {
            fields.first().cloned().unwrap_or_default()
        } else {
            String::new()
        };
        let ip = fields.get(ip_index).cloned().unwrap_or_default();
        let port = fields
            .get(ip_index + 1)
            .and_then(|value| value.trim().parse::<u16>().ok())
            .unwrap_or(0);
        let status = fields
            .get(ip_index + 2)
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let malware = fields
            .get(ip_index + 3)
            .or_else(|| fields.last())
            .map(|value| normalize_family(value))
            .unwrap_or_else(|| "botnet".to_string());

        out.push(BotnetC2Indicator {
            rank: out.len() + 1,
            ip: ip.clone(),
            ip_safe: defang_indicator(&ip),
            port,
            status,
            malware,
            first_seen,
            source: "Feodo Tracker".to_string(),
            risk: "watch".to_string(),
            score: 0,
            bar_width: 0,
            note_fa: String::new(),
        });
    }
    out
}

fn parse_sslbl_ja3_csv(text: &str) -> Vec<TlsThreatIndicator> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = split_csv_line(line);
        if fields.len() < 3 || fields[0].to_lowercase().contains("ja3") {
            continue;
        }
        let fingerprint = fields.first().cloned().unwrap_or_default();
        if fingerprint.len() < 24 {
            continue;
        }
        let first_seen = fields.get(1).cloned().unwrap_or_default();
        let last_seen = fields.get(2).cloned().unwrap_or_default();
        let reason = fields
            .get(3)
            .cloned()
            .or_else(|| fields.get(2).cloned())
            .unwrap_or_else(|| "malicious_tls".to_string());
        out.push(TlsThreatIndicator {
            rank: out.len() + 1,
            indicator_type: "JA3".to_string(),
            fingerprint: fingerprint.clone(),
            fingerprint_safe: truncate_middle(&fingerprint, 18),
            first_seen,
            last_seen,
            reason: normalize_family(&reason),
            source: "SSLBL JA3".to_string(),
            risk: "watch".to_string(),
            score: 0,
            bar_width: 0,
            note_fa: String::new(),
        });
    }
    out
}

fn parse_sslbl_cert_csv(text: &str) -> Vec<TlsThreatIndicator> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = split_csv_line(line);
        if fields.len() < 2 || fields[0].to_lowercase().contains("listing") {
            continue;
        }
        let first_seen = fields.first().cloned().unwrap_or_default();
        let fingerprint = fields.get(1).cloned().unwrap_or_default();
        if fingerprint.len() < 32 {
            continue;
        }
        let reason = fields
            .get(2)
            .cloned()
            .unwrap_or_else(|| "malicious_certificate".to_string());
        out.push(TlsThreatIndicator {
            rank: out.len() + 1,
            indicator_type: "SSL cert".to_string(),
            fingerprint: fingerprint.clone(),
            fingerprint_safe: truncate_middle(&fingerprint, 18),
            first_seen,
            last_seen: String::new(),
            reason: normalize_family(&reason),
            source: "SSLBL cert".to_string(),
            risk: "watch".to_string(),
            score: 0,
            bar_width: 0,
            note_fa: String::new(),
        });
    }
    out
}

fn finalize_botnet_c2(items: &mut [BotnetC2Indicator]) {
    let total = items.len().max(1);
    for (idx, item) in items.iter_mut().enumerate() {
        item.rank = idx + 1;
        item.malware = normalize_family(&item.malware);
        item.ip_safe = defang_indicator(&item.ip);
        let mut score = 45 + ((total - idx) * 35 / total);
        if item.status.to_lowercase().contains("online") {
            score += 15;
        }
        if item.port == 80 || item.port == 443 || item.port == 8080 || item.port == 8443 {
            score += 6;
        }
        if is_named_malware_family(&item.malware) {
            score += 10;
        }
        item.score = score.clamp(10, 100);
        item.bar_width = item.score.clamp(10, 100);
        item.risk = if item.score >= 78 {
            "high"
        } else if item.score >= 56 {
            "medium"
        } else {
            "watch"
        }
        .to_string();
        item.note_fa = format!(
            "{} به‌عنوان C2 botnet در Feodo دیده شده؛ فقط برای correlation دفاعی و مسدودسازی داخلی استفاده شود.",
            item.malware
        );
    }
    items.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.malware.cmp(&b.malware))
    });
}

fn finalize_tls_threats(items: &mut [TlsThreatIndicator]) {
    let total = items.len().max(1);
    for (idx, item) in items.iter_mut().enumerate() {
        item.rank = idx + 1;
        item.reason = normalize_family(&item.reason);
        item.fingerprint_safe = truncate_middle(&item.fingerprint, 18);
        let mut score = 40 + ((total - idx) * 35 / total);
        if is_named_malware_family(&item.reason) || item.reason.to_lowercase().contains("botnet") {
            score += 15;
        }
        if item.indicator_type == "JA3" {
            score += 5;
        }
        item.score = score.clamp(10, 100);
        item.bar_width = item.score.clamp(10, 100);
        item.risk = if item.score >= 78 {
            "high"
        } else if item.score >= 56 {
            "medium"
        } else {
            "watch"
        }
        .to_string();
        item.note_fa = format!(
            "{} از SSLBL دریافت شده و فقط به‌صورت fingerprint metadata نمایش داده می‌شود.",
            item.indicator_type
        );
    }
    items.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.indicator_type.cmp(&b.indicator_type))
    });
}

fn is_named_malware_family(value: &str) -> bool {
    let lower = value.to_lowercase();
    [
        "emotet", "dridex", "trickbot", "qakbot", "qbot", "bazar", "icedid", "gozi", "ramnit",
        "lokibot", "redline", "formbook",
    ]
    .iter()
    .any(|family| lower.contains(family))
}

fn looks_like_ipv4(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 4 && parts.iter().all(|part| part.parse::<u8>().is_ok())
}

fn truncate_middle(value: &str, keep: usize) -> String {
    if value.chars().count() <= keep.saturating_mul(2) + 3 {
        return value.to_string();
    }
    let start = value.chars().take(keep).collect::<String>();
    let end = value
        .chars()
        .rev()
        .take(keep)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("{}…{}", start, end)
}

fn count_chart_names(names: &[String], limit: usize) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for name in names {
        let key = normalize_family(name);
        if !key.trim().is_empty() && key != "unknown" && key != "-" {
            *counts.entry(key).or_insert(0) += 1;
        }
    }
    let mut rows = counts.into_iter().collect::<Vec<_>>();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let max = rows
        .iter()
        .map(|(_, count)| *count)
        .max()
        .unwrap_or(1)
        .max(1);
    rows.into_iter()
        .take(limit)
        .map(|(name, count)| {
            let width = ((count as f64 / max as f64) * 100.0).round() as usize;
            json!({
                "name": truncate_chars(&name, 38),
                "count": count,
                "bar_width": width.clamp(12, 100)
            })
        })
        .collect()
}

fn empty_botnet_c2_pulse(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "Feodo Tracker + SSLBL",
        "level": "Unknown",
        "summary_fa": "داده Botnet C2 Pulse در این اجرا در دسترس نبود.",
        "last_updated": "",
        "metadata_only": true,
        "totals": {
            "c2": 0,
            "tls": 0,
            "high": 0,
            "families": 0,
            "ports": 0
        },
        "c2": [],
        "tls": [],
        "family_chart": [],
        "port_chart": [],
        "tls_chart": []
    })
}

fn fetch_supply_chain_radar_or_fallback(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Value {
    if !config.intel.enabled || !config.intel.supply_chain.enabled {
        return empty_supply_chain_radar("disabled");
    }

    match fetch_supply_chain_radar(config, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  Supply Chain Radar skipped: {err:#}");
            let mut fallback = empty_supply_chain_radar("error");
            fallback["error"] = json!(err.to_string());
            fallback
        }
    }
}

fn fetch_supply_chain_radar(config: &Config, offline: bool, refresh_cache: bool) -> Result<Value> {
    eprintln!("→ fetching Supply Chain radar");
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(45))
        .build()
        .context("failed to build HTTP client for Supply Chain radar")?;

    let sc = &config.intel.supply_chain;
    let per_ecosystem = (sc.max_advisories / sc.ecosystems.len().max(1)).clamp(3, 8);
    let mut seen = HashSet::new();
    let mut advisories = Vec::new();

    for ecosystem in &sc.ecosystems {
        let url = format!(
            "{}?type=reviewed&ecosystem={}&per_page={}&sort=published&direction=desc",
            sc.github_advisories_url.trim_end_matches('/'),
            ecosystem,
            per_ecosystem
        );
        let label = format!("GitHub Advisory {ecosystem}");
        match get_bytes_cached_intel(&client, config, &url, &label, offline, refresh_cache) {
            Ok(bytes) => {
                let rows: Value = serde_json::from_slice(&bytes).with_context(|| {
                    format!("GitHub advisory response was not valid JSON for {ecosystem}")
                })?;
                let Some(items) = rows.as_array() else {
                    continue;
                };
                for item in items {
                    if let Some(advisory) = map_github_advisory(
                        item,
                        ecosystem,
                        &config.intel.supply_chain.osv_base_url,
                    ) {
                        let key = advisory
                            .get("ghsa_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        if !key.is_empty() && seen.insert(key) {
                            advisories.push(advisory);
                        }
                    }
                }
            }
            Err(err) => eprintln!("⚠️  skipped GitHub Advisory {ecosystem}: {err:#}"),
        }
        thread::sleep(Duration::from_millis(config.intel.sleep_ms_between_sources));
    }

    advisories.sort_by(|a, b| {
        let ar = a.get("rank_score").and_then(|v| v.as_i64()).unwrap_or(0);
        let br = b.get("rank_score").and_then(|v| v.as_i64()).unwrap_or(0);
        br.cmp(&ar)
    });
    advisories.truncate(sc.max_advisories);
    annotate_supply_bars(&mut advisories);

    let mut ecosystem_counts = HashMap::new();
    let mut severity_counts = HashMap::new();
    let mut package_counts = HashMap::new();
    let mut fixed = 0usize;
    let mut critical = 0usize;
    let mut high = 0usize;

    for advisory in &advisories {
        let ecosystem = advisory
            .get("ecosystem")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let severity = advisory
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let package = advisory
            .get("package")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        *ecosystem_counts.entry(ecosystem).or_insert(0) += 1;
        *severity_counts.entry(severity.clone()).or_insert(0) += 1;
        if package != "unknown" {
            *package_counts.entry(package).or_insert(0) += 1;
        }
        if advisory
            .get("fix_available")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            fixed += 1;
        }
        match severity.as_str() {
            "critical" => critical += 1,
            "high" => high += 1,
            _ => {}
        }
    }

    let total = advisories.len();
    let level = if critical > 0 || high >= 5 {
        "High"
    } else if high > 0 || total >= 12 {
        "Medium"
    } else if total > 0 {
        "Watch"
    } else {
        "Low"
    };

    let summary_fa = if total == 0 {
        "در این اجرا advisory قابل نمایش برای supply chain دریافت نشد.".to_string()
    } else {
        format!("{total} advisory تازه/اخیر از اکوسیستم‌های open-source دیده شد؛ {high} مورد high و {critical} مورد critical است.")
    };

    Ok(json!({
        "enabled": true,
        "ok": total > 0,
        "provider": "GitHub Global Advisories + OSV references",
        "level": level,
        "summary_fa": summary_fa,
        "last_updated": Local::now().format("%Y-%m-%d %H:%M").to_string(),
        "refresh_hours": config.intel.refresh_hours,
        "totals": {
            "advisories": total,
            "critical": critical,
            "high": high,
            "fixed": fixed,
            "ecosystems": ecosystem_counts.len()
        },
        "advisories": advisories,
        "ecosystem_chart": count_chart_from_counts(ecosystem_counts, 8),
        "severity_chart": count_chart_from_counts(severity_counts, 5),
        "package_chart": count_chart_from_counts(package_counts, 8),
        "source_health": {
            "cache_dir": config.intel.cache_dir.clone(),
            "refresh_hours": config.intel.refresh_hours,
            "sources": ["GitHub Global Advisories", "OSV vulnerability pages"]
        }
    }))
}

fn map_github_advisory(
    item: &Value,
    fallback_ecosystem: &str,
    osv_base_url: &str,
) -> Option<Value> {
    let ghsa_id = item.get("ghsa_id").and_then(|v| v.as_str())?.to_string();
    let cve_id = item
        .get("cve_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let summary = truncate_chars(
        item.get("summary").and_then(|v| v.as_str()).unwrap_or(""),
        180,
    );
    let severity = item
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_lowercase();
    let published = item
        .get("published_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let updated = item
        .get("updated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let html_url = item
        .get("html_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let cvss = item
        .get("cvss")
        .and_then(|v| v.get("score"))
        .and_then(|v| v.as_f64())
        .or_else(|| {
            item.get("cvss_severities")
                .and_then(|v| v.get("cvss_v4"))
                .and_then(|v| v.get("score"))
                .and_then(|v| v.as_f64())
        })
        .or_else(|| {
            item.get("cvss_severities")
                .and_then(|v| v.get("cvss_v3"))
                .and_then(|v| v.get("score"))
                .and_then(|v| v.as_f64())
        })
        .unwrap_or(0.0);
    let epss = item
        .get("epss")
        .and_then(|v| v.get("percentage"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let vuln = item
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first());
    let ecosystem = vuln
        .and_then(|v| v.get("package"))
        .and_then(|pkg| pkg.get("ecosystem"))
        .and_then(|v| v.as_str())
        .unwrap_or(fallback_ecosystem)
        .to_string();
    let package = vuln
        .and_then(|v| v.get("package"))
        .and_then(|pkg| pkg.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let vulnerable_range = vuln
        .and_then(|v| v.get("vulnerable_version_range"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let patched = vuln
        .and_then(|v| v.get("first_patched_version"))
        .and_then(|v| v.get("identifier"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let fix_available = !patched.trim().is_empty();

    let identifiers = item
        .get("identifiers")
        .and_then(|v| v.as_array())
        .map(|ids| {
            ids.iter()
                .filter_map(|id| {
                    id.get("value")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .take(4)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let risk = supply_chain_risk(&severity, cvss, epss);
    let rank_score = supply_chain_rank_score(&severity, cvss, epss, fix_available);
    let osv_id = if !ghsa_id.is_empty() {
        ghsa_id.as_str()
    } else {
        cve_id.as_str()
    };
    let osv_url = if osv_id.is_empty() {
        String::new()
    } else {
        format!("{}/{}", osv_base_url.trim_end_matches('/'), osv_id)
    };

    Some(json!({
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "summary": summary,
        "severity": severity,
        "ecosystem": ecosystem,
        "package": package,
        "vulnerable_range": vulnerable_range,
        "patched_version": patched,
        "fix_available": fix_available,
        "published": published,
        "updated": updated,
        "html_url": html_url,
        "osv_url": osv_url,
        "identifiers": identifiers,
        "cvss": cvss,
        "epss": epss,
        "risk": risk,
        "rank_score": rank_score,
        "bar_width": 0,
        "note_fa": supply_chain_note(&severity, fix_available, &package),
    }))
}

fn supply_chain_rank_score(severity: &str, cvss: f64, epss: f64, fix_available: bool) -> i64 {
    let sev = match severity {
        "critical" => 90,
        "high" => 72,
        "medium" => 48,
        "low" => 24,
        _ => 16,
    };
    let cvss_bonus = (cvss * 3.0).round() as i64;
    let epss_bonus = (epss * 100.0).round() as i64;
    let fix_bonus = if fix_available { 6 } else { 0 };
    sev + cvss_bonus + epss_bonus + fix_bonus
}

fn supply_chain_risk(severity: &str, cvss: f64, epss: f64) -> &'static str {
    if severity == "critical" || cvss >= 9.0 || epss >= 0.5 {
        "high"
    } else if severity == "high" || cvss >= 7.0 || epss >= 0.1 {
        "medium"
    } else {
        "watch"
    }
}

fn supply_chain_note(severity: &str, fix_available: bool, package: &str) -> String {
    if severity == "critical" || severity == "high" {
        if fix_available {
            return format!("برای package {package} نسخه patched وجود دارد؛ در SBOM و dependency inventory تطبیق شود.");
        }
        return format!("برای package {package} advisory پرریسک دیده شده؛ وضعیت patched version را در advisory رسمی بررسی کن.");
    }
    "برای آگاهی از ریسک supply chain نگه داشته شود؛ این رادار dependency scan انجام نمی‌دهد."
        .to_string()
}

fn annotate_supply_bars(advisories: &mut [Value]) {
    let max_score = advisories
        .iter()
        .filter_map(|row| row.get("rank_score").and_then(|v| v.as_i64()))
        .max()
        .unwrap_or(1)
        .max(1);
    for row in advisories {
        let score = row.get("rank_score").and_then(|v| v.as_i64()).unwrap_or(1);
        let width = ((score as f64 / max_score as f64) * 100.0).round() as usize;
        row["bar_width"] = json!(width.clamp(12, 100));
    }
}

fn fetch_ransomware_pulse_or_fallback(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Value {
    if !config.intel.enabled || !config.intel.ransomware.enabled {
        return empty_ransomware_pulse("disabled");
    }

    match fetch_ransomware_pulse(config, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  Ransomware Pulse skipped: {err:#}");
            let mut fallback = empty_ransomware_pulse("error");
            fallback["error"] = json!(err.to_string());
            fallback
        }
    }
}

fn fetch_ransomware_pulse(config: &Config, offline: bool, refresh_cache: bool) -> Result<Value> {
    eprintln!("→ fetching Ransomware Pulse");
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(45))
        .build()
        .context("failed to build HTTP client for Ransomware Pulse")?;

    let rw = &config.intel.ransomware;
    let mut urls = Vec::new();
    let configured = rw.recent_victims_url.trim_end_matches('/').to_string();
    if configured.contains('?') {
        urls.push(format!("{}&limit={}", configured, rw.max_victims.max(1)));
    } else {
        urls.push(format!("{}?limit={}", configured, rw.max_victims.max(1)));
        urls.push(configured.clone());
    }
    let base = "https://api.ransomware.live/v2";
    urls.push(format!(
        "{base}/victims/recent?limit={}",
        rw.max_victims.max(1)
    ));
    urls.push(format!("{base}/recentvictims/{}", rw.max_victims.max(1)));

    let mut last_error: Option<anyhow::Error> = None;
    let mut body = None;
    for (idx, url) in urls.into_iter().enumerate() {
        let label = if idx == 0 {
            "Ransomware.live recent victims".to_string()
        } else {
            format!("Ransomware.live fallback endpoint {idx}")
        };
        match get_bytes_cached_intel(&client, config, &url, &label, offline, refresh_cache) {
            Ok(bytes) => {
                body = Some(bytes);
                break;
            }
            Err(err) => {
                last_error = Some(err);
            }
        }
    }

    let bytes = body.ok_or_else(|| {
        last_error.unwrap_or_else(|| anyhow::anyhow!("no Ransomware.live endpoint returned data"))
    })?;
    let raw: Value =
        serde_json::from_slice(&bytes).context("Ransomware.live response was not valid JSON")?;
    let rows = extract_ransomware_rows(&raw);

    let mut seen = HashSet::new();
    let mut victims = Vec::new();
    for row in rows {
        if let Some(victim) = map_ransomware_victim(row) {
            let key = format!(
                "{}:{}",
                victim.group.to_lowercase(),
                victim.victim_safe.to_lowercase()
            );
            if seen.insert(key) {
                victims.push(victim);
            }
        }
    }

    victims.sort_by(|a, b| {
        b.recency_score
            .cmp(&a.recency_score)
            .then_with(|| a.group.cmp(&b.group))
    });
    victims.truncate(rw.max_victims);
    finalize_ransomware_victims(&mut victims);

    let mut group_counts = HashMap::new();
    let mut country_counts = HashMap::new();
    let mut sector_counts = HashMap::new();
    let mut activity_counts = HashMap::new();
    let mut recent_24h = 0usize;
    let mut recent_7d = 0usize;

    for victim in &victims {
        *group_counts.entry(victim.group.clone()).or_insert(0) += 1;
        if victim.country != "unknown" {
            *country_counts.entry(victim.country.clone()).or_insert(0) += 1;
        }
        if victim.sector != "unknown" {
            *sector_counts.entry(victim.sector.clone()).or_insert(0) += 1;
        }
        if !victim.claimed_date.is_empty() && victim.claimed_date != "unknown" {
            *activity_counts
                .entry(victim.claimed_date.clone())
                .or_insert(0) += 1;
        }
        if victim.recency_score >= 90 {
            recent_24h += 1;
        }
        if victim.recency_score >= 55 {
            recent_7d += 1;
        }
    }

    let total = victims.len();
    let level = if recent_24h >= 3 || total >= 20 {
        "High"
    } else if recent_7d >= 6 || total >= 10 {
        "Medium"
    } else if total > 0 {
        "Watch"
    } else {
        "Low"
    };
    let summary_fa = if total == 0 {
        "در این اجرا claim تازه قابل نمایش از Ransomware.live دریافت نشد.".to_string()
    } else {
        format!("{total} claim عمومی ransomware از Ransomware.live وارد رادار شد؛ {recent_7d} مورد در بازه نزدیک به ۷ روز اخیر دیده می‌شود.")
    };

    Ok(json!({
        "enabled": true,
        "ok": total > 0,
        "provider": "Ransomware.live public API",
        "level": level,
        "summary_fa": summary_fa,
        "last_updated": Local::now().format("%Y-%m-%d %H:%M").to_string(),
        "refresh_hours": config.intel.refresh_hours,
        "totals": {
            "victims": total,
            "groups": group_counts.len(),
            "countries": country_counts.len(),
            "sectors": sector_counts.len(),
            "recent_24h": recent_24h,
            "recent_7d": recent_7d
        },
        "victims": victims,
        "group_chart": count_chart_from_counts(group_counts, 8),
        "country_chart": count_chart_from_counts(country_counts, 8),
        "sector_chart": count_chart_from_counts(sector_counts, 8),
        "activity_chart": count_chart_from_counts(activity_counts, 10),
        "source_health": {
            "cache_dir": config.intel.cache_dir.clone(),
            "refresh_hours": config.intel.refresh_hours,
            "sources": ["Ransomware.live recent victims"]
        }
    }))
}

fn extract_ransomware_rows(value: &Value) -> Vec<&Value> {
    if let Some(items) = value.as_array() {
        return items.iter().collect();
    }
    for key in ["victims", "data", "results", "items", "recent", "posts"] {
        if let Some(items) = value.get(key).and_then(|v| v.as_array()) {
            return items.iter().collect();
        }
    }
    Vec::new()
}

fn map_ransomware_victim(row: &Value) -> Option<RansomwareVictim> {
    let victim_name = first_text(row, &["victim", "name", "post_title", "title", "company"])?;
    let group = first_text(
        row,
        &["group", "group_name", "ransomware", "actor", "family"],
    )
    .unwrap_or_else(|| "unknown".to_string());
    let country = first_text(
        row,
        &["country", "country_code", "countrycode", "country_name"],
    )
    .unwrap_or_else(|| "unknown".to_string());
    let sector = first_text(row, &["sector", "activity", "industry", "business_sector"])
        .unwrap_or_else(|| "unknown".to_string());
    let raw_date = first_text(
        row,
        &[
            "attackdate",
            "date",
            "discovered",
            "published",
            "published_at",
            "created_at",
            "updated",
            "updated_at",
        ],
    )
    .unwrap_or_default();
    let claimed_date = normalize_claim_date(&raw_date).unwrap_or_else(|| {
        if raw_date.is_empty() {
            "unknown".to_string()
        } else {
            truncate_chars(&raw_date, 20)
        }
    });
    let recency_score = ransomware_recency_score(&claimed_date);
    let critical_sector = is_critical_ransomware_sector(&sector);
    let risk = if recency_score >= 90 || critical_sector {
        "high"
    } else if recency_score >= 55 {
        "medium"
    } else {
        "watch"
    }
    .to_string();
    let note_fa = ransomware_note(&group, &country, &sector, &claimed_date);

    Some(RansomwareVictim {
        rank: 0,
        victim_safe: sanitize_victim_label(&victim_name),
        group: truncate_chars(&clean_text(&group), 48),
        country: normalize_short_value(&country),
        sector: truncate_chars(&normalize_short_value(&sector), 44),
        claimed_date,
        recency_score,
        risk,
        bar_width: 12,
        note_fa,
    })
}

fn first_text(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(raw) = value.get(*key) {
            if let Some(text) = raw.as_str() {
                let cleaned = clean_text(text);
                if !cleaned.is_empty() {
                    return Some(cleaned);
                }
            } else if raw.is_number() || raw.is_boolean() {
                return Some(raw.to_string());
            }
        }
    }
    None
}

fn sanitize_victim_label(input: &str) -> String {
    let cleaned = clean_text(input);
    let without_url = cleaned
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("www.")
        .to_string();
    truncate_chars(&without_url, 72)
}

fn normalize_short_value(input: &str) -> String {
    let cleaned = clean_text(input);
    if cleaned.is_empty() || cleaned == "-" || cleaned.eq_ignore_ascii_case("null") {
        "unknown".to_string()
    } else {
        truncate_chars(&cleaned, 42)
    }
}

fn normalize_claim_date(raw: &str) -> Option<String> {
    let cleaned = clean_text(raw);
    if cleaned.len() >= 10 {
        let first = &cleaned[..10.min(cleaned.len())];
        if NaiveDate::parse_from_str(first, "%Y-%m-%d").is_ok() {
            return Some(first.to_string());
        }
    }
    for fmt in ["%d/%m/%Y", "%m/%d/%Y", "%Y/%m/%d"] {
        if let Ok(date) = NaiveDate::parse_from_str(&cleaned, fmt) {
            return Some(date.format("%Y-%m-%d").to_string());
        }
    }
    None
}

fn ransomware_recency_score(claimed_date: &str) -> usize {
    let Ok(date) = NaiveDate::parse_from_str(claimed_date, "%Y-%m-%d") else {
        return 30;
    };
    let today = Local::now().date_naive();
    let days = today.signed_duration_since(date).num_days();
    if days <= 1 {
        100
    } else if days <= 3 {
        82
    } else if days <= 7 {
        62
    } else if days <= 14 {
        44
    } else {
        28
    }
}

fn is_critical_ransomware_sector(sector: &str) -> bool {
    let lower = sector.to_lowercase();
    lower.contains("health")
        || lower.contains("hospital")
        || lower.contains("government")
        || lower.contains("education")
        || lower.contains("energy")
        || lower.contains("transport")
        || lower.contains("finance")
        || lower.contains("manufacturing")
}

fn ransomware_note(group: &str, country: &str, sector: &str, claimed_date: &str) -> String {
    let mut parts = Vec::new();
    if group != "unknown" {
        parts.push(format!("گروه {group}"));
    }
    if country != "unknown" {
        parts.push(format!("کشور {country}"));
    }
    if sector != "unknown" {
        parts.push(format!("بخش {sector}"));
    }
    if claimed_date != "unknown" && !claimed_date.is_empty() {
        parts.push(format!("تاریخ claim {claimed_date}"));
    }
    if parts.is_empty() {
        "claim عمومی ransomware برای آگاهی موقعیتی ثبت شده؛ لینک leak یا محتوای حساس نمایش داده نمی‌شود.".to_string()
    } else {
        format!(
            "{}؛ فقط برای آگاهی موقعیتی و بدون لینک leak نمایش داده شده است.",
            parts.join(" · ")
        )
    }
}

fn finalize_ransomware_victims(victims: &mut [RansomwareVictim]) {
    victims.sort_by(|a, b| {
        b.recency_score
            .cmp(&a.recency_score)
            .then_with(|| a.group.cmp(&b.group))
    });
    let max_score = victims
        .iter()
        .map(|v| v.recency_score)
        .max()
        .unwrap_or(1)
        .max(1);
    for (idx, victim) in victims.iter_mut().enumerate() {
        victim.rank = idx + 1;
        victim.bar_width = (((victim.recency_score as f64 / max_score as f64) * 100.0).round()
            as usize)
            .clamp(12, 100);
    }
}

fn empty_ransomware_pulse(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "Ransomware.live public API",
        "level": "Unknown",
        "summary_fa": "داده Ransomware Pulse در این اجرا در دسترس نبود.",
        "last_updated": "",
        "refresh_hours": 1,
        "totals": {"victims": 0, "groups": 0, "countries": 0, "sectors": 0, "recent_24h": 0, "recent_7d": 0},
        "victims": [],
        "group_chart": [],
        "country_chart": [],
        "sector_chart": [],
        "activity_chart": []
    })
}

fn empty_supply_chain_radar(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "GitHub Global Advisories + OSV references",
        "level": "Unknown",
        "summary_fa": "داده Supply Chain Radar در این اجرا در دسترس نبود.",
        "last_updated": "",
        "refresh_hours": 1,
        "totals": {"advisories": 0, "critical": 0, "high": 0, "fixed": 0, "ecosystems": 0},
        "advisories": [],
        "ecosystem_chart": [],
        "severity_chart": [],
        "package_chart": []
    })
}

fn empty_infrastructure_radar(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "Shodan InternetDB + DShield top IPs",
        "level": "Unknown",
        "summary_fa": "داده Suspicious Infrastructure در این اجرا در دسترس نبود.",
        "last_updated": "",
        "refresh_hours": 1,
        "totals": {"candidates": 0, "hosts": 0, "high": 0, "vulns": 0, "ports": 0},
        "hosts": [],
        "port_chart": [],
        "risk_chart": []
    })
}

fn empty_attack_pressure(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "SANS ISC / DShield",
        "level": "Unknown",
        "summary_fa": "داده Attack Pressure در این اجرا در دسترس نبود.",
        "last_updated": "",
        "refresh_hours": 1,
        "top_ports": [],
        "scanning_ports": [],
        "reported_ports": [],
        "targeted_ports": []
    })
}

fn intel_source_count(config: &Config) -> usize {
    if !config.intel.enabled {
        return 0;
    }

    let mut count = 0;
    if config.intel.attack_pressure.enabled {
        count += 1;
    }
    if config.intel.ioc_radar.enabled {
        count += 2;
    }
    if config.intel.infrastructure.enabled {
        count += 1;
    }
    if config.intel.supply_chain.enabled {
        count += 2;
    }
    if config.intel.ransomware.enabled {
        count += 1;
    }
    if config.intel.botnet_c2.enabled {
        count += 2;
    }
    count
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
    let news_lanes = build_news_lanes(&global);

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
    let epss_tracked = cves
        .iter()
        .filter(|c| c.epss > 0.0 || c.epss_percentile > 0.0)
        .count();
    let epss_rising_count = cves.iter().filter(|c| c.epss_momentum == "rising").count();
    let epss_stable_count = cves.iter().filter(|c| c.epss_momentum == "stable").count();
    let epss_falling_count = cves.iter().filter(|c| c.epss_momentum == "falling").count();
    let vulnrichment_checked = cve_count.min(config.cve.max_vulnrichment);
    let vulnrichment_hits = cves.iter().filter(|c| c.cisa_vulnrichment).count();
    let vulnrichment_missing = vulnrichment_checked.saturating_sub(vulnrichment_hits);

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
            "epss_tracked": epss_tracked,
            "epss_rising": epss_rising_count,
            "epss_stable": epss_stable_count,
            "epss_falling": epss_falling_count,
            "vulnrichment_checked": vulnrichment_checked,
            "vulnrichment_hits": vulnrichment_hits,
            "vulnrichment_missing": vulnrichment_missing,
            "botnet_c2": 0,
            "malicious_tls": 0,
            "rss_sources": config.sources.len(),
            "intel_sources": intel_source_count(config)
        },
        "source_health": {
            "rss_sources": config.sources.len(),
            "source_names": config.sources.iter().map(|source| source.name.clone()).collect::<Vec<_>>(),
            "failed_rss_sources": 0,
            "rss_failures": [],
            "http_cache": config.cache.enabled,
            "cache_ttl_minutes": config.cache.ttl_minutes,
            "ai_cache_dir": config.gemini.cache_dir.clone(),
            "intel_sources": intel_source_count(config),
            "intel_cache_dir": config.intel.cache_dir.clone()
        },
        "priority_alert": priority,
        "iran_radar": iran,
        "global_news": global,
        "news_lanes": news_lanes,
        "cves": cves
    }))
}

fn build_news_lanes(global: &[FeedItem]) -> Value {
    let mut active_exploitation = Vec::new();
    let mut vulnerabilities = Vec::new();
    let mut malware_incidents = Vec::new();
    let mut ai_security = Vec::new();
    let mut general = Vec::new();

    for item in global {
        match item.category.as_str() {
            "active_exploitation" => active_exploitation.push(item.clone()),
            "vulnerability" => vulnerabilities.push(item.clone()),
            "malware_incident" => malware_incidents.push(item.clone()),
            "ai_security" => ai_security.push(item.clone()),
            _ => general.push(item.clone()),
        }
    }

    json!({
        "active_exploitation": active_exploitation.into_iter().take(6).collect::<Vec<_>>(),
        "vulnerabilities": vulnerabilities.into_iter().take(6).collect::<Vec<_>>(),
        "malware_incidents": malware_incidents.into_iter().take(6).collect::<Vec<_>>(),
        "ai_security": ai_security.into_iter().take(6).collect::<Vec<_>>(),
        "general": general.into_iter().take(8).collect::<Vec<_>>()
    })
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

struct GeminiEditResult {
    brief: Value,
    calls_used: u8,
    cache_hit: bool,
}

fn enhance_brief_with_gemini(
    config: &Config,
    brief: &Value,
    refresh_ai: bool,
    offline: bool,
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

    if offline {
        let edited = mark_ai_status(
            brief.clone(),
            false,
            false,
            &config.gemini.model,
            0,
            Some("offline mode has no matching Gemini cache".to_string()),
        );
        return Ok(GeminiEditResult {
            brief: edited,
            calls_used: 0,
            cache_hit: false,
        });
    }

    let api_key = get_env_or_dotenv("GEMINI_API_KEY")
        .context("GEMINI_API_KEY is not set. Put it in .env or export it before using --ai")?;

    let prompt = build_gemini_prompt(&compact)?;

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

    let text = send_gemini_prompt(
        &client,
        &url,
        &api_key,
        &prompt,
        config.gemini.temperature,
        8192,
    )
    .context("Gemini request failed")?;
    let cleaned = clean_json_block(&text);
    let (ai_json, calls_used) = match serde_json::from_str::<Value>(&cleaned) {
        Ok(value) => (value, 1),
        Err(parse_error) => {
            eprintln!("↳ Gemini JSON parse failed; attempting one repair pass");
            let repair_prompt = build_gemini_repair_prompt(&cleaned, &parse_error.to_string());
            let repaired_text =
                send_gemini_prompt(&client, &url, &api_key, &repair_prompt, 0.0, 8192)
                    .context("Gemini repair request failed")?;
            let repaired = clean_json_block(&repaired_text);
            let value: Value = serde_json::from_str(&repaired).with_context(|| {
                format!(
                    "Gemini returned text, but it was not valid JSON after repair: {}",
                    json_parse_hint(&repaired)
                )
            })?;
            (value, 2)
        }
    };
    let ai_json = validate_ai_result_shape(&ai_json)?;

    write_ai_cache(config, &cache_key, &ai_json)?;

    let edited = merge_ai_result(brief.clone(), &ai_json);
    Ok(GeminiEditResult {
        brief: mark_ai_status(edited, true, false, &config.gemini.model, calls_used, None),
        calls_used,
        cache_hit: false,
    })
}

fn send_gemini_prompt(
    client: &Client,
    url: &str,
    api_key: &str,
    prompt: &str,
    temperature: f64,
    max_output_tokens: u32,
) -> Result<String> {
    let request_body = json!({
        "contents": [{
            "role": "user",
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "temperature": temperature,
            "candidateCount": 1,
            "maxOutputTokens": max_output_tokens,
            "responseMimeType": "application/json",
            "responseSchema": gemini_response_schema()
        }
    });

    let response_json: Value = client
        .post(url)
        .header("x-goog-api-key", api_key)
        .json(&request_body)
        .send()
        .and_then(|response| response.error_for_status())
        .context("Gemini request failed")?
        .json()
        .context("Gemini response was not valid JSON")?;

    extract_gemini_text(&response_json).context("Gemini response did not include text")
}

fn build_gemini_repair_prompt(broken_json: &str, parse_error: &str) -> String {
    format!(
        "Repair the following truncated or invalid JSON so it becomes valid JSON only.\n\nRules:\n- Return JSON only, no markdown.\n- Preserve the same schema and field names.\n- If a string is incomplete, close it safely.\n- If an array/object is incomplete, close it safely.\n- Do not add new source URLs, IOCs, leak links, or user-facing actions.\n- Keep Persian text concise.\n\nParser error: {parse_error}\n\nBroken JSON:\n{broken_json}"
    )
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
            }
        },
        "required": ["priority_alert", "iran_radar", "global_news", "cves"]
    })
}

fn build_gemini_prompt(compact: &Value) -> Result<String> {
    Ok(format!(
        r#"You are the Persian editorial layer for SecPath Radar, a defensive daily cybersecurity intelligence brief.

Input is JSON generated from RSS, NVD, CISA KEV, and EPSS. Your job is to add a Persian display layer while preserving the original machine-generated/source fields.

Hard rules:
- Do not invent facts, CVEs, sources, URLs, exploitation status, affected products, victim geography, attribution, or exploit details.
- Do not rewrite or return immutable fields such as url, source, cve_id, risk_score, cvss, epss, kev, severity, published, iran_context, tags, title, or summary.
- Return editorial fields only: title_fa, summary_fa, why_it_matters, ops_note, and recommended_action for CVEs.
- Keep the same item order and approximate same item count for iran_radar, global_news, and cves.
- If an item is unclear, write a cautious Persian summary and say the original advisory should be checked.
- Do not move Iran-related items between sections. If Iran appears only as attribution, do not imply the target is inside Iran.
- Use defensive language only. No exploit chains, payloads, bypass steps, or unauthorized access guidance.
- summary_fa: 1 short Persian sentence, max 170 characters.
- why_it_matters: 1 Persian sentence about operational impact, max 150 characters.
- ops_note: 1 Persian action sentence for SOC/admin teams, max 160 characters.
- title_fa: concise Persian headline, max 70 characters. For CVEs, include product/impact, not a full NVD sentence.
- Return valid JSON only. No markdown fences, comments, trailing commas, or explanatory text.
- Prefer short strings over complete sentences if needed; never stop mid-string.

Return this exact top-level shape:
{{
  "priority_alert": {{"title_fa":"...", "summary_fa":"...", "why_it_matters":"...", "ops_note":"..."}},
  "iran_radar": [{{"title_fa":"...", "summary_fa":"...", "why_it_matters":"...", "ops_note":"..."}}],
  "global_news": [{{"title_fa":"...", "summary_fa":"...", "why_it_matters":"...", "ops_note":"..."}}],
  "cves": [{{"title_fa":"...", "summary_fa":"...", "why_it_matters":"...", "recommended_action":"...", "ops_note":"..."}}]
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
            | "category"
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

fn build_executive_snapshot(brief: &Value) -> Value {
    let total_items = stat_u64(brief, "total_items");
    let cves = stat_u64(brief, "cves");
    let critical_cves = stat_u64(brief, "critical_cves");
    let kev = stat_u64(brief, "kev");
    let iocs = stat_u64(brief, "iocs");
    let botnet_c2 = stat_u64(brief, "botnet_c2");
    let malicious_tls = stat_u64(brief, "malicious_tls");
    let infrastructure_hosts = stat_u64(brief, "infrastructure_hosts");
    let supply_advisories = stat_u64(brief, "supply_chain_advisories");
    let ransomware_victims = stat_u64(brief, "ransomware_victims");
    let failed_rss = stat_u64(brief, "failed_rss_sources");

    let infra_high = path_u64(brief, &["infrastructure_radar", "totals", "high"]);
    let supply_critical = path_u64(brief, &["supply_chain_radar", "totals", "critical"]);
    let supply_high = path_u64(brief, &["supply_chain_radar", "totals", "high"]);
    let ransomware_24h = path_u64(brief, &["ransomware_pulse", "totals", "recent_24h"]);
    let attack_level = path_string(brief, &["attack_pressure", "level"], "Unknown");

    let score = (critical_cves * 18
        + kev * 20
        + iocs.min(60)
        + botnet_c2.min(25)
        + malicious_tls.min(20)
        + infrastructure_hosts.min(25)
        + infra_high * 10
        + supply_critical * 12
        + supply_high * 4
        + ransomware_24h * 5
        + failed_rss * 4)
        .min(100);
    let level = snapshot_level(score);

    let cve_score = (critical_cves * 32 + kev * 28 + cves * 4).min(100).max(12);
    let intel_score = (iocs.min(55)
        + botnet_c2.min(25)
        + malicious_tls.min(20)
        + infrastructure_hosts.min(25)
        + infra_high * 10)
        .min(100)
        .max(12);
    let ecosystem_score =
        (supply_critical * 18 + supply_high * 8 + ransomware_24h * 7 + ransomware_victims.min(25))
            .min(100)
            .max(12);

    let top_port = top_attack_port(brief);
    let top_ioc = first_chart_entry(brief, &["ioc_radar", "malware_chart"])
        .or_else(|| first_chart_entry(brief, &["ioc_radar", "source_chart"]))
        .unwrap_or_else(|| ("بدون IOC برجسته".to_string(), 0));
    let top_ransomware = first_chart_entry(brief, &["ransomware_pulse", "group_chart"])
        .unwrap_or_else(|| ("بدون گروه برجسته".to_string(), 0));
    let top_supply = first_chart_entry(brief, &["supply_chain_radar", "severity_chart"])
        .unwrap_or_else(|| ("بدون severity برجسته".to_string(), 0));

    let impact_a = cves + critical_cves + kev;
    let impact_b = iocs + infrastructure_hosts + botnet_c2 + malicious_tls;
    let impact_c = supply_advisories + ransomware_victims;
    let impact_max = impact_a.max(impact_b).max(impact_c).max(1);

    json!({
        "title": "Static Executive Snapshot",
        "level": level,
        "score": score,
        "bar_width": score.max(12),
        "generated_at": brief.get("generated_at").cloned().unwrap_or(Value::Null),
        "summary_fa": format!(
            "خلاصه ۶۰ ثانیه‌ای: در این اجرا {} آیتم، {} CVE، {} IOC، {} C2 botnet، {} host مشکوک، {} advisory زنجیره تأمین و {} claim ransomware دیده شد.",
            total_items, cves, iocs, botnet_c2, infrastructure_hosts, supply_advisories, ransomware_victims
        ),
        "risk_cards": [
            {
                "title": "ریسک آسیب‌پذیری‌ها",
                "metric": format!("{} critical / {} CVE", critical_cves, cves),
                "level": snapshot_level(cve_score),
                "bar_width": cve_score,
                "note_fa": if critical_cves > 0 { "CVEهای critical باید در اولویت patch و exposure review دیده شوند." } else { "در این اجرا CVE critical برجسته‌ای دیده نشده است." }
            },
            {
                "title": "IOC و زیرساخت مشکوک",
                "metric": format!("{} IOC / {} C2 / {} host", iocs, botnet_c2, infrastructure_hosts),
                "level": snapshot_level(intel_score),
                "bar_width": intel_score,
                "note_fa": if botnet_c2 > 0 { "سیگنال‌های C2 و زیرساخت برای correlation دفاعی کنار هم دیده می‌شوند." } else if infra_high > 0 { "برخی hostها با exposure یا vulnerability hint بالاتر دیده شده‌اند." } else { "سیگنال‌های زیرساختی برای correlation دفاعی نگه داشته شده‌اند." }
            },
            {
                "title": "Supply Chain و Ransomware",
                "metric": format!("{} advisory / {} claims", supply_advisories, ransomware_victims),
                "level": snapshot_level(ecosystem_score),
                "bar_width": ecosystem_score,
                "note_fa": "این بخش فشار اکوسیستم نرم‌افزار و claimهای عمومی ransomware را در یک نگاه ترکیب می‌کند."
            }
        ],
        "rising_signals": [
            {
                "title": "Attack Pressure",
                "metric": top_port.0,
                "level": top_port.2,
                "bar_width": top_port.1.max(12),
                "note_fa": format!("سطح کلی DShield در این اجرا {} گزارش شده است.", attack_level)
            },
            {
                "title": "IOC Pattern",
                "metric": format!("{} · {}", top_ioc.0, top_ioc.1),
                "level": if top_ioc.1 >= 5 { "high" } else if top_ioc.1 >= 2 { "medium" } else { "watch" },
                "bar_width": ((top_ioc.1 * 20).min(100)).max(12),
                "note_fa": "بیشترین الگوی IOC برای triage و correlation دفاعی نمایش داده شده است."
            },
            {
                "title": "Ransomware / Ecosystem",
                "metric": format!("{} · {} | {} · {}", top_ransomware.0, top_ransomware.1, top_supply.0, top_supply.1),
                "level": if ransomware_24h >= 8 || supply_critical >= 3 { "high" } else if ransomware_24h >= 3 || supply_high >= 5 { "medium" } else { "watch" },
                "bar_width": ((ransomware_24h * 10 + supply_critical * 15 + supply_high * 4).min(100)).max(12),
                "note_fa": "Claimهای عمومی ransomware و advisoryهای package در یک سیگنال فشرده آمده‌اند."
            }
        ],
        "impact_sources": [
            {
                "name": "NVD + CISA KEV + EPSS",
                "count": impact_a,
                "bar_width": relative_width(impact_a, impact_max),
                "note_fa": "هسته اولویت‌بندی CVE و exploitability."
            },
            {
                "name": "DShield + abuse.ch + SSLBL + InternetDB",
                "count": impact_b,
                "bar_width": relative_width(impact_b, impact_max),
                "note_fa": "فشار حمله، IOC و زیرساخت قابل مشاهده."
            },
            {
                "name": "GitHub Advisories + OSV + Ransomware.live",
                "count": impact_c,
                "bar_width": relative_width(impact_c, impact_max),
                "note_fa": "ریسک اکوسیستم نرم‌افزار و claimهای عمومی."
            }
        ]
    })
}

fn stat_u64(brief: &Value, key: &str) -> u64 {
    path_u64(brief, &["stats", key])
}

fn path_value<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for part in path {
        current = current.get(*part)?;
    }
    Some(current)
}

fn path_u64(value: &Value, path: &[&str]) -> u64 {
    path_value(value, path)
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

fn path_string(value: &Value, path: &[&str], fallback: &str) -> String {
    path_value(value, path)
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| fallback.to_string())
}

fn first_chart_entry(brief: &Value, path: &[&str]) -> Option<(String, u64)> {
    let row = path_value(brief, path)?.as_array()?.first()?;
    let name = row.get("name")?.as_str()?.trim();
    if name.is_empty() {
        return None;
    }
    Some((
        truncate_chars(name, 36),
        row.get("count").and_then(|v| v.as_u64()).unwrap_or(0),
    ))
}

fn top_attack_port(brief: &Value) -> (String, u64, &'static str) {
    let Some(row) = path_value(brief, &["attack_pressure", "top_ports"])
        .and_then(|v| v.as_array())
        .and_then(|items| items.first())
    else {
        return ("بدون پورت برجسته".to_string(), 12, "watch");
    };
    let port = row
        .get("port")
        .and_then(|v| v.as_u64())
        .map(|p| p.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    let service = row
        .get("service")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let pressure = row
        .get("pressure_score")
        .and_then(|v| v.as_u64())
        .unwrap_or(12)
        .max(12)
        .min(100);
    let risk = row.get("risk").and_then(|v| v.as_str()).unwrap_or("watch");
    let level = match risk {
        "high" => "high",
        "medium" => "medium",
        _ => "watch",
    };
    (
        format!("port {} · {}", port, truncate_chars(service, 20)),
        pressure,
        level,
    )
}

fn relative_width(value: u64, max: u64) -> u64 {
    if max == 0 {
        return 12;
    }
    (((value as f64 / max as f64) * 100.0).round() as u64).clamp(12, 100)
}

fn snapshot_level(score: u64) -> &'static str {
    if score >= 70 {
        "high"
    } else if score >= 40 {
        "medium"
    } else {
        "watch"
    }
}

fn apply_local_polish(brief: &mut Value) {
    brief["version"] = json!("v0.4.18-botnet-c2-pulse");

    if brief.get("source_health").is_none() {
        brief["source_health"] = json!({
            "rss_sources": 0,
            "source_names": [],
            "http_cache": true,
            "cache_ttl_minutes": 0,
            "ai_cache_dir": "data/cache/ai",
            "intel_sources": 0,
            "intel_cache_dir": "data/cache/intel"
        });
    }
    if brief["source_health"].get("source_names").is_none() {
        brief["source_health"]["source_names"] = json!([]);
    }
    if brief["source_health"].get("intel_sources").is_none() {
        brief["source_health"]["intel_sources"] = json!(0);
    }
    if brief["source_health"].get("failed_rss_sources").is_none() {
        brief["source_health"]["failed_rss_sources"] = json!(0);
    }
    if brief["source_health"].get("rss_failures").is_none() {
        brief["source_health"]["rss_failures"] = json!([]);
    }
    if brief.get("attack_pressure").is_none() {
        brief["attack_pressure"] = empty_attack_pressure("missing");
    }
    if brief.get("ioc_radar").is_none() {
        brief["ioc_radar"] = empty_ioc_radar("missing");
    }
    if brief.get("infrastructure_radar").is_none() {
        brief["infrastructure_radar"] = empty_infrastructure_radar("missing");
    }
    if brief.get("supply_chain_radar").is_none() {
        brief["supply_chain_radar"] = empty_supply_chain_radar("missing");
    }
    if brief.get("ransomware_pulse").is_none() {
        brief["ransomware_pulse"] = empty_ransomware_pulse("missing");
    }
    if brief.get("executive_snapshot").is_none() {
        brief["executive_snapshot"] = json!({});
    }
    if brief.get("stats").and_then(|v| v.get("iocs")).is_none() {
        let ioc_total = brief
            .get("ioc_radar")
            .and_then(|radar| radar.get("totals"))
            .and_then(|totals| totals.get("total"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["iocs"] = json!(ioc_total);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("infrastructure_hosts"))
        .is_none()
    {
        let infra_total = brief
            .get("infrastructure_radar")
            .and_then(|radar| radar.get("totals"))
            .and_then(|totals| totals.get("hosts"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["infrastructure_hosts"] = json!(infra_total);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("supply_chain_advisories"))
        .is_none()
    {
        let supply_total = brief
            .get("supply_chain_radar")
            .and_then(|radar| radar.get("totals"))
            .and_then(|totals| totals.get("advisories"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["supply_chain_advisories"] = json!(supply_total);
    }
    let cve_items = brief
        .get("cves")
        .and_then(|items| items.as_array())
        .cloned()
        .unwrap_or_default();
    if brief
        .get("stats")
        .and_then(|v| v.get("epss_tracked"))
        .is_none()
    {
        let tracked = cve_items
            .iter()
            .filter(|cve| {
                cve.get("epss").and_then(|v| v.as_f64()).unwrap_or(0.0) > 0.0
                    || cve
                        .get("epss_percentile")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0)
                        > 0.0
            })
            .count();
        brief["stats"]["epss_tracked"] = json!(tracked);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("epss_rising"))
        .is_none()
    {
        let rising = cve_items
            .iter()
            .filter(|cve| cve.get("epss_momentum").and_then(|v| v.as_str()) == Some("rising"))
            .count();
        brief["stats"]["epss_rising"] = json!(rising);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("epss_stable"))
        .is_none()
    {
        let stable = cve_items
            .iter()
            .filter(|cve| cve.get("epss_momentum").and_then(|v| v.as_str()) == Some("stable"))
            .count();
        brief["stats"]["epss_stable"] = json!(stable);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("epss_falling"))
        .is_none()
    {
        let falling = cve_items
            .iter()
            .filter(|cve| cve.get("epss_momentum").and_then(|v| v.as_str()) == Some("falling"))
            .count();
        brief["stats"]["epss_falling"] = json!(falling);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("vulnrichment_hits"))
        .is_none()
    {
        let hits = cve_items
            .iter()
            .filter(|cve| {
                cve.get("cisa_vulnrichment")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            })
            .count();
        brief["stats"]["vulnrichment_hits"] = json!(hits);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("vulnrichment_checked"))
        .is_none()
    {
        let checked = cve_items.len().min(10);
        brief["stats"]["vulnrichment_checked"] = json!(checked);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("vulnrichment_missing"))
        .is_none()
    {
        let checked = brief["stats"]["vulnrichment_checked"].as_u64().unwrap_or(0);
        let hits = brief["stats"]["vulnrichment_hits"].as_u64().unwrap_or(0);
        brief["stats"]["vulnrichment_missing"] = json!(checked.saturating_sub(hits));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("ransomware_victims"))
        .is_none()
    {
        let ransomware_total = brief
            .get("ransomware_pulse")
            .and_then(|radar| radar.get("totals"))
            .and_then(|totals| totals.get("victims"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["ransomware_victims"] = json!(ransomware_total);
    }

    polish_priority(brief);
    polish_array_items(brief, "iran_radar", 88, 240);
    polish_array_items(brief, "global_news", 88, 240);
    polish_cves(brief);
    add_editorial_display_fields(brief);
    brief["brief_notes"] = json!(build_brief_notes(brief));
    let executive_snapshot = build_executive_snapshot(brief);
    brief["executive_snapshot"] = executive_snapshot;
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
    let cleaned = concise_title(title, 90);
    if cleaned.trim().is_empty() {
        return "سیگنال امنیتی قابل بررسی".to_string();
    }
    if contains_persian(&cleaned) {
        return truncate_chars(&cleaned, 72);
    }

    let lower = cleaned.to_lowercase();
    let focus = persian_focus_label(&cleaned);
    let headline = if lower.contains("actively exploited")
        || lower.contains("exploited in the wild")
        || lower.contains("mass exploitation")
    {
        format!("هشدار بهره‌برداری فعال درباره {focus}")
    } else if lower.contains("zero-day") || lower.contains("0-day") {
        format!("هشدار آسیب‌پذیری روز-صفر در {focus}")
    } else if lower.contains("cve-")
        || lower.contains("vulnerability")
        || lower.contains("vulnerabilities")
        || lower.contains("flaw")
        || lower.contains("bug")
    {
        format!("آسیب‌پذیری مهم در {focus}")
    } else if lower.contains("patch")
        || lower.contains("security update")
        || lower.contains("fixed")
        || lower.contains("fixes")
    {
        format!("به‌روزرسانی امنیتی برای {focus}")
    } else if lower.contains("ransomware") {
        format!("گزارش فعالیت باج‌افزاری مرتبط با {focus}")
    } else if lower.contains("malware")
        || lower.contains("trojan")
        || lower.contains("botnet")
        || lower.contains("backdoor")
    {
        format!("ردیابی بدافزار مرتبط با {focus}")
    } else if lower.contains("phishing") || lower.contains("credential") {
        format!("هشدار فیشینگ و سرقت اعتبار درباره {focus}")
    } else if lower.contains("breach")
        || lower.contains("data leak")
        || lower.contains("stolen")
        || lower.contains("incident")
    {
        format!("گزارش رخداد امنیتی درباره {focus}")
    } else if lower.contains("ai")
        || lower.contains("llm")
        || lower.contains("artificial intelligence")
    {
        format!("ریسک امنیتی هوش مصنوعی در {focus}")
    } else {
        format!("خبر امنیتی تازه درباره {focus}")
    };

    truncate_chars(&headline, 72)
}

fn fallback_persian_summary(summary: &str, fallback_prefix: &str) -> String {
    let cleaned = non_empty_summary(summary, 220);
    if contains_persian(&cleaned) {
        return truncate_chars(&cleaned, 190);
    }

    let lower = cleaned.to_lowercase();
    let focus = persian_focus_label(&cleaned);
    let text = if lower.contains("actively exploited")
        || lower.contains("exploited in the wild")
        || lower.contains("mass exploitation")
    {
        format!("این سیگنال نشانه بهره‌برداری فعال پیرامون {focus} دارد؛ exposure دارایی‌های مرتبط باید سریع بررسی شود.")
    } else if lower.contains("cve-")
        || lower.contains("vulnerability")
        || lower.contains("vulnerabilities")
        || lower.contains("flaw")
        || lower.contains("bug")
    {
        format!("این آیتم به آسیب‌پذیری در {focus} اشاره دارد و باید با موجودی دارایی‌ها و برنامه وصله تطبیق داده شود.")
    } else if lower.contains("ransomware") {
        format!("این گزارش به فعالیت باج‌افزاری مرتبط با {focus} اشاره دارد و برای پایش ریسک تداوم سرویس مهم است.")
    } else if lower.contains("malware")
        || lower.contains("trojan")
        || lower.contains("botnet")
        || lower.contains("backdoor")
    {
        format!("این سیگنال به بدافزار یا زیرساخت مخرب مرتبط با {focus} اشاره دارد و برای correlation دفاعی قابل استفاده است.")
    } else if lower.contains("supply chain")
        || lower.contains("package")
        || lower.contains("dependency")
    {
        format!("این آیتم به ریسک زنجیره تأمین نرم‌افزار پیرامون {focus} اشاره دارد و باید با وابستگی‌های واقعی مقایسه شود.")
    } else if lower.contains("phishing") || lower.contains("credential") {
        format!("این سیگنال به فیشینگ یا سرقت اعتبار مرتبط با {focus} اشاره دارد و برای پایش هویت و ایمیل مهم است.")
    } else if !fallback_prefix.trim().is_empty() {
        format!("{fallback_prefix}؛ موضوع اصلی برای پایش امروز {focus} است.")
    } else {
        format!(
            "این خبر امنیتی درباره {focus} برای آگاهی موقعیتی و اولویت‌بندی روزانه قابل بررسی است."
        )
    };

    truncate_chars(&text, 190)
}

fn persian_focus_label(text: &str) -> String {
    if let Some(cve) = first_cve_id(text) {
        return cve;
    }

    let lower = text.to_lowercase();
    let known = [
        ("microsoft", "Microsoft"),
        ("windows", "Windows"),
        ("exchange", "Exchange"),
        ("office", "Office"),
        ("azure", "Azure"),
        ("github", "GitHub"),
        ("gitlab", "GitLab"),
        ("gitea", "Gitea"),
        ("google chrome", "Chrome"),
        ("chrome", "Chrome"),
        ("android", "Android"),
        ("apple", "Apple"),
        ("ios", "iOS"),
        ("macos", "macOS"),
        ("linux", "Linux"),
        ("kernel", "Linux Kernel"),
        ("cisco", "Cisco"),
        ("fortinet", "Fortinet"),
        ("fortigate", "FortiGate"),
        ("palo alto", "Palo Alto"),
        ("ivanti", "Ivanti"),
        ("vmware", "VMware"),
        ("citrix", "Citrix"),
        ("apache", "Apache"),
        ("nginx", "Nginx"),
        ("wordpress", "WordPress"),
        ("drupal", "Drupal"),
        ("kubernetes", "Kubernetes"),
        ("docker", "Docker"),
        ("jenkins", "Jenkins"),
        ("npm", "npm"),
        ("pypi", "PyPI"),
        ("maven", "Maven"),
        ("rust", "Rust"),
        ("golang", "Go"),
        ("go ", "Go"),
        ("ransomware", "باج‌افزار"),
        ("malware", "بدافزار"),
        ("phishing", "فیشینگ"),
        ("botnet", "بات‌نت"),
        ("zero-day", "روز-صفر"),
    ];

    let mut hits: Vec<&str> = Vec::new();
    for (needle, label) in known {
        if lower.contains(needle) && !hits.contains(&label) {
            hits.push(label);
        }
        if hits.len() >= 2 {
            break;
        }
    }
    if !hits.is_empty() {
        return hits.join(" / ");
    }

    let mut tokens: Vec<String> = Vec::new();
    for raw in text.split_whitespace() {
        let token = raw.trim_matches(|ch: char| {
            !(ch.is_alphanumeric() || ch == '-' || ch == '_' || ch == '.' || ch == '/')
        });
        if token.len() < 3 || token.len() > 32 || is_noise_token(token) {
            continue;
        }
        let has_signal_case = token.chars().any(|ch| ch.is_ascii_uppercase())
            || token.contains('-')
            || token.contains('.')
            || token.contains('/');
        if has_signal_case && !tokens.iter().any(|existing| existing == token) {
            tokens.push(token.to_string());
        }
        if tokens.len() >= 2 {
            break;
        }
    }

    if tokens.is_empty() {
        "دارایی یا سرویس مهم".to_string()
    } else {
        tokens.join(" / ")
    }
}

fn first_cve_id(text: &str) -> Option<String> {
    for raw in text.split_whitespace() {
        let token = raw
            .trim_matches(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-'))
            .to_ascii_uppercase();
        if token.starts_with("CVE-") && token.len() >= 13 {
            return Some(token);
        }
    }
    None
}

fn is_noise_token(token: &str) -> bool {
    let lower = token.to_lowercase();
    matches!(
        lower.as_str(),
        "the"
            | "and"
            | "for"
            | "from"
            | "with"
            | "that"
            | "this"
            | "into"
            | "after"
            | "before"
            | "over"
            | "under"
            | "new"
            | "old"
            | "security"
            | "cyber"
            | "hackers"
            | "attacks"
            | "attack"
            | "vulnerability"
            | "vulnerabilities"
            | "critical"
            | "high"
            | "medium"
            | "low"
            | "warning"
            | "alert"
            | "update"
            | "updates"
            | "patch"
            | "patches"
            | "users"
            | "companies"
            | "researchers"
    )
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
    let sources = brief
        .get("source_health")
        .and_then(|v| v.get("rss_sources"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let failed_sources = brief
        .get("source_health")
        .and_then(|v| v.get("failed_rss_sources"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let attack_pressure_ok = brief
        .get("attack_pressure")
        .and_then(|v| v.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ioc_radar_ok = brief
        .get("ioc_radar")
        .and_then(|v| v.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let infrastructure_ok = brief
        .get("infrastructure_radar")
        .and_then(|v| v.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let supply_chain_ok = brief
        .get("supply_chain_radar")
        .and_then(|v| v.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ransomware_ok = brief
        .get("ransomware_pulse")
        .and_then(|v| v.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if ai_enabled && ai_ok && ai_cache {
        notes.push(
            "نسخه فارسی این رادار از cache هوش مصنوعی آماده شده و داده خام منابع حفظ شده است."
                .to_string(),
        );
    } else if ai_enabled && ai_ok {
        notes.push(
            "نسخه فارسی این رادار با یک ویرایش هوش مصنوعی ساخته و برای اجرای بعدی cache شد."
                .to_string(),
        );
    } else if ai_enabled {
        notes.push(
            "لایه فارسی‌سازی هوش مصنوعی در این اجرا کامل نشد؛ خروجی با fallback محلی ساخته شده است."
                .to_string(),
        );
    } else {
        notes.push(
            "این خروجی بدون هوش مصنوعی ساخته شده و فقط از ruleهای محلی استفاده می‌کند.".to_string(),
        );
    }

    if sources > 0 {
        let mut coverage = format!(
            "پوشش خبری این نسخه از {sources} منبع RSS به‌همراه NVD، CISA KEV و EPSS ساخته شده است."
        );
        if attack_pressure_ok {
            coverage.push_str(" لایه Attack Pressure نیز از DShield/SANS اضافه شده است.");
        }
        if ioc_radar_ok {
            coverage.push_str(" IOC Radar هم از URLhaus و ThreatFox ساخته شده است.");
        }
        if infrastructure_ok {
            coverage
                .push_str(" Suspicious Infrastructure نیز با Shodan InternetDB enrich شده است.");
        }
        if supply_chain_ok {
            coverage.push_str(
                " Supply Chain Radar نیز از GitHub Advisories و OSV reference ساخته شده است.",
            );
        }
        if ransomware_ok {
            coverage.push_str(" Ransomware Pulse هم از Ransomware.live به صورت آماری و بدون لینک leak ساخته شده است.");
        }
        if failed_sources > 0 {
            coverage.push_str(&format!(
                " {failed_sources} منبع RSS در این اجرا skip شد و در Source Health ثبت شده است."
            ));
        }
        notes.push(coverage);
    }

    notes.into_iter().take(2).collect()
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

fn copy_static_assets(out_path: &PathBuf) -> Result<()> {
    let Some(site_dir) = out_path.parent() else {
        return Ok(());
    };

    let src = PathBuf::from("assets");
    if !src.exists() {
        return Ok(());
    }

    let dest = site_dir.join("assets");
    copy_dir_recursive(&src, &dest)
}

fn copy_dir_recursive(src: &PathBuf, dest: &PathBuf) -> Result<()> {
    fs::create_dir_all(dest)
        .with_context(|| format!("failed to create asset directory: {}", dest.display()))?;

    for entry in fs::read_dir(src)
        .with_context(|| format!("failed to read asset directory: {}", src.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let target = dest.join(entry.file_name());

        if path.is_dir() {
            copy_dir_recursive(&path, &target)?;
        } else {
            fs::copy(&path, &target).with_context(|| {
                format!(
                    "failed to copy static asset from {} to {}",
                    path.display(),
                    target.display()
                )
            })?;
        }
    }

    Ok(())
}

fn get_bytes_cached_intel(
    client: &Client,
    config: &Config,
    url: &str,
    label: &str,
    offline: bool,
    refresh_cache: bool,
) -> Result<Vec<u8>> {
    let cache_key = cache_key(url, &[]);
    let ttl_minutes = config.intel.refresh_hours.saturating_mul(60).max(60);

    if !refresh_cache {
        if let Some(bytes) =
            read_cache_from_dir(&config.intel.cache_dir, &cache_key, ttl_minutes, false)?
        {
            eprintln!("  ↳ cache hit: {label}");
            return Ok(bytes);
        }
    }

    if offline {
        return read_cache_from_dir(&config.intel.cache_dir, &cache_key, ttl_minutes, true)?
            .with_context(|| format!("offline mode has no cached response for {label}"));
    }

    match client
        .get(url)
        .send()
        .and_then(|response| response.error_for_status())
    {
        Ok(response) => {
            let bytes = response
                .bytes()
                .with_context(|| format!("failed to read response body for {label}"))?
                .to_vec();
            write_cache_to_dir(&config.intel.cache_dir, &cache_key, &bytes)?;
            Ok(bytes)
        }
        Err(err) => {
            if let Some(bytes) =
                read_cache_from_dir(&config.intel.cache_dir, &cache_key, ttl_minutes, true)?
            {
                eprintln!("⚠️  using stale intel cache for {label}: {err}");
                Ok(bytes)
            } else {
                Err(err).with_context(|| format!("request failed for {label}: {url}"))
            }
        }
    }
}

fn cache_path_in_dir(cache_dir: &str, cache_key: &str) -> PathBuf {
    let mut hasher = DefaultHasher::new();
    cache_key.hash(&mut hasher);
    let hash = hasher.finish();
    PathBuf::from(cache_dir).join(format!("{hash:016x}.bin"))
}

fn read_cache_from_dir(
    cache_dir: &str,
    cache_key: &str,
    ttl_minutes: u64,
    allow_stale: bool,
) -> Result<Option<Vec<u8>>> {
    let path = cache_path_in_dir(cache_dir, cache_key);
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
        let ttl = Duration::from_secs(ttl_minutes.saturating_mul(60));

        if age > ttl {
            return Ok(None);
        }
    }

    fs::read(&path)
        .map(Some)
        .with_context(|| format!("failed to read cache file: {}", path.display()))
}

fn write_cache_to_dir(cache_dir: &str, cache_key: &str, bytes: &[u8]) -> Result<()> {
    let path = cache_path_in_dir(cache_dir, cache_key);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create cache directory: {}", parent.display()))?;
    }
    fs::write(&path, bytes)
        .with_context(|| format!("failed to write cache file: {}", path.display()))?;
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
