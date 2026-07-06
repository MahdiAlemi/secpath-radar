#![recursion_limit = "256"]

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
    writeup_sources: Vec<SourceConfig>,
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
    #[serde(default)]
    greynoise: GreyNoiseConfig,
    #[serde(default)]
    phishing: PhishingPulseConfig,
    #[serde(default)]
    ics_ot: IcsOtConfig,
    #[serde(default)]
    nuclei_coverage: NucleiCoverageConfig,
    #[serde(default)]
    poc_watch: PocWatchConfig,
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
            greynoise: GreyNoiseConfig::default(),
            phishing: PhishingPulseConfig::default(),
            ics_ot: IcsOtConfig::default(),
            nuclei_coverage: NucleiCoverageConfig::default(),
            poc_watch: PocWatchConfig::default(),
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

#[derive(Debug, Deserialize, Clone)]
struct GreyNoiseConfig {
    #[serde(default = "default_greynoise_enabled")]
    enabled: bool,
    #[serde(default = "default_greynoise_max_lookups")]
    max_lookups: usize,
    #[serde(default = "default_greynoise_community_api_url")]
    community_api_url: String,
    #[serde(default = "default_greynoise_api_key_env")]
    api_key_env: String,
}

impl Default for GreyNoiseConfig {
    fn default() -> Self {
        Self {
            enabled: default_greynoise_enabled(),
            max_lookups: default_greynoise_max_lookups(),
            community_api_url: default_greynoise_community_api_url(),
            api_key_env: default_greynoise_api_key_env(),
        }
    }
}

fn default_greynoise_enabled() -> bool {
    true
}

fn default_greynoise_max_lookups() -> usize {
    8
}

fn default_greynoise_community_api_url() -> String {
    "https://api.greynoise.io/v3/community".to_string()
}

fn default_greynoise_api_key_env() -> String {
    "GREYNOISE_API_KEY".to_string()
}

#[derive(Debug, Deserialize, Clone)]
struct PhishingPulseConfig {
    #[serde(default = "default_phishing_enabled")]
    enabled: bool,
    #[serde(default = "default_phishing_max_urls")]
    max_urls: usize,
    #[serde(default = "default_openphish_feed_url")]
    openphish_feed_url: String,
}

impl Default for PhishingPulseConfig {
    fn default() -> Self {
        Self {
            enabled: default_phishing_enabled(),
            max_urls: default_phishing_max_urls(),
            openphish_feed_url: default_openphish_feed_url(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct IcsOtConfig {
    #[serde(default = "default_ics_ot_enabled")]
    enabled: bool,
    #[serde(default = "default_ics_ot_max_advisories")]
    max_advisories: usize,
    #[serde(default = "default_ics_ot_advisories_feed_url")]
    ics_advisories_feed_url: String,
}

fn default_ics_ot_enabled() -> bool {
    true
}

fn default_ics_ot_max_advisories() -> usize {
    12
}

fn default_ics_ot_advisories_feed_url() -> String {
    "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml".to_string()
}

impl Default for IcsOtConfig {
    fn default() -> Self {
        Self {
            enabled: default_ics_ot_enabled(),
            max_advisories: default_ics_ot_max_advisories(),
            ics_advisories_feed_url: default_ics_ot_advisories_feed_url(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct NucleiCoverageConfig {
    #[serde(default = "default_nuclei_coverage_enabled")]
    enabled: bool,
    #[serde(default = "default_nuclei_coverage_max_templates")]
    max_templates: usize,
    #[serde(default = "default_nuclei_coverage_max_missing")]
    max_missing: usize,
    #[serde(default = "default_nuclei_templates_tree_url")]
    templates_tree_url: String,
}

impl Default for NucleiCoverageConfig {
    fn default() -> Self {
        Self {
            enabled: default_nuclei_coverage_enabled(),
            max_templates: default_nuclei_coverage_max_templates(),
            max_missing: default_nuclei_coverage_max_missing(),
            templates_tree_url: default_nuclei_templates_tree_url(),
        }
    }
}

fn default_nuclei_coverage_enabled() -> bool {
    true
}

fn default_nuclei_coverage_max_templates() -> usize {
    12
}

fn default_nuclei_coverage_max_missing() -> usize {
    8
}

fn default_nuclei_templates_tree_url() -> String {
    "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1"
        .to_string()
}

#[derive(Debug, Deserialize, Clone)]
struct PocWatchConfig {
    #[serde(default = "default_poc_watch_enabled")]
    enabled: bool,
    #[serde(default = "default_poc_watch_recent_days")]
    recent_days: i64,
    #[serde(default = "default_poc_watch_max_repos_per_cve")]
    max_repos_per_cve: usize,
    #[serde(default = "default_poc_watch_max_results")]
    max_results: usize,
    #[serde(default = "default_poc_watch_max_search_results_per_query")]
    max_search_results_per_query: usize,
    #[serde(default = "default_github_search_repositories_url")]
    github_search_repositories_url: String,
    #[serde(default = "default_github_token_env")]
    github_token_env: String,
}

impl Default for PocWatchConfig {
    fn default() -> Self {
        Self {
            enabled: default_poc_watch_enabled(),
            recent_days: default_poc_watch_recent_days(),
            max_repos_per_cve: default_poc_watch_max_repos_per_cve(),
            max_results: default_poc_watch_max_results(),
            max_search_results_per_query: default_poc_watch_max_search_results_per_query(),
            github_search_repositories_url: default_github_search_repositories_url(),
            github_token_env: default_github_token_env(),
        }
    }
}

fn default_poc_watch_enabled() -> bool {
    true
}

fn default_poc_watch_recent_days() -> i64 {
    30
}

fn default_poc_watch_max_repos_per_cve() -> usize {
    1
}

fn default_poc_watch_max_results() -> usize {
    18
}

fn default_poc_watch_max_search_results_per_query() -> usize {
    30
}

fn default_github_search_repositories_url() -> String {
    "https://api.github.com/search/repositories".to_string()
}

fn default_github_token_env() -> String {
    "GITHUB_TOKEN".to_string()
}

fn default_phishing_enabled() -> bool {
    true
}

fn default_phishing_max_urls() -> usize {
    24
}

fn default_openphish_feed_url() -> String {
    "https://openphish.com/feed.txt".to_string()
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

#[derive(Debug, Clone, Serialize)]
struct GreyNoiseContextRow {
    rank: usize,
    ip: String,
    ip_safe: String,
    source: String,
    reason: String,
    classification: String,
    noise: bool,
    riot: bool,
    name: String,
    last_seen: String,
    risk: String,
    score: usize,
    bar_width: usize,
    note_fa: String,
}

#[derive(Debug, Clone)]
struct GreyNoiseCandidate {
    ip: String,
    source: String,
    reason: String,
}

#[derive(Debug, Clone, Serialize)]
struct PhishingUrlIndicator {
    rank: usize,
    url_safe: String,
    host_safe: String,
    host: String,
    tld: String,
    brand_hint: String,
    scheme: String,
    path_depth: usize,
    source: String,
    risk: String,
    score: usize,
    bar_width: usize,
    note_fa: String,
}

#[derive(Debug, Clone, Serialize)]
struct IcsAdvisoryItem {
    rank: usize,
    advisory_id: String,
    title: String,
    vendor: String,
    equipment: String,
    sector: String,
    cves: Vec<String>,
    cve_count: usize,
    cvss: f64,
    published: String,
    risk: String,
    score: usize,
    bar_width: usize,
    source: String,
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

        let (writeup_items, writeup_failures) = if args.fetch {
            fetch_writeup_feeds(&config, args.offline, args.refresh_cache)?
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

        let mut brief = build_brief(&config, items, writeup_items, cves)?;
        brief["source_health"]["failed_rss_sources"] = json!(rss_failures.len());
        brief["source_health"]["rss_failures"] = json!(rss_failures);
        brief["source_health"]["writeup_sources"] = json!(config.writeup_sources.len());
        brief["source_health"]["failed_writeup_sources"] = json!(writeup_failures.len());
        brief["source_health"]["writeup_failures"] = json!(writeup_failures);
        brief["stats"]["failed_rss_sources"] = brief["source_health"]["failed_rss_sources"].clone();
        brief["stats"]["writeup_feed_sources"] = brief["source_health"]["writeup_sources"].clone();
        brief["stats"]["failed_writeup_sources"] =
            brief["source_health"]["failed_writeup_sources"].clone();
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

        let greynoise_context = fetch_greynoise_context_or_fallback(
            &config,
            &brief["infrastructure_radar"],
            &brief["botnet_c2_pulse"],
            args.offline,
            args.refresh_cache,
        );
        let greynoise_noise = greynoise_context
            .get("totals")
            .and_then(|totals| totals.get("noise"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        let greynoise_malicious = greynoise_context
            .get("totals")
            .and_then(|totals| totals.get("malicious"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        let greynoise_riot = greynoise_context
            .get("totals")
            .and_then(|totals| totals.get("riot"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["greynoise_noise"] = json!(greynoise_noise);
        brief["stats"]["greynoise_malicious"] = json!(greynoise_malicious);
        brief["stats"]["greynoise_riot"] = json!(greynoise_riot);
        brief["greynoise_context"] = greynoise_context;

        let phishing_pulse =
            fetch_phishing_pulse_or_fallback(&config, args.offline, args.refresh_cache);
        brief["stats"]["phishing_urls"] = json!(path_u64(&phishing_pulse, &["totals", "urls"]));
        brief["stats"]["phishing_high"] = json!(path_u64(&phishing_pulse, &["totals", "high"]));
        brief["stats"]["phishing_tlds"] = json!(path_u64(&phishing_pulse, &["totals", "tlds"]));
        brief["phishing_pulse"] = phishing_pulse;

        let ics_ot_pulse =
            fetch_ics_ot_pulse_or_fallback(&config, args.offline, args.refresh_cache);
        brief["stats"]["ics_advisories"] =
            json!(path_u64(&ics_ot_pulse, &["totals", "advisories"]));
        brief["stats"]["ics_high"] = json!(path_u64(&ics_ot_pulse, &["totals", "high"]));
        brief["stats"]["ics_vendors"] = json!(path_u64(&ics_ot_pulse, &["totals", "vendors"]));
        brief["ics_ot_pulse"] = ics_ot_pulse;

        let nuclei_coverage = fetch_nuclei_coverage_or_fallback(
            &config,
            &brief["cves"],
            args.offline,
            args.refresh_cache,
        );
        brief["stats"]["nuclei_covered_cves"] =
            json!(path_u64(&nuclei_coverage, &["totals", "covered_cves"]));
        brief["stats"]["nuclei_coverage_pct"] =
            json!(path_u64(&nuclei_coverage, &["totals", "coverage_pct"]));
        brief["nuclei_coverage"] = nuclei_coverage;

        let poc_watch =
            fetch_poc_watch_or_fallback(&config, &brief["cves"], args.offline, args.refresh_cache);
        brief["stats"]["poc_watch"] = json!(path_u64(&poc_watch, &["totals", "repos"]));
        brief["stats"]["poc_watch_high"] = json!(path_u64(&poc_watch, &["totals", "high"]));
        brief["stats"]["poc_watch_cves"] =
            json!(path_u64(&poc_watch, &["totals", "cves_with_poc"]));
        brief["poc_watch"] = poc_watch;

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

    let previous_brief = read_previous_latest_brief();
    apply_local_polish(&mut brief);
    attach_history_snapshot(&mut brief, previous_brief.as_ref());
    brief["triage_signals"] = build_triage_signals(&brief);
    if let Err(err) = write_history_snapshot(&brief) {
        eprintln!("⚠️  history snapshot skipped: {err:#}");
    }

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

fn fetch_writeup_feeds(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<(Vec<FeedItem>, Vec<SourceFailure>)> {
    if config.writeup_sources.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(18))
        .build()
        .context("failed to build HTTP client for writeup feeds")?;

    let mut seen = HashSet::new();
    let mut all = Vec::new();
    let mut failures = Vec::new();

    for source in &config.writeup_sources {
        eprintln!("→ fetching writeups {}", source.name);

        match fetch_source(&client, source, config, offline, refresh_cache) {
            Ok(mut items) => {
                for item in &mut items {
                    item.tags.push("Writeup Source".to_string());
                }
                all.append(&mut items)
            }
            Err(err) => {
                eprintln!("⚠️  skipped writeup source {}: {err:#}", source.name);
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

    sort_news_latest_first(&mut deduped);
    let max_writeups = (config.fetch.max_total_items / 2).max(24).min(60);
    deduped.truncate(max_writeups);

    eprintln!(
        "✅ fetched+deduped writeup feeds: {} items from {} sources",
        deduped.len(),
        config.writeup_sources.len().saturating_sub(failures.len())
    );
    Ok((deduped, failures))
}

fn source_error_summary(error: &str) -> String {
    let compact = clean_text(error);
    truncate_chars(&compact, 160)
}

fn is_offline_cache_miss_error(error_text: &str) -> bool {
    error_text
        .to_ascii_lowercase()
        .contains("offline mode has no cached response")
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

fn fetch_greynoise_context_or_fallback(
    config: &Config,
    infrastructure_radar: &Value,
    botnet_c2_pulse: &Value,
    offline: bool,
    refresh_cache: bool,
) -> Value {
    if !config.intel.enabled || !config.intel.greynoise.enabled {
        return empty_greynoise_context("disabled");
    }

    match fetch_greynoise_context(
        config,
        infrastructure_radar,
        botnet_c2_pulse,
        offline,
        refresh_cache,
    ) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  GreyNoise Context skipped: {err:#}");
            let mut fallback = empty_greynoise_context("error");
            fallback["error"] = json!(err.to_string());
            fallback
        }
    }
}

fn fetch_greynoise_context(
    config: &Config,
    infrastructure_radar: &Value,
    botnet_c2_pulse: &Value,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
    let cfg = &config.intel.greynoise;
    eprintln!("→ fetching GreyNoise Infrastructure Context");

    if offline {
        if let Some(value) = read_greynoise_context_aggregate(config)? {
            eprintln!("  ↳ cache hit: GreyNoise Context aggregate");
            return Ok(value);
        }
    }

    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(18))
        .build()
        .context("failed to build HTTP client for GreyNoise Context")?;

    let candidates =
        greynoise_candidates_from_signals(infrastructure_radar, botnet_c2_pulse, cfg.max_lookups);
    if candidates.is_empty() {
        return Ok(json!({
            "enabled": true,
            "ok": true,
            "provider": "GreyNoise Community API",
            "source_url": cfg.community_api_url.clone(),
            "level": "Low",
            "summary_fa": "در این اجرا IP مناسبی برای context گیری GreyNoise انتخاب نشد.",
            "last_updated": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            "passive_lookup": true,
            "totals": {"checked": 0, "noise": 0, "malicious": 0, "riot": 0, "no_data": 0, "errors": 0},
            "contexts": [],
            "classification_chart": [],
            "noise_chart": []
        }));
    }

    let mut rows = Vec::new();
    let mut no_data = 0usize;
    let mut errors = 0usize;
    for (idx, candidate) in candidates.iter().enumerate() {
        if idx > 0 {
            thread::sleep(Duration::from_millis(config.intel.sleep_ms_between_sources));
        }
        match fetch_greynoise_candidate(&client, config, candidate, offline, refresh_cache) {
            Ok(row) => {
                if row.classification == "unknown" && !row.noise && !row.riot {
                    no_data += 1;
                }
                rows.push(row);
            }
            Err(err) => {
                let text = err.to_string();
                if text.contains("429") || text.to_lowercase().contains("rate") {
                    eprintln!("  ↳ GreyNoise rate limit reached after {} lookup(s); keeping collected context", rows.len());
                    errors += 1;
                    break;
                }
                if !offline {
                    eprintln!("⚠️  skipped GreyNoise {}: {err:#}", candidate.ip);
                }
                errors += 1;
            }
        }
    }

    finalize_greynoise_rows(&mut rows);
    let noise_count = rows.iter().filter(|row| row.noise).count();
    let riot_count = rows.iter().filter(|row| row.riot).count();
    let malicious_count = rows
        .iter()
        .filter(|row| row.classification == "malicious")
        .count();
    let checked = rows.len();

    let level = if malicious_count > 0 || noise_count >= 4 {
        "High"
    } else if noise_count >= 1 || checked >= 4 {
        "Medium"
    } else {
        "Low"
    };

    let summary_fa = match level {
        "High" => "برخی IPهای زیرساختی یا C2 در GreyNoise به‌عنوان noise یا malicious دیده شده‌اند؛ این فقط context دفاعی است.",
        "Medium" => "چند IP در GreyNoise context قابل مشاهده دارند؛ برای کاهش false positive و اولویت‌بندی مناسب است.",
        _ => "GreyNoise برای IPهای انتخاب‌شده سیگنال پرریسک برجسته‌ای نشان نمی‌دهد.",
    };

    let value = json!({
        "enabled": true,
        "ok": errors == 0 || !rows.is_empty(),
        "provider": "GreyNoise Community API",
        "source_url": cfg.community_api_url.clone(),
        "level": level,
        "summary_fa": summary_fa,
        "last_updated": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "passive_lookup": true,
        "rate_limited_possible": true,
        "cached": false,
        "offline_cache": false,
        "totals": {
            "checked": checked,
            "noise": noise_count,
            "malicious": malicious_count,
            "riot": riot_count,
            "no_data": no_data,
            "errors": errors
        },
        "contexts": rows,
        "classification_chart": greynoise_classification_chart(&rows),
        "noise_chart": greynoise_noise_chart(&rows)
    });

    if checked > 0 || errors == 0 {
        if let Err(err) = write_greynoise_context_aggregate(config, &value) {
            eprintln!("⚠️  failed to write GreyNoise aggregate cache: {err:#}");
        }
    }

    Ok(value)
}

fn greynoise_candidates_from_signals(
    infrastructure_radar: &Value,
    botnet_c2_pulse: &Value,
    limit: usize,
) -> Vec<GreyNoiseCandidate> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    if let Some(hosts) = infrastructure_radar
        .get("hosts")
        .and_then(|value| value.as_array())
    {
        for host in hosts {
            let Some(ip) = host.get("ip").and_then(|value| value.as_str()) else {
                continue;
            };
            if !looks_like_ipv4(ip) || !seen.insert(ip.to_string()) {
                continue;
            }
            out.push(GreyNoiseCandidate {
                ip: ip.to_string(),
                source: host
                    .get("source")
                    .and_then(|value| value.as_str())
                    .unwrap_or("Infrastructure")
                    .to_string(),
                reason: host
                    .get("reason")
                    .and_then(|value| value.as_str())
                    .unwrap_or("suspicious infrastructure")
                    .to_string(),
            });
            if out.len() >= limit {
                return out;
            }
        }
    }

    if let Some(items) = botnet_c2_pulse.get("c2").and_then(|value| value.as_array()) {
        for item in items {
            let Some(ip) = item.get("ip").and_then(|value| value.as_str()) else {
                continue;
            };
            if !looks_like_ipv4(ip) || !seen.insert(ip.to_string()) {
                continue;
            }
            out.push(GreyNoiseCandidate {
                ip: ip.to_string(),
                source: item
                    .get("source")
                    .and_then(|value| value.as_str())
                    .unwrap_or("Botnet C2")
                    .to_string(),
                reason: item
                    .get("malware")
                    .and_then(|value| value.as_str())
                    .unwrap_or("botnet c2")
                    .to_string(),
            });
            if out.len() >= limit {
                return out;
            }
        }
    }

    out
}

fn fetch_greynoise_candidate(
    client: &Client,
    config: &Config,
    candidate: &GreyNoiseCandidate,
    offline: bool,
    refresh_cache: bool,
) -> Result<GreyNoiseContextRow> {
    let bytes =
        get_greynoise_context_cached(client, config, &candidate.ip, offline, refresh_cache)?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("GreyNoise response was not JSON for {}", candidate.ip))?;

    let noise = value
        .get("noise")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let riot = value
        .get("riot")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let mut classification = value
        .get("classification")
        .and_then(|value| value.as_str())
        .unwrap_or(if riot { "benign" } else { "unknown" })
        .to_lowercase();
    if classification.trim().is_empty() {
        classification = "unknown".to_string();
    }
    let name = value
        .get("name")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("unknown")
        .to_string();
    let last_seen = value
        .get("last_seen")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();

    let (risk, score) = greynoise_risk_score(&classification, noise, riot);
    let note_fa = greynoise_note(&classification, noise, riot, &name);

    Ok(GreyNoiseContextRow {
        rank: 0,
        ip: candidate.ip.clone(),
        ip_safe: defang_indicator(&candidate.ip),
        source: candidate.source.clone(),
        reason: candidate.reason.clone(),
        classification,
        noise,
        riot,
        name: truncate_chars(&name, 48),
        last_seen,
        risk: risk.to_string(),
        score,
        bar_width: score.clamp(12, 100),
        note_fa,
    })
}

fn greynoise_context_aggregate_cache_key() -> String {
    cache_key("greynoise://community-context/aggregate-v1", &[])
}

fn read_greynoise_context_aggregate(config: &Config) -> Result<Option<Value>> {
    let cache_key = greynoise_context_aggregate_cache_key();
    let ttl_minutes = config.intel.refresh_hours.saturating_mul(60).max(60);
    let Some(bytes) = read_cache_from_dir(&config.intel.cache_dir, &cache_key, ttl_minutes, true)?
    else {
        return Ok(None);
    };
    let mut value: Value = serde_json::from_slice(&bytes)
        .context("cached GreyNoise Context aggregate was not valid JSON")?;
    value["cached"] = json!(true);
    value["offline_cache"] = json!(true);
    Ok(Some(value))
}

fn write_greynoise_context_aggregate(config: &Config, value: &Value) -> Result<()> {
    let cache_key = greynoise_context_aggregate_cache_key();
    let bytes =
        serde_json::to_vec(value).context("failed to serialize GreyNoise Context aggregate")?;
    write_cache_to_dir(&config.intel.cache_dir, &cache_key, &bytes)
}

fn get_greynoise_context_cached(
    client: &Client,
    config: &Config,
    ip: &str,
    offline: bool,
    refresh_cache: bool,
) -> Result<Vec<u8>> {
    let cfg = &config.intel.greynoise;
    let url = format!("{}/{}", cfg.community_api_url.trim_end_matches('/'), ip);
    let label = format!("GreyNoise Community {}", ip);
    let cache_key = cache_key(&url, &[]);
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

    let mut request = client.get(&url);
    if let Ok(api_key) = env::var(&cfg.api_key_env) {
        if !api_key.trim().is_empty() {
            request = request.header("key", api_key.trim().to_string());
        }
    }

    let response = request
        .send()
        .with_context(|| format!("request failed for {label}: {url}"))?;
    let status = response.status().as_u16();
    let bytes = response
        .bytes()
        .with_context(|| format!("failed to read response body for {label}"))?
        .to_vec();

    if status == 200 || status == 404 {
        write_cache_to_dir(&config.intel.cache_dir, &cache_key, &bytes)?;
        Ok(bytes)
    } else if let Some(cached) =
        read_cache_from_dir(&config.intel.cache_dir, &cache_key, ttl_minutes, true)?
    {
        eprintln!("⚠️  using stale intel cache for {label}: HTTP {status}");
        Ok(cached)
    } else {
        anyhow::bail!("GreyNoise Community API returned HTTP {status} for {ip}");
    }
}

fn finalize_greynoise_rows(rows: &mut [GreyNoiseContextRow]) {
    rows.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.ip.cmp(&b.ip)));
    let max_score = rows.iter().map(|row| row.score).max().unwrap_or(1).max(1);
    for (idx, row) in rows.iter_mut().enumerate() {
        row.rank = idx + 1;
        row.ip_safe = defang_indicator(&row.ip);
        row.bar_width =
            (((row.score as f64 / max_score as f64) * 100.0).round() as usize).clamp(12, 100);
    }
}

fn greynoise_risk_score(classification: &str, noise: bool, riot: bool) -> (&'static str, usize) {
    if classification == "malicious" {
        ("high", 92)
    } else if noise {
        ("medium", 68)
    } else if riot || classification == "benign" {
        ("low", 18)
    } else {
        ("watch", 32)
    }
}

fn greynoise_note(classification: &str, noise: bool, riot: bool, name: &str) -> String {
    if classification == "malicious" {
        return "GreyNoise این IP را malicious طبقه‌بندی کرده؛ برای کاهش false positive و triage دفاعی استفاده شود.".to_string();
    }
    if noise {
        return "این IP در GreyNoise به‌عنوان internet noise/scanner دیده شده؛ اولویت بررسی را با سایر سیگنال‌ها تطبیق بده.".to_string();
    }
    if riot {
        return format!(
            "این IP در RIOT/Business Services دیده شده و احتمالاً سرویس شناخته‌شده است: {}.",
            truncate_chars(name, 36)
        );
    }
    "GreyNoise برای این IP سیگنال scanning یا RIOT برجسته‌ای نشان نمی‌دهد.".to_string()
}

fn greynoise_classification_chart(rows: &[GreyNoiseContextRow]) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for row in rows {
        *counts.entry(row.classification.clone()).or_insert(0) += 1;
    }
    count_chart_from_counts(counts, 5)
}

fn greynoise_noise_chart(rows: &[GreyNoiseContextRow]) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for row in rows {
        let key = if row.noise {
            "noise"
        } else if row.riot {
            "riot"
        } else {
            "quiet"
        };
        *counts.entry(key.to_string()).or_insert(0) += 1;
    }
    count_chart_from_counts(counts, 4)
}

fn empty_greynoise_context(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "GreyNoise Community API",
        "level": "Unknown",
        "summary_fa": "داده GreyNoise Context در این اجرا در دسترس نبود.",
        "last_updated": "",
        "passive_lookup": true,
        "totals": {"checked": 0, "noise": 0, "malicious": 0, "riot": 0, "no_data": 0, "errors": 0},
        "contexts": [],
        "classification_chart": [],
        "noise_chart": []
    })
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

fn fetch_phishing_pulse_or_fallback(config: &Config, offline: bool, refresh_cache: bool) -> Value {
    if !config.intel.enabled || !config.intel.phishing.enabled {
        return empty_phishing_pulse("disabled");
    }

    match fetch_phishing_pulse(config, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  Phishing Pulse skipped: {err:#}");
            empty_phishing_pulse("error")
        }
    }
}

fn fetch_phishing_pulse(config: &Config, offline: bool, refresh_cache: bool) -> Result<Value> {
    let client = Client::builder()
        .timeout(Duration::from_secs(22))
        .user_agent(&config.fetch.user_agent)
        .build()
        .context("failed to build HTTP client for Phishing Pulse")?;

    let cfg = &config.intel.phishing;
    eprintln!("→ fetching Phishing Pulse");
    let bytes = get_bytes_cached_intel(
        &client,
        config,
        &cfg.openphish_feed_url,
        "OpenPhish community feed",
        offline,
        refresh_cache,
    )?;
    let text = String::from_utf8_lossy(&bytes);
    let mut indicators = parse_openphish_feed(&text, cfg.max_urls);
    finalize_phishing_indicators(&mut indicators);

    let high = indicators.iter().filter(|item| item.risk == "high").count();
    let tlds = indicators
        .iter()
        .map(|item| item.tld.clone())
        .collect::<HashSet<_>>()
        .len();
    let brands = indicators
        .iter()
        .map(|item| item.brand_hint.clone())
        .collect::<HashSet<_>>()
        .len();
    let tld_chart = phishing_tld_chart(&indicators, 8);
    let brand_chart = phishing_brand_chart(&indicators, 8);
    let risk_chart = phishing_risk_chart(&indicators);
    let level = if high >= 6 {
        "High"
    } else if indicators.len() >= 10 {
        "Medium"
    } else if indicators.is_empty() {
        "Unknown"
    } else {
        "Watch"
    };
    let summary_fa = if indicators.is_empty() {
        "در این اجرا URL فیشینگ تازه‌ای از feed عمومی دریافت نشد.".to_string()
    } else if high > 0 {
        format!("{} URL فیشینگ فعال از OpenPhish دریافت شد؛ {} مورد پرریسک lexical/host دیده می‌شود. همه URLها defanged هستند.", indicators.len(), high)
    } else {
        format!("{} URL فیشینگ فعال از OpenPhish دریافت شد؛ خروجی فقط برای آگاهی و correlation دفاعی است.", indicators.len())
    };

    Ok(json!({
        "enabled": true,
        "ok": true,
        "provider": "OpenPhish Community Feed",
        "level": level,
        "summary_fa": summary_fa,
        "last_updated": Local::now().format("%Y-%m-%d %H:%M").to_string(),
        "metadata_only": true,
        "defanged": true,
        "totals": {
            "urls": indicators.len(),
            "high": high,
            "tlds": tlds,
            "brands": brands
        },
        "urls": indicators,
        "tld_chart": tld_chart,
        "brand_chart": brand_chart,
        "risk_chart": risk_chart,
    }))
}

fn parse_openphish_feed(text: &str, limit: usize) -> Vec<PhishingUrlIndicator> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines() {
        let url = line.trim().trim_matches('"').trim_matches('\'');
        if url.is_empty() || url.starts_with('#') || !url.contains('.') {
            continue;
        }
        let Some(host) = phishing_host(url) else {
            continue;
        };
        if !seen.insert(url.to_string()) {
            continue;
        }
        let tld = phishing_tld(&host);
        let brand_hint = phishing_brand_hint(url, &host);
        let scheme = if url.to_lowercase().starts_with("https://") {
            "https"
        } else if url.to_lowercase().starts_with("http://") {
            "http"
        } else {
            "unknown"
        };
        let path_depth = phishing_path_depth(url);
        let score = phishing_score(url, &host, scheme, path_depth, &brand_hint);
        let risk = if score >= 76 {
            "high"
        } else if score >= 52 {
            "medium"
        } else {
            "watch"
        };
        out.push(PhishingUrlIndicator {
            rank: 0,
            url_safe: defang_indicator(url),
            host_safe: defang_indicator(&host),
            host,
            tld,
            brand_hint,
            scheme: scheme.to_string(),
            path_depth,
            source: "OpenPhish".to_string(),
            risk: risk.to_string(),
            score,
            bar_width: score.clamp(12, 100),
            note_fa: "URL فیشینگ به‌صورت defanged نمایش داده شده؛ آن را باز نکن و فقط برای correlation دفاعی استفاده کن.".to_string(),
        });
        if out.len() >= limit.max(1) {
            break;
        }
    }
    out
}

fn phishing_host(url: &str) -> Option<String> {
    let mut rest = url.trim();
    if let Some(idx) = rest.find("://") {
        rest = &rest[idx + 3..];
    }
    if let Some(idx) = rest.find('@') {
        rest = &rest[idx + 1..];
    }
    let host_port = rest
        .split(|ch| ch == '/' || ch == '?' || ch == '#')
        .next()
        .unwrap_or("");
    let host = host_port
        .trim_matches('[')
        .trim_matches(']')
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .trim_start_matches("www.")
        .to_lowercase();
    if host.is_empty() || !host.contains('.') {
        None
    } else {
        Some(truncate_chars(&host, 80))
    }
}

fn phishing_tld(host: &str) -> String {
    host.rsplit('.')
        .next()
        .filter(|part| !part.is_empty())
        .map(|part| truncate_chars(part, 16))
        .unwrap_or_else(|| "unknown".to_string())
}

fn phishing_path_depth(url: &str) -> usize {
    let rest = if let Some(idx) = url.find("://") {
        &url[idx + 3..]
    } else {
        url
    };
    let path = rest.splitn(2, '/').nth(1).unwrap_or("");
    path.split('/')
        .filter(|part| !part.trim().is_empty())
        .count()
}

fn phishing_brand_hint(url: &str, host: &str) -> String {
    let lower = format!("{} {}", url.to_lowercase(), host.to_lowercase());
    let pairs = [
        ("microsoft", "Microsoft/Cloud"),
        ("office", "Microsoft/Cloud"),
        ("outlook", "Microsoft/Cloud"),
        ("onedrive", "Microsoft/Cloud"),
        ("paypal", "Payments"),
        ("bank", "Banking"),
        ("wallet", "Crypto/Wallet"),
        ("crypto", "Crypto/Wallet"),
        ("facebook", "Meta/Social"),
        ("instagram", "Meta/Social"),
        ("meta", "Meta/Social"),
        ("google", "Google/Cloud"),
        ("apple", "Apple"),
        ("amazon", "Amazon/Retail"),
        ("netflix", "Streaming"),
        ("telegram", "Messaging"),
        ("whatsapp", "Messaging"),
        ("login", "Credential Harvest"),
        ("verify", "Credential Harvest"),
        ("account", "Credential Harvest"),
    ];
    for (needle, label) in pairs {
        if lower.contains(needle) {
            return label.to_string();
        }
    }
    "Unknown target".to_string()
}

fn phishing_score(
    url: &str,
    host: &str,
    scheme: &str,
    path_depth: usize,
    brand_hint: &str,
) -> usize {
    let mut score = 42_usize;
    let lower = url.to_lowercase();
    if scheme == "http" {
        score += 10;
    }
    if host.chars().filter(|ch| *ch == '.').count() >= 3 {
        score += 8;
    }
    if host.split('.').any(|part| part.parse::<u8>().is_ok()) {
        score += 10;
    }
    if path_depth >= 4 {
        score += 10;
    }
    if lower.len() > 120 {
        score += 8;
    }
    for needle in [
        "login", "verify", "account", "secure", "update", "wallet", "password", "invoice",
    ] {
        if lower.contains(needle) {
            score += 6;
            break;
        }
    }
    if brand_hint != "Unknown target" {
        score += 8;
    }
    score.min(100).max(12)
}

fn finalize_phishing_indicators(items: &mut [PhishingUrlIndicator]) {
    items.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.host.cmp(&b.host)));
    let max_score = items
        .iter()
        .map(|item| item.score)
        .max()
        .unwrap_or(1)
        .max(1);
    for (idx, item) in items.iter_mut().enumerate() {
        item.rank = idx + 1;
        item.url_safe = defang_indicator(
            &item
                .url_safe
                .replace("hxxps://", "https://")
                .replace("hxxp://", "http://")
                .replace("[.]", "."),
        );
        item.host_safe = defang_indicator(&item.host);
        item.bar_width =
            (((item.score as f64 / max_score as f64) * 100.0).round() as usize).clamp(12, 100);
    }
}

fn phishing_tld_chart(items: &[PhishingUrlIndicator], limit: usize) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for item in items {
        *counts.entry(item.tld.clone()).or_insert(0) += 1;
    }
    count_chart_from_counts(counts, limit)
}

fn phishing_brand_chart(items: &[PhishingUrlIndicator], limit: usize) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for item in items {
        *counts.entry(item.brand_hint.clone()).or_insert(0) += 1;
    }
    count_chart_from_counts(counts, limit)
}

fn phishing_risk_chart(items: &[PhishingUrlIndicator]) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for item in items {
        *counts.entry(item.risk.clone()).or_insert(0) += 1;
    }
    count_chart_from_counts(counts, 4)
}

fn empty_phishing_pulse(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "OpenPhish Community Feed",
        "level": "Unknown",
        "summary_fa": "داده Phishing Pulse در این اجرا در دسترس نبود.",
        "last_updated": "",
        "metadata_only": true,
        "defanged": true,
        "totals": {"urls": 0, "high": 0, "tlds": 0, "brands": 0},
        "urls": [],
        "tld_chart": [],
        "brand_chart": [],
        "risk_chart": []
    })
}

fn fetch_ics_ot_pulse_or_fallback(config: &Config, offline: bool, refresh_cache: bool) -> Value {
    if !config.intel.enabled || !config.intel.ics_ot.enabled {
        return empty_ics_ot_pulse("disabled");
    }

    match fetch_ics_ot_pulse(config, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  ICS/OT Advisory Pulse skipped: {err:#}");
            empty_ics_ot_pulse("fetch_error")
        }
    }
}

fn fetch_ics_ot_pulse(config: &Config, offline: bool, refresh_cache: bool) -> Result<Value> {
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(18))
        .build()
        .context("failed to build HTTP client for ICS/OT Advisory Pulse")?;

    eprintln!("→ fetching ICS/OT Advisory Pulse");
    let bytes = get_bytes_cached_intel(
        &client,
        config,
        &config.intel.ics_ot.ics_advisories_feed_url,
        "CISA ICS advisories feed",
        offline,
        refresh_cache,
    )?;

    let feed = parser::parse(&bytes[..]).context("failed to parse CISA ICS advisories feed")?;
    let mut advisories = Vec::new();

    for entry in feed.entries.iter().take(config.intel.ics_ot.max_advisories) {
        let title = entry
            .title
            .as_ref()
            .map(|t| clean_text(&t.content))
            .unwrap_or_else(|| "ICS advisory".to_string());
        let url = entry
            .links
            .first()
            .map(|link| link.href.clone())
            .unwrap_or_else(|| config.intel.ics_ot.ics_advisories_feed_url.clone());
        let raw_summary = entry
            .summary
            .as_ref()
            .map(|s| s.content.clone())
            .or_else(|| entry.content.as_ref().and_then(|c| c.body.clone()))
            .unwrap_or_default();
        let detail = clean_ics_description(&raw_summary);
        let published = entry
            .published
            .or(entry.updated)
            .map(|d| d.to_rfc3339())
            .unwrap_or_default();

        let advisory_id = extract_ics_advisory_id(&title, &url);
        let vendor = extract_labeled_field(
            &detail,
            "Vendor:",
            &[
                "Equipment:",
                "Product Version:",
                "Product:",
                "Vulnerabilities:",
                "CRITICAL INFRASTRUCTURE SECTORS:",
                "COUNTRIES/AREAS DEPLOYED:",
            ],
        )
        .map(|value| clean_ics_entity_value(&value))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| infer_vendor_from_title(&title));
        let equipment = extract_labeled_field(
            &detail,
            "Equipment:",
            &[
                "Product Version:",
                "Vulnerabilities:",
                "CRITICAL INFRASTRUCTURE SECTORS:",
                "COUNTRIES/AREAS DEPLOYED:",
                "COMPANY HEADQUARTERS LOCATION:",
            ],
        )
        .or_else(|| {
            extract_labeled_field(
                &detail,
                "Product Version:",
                &[
                    "Vulnerabilities:",
                    "CRITICAL INFRASTRUCTURE SECTORS:",
                    "COUNTRIES/AREAS DEPLOYED:",
                    "COMPANY HEADQUARTERS LOCATION:",
                ],
            )
        })
        .map(|value| clean_ics_entity_value(&value))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| infer_equipment_from_title(&title, &vendor));
        let sector = extract_labeled_field(
            &detail,
            "CRITICAL INFRASTRUCTURE SECTORS:",
            &[
                "COUNTRIES/AREAS DEPLOYED:",
                "COMPANY HEADQUARTERS LOCATION:",
                "RESEARCHER",
                "MITIGATIONS",
            ],
        )
        .map(|value| first_list_value(&value))
        .unwrap_or_else(|| infer_ics_sector(&detail));
        let cves = extract_cve_ids(&detail);
        let cvss = extract_cvss_score(&detail);
        let (risk, score) = ics_risk_from_detail(cvss, &detail);
        let rank = advisories.len() + 1;
        advisories.push(IcsAdvisoryItem {
            rank,
            advisory_id,
            title: truncate_chars(&title, 90),
            vendor: truncate_chars(&vendor, 42),
            equipment: truncate_chars(&equipment, 58),
            sector: truncate_chars(&sector, 42),
            cve_count: cves.len(),
            cves,
            cvss,
            published,
            risk,
            score,
            bar_width: score.max(12).min(100),
            source: "CISA ICS Advisories".to_string(),
            note_fa: ics_note_fa(cvss, &detail),
        });
    }

    finalize_ics_advisories(&mut advisories);
    let mut vendor_counts: HashMap<String, usize> = HashMap::new();
    let mut sector_counts: HashMap<String, usize> = HashMap::new();
    let mut severity_counts: HashMap<String, usize> = HashMap::new();
    for item in &advisories {
        *vendor_counts.entry(item.vendor.clone()).or_insert(0) += 1;
        *sector_counts.entry(item.sector.clone()).or_insert(0) += 1;
        *severity_counts.entry(item.risk.clone()).or_insert(0) += 1;
    }

    let high = advisories.iter().filter(|item| item.risk == "high").count();
    let cves_total: usize = advisories.iter().map(|item| item.cve_count).sum();
    let summary_fa = if advisories.is_empty() {
        "در این اجرا advisory تازه ICS/OT از CISA در cache فعلی دیده نشد.".to_string()
    } else if high > 0 {
        format!("{} advisory صنعتی/OT از CISA خوانده شد؛ {} مورد سطح بالا و {} CVE برای triage دفاعی دیده می‌شود.", advisories.len(), high, cves_total)
    } else {
        format!("{} advisory صنعتی/OT از CISA خوانده شد؛ تمرکز روی vendor، تجهیز و CVE برای مرور دفاعی است.", advisories.len())
    };

    Ok(json!({
        "ok": true,
        "provider": "CISA ICS Advisories",
        "source_url": config.intel.ics_ot.ics_advisories_feed_url,
        "summary_fa": summary_fa,
        "totals": {
            "advisories": advisories.len(),
            "high": high,
            "vendors": vendor_counts.len(),
            "sectors": sector_counts.len(),
            "cves": cves_total
        },
        "advisories": advisories,
        "vendor_chart": count_chart_from_counts(vendor_counts, 6),
        "sector_chart": count_chart_from_counts(sector_counts, 6),
        "risk_chart": count_chart_from_counts(severity_counts, 4),
        "safe_mode": "metadata only; no active scan; no exploit content"
    }))
}

fn clean_ics_description(raw: &str) -> String {
    let once = clean_text(raw);
    let twice = clean_text(&once);
    clean_text(&twice)
}

fn extract_labeled_field(text: &str, label: &str, next_labels: &[&str]) -> Option<String> {
    let lower = text.to_lowercase();
    let needle = label.to_lowercase();
    let start = lower.find(&needle)? + needle.len();
    let tail = &text[start..];
    let lower_tail = &lower[start..];
    let mut end = tail.len();
    for next in next_labels {
        if let Some(idx) = lower_tail.find(&next.to_lowercase()) {
            if idx > 0 && idx < end {
                end = idx;
            }
        }
    }
    let value = clean_text(&tail[..end])
        .trim_matches(|ch: char| ch == ':' || ch == '-' || ch == '–' || ch.is_whitespace())
        .to_string();
    if value.is_empty() {
        None
    } else {
        Some(truncate_chars(&value, 90))
    }
}

fn clean_ics_entity_value(value: &str) -> String {
    let mut out = clean_text(value);
    let markers = [
        "Product Version:",
        "Product:",
        "Equipment:",
        "Vulnerabilities:",
        "CRITICAL INFRASTRUCTURE SECTORS:",
        "COUNTRIES/AREAS DEPLOYED:",
        "COMPANY HEADQUARTERS LOCATION:",
    ];
    let lower = out.to_lowercase();
    let mut cut_at = out.len();
    for marker in markers {
        if let Some(idx) = lower.find(&marker.to_lowercase()) {
            if idx > 0 && idx < cut_at {
                cut_at = idx;
            }
        }
    }
    out = out[..cut_at]
        .trim_matches(|ch: char| ch == ':' || ch == '-' || ch == '–' || ch.is_whitespace())
        .to_string();
    let compact = out.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_chars(&compact, 42)
}

fn extract_ics_advisory_id(title: &str, url: &str) -> String {
    for raw in title.split_whitespace().chain(url.split('/')) {
        let token = raw
            .trim_matches(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-'))
            .to_ascii_uppercase();
        if token.starts_with("ICSA-") || token.starts_with("ICSMA-") {
            return token;
        }
    }
    url.rsplit('/')
        .next()
        .unwrap_or("ics-advisory")
        .to_ascii_uppercase()
}

fn infer_vendor_from_title(title: &str) -> String {
    let words = title
        .split_whitespace()
        .take(3)
        .collect::<Vec<_>>()
        .join(" ");
    if words.trim().is_empty() {
        "Unknown vendor".to_string()
    } else {
        words
    }
}

fn infer_equipment_from_title(title: &str, vendor: &str) -> String {
    let value = title.replacen(vendor, "", 1).trim().to_string();
    if value.is_empty() {
        "Unknown equipment".to_string()
    } else {
        value
    }
}

fn first_list_value(value: &str) -> String {
    value
        .split(|ch| ch == ',' || ch == ';' || ch == '/')
        .next()
        .unwrap_or(value)
        .trim()
        .to_string()
}

fn infer_ics_sector(text: &str) -> String {
    let lower = text.to_lowercase();
    let pairs = [
        ("energy", "Energy"),
        ("water", "Water/Wastewater"),
        ("manufacturing", "Critical Manufacturing"),
        ("transport", "Transportation"),
        ("health", "Healthcare"),
        ("chemical", "Chemical"),
        ("communications", "Communications"),
        ("commercial", "Commercial Facilities"),
    ];
    for (needle, label) in pairs {
        if lower.contains(needle) {
            return label.to_string();
        }
    }
    "ICS/OT".to_string()
}

fn extract_cvss_score(text: &str) -> f64 {
    let lower = text.to_lowercase();
    let Some(start) = lower.find("cvss") else {
        return 0.0;
    };
    let end = text.len().min(start + 80);
    let tail = &text[start..end];
    for token in tail.split(|ch: char| !(ch.is_ascii_digit() || ch == '.')) {
        if token.is_empty() || token == "." {
            continue;
        }
        if let Ok(score) = token.parse::<f64>() {
            if (0.0..=10.0).contains(&score) {
                return score;
            }
        }
    }
    0.0
}

fn ics_risk_from_detail(cvss: f64, detail: &str) -> (String, usize) {
    let lower = detail.to_lowercase();
    let mut score = if cvss >= 9.0 {
        88
    } else if cvss >= 7.0 {
        72
    } else if cvss >= 4.0 {
        48
    } else {
        32
    };
    if lower.contains("exploitable remotely")
        || lower.contains("public exploits")
        || lower.contains("low attack complexity")
    {
        score += 8;
    }
    if lower.contains("internet") || lower.contains("remote access") {
        score += 4;
    }
    let score = score.min(100);
    let risk = if score >= 82 {
        "high"
    } else if score >= 58 {
        "medium"
    } else {
        "watch"
    };
    (risk.to_string(), score)
}

fn ics_note_fa(cvss: f64, detail: &str) -> String {
    let lower = detail.to_lowercase();
    if cvss >= 9.0 {
        "Advisory صنعتی با CVSS بحرانی؛ برای assetهای OT/ICS باید اولویت patch، segmentation و exposure review بررسی شود.".to_string()
    } else if lower.contains("exploitable remotely") || lower.contains("low attack complexity") {
        "در متن CISA نشانه قابلیت بهره‌برداری remote/low-complexity دیده می‌شود؛ برای triage دفاعی با موجودی OT تطبیق بده.".to_string()
    } else {
        "این advisory برای آگاهی OT/ICS و تطبیق با vendor/equipment محیط نگه داشته شده است."
            .to_string()
    }
}

fn finalize_ics_advisories(items: &mut [IcsAdvisoryItem]) {
    items.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| b.cve_count.cmp(&a.cve_count))
    });
    for (idx, item) in items.iter_mut().enumerate() {
        item.rank = idx + 1;
        item.bar_width = item.score.max(12).min(100);
    }
}

fn empty_ics_ot_pulse(reason: &str) -> Value {
    json!({
        "ok": false,
        "reason": reason,
        "provider": "CISA ICS Advisories",
        "summary_fa": "داده ICS/OT Advisory Pulse در این اجرا در دسترس نبود.",
        "totals": {"advisories": 0, "high": 0, "vendors": 0, "sectors": 0, "cves": 0},
        "advisories": [],
        "vendor_chart": [],
        "sector_chart": [],
        "risk_chart": [],
        "safe_mode": "metadata only; no active scan; no exploit content"
    })
}

fn fetch_nuclei_coverage_or_fallback(
    config: &Config,
    cves: &Value,
    offline: bool,
    refresh_cache: bool,
) -> Value {
    if !config.intel.enabled || !config.intel.nuclei_coverage.enabled {
        return empty_nuclei_coverage("disabled");
    }

    match fetch_nuclei_coverage(config, cves, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  Nuclei Template Coverage skipped: {err:#}");
            let mut fallback = empty_nuclei_coverage("fetch_error");
            fallback["errors"] = json!([source_error_summary(&err.to_string())]);
            fallback
        }
    }
}

fn fetch_nuclei_coverage(
    config: &Config,
    cves: &Value,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
    let cfg = &config.intel.nuclei_coverage;
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(35))
        .build()
        .context("failed to build HTTP client for Nuclei Template Coverage")?;

    eprintln!("→ fetching Nuclei Template Coverage index");
    let label = "ProjectDiscovery nuclei-templates tree";
    let mut cache_misses = 0_u64;
    let mut errors = Vec::new();

    let tree_value = match get_bytes_cached_intel(
        &client,
        config,
        &cfg.templates_tree_url,
        label,
        offline,
        refresh_cache,
    ) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes)
            .context("ProjectDiscovery nuclei-templates tree was not valid JSON")?,
        Err(err) => {
            let err_text = err.to_string();
            if offline && is_offline_cache_miss_error(&err_text) {
                eprintln!("  ↳ cache miss: {label}");
                cache_misses = 1;
                Value::Null
            } else {
                errors.push(json!(source_error_summary(&err_text)));
                Value::Null
            }
        }
    };

    let dashboard_cves = dashboard_cve_metadata(cves);
    let dashboard_total = dashboard_cves.len();
    let mut cve_to_paths: HashMap<String, Vec<String>> = HashMap::new();
    let mut protocol_counts: HashMap<String, usize> = HashMap::new();
    let mut indexed_template_paths = 0usize;
    let tree_truncated = tree_value
        .get("truncated")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    if let Some(nodes) = tree_value.get("tree").and_then(|value| value.as_array()) {
        for node in nodes {
            if node.get("type").and_then(|value| value.as_str()) != Some("blob") {
                continue;
            }
            let Some(path) = node.get("path").and_then(|value| value.as_str()) else {
                continue;
            };
            let path_lower = path.to_ascii_lowercase();
            if !(path_lower.ends_with(".yaml") || path_lower.ends_with(".yml")) {
                continue;
            }
            let cve_ids = extract_cve_ids(path);
            if cve_ids.is_empty() {
                continue;
            }
            indexed_template_paths += 1;
            let protocol = nuclei_protocol_from_path(path);
            *protocol_counts.entry(protocol).or_insert(0) += 1;
            for cve_id in cve_ids {
                cve_to_paths
                    .entry(cve_id)
                    .or_insert_with(Vec::new)
                    .push(path.to_string());
            }
        }
    }

    let indexed_cves = cve_to_paths.len();
    let mut covered = Vec::new();
    let mut missing = Vec::new();
    let mut severity_counts: HashMap<String, usize> = HashMap::new();

    for row in &dashboard_cves {
        let cve_id = value_str(row, "cve_id").to_string();
        let severity = value_str(row, "severity").to_string();
        let title_fa = value_str(row, "title_fa").to_string();
        if let Some(paths) = cve_to_paths.get(&cve_id) {
            let first_path = paths.first().cloned().unwrap_or_default();
            *severity_counts.entry(severity.clone()).or_insert(0) += 1;
            let score = nuclei_coverage_score(&severity, paths.len());
            covered.push(json!({
                "cve_id": cve_id,
                "severity": severity,
                "title_fa": title_fa,
                "template_path": first_path,
                "template_path_safe": truncate_chars(&first_path, 82),
                "protocol": nuclei_protocol_from_path(&first_path),
                "template_count": paths.len(),
                "risk": nuclei_coverage_risk(&severity),
                "score": score,
                "bar_width": score.clamp(12, 100),
                "note_fa": nuclei_coverage_note_fa(&severity, paths.len()),
                "safe_mode": "metadata only; template path only; no nuclei execution; no scan target"
            }));
        } else if missing.len() < cfg.max_missing {
            missing.push(json!({
                "cve_id": cve_id,
                "severity": severity,
                "title_fa": title_fa,
                "risk": nuclei_coverage_risk(&severity),
                "note_fa": "برای این CVE در index فعلی nuclei-templates مسیر template دیده نشد."
            }));
        }
    }

    covered.sort_by(|a, b| {
        path_u64(b, &["score"])
            .cmp(&path_u64(a, &["score"]))
            .then_with(|| value_str(a, "cve_id").cmp(value_str(b, "cve_id")))
    });
    covered.truncate(cfg.max_templates);

    let covered_cves = dashboard_cves
        .iter()
        .filter(|row| {
            row.get("cve_id")
                .and_then(|value| value.as_str())
                .map(|cve_id| cve_to_paths.contains_key(cve_id))
                .unwrap_or(false)
        })
        .count();
    let missing_cves = dashboard_total.saturating_sub(covered_cves);
    let coverage_pct = if dashboard_total == 0 {
        0
    } else {
        ((covered_cves as f64 / dashboard_total as f64) * 100.0).round() as u64
    };

    let summary_fa = if cache_misses > 0 {
        "در حالت offline، cache قبلی برای index عمومی nuclei-templates وجود نداشت؛ با یک اجرای online، coverage بعداً از cache خوانده می‌شود.".to_string()
    } else if dashboard_total == 0 {
        "CVE فعالی در این اجرا برای سنجش پوشش Nuclei وجود نداشت.".to_string()
    } else if covered_cves == 0 {
        format!("از {dashboard_total} CVE فعلی، مسیر template متناظر در index عمومی nuclei-templates دیده نشد یا index/cache محدود بود.")
    } else {
        format!("{covered_cves} از {dashboard_total} CVE فعلی در index عمومی nuclei-templates مسیر template دارند؛ این فقط سنجش پوشش metadata است و هیچ scan اجرا نمی‌شود.")
    };

    let mut coverage_counts = HashMap::new();
    coverage_counts.insert("covered".to_string(), covered_cves);
    coverage_counts.insert("missing".to_string(), missing_cves);

    Ok(json!({
        "enabled": true,
        "ok": errors.is_empty(),
        "provider": "ProjectDiscovery nuclei-templates Git tree",
        "source": "projectdiscovery/nuclei-templates path metadata",
        "mode": "template_path_coverage",
        "summary_fa": summary_fa,
        "safe_mode": "metadata only; no nuclei execution; no active scan; no target input; no exploit content",
        "last_updated": Local::now().format("%Y-%m-%d %H:%M").to_string(),
        "totals": {
            "dashboard_cves": dashboard_total,
            "covered_cves": covered_cves,
            "missing_cves": missing_cves,
            "coverage_pct": coverage_pct,
            "indexed_cves": indexed_cves,
            "template_paths": indexed_template_paths,
            "tree_truncated": tree_truncated,
            "cache_misses": cache_misses,
            "errors": errors.len()
        },
        "covered": covered,
        "missing": missing,
        "coverage_chart": count_chart(coverage_counts, 2),
        "severity_chart": count_chart(severity_counts, 5),
        "protocol_chart": count_chart(protocol_counts, 6),
        "errors": errors
    }))
}

fn dashboard_cve_metadata(cves: &Value) -> Vec<Value> {
    let mut seen = HashSet::new();
    let mut rows = Vec::new();
    let Some(items) = cves.as_array() else {
        return rows;
    };
    for item in items {
        let cve_id = item
            .get("cve_id")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .trim()
            .to_ascii_uppercase();
        if !is_cve_id(&cve_id) || !seen.insert(cve_id.clone()) {
            continue;
        }
        rows.push(json!({
            "cve_id": cve_id,
            "severity": item.get("severity").and_then(|value| value.as_str()).unwrap_or("UNKNOWN"),
            "title_fa": item.get("title_fa").and_then(|value| value.as_str()).unwrap_or("CVE فعلی داشبورد")
        }));
    }
    rows
}

fn nuclei_protocol_from_path(path: &str) -> String {
    path.split('/')
        .next()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("templates")
        .to_string()
}

fn nuclei_coverage_risk(severity: &str) -> &'static str {
    match severity.to_ascii_uppercase().as_str() {
        "CRITICAL" => "high",
        "HIGH" => "high",
        "MEDIUM" => "medium",
        _ => "watch",
    }
}

fn nuclei_coverage_score(severity: &str, template_count: usize) -> usize {
    let base = match severity.to_ascii_uppercase().as_str() {
        "CRITICAL" => 84,
        "HIGH" => 72,
        "MEDIUM" => 54,
        _ => 36,
    };
    (base + template_count.saturating_sub(1).min(4) * 4).min(100)
}

fn nuclei_coverage_note_fa(severity: &str, template_count: usize) -> String {
    if severity.eq_ignore_ascii_case("CRITICAL") || severity.eq_ignore_ascii_case("HIGH") {
        format!("برای این CVE مسیر template عمومی Nuclei دیده شد ({template_count} مورد). این فقط نشانه پوشش detection است، نه اجرای scan.")
    } else {
        format!("پوشش template برای این CVE در index عمومی Nuclei دیده شد ({template_count} مورد)، به‌صورت metadata-only.")
    }
}

fn empty_nuclei_coverage(reason: &str) -> Value {
    json!({
        "enabled": false,
        "ok": false,
        "reason": reason,
        "provider": "ProjectDiscovery nuclei-templates Git tree",
        "mode": "template_path_coverage",
        "summary_fa": "داده Nuclei Template Coverage در این اجرا در دسترس نبود.",
        "safe_mode": "metadata only; no nuclei execution; no active scan; no target input; no exploit content",
        "totals": {
            "dashboard_cves": 0,
            "covered_cves": 0,
            "missing_cves": 0,
            "coverage_pct": 0,
            "indexed_cves": 0,
            "template_paths": 0,
            "tree_truncated": false,
            "cache_misses": 0,
            "errors": 0
        },
        "covered": [],
        "missing": [],
        "coverage_chart": [],
        "severity_chart": [],
        "protocol_chart": [],
        "errors": []
    })
}

fn fetch_poc_watch_or_fallback(
    config: &Config,
    _cves: &Value,
    offline: bool,
    refresh_cache: bool,
) -> Value {
    if !config.intel.enabled || !config.intel.poc_watch.enabled {
        return empty_poc_watch("disabled");
    }

    match fetch_poc_watch(config, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  Latest PoC Watch skipped: {err:#}");
            empty_poc_watch("fetch_error")
        }
    }
}

fn fetch_poc_watch(config: &Config, offline: bool, refresh_cache: bool) -> Result<Value> {
    let cfg = &config.intel.poc_watch;
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(20))
        .build()
        .context("failed to build HTTP client for Latest PoC Watch")?;

    let recent_days = cfg.recent_days.max(1);
    let since = (Utc::now().date_naive() - ChronoDuration::days(recent_days))
        .format("%Y-%m-%d")
        .to_string();
    let queries = latest_poc_search_queries(&since);

    eprintln!("→ fetching Latest PoC Watch metadata");

    let mut candidates = Vec::new();
    let mut errors = Vec::new();
    let mut cache_misses = 0_u64;

    for (index, query) in queries.iter().enumerate() {
        let label = format!("Latest GitHub PoC metadata query {}", index + 1);
        match fetch_github_repository_search(
            &client,
            config,
            cfg,
            query,
            &label,
            offline,
            refresh_cache,
        ) {
            Ok(value) => {
                if let Some(items) = value.get("items").and_then(|v| v.as_array()) {
                    for repo in items {
                        candidates.extend(map_github_latest_poc_candidates(repo));
                    }
                }
            }
            Err(err) => {
                let err_text = err.to_string();
                if offline && is_offline_cache_miss_error(&err_text) {
                    eprintln!(
                        "  ↳ cache miss: Latest GitHub PoC metadata query {}",
                        index + 1
                    );
                    cache_misses += 1;
                } else {
                    eprintln!(
                        "⚠️  skipped Latest GitHub PoC metadata query {}: {err:#}",
                        index + 1
                    );
                    errors.push(json!({
                        "query": index + 1,
                        "error": source_error_summary(&err_text)
                    }));
                }
            }
        }
        thread::sleep(Duration::from_millis(config.intel.sleep_ms_between_sources));
    }

    let raw_candidates = candidates.len() as u64;
    let mut seen_repo_cve = HashSet::new();
    candidates.retain(|item| {
        let key = format!(
            "{}::{}",
            item.get("cve_id").and_then(|v| v.as_str()).unwrap_or(""),
            item.get("repo").and_then(|v| v.as_str()).unwrap_or("")
        );
        seen_repo_cve.insert(key)
    });

    candidates.sort_by(|a, b| {
        path_u64(b, &["published_ts"])
            .cmp(&path_u64(a, &["published_ts"]))
            .then_with(|| path_u64(b, &["score"]).cmp(&path_u64(a, &["score"])))
            .then_with(|| value_str(a, "repo").cmp(value_str(b, "repo")))
    });

    let mut cve_seen_counts: HashMap<String, usize> = HashMap::new();
    let per_cve_limit = cfg.max_repos_per_cve.max(1);
    let mut grouped = Vec::new();
    for item in candidates {
        let cve_id = item
            .get("cve_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let count = cve_seen_counts.entry(cve_id).or_insert(0);
        if *count < per_cve_limit {
            grouped.push(item);
            *count += 1;
        }
        if grouped.len() >= cfg.max_results {
            break;
        }
    }

    let repos = grouped.len() as u64;
    let high = grouped
        .iter()
        .filter(|item| item.get("risk").and_then(|v| v.as_str()) == Some("high"))
        .count() as u64;
    let cves_with_poc = grouped
        .iter()
        .filter_map(|item| item.get("cve_id").and_then(|v| v.as_str()))
        .collect::<HashSet<_>>()
        .len() as u64;
    let fresh = grouped
        .iter()
        .filter(|item| path_u64(item, &["age_days"]) <= 7)
        .count() as u64;

    let mut cve_counts: HashMap<String, usize> = HashMap::new();
    let mut risk_counts: HashMap<String, usize> = HashMap::new();
    for item in &grouped {
        if let Some(cve_id) = item.get("cve_id").and_then(|v| v.as_str()) {
            *cve_counts.entry(cve_id.to_string()).or_insert(0) += 1;
        }
        if let Some(risk) = item.get("risk").and_then(|v| v.as_str()) {
            *risk_counts.entry(risk.to_string()).or_insert(0) += 1;
        }
    }

    let summary_fa = if repos == 0 && offline && cache_misses == queries.len() as u64 {
        format!("در حالت offline، cache قبلی برای جست‌وجوهای جدید PoC وجود نداشت؛ با یک اجرای online، جریان زمانی PoC پر می‌شود و بعداً offline از cache خوانده می‌شود.")
    } else if repos == 0 {
        format!("در بازه {} روز اخیر، PoC عمومی جدید و قابل نمایش به‌صورت metadata-only از جریان زمانی GitHub دیده نشد یا cache/API محدود بود.", recent_days)
    } else {
        format!("{repos} PoC metadata جدید برای {cves_with_poc} CVE از جریان زمانی GitHub استخراج شد؛ مبنا زمان انتشار repository است، نه جست‌وجو روی CVEهای داشبورد.")
    };

    Ok(json!({
        "enabled": true,
        "ok": errors.is_empty(),
        "provider": "GitHub Repository Search API",
        "source": "GitHub latest repository metadata only",
        "mode": "latest_poc_stream",
        "window_days": recent_days,
        "safe_mode": "metadata only; no exploit code; no raw links; no clone/download commands; repository URLs are not rendered in UI",
        "summary_fa": summary_fa,
        "totals": {
            "cves_checked": 0,
            "cves_with_poc": cves_with_poc,
            "repos": repos,
            "high": high,
            "fresh": fresh,
            "raw_candidates": raw_candidates,
            "kev_related": 0,
            "epss_rising_related": 0,
            "queries": queries.len(),
            "cache_misses": cache_misses,
            "errors": errors.len()
        },
        "repos": grouped,
        "cve_chart": count_chart(cve_counts, 8),
        "risk_chart": count_chart(risk_counts, 4),
        "errors": errors
    }))
}

fn latest_poc_search_queries(since: &str) -> Vec<String> {
    vec![
        format!("CVE PoC in:name,description,readme created:>={since}"),
        format!("CVE exploit in:name,description,readme created:>={since}"),
        format!("CVE proof-of-concept in:name,description,readme created:>={since}"),
        format!("CVE reproducer in:name,description,readme created:>={since}"),
    ]
}

fn fetch_github_repository_search(
    client: &Client,
    config: &Config,
    cfg: &PocWatchConfig,
    query: &str,
    label: &str,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
    let per_page = cfg.max_search_results_per_query.clamp(8, 50).to_string();
    let query_params = [
        ("q", query),
        ("sort", "updated"),
        ("order", "desc"),
        ("per_page", per_page.as_str()),
    ];
    let cache_key = cache_key(&cfg.github_search_repositories_url, &query_params);
    let ttl_minutes = config.intel.refresh_hours.saturating_mul(60).max(60);

    if !refresh_cache {
        if let Some(bytes) =
            read_cache_from_dir(&config.intel.cache_dir, &cache_key, ttl_minutes, false)?
        {
            eprintln!("  ↳ cache hit: {label}");
            return serde_json::from_slice(&bytes)
                .with_context(|| format!("cached GitHub search was not valid JSON for {label}"));
        }
    }

    if offline {
        let bytes = read_cache_from_dir(&config.intel.cache_dir, &cache_key, ttl_minutes, true)?
            .with_context(|| format!("offline mode has no cached response for {label}"))?;
        return serde_json::from_slice(&bytes)
            .with_context(|| format!("cached GitHub search was not valid JSON for {label}"));
    }

    let mut request = client
        .get(&cfg.github_search_repositories_url)
        .query(&query_params)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28");

    if let Ok(token) = env::var(&cfg.github_token_env) {
        let token = token.trim();
        if !token.is_empty() {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
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
            write_cache_to_dir(&config.intel.cache_dir, &cache_key, &bytes)?;
            serde_json::from_slice(&bytes)
                .with_context(|| format!("GitHub search response was not valid JSON for {label}"))
        }
        Err(err) => {
            if let Some(bytes) =
                read_cache_from_dir(&config.intel.cache_dir, &cache_key, ttl_minutes, true)?
            {
                eprintln!("⚠️  using stale intel cache for {label}: {err}");
                serde_json::from_slice(&bytes)
                    .with_context(|| format!("cached GitHub search was not valid JSON for {label}"))
            } else {
                Err(err).with_context(|| {
                    format!(
                        "request failed for {label}: {}",
                        cfg.github_search_repositories_url
                    )
                })
            }
        }
    }
}

fn is_cve_id(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();
    parts.len() == 3
        && parts[0].eq_ignore_ascii_case("CVE")
        && parts[1].len() == 4
        && parts[1].chars().all(|ch| ch.is_ascii_digit())
        && parts[2].len() >= 4
        && parts[2].chars().all(|ch| ch.is_ascii_digit())
}

fn map_github_latest_poc_candidates(repo: &Value) -> Vec<Value> {
    let full_name = match repo.get("full_name").and_then(|v| v.as_str()) {
        Some(value) => value.trim(),
        None => return Vec::new(),
    };
    let description = repo
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let topics = repo
        .get("topics")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let text = format!(
        "{} {} {}",
        full_name.to_ascii_lowercase(),
        description.to_ascii_lowercase(),
        topics.to_ascii_lowercase()
    );

    if github_poc_negative_match(&text) || !github_latest_poc_positive_signal(&text) {
        return Vec::new();
    }

    let cve_ids = extract_cve_ids(&text);
    if cve_ids.is_empty() {
        return Vec::new();
    }

    let stars = repo
        .get("stargazers_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let forks = repo
        .get("forks_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let updated_at = repo
        .get("updated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let created_at = repo
        .get("created_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let pushed_at = repo
        .get("pushed_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let language = repo
        .get("language")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let published_ts = parse_rfc3339_timestamp(&created_at).unwrap_or(0).max(0) as u64;
    let updated_ts = parse_rfc3339_timestamp(&updated_at).unwrap_or(0).max(0) as u64;
    let score = github_poc_score(stars, forks, &created_at, &updated_at, &text);
    let risk = if score >= 78 {
        "high"
    } else if score >= 50 {
        "medium"
    } else {
        "watch"
    };
    let repo_type = github_poc_repo_type(&text);
    let age_days = poc_age_days(&created_at);
    let age_fa = poc_age_label_fa(age_days);

    cve_ids
        .into_iter()
        .map(|cve_id| {
            let note_fa = github_poc_note_fa(&cve_id, risk, repo_type, age_days);
            let title = format!("{} latest public PoC metadata", cve_id);
            let title_fa = format!("PoC عمومی تازه برای {}", cve_id);
            json!({
                "cve_id": cve_id,
                "repo": full_name,
                "repo_safe": full_name,
                "github_path": format!("github.com/{full_name}"),
                "url_rendered": false,
                "title": title,
                "title_fa": title_fa,
                "description": concise_text(description, 180),
                "description_fa": fallback_persian_summary(description, "این repository فقط به‌عنوان metadata برای وجود PoC عمومی جدید ثبت شده است"),
                "stars": stars,
                "forks": forks,
                "language": language.clone(),
                "created_at": created_at.clone(),
                "published_at": created_at.clone(),
                "published_ts": published_ts,
                "updated_at": updated_at.clone(),
                "updated_ts": updated_ts,
                "pushed_at": pushed_at.clone(),
                "age_days": age_days,
                "age_fa": age_fa.clone(),
                "repo_type": repo_type,
                "risk": risk,
                "score": score,
                "bar_width": score,
                "note_fa": note_fa,
                "safe_mode": "metadata only; no code, no raw URL, no clone/download command",
                "tags": github_poc_tags(repo_type, risk, age_days)
            })
        })
        .collect()
}

fn extract_cve_ids(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut values = Vec::new();
    let mut seen = HashSet::new();
    let mut index = 0usize;

    while index + 9 <= bytes.len() {
        let has_cve_prefix = index + 4 <= bytes.len()
            && bytes[index].eq_ignore_ascii_case(&b'c')
            && bytes[index + 1].eq_ignore_ascii_case(&b'v')
            && bytes[index + 2].eq_ignore_ascii_case(&b'e')
            && bytes[index + 3] == b'-';
        if has_cve_prefix {
            let mut end = index + 4;
            let year_start = end;
            while end < bytes.len() && bytes[end].is_ascii_digit() && end - year_start < 4 {
                end += 1;
            }
            if end - year_start == 4 && end < bytes.len() && bytes[end] == b'-' {
                end += 1;
                let id_start = end;
                while end < bytes.len() && bytes[end].is_ascii_digit() {
                    end += 1;
                }
                if end - id_start >= 4 {
                    let cve_id = String::from_utf8_lossy(&bytes[index..end]).to_ascii_uppercase();
                    if is_cve_id(&cve_id) && seen.insert(cve_id.clone()) {
                        values.push(cve_id);
                    }
                    index = end;
                    continue;
                }
            }
        }
        index += 1;
    }

    values
}

fn github_poc_negative_match(text: &str) -> bool {
    [
        "advisory-database",
        "cvelist",
        "cve-list",
        "cve database",
        "cve dictionary",
        "nvd mirror",
        "vulnerability database",
        "vuldb",
        "oval definitions",
        "nessus plugin",
        "scanner collection",
        "awesome-cve",
        "poc-in-github",
        "nomi-sec",
        "trickest",
        "nuclei-templates",
        "template collection",
        "exploitdb mirror",
        "packetstorm mirror",
        "weekly roundup",
        "monthly roundup",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn github_latest_poc_positive_signal(text: &str) -> bool {
    [
        "poc",
        "proof-of-concept",
        "proof of concept",
        "exploit",
        "exp",
        "rce",
        "privilege escalation",
        "local privilege escalation",
        "lpe",
        "weaponized",
        "reproducer",
        "trigger",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn github_poc_repo_type(text: &str) -> &'static str {
    if text.contains("proof-of-concept")
        || text.contains("proof of concept")
        || text.contains("poc")
    {
        "poc"
    } else if text.contains("exploit")
        || text.contains("rce")
        || text.contains("privilege escalation")
    {
        "exploit-metadata"
    } else if text.contains("reproducer") || text.contains("trigger") {
        "reproducer"
    } else {
        "public-reference"
    }
}

fn github_poc_score(stars: u64, forks: u64, created_at: &str, updated_at: &str, text: &str) -> u64 {
    let mut score = 24_u64;
    score += stars.min(80) / 4;
    score += forks.min(40) / 4;
    if text.contains("exploit") || text.contains("rce") {
        score += 16;
    } else if text.contains("poc")
        || text.contains("proof-of-concept")
        || text.contains("proof of concept")
    {
        score += 12;
    }
    if text.contains("weaponized") {
        score += 10;
    }
    if text.contains("reproducer") || text.contains("trigger") {
        score += 6;
    }

    let age_days = poc_age_days(created_at);
    if age_days <= 1 {
        score += 24;
    } else if age_days <= 3 {
        score += 18;
    } else if age_days <= 7 {
        score += 12;
    } else if age_days <= 30 {
        score += 6;
    }

    let updated_ts = parse_rfc3339_timestamp(updated_at).unwrap_or(0);
    let created_ts = parse_rfc3339_timestamp(created_at).unwrap_or(0);
    if created_ts > 0 && updated_ts >= created_ts && updated_ts - created_ts <= 604_800 {
        score += 4;
    }

    score.clamp(12, 100)
}

fn poc_age_days(timestamp: &str) -> u64 {
    let event_ts = parse_rfc3339_timestamp(timestamp).unwrap_or(0);
    if event_ts <= 0 {
        return 365;
    }
    ((Utc::now().timestamp() - event_ts).max(0) / 86_400) as u64
}

fn poc_age_label_fa(age_days: u64) -> String {
    if age_days == 0 {
        "امروز".to_string()
    } else if age_days == 1 {
        "دیروز".to_string()
    } else if age_days < 7 {
        format!("{} روز پیش", age_days)
    } else if age_days < 30 {
        format!("{} هفته پیش", (age_days as f64 / 7.0).ceil() as u64)
    } else if age_days < 365 {
        format!("{} ماه پیش", (age_days as f64 / 30.0).ceil() as u64)
    } else {
        "قدیمی".to_string()
    }
}

fn parse_rfc3339_timestamp(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.timestamp())
}

fn github_poc_note_fa(cve_id: &str, risk: &str, repo_type: &str, age_days: u64) -> String {
    if age_days <= 1 {
        format!("{} از جریان جدیدترین PoCهای عمومی استخراج شد؛ داده فقط metadata است و کد یا دستور اجرا نمایش داده نمی‌شود.", cve_id)
    } else if risk == "high" || repo_type == "exploit-metadata" {
        format!("برای {} نشانه PoC/exploit عمومی تازه دیده شده؛ فقط برای آگاهی دفاعی و اولویت‌بندی patch استفاده شود.", cve_id)
    } else {
        format!("برای {} metadata مربوط به PoC عمومی جدید دیده شده؛ قبل از تصمیم عملیاتی اعتبارسنجی دستی لازم است.", cve_id)
    }
}

fn github_poc_tags(repo_type: &str, risk: &str, age_days: u64) -> Vec<String> {
    let mut tags = vec![
        "latest-first".to_string(),
        repo_type.to_string(),
        risk.to_string(),
    ];
    if age_days <= 7 {
        tags.push("fresh".to_string());
    }
    tags
}

fn empty_poc_watch(reason: &str) -> Value {
    json!({
        "enabled": reason != "disabled",
        "ok": false,
        "provider": "GitHub Repository Search API",
        "source": reason,
        "mode": "latest_poc_stream",
        "window_days": 0,
        "safe_mode": "metadata only; no exploit code; no raw links; no clone/download commands",
        "summary_fa": "Latest PoC Watch در این اجرا داده‌ای ندارد.",
        "totals": {
            "cves_checked": 0,
            "cves_with_poc": 0,
            "repos": 0,
            "high": 0,
            "fresh": 0,
            "raw_candidates": 0,
            "kev_related": 0,
            "epss_rising_related": 0,
            "queries": 0,
            "cache_misses": 0,
            "errors": 0
        },
        "repos": [],
        "cve_chart": [],
        "risk_chart": [],
        "errors": []
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
    if config.intel.greynoise.enabled {
        count += 1;
    }
    if config.intel.phishing.enabled {
        count += 1;
    }
    if config.intel.ics_ot.enabled {
        count += 1;
    }
    if config.intel.nuclei_coverage.enabled {
        count += 1;
    }
    if config.intel.poc_watch.enabled {
        count += 1;
    }
    count
}

fn build_brief(
    config: &Config,
    items: Vec<FeedItem>,
    writeup_items: Vec<FeedItem>,
    mut cves: Vec<CveItem>,
) -> Result<Value> {
    let now = Local::now();
    let date_en = format!("{}-{:02}-{:02}", now.year(), now.month(), now.day());
    let generated_at = now.format("%Y-%m-%d %H:%M").to_string();

    let requested_news_day = now.date_naive();
    let mut effective_news_day = requested_news_day;
    let mut news_window_mode = "local-day";
    let news_display_floor = (config.limits.global_news + config.limits.iran_radar + 5)
        .max(12)
        .min(items.len().max(1));
    let mut daily_items: Vec<_> = items
        .iter()
        .filter(|item| feed_item_is_local_day(item, requested_news_day))
        .cloned()
        .collect();
    sort_news_latest_first(&mut daily_items);
    let current_day_news_total = daily_items.len();

    if daily_items.len() < news_display_floor {
        let mut seen_keys: HashSet<String> = daily_items.iter().map(news_dedupe_key).collect();
        let mut backfill: Vec<_> = items
            .iter()
            .filter(|item| !seen_keys.contains(&news_dedupe_key(item)))
            .cloned()
            .collect();
        sort_news_latest_first(&mut backfill);
        let needed = news_display_floor.saturating_sub(daily_items.len());
        for item in backfill.into_iter().take(needed) {
            seen_keys.insert(news_dedupe_key(&item));
            daily_items.push(item);
        }
        if current_day_news_total == 0 {
            news_window_mode = "latest-feed-backfill";
            if let Some(latest_feed_day) = latest_feed_item_local_day(&daily_items)
                .or_else(|| latest_feed_item_local_day(&items))
            {
                effective_news_day = latest_feed_day;
            }
        } else if daily_items.len() > current_day_news_total {
            news_window_mode = "local-day-with-latest-backfill";
        }
        sort_news_latest_first(&mut daily_items);
    }

    let mut breaking_news: Vec<_> = daily_items
        .iter()
        .filter(|item| is_breaking_news_item(item))
        .cloned()
        .collect();
    sort_breaking_news(&mut breaking_news);
    breaking_news.truncate(5);
    let breaking_keys: HashSet<String> = breaking_news.iter().map(news_dedupe_key).collect();

    let mut iran: Vec<_> = daily_items
        .iter()
        .filter(|item| item.iran_related && !breaking_keys.contains(&news_dedupe_key(item)))
        .cloned()
        .collect();
    let mut global: Vec<_> = daily_items
        .iter()
        .filter(|item| !item.iran_related && !breaking_keys.contains(&news_dedupe_key(item)))
        .cloned()
        .collect();
    sort_news_latest_first(&mut iran);
    sort_news_latest_first(&mut global);
    let daily_news_total = daily_items.len();
    let backfill_news_total = daily_news_total.saturating_sub(current_day_news_total);
    let daily_news_hidden = items.len().saturating_sub(daily_news_total);
    let effective_news_date = format!(
        "{}-{:02}-{:02}",
        effective_news_day.year(),
        effective_news_day.month(),
        effective_news_day.day()
    );
    let news_window_note_fa = match news_window_mode {
        "latest-feed-backfill" => format!(
            "برای تاریخ محلی {} خبر زمان‌دار کافی در cache نبود؛ تازه‌ترین آیتم‌های موجود از cache نمایش داده شدند، با اولویت تاریخ جدیدتر.",
            date_en
        ),
        "local-day-with-latest-backfill" => format!(
            "{} خبر برای امروز پیدا شد؛ برای جلوگیری از خالی‌شدن پنل، {} آیتم تازه‌تر/مهم از cache هم اضافه شد. خبرهای جدیدتر همچنان بالاتر هستند.",
            current_day_news_total, backfill_news_total
        ),
        _ if daily_news_total == 0 => "در پنجره امروز هنوز خبر قابل نمایش در cache فعلی دیده نشده است.".to_string(),
        _ => "خبرهای پنجره روز محلی نمایش داده می‌شوند؛ جدیدترین خبرها بالاتر قرار می‌گیرند.".to_string(),
    };
    iran.truncate(config.limits.iran_radar);
    global.truncate(config.limits.global_news);
    let news_lanes = build_news_lanes(&global);
    let writeups_pulse = build_writeups_pulse(&writeup_items);
    let writeups_total = writeups_pulse
        .get("totals")
        .and_then(|value| value.get("writeups"))
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let writeup_sources = writeups_pulse
        .get("totals")
        .and_then(|value| value.get("sources"))
        .and_then(|value| value.as_u64())
        .unwrap_or(0);

    cves.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));
    cves.truncate(config.limits.cves);

    let news_priority = breaking_news
        .iter()
        .chain(iran.iter())
        .chain(global.iter())
        .max_by_key(|item| item.risk_score);
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
        "date_en": date_en.clone(),
        "risk_level": risk_level,
        "generated_at": generated_at,
        "stats": {
            "total_items": items.len() + cve_count,
            "iran_items": iran.len(),
            "global_news": global.len(),
            "breaking_news": breaking_news.len(),
            "daily_news": daily_news_total,
            "current_day_news": current_day_news_total,
            "news_backfill": backfill_news_total,
            "daily_news_hidden": daily_news_hidden,
            "rss_items_fetched": items.len(),
            "writeups": writeups_total,
            "writeup_sources": writeup_sources,
            "poc_watch": 0,
            "poc_watch_high": 0,
            "poc_watch_cves": 0,
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
            "greynoise_noise": 0,
            "greynoise_malicious": 0,
            "greynoise_riot": 0,
            "phishing_urls": 0,
            "phishing_high": 0,
            "phishing_tlds": 0,
            "ics_advisories": 0,
            "ics_high": 0,
            "ics_vendors": 0,
            "nuclei_covered_cves": 0,
            "nuclei_coverage_pct": 0,
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
        "news_window": {
            "mode": news_window_mode,
            "date": effective_news_date,
            "requested_date": date_en.clone(),
            "start": "00:00",
            "end": "23:59",
            "timezone": now.format("%:z").to_string(),
            "rss_items_fetched": items.len(),
            "daily_news": daily_news_total,
            "current_day_news": current_day_news_total,
            "backfill_news": backfill_news_total,
            "hidden_old_or_undated": daily_news_hidden,
            "note_fa": news_window_note_fa
        },
        "breaking_news": breaking_news,
        "iran_radar": iran,
        "global_news": global,
        "news_lanes": news_lanes,
        "writeups_pulse": writeups_pulse,
        "cves": cves
    }))
}

fn parse_feed_item_local_time(item: &FeedItem) -> Option<chrono::DateTime<Local>> {
    if item.published.trim().is_empty() {
        return None;
    }

    chrono::DateTime::parse_from_rfc3339(&item.published)
        .map(|dt| dt.with_timezone(&Local))
        .ok()
}

fn feed_item_is_local_day(item: &FeedItem, day: NaiveDate) -> bool {
    parse_feed_item_local_time(item)
        .map(|dt| dt.date_naive() == day)
        .unwrap_or(false)
}

fn latest_feed_item_local_day(items: &[FeedItem]) -> Option<NaiveDate> {
    items
        .iter()
        .filter_map(parse_feed_item_local_time)
        .max()
        .map(|dt| dt.date_naive())
}

fn feed_item_timestamp(item: &FeedItem) -> i64 {
    parse_feed_item_local_time(item)
        .map(|dt| dt.timestamp())
        .unwrap_or(0)
}

fn sort_news_latest_first(items: &mut [FeedItem]) {
    items.sort_by(|a, b| {
        feed_item_timestamp(b)
            .cmp(&feed_item_timestamp(a))
            .then_with(|| b.risk_score.cmp(&a.risk_score))
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.title.cmp(&b.title))
    });
}

fn sort_breaking_news(items: &mut [FeedItem]) {
    items.sort_by(|a, b| {
        b.risk_score
            .cmp(&a.risk_score)
            .then_with(|| feed_item_timestamp(b).cmp(&feed_item_timestamp(a)))
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.title.cmp(&b.title))
    });
}

fn news_dedupe_key(item: &FeedItem) -> String {
    if !item.url.trim().is_empty() {
        item.url.trim().to_ascii_lowercase()
    } else {
        format!(
            "{}::{}",
            item.source.to_ascii_lowercase(),
            item.title.to_ascii_lowercase()
        )
    }
}

fn is_breaking_news_item(item: &FeedItem) -> bool {
    if item.risk_score >= 8 {
        return true;
    }
    if matches!(
        item.category.as_str(),
        "active_exploitation" | "malware_incident"
    ) && item.risk_score >= 6
    {
        return true;
    }

    let haystack = format!(
        "{} {} {}",
        item.title.to_ascii_lowercase(),
        item.summary.to_ascii_lowercase(),
        item.tags.join(" ").to_ascii_lowercase()
    );
    [
        "zero-day",
        "0-day",
        "actively exploited",
        "exploited in the wild",
        "mass exploitation",
        "ransomware",
        "critical vulnerability",
        "emergency patch",
        "data breach",
    ]
    .iter()
    .any(|needle| haystack.contains(needle))
}

fn news_time_display_fields(published: &str) -> (String, String, String) {
    let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(published) else {
        return ("".to_string(), "".to_string(), "زمان نامشخص".to_string());
    };
    let local = parsed.with_timezone(&Local);
    let date = local.format("%Y-%m-%d").to_string();
    let time = local.format("%H:%M").to_string();
    let label = if local.date_naive() == Local::now().date_naive() {
        format!("امروز {time}")
    } else {
        format!("{date} {time}")
    };
    (date, time, label)
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

fn build_writeups_pulse(items: &[FeedItem]) -> Value {
    let mut candidates: Vec<FeedItem> = items
        .iter()
        .filter(|item| is_writeup_item(item))
        .cloned()
        .collect();
    sort_news_latest_first(&mut candidates);

    let total_candidates = candidates.len();
    let mut source_counts: HashMap<String, usize> = HashMap::new();
    let mut kind_counts: HashMap<String, usize> = HashMap::new();
    for item in &candidates {
        *source_counts.entry(item.source.clone()).or_insert(0) += 1;
        *kind_counts
            .entry(writeup_kind(item).to_string())
            .or_insert(0) += 1;
    }

    let writeups: Vec<Value> = candidates
        .iter()
        .take(12)
        .enumerate()
        .map(|(idx, item)| writeup_item_value(idx + 1, item))
        .collect();
    let visible = writeups.len();
    let hidden = total_candidates.saturating_sub(visible);
    let sources = source_counts.len();
    let kinds = kind_counts.len();
    let source_chart = count_chart(source_counts, 6);
    let kind_chart = count_chart(kind_counts, 6);

    let summary_fa = if visible == 0 {
        "در پنجره خبری فعلی writeup تحلیلی تازه‌ای از منابع موجود دیده نشد.".to_string()
    } else if hidden > 0 {
        format!("{visible} writeup تحلیلی تازه نمایش داده شد و {hidden} مورد کم‌اولویت‌تر برای فشردگی پنهان شد؛ جدیدترین تحلیل‌ها بالاتر هستند.")
    } else {
        format!("{visible} writeup تحلیلی تازه از {sources} منبع جدا شد؛ این بخش خبر خام را از تحلیل فنی جدا می‌کند.")
    };

    json!({
        "enabled": true,
        "source": "Dedicated research/writeup RSS feeds",
        "safe_mode": "summary and metadata only; no exploit steps; no code execution",
        "summary_fa": summary_fa,
        "totals": {
            "writeups": visible,
            "candidates": total_candidates,
            "hidden": hidden,
            "sources": sources,
            "kinds": kinds
        },
        "writeups": writeups,
        "source_chart": source_chart,
        "kind_chart": kind_chart
    })
}

fn empty_writeups_pulse(reason: &str) -> Value {
    json!({
        "enabled": false,
        "source": reason,
        "safe_mode": "summary and metadata only; no exploit steps; no code execution",
        "summary_fa": "Writeups Pulse در این اجرا داده‌ای ندارد.",
        "totals": {
            "writeups": 0,
            "candidates": 0,
            "hidden": 0,
            "sources": 0,
            "kinds": 0
        },
        "writeups": [],
        "source_chart": [],
        "kind_chart": []
    })
}

fn writeup_item_value(rank: usize, item: &FeedItem) -> Value {
    let (published_date_local, published_time_local, freshness_label) =
        news_time_display_fields(&item.published);
    let kind = writeup_kind(item);
    let score = writeup_score(item).clamp(12, 100);
    let risk = if score >= 78 {
        "high"
    } else if score >= 52 {
        "medium"
    } else {
        "watch"
    };

    json!({
        "rank": rank,
        "title": item.title.clone(),
        "title_fa": writeup_title_fa(kind, &item.title),
        "summary": item.summary.clone(),
        "summary_fa": fallback_persian_summary(&item.summary, "این writeup برای تحلیل فنی روز قابل توجه است"),
        "source": item.source.clone(),
        "url": item.url.clone(),
        "published": item.published.clone(),
        "published_date_local": published_date_local,
        "published_time_local": published_time_local,
        "freshness_label": freshness_label,
        "kind": kind,
        "kind_fa": writeup_kind_fa(kind),
        "risk": risk,
        "risk_score": score,
        "bar_width": score,
        "tags": writeup_tags(item),
        "note_fa": writeup_note_fa(kind),
        "safe_mode": "metadata only"
    })
}

fn is_writeup_item(item: &FeedItem) -> bool {
    let source = item.source.to_ascii_lowercase();
    let title = item.title.to_ascii_lowercase();
    let summary = item.summary.to_ascii_lowercase();
    let text = format!(
        "{title} {summary} {}",
        item.tags.join(" ").to_ascii_lowercase()
    );

    // Writeups now come from a dedicated source list, not from the Daily News feed.
    // This guard keeps the panel focused on analysis/research and prevents normal
    // news, newsletters, patch roundups, and product updates from leaking in.
    let dedicated_writeup_source = [
        "the dfir report",
        "portswigger research",
        "unit 42",
        "cisco talos",
        "projectdiscovery research",
        "projectdiscovery blog",
        "zero day initiative research",
        "securelist",
        "google cloud threat intelligence",
        "microsoft security blog",
        "cloudflare security research",
        "rapid7 research",
    ];
    let dedicated_writeup_source = dedicated_writeup_source
        .iter()
        .any(|needle| source.contains(needle));

    if !dedicated_writeup_source {
        return false;
    }

    let hard_negative = [
        "weekly metasploit update",
        "metasploit update",
        "weekly wrap",
        "wrap-up",
        "roundup",
        "in other news",
        "noteworthy stories",
        "podcast",
        "webinar",
        "newsletter",
        "patch tuesday",
        "security update review",
        "release notes",
        "product update",
        "advisory released",
        "continues with community help",
        "conference",
        "event recap",
        "hiring",
        "job",
    ]
    .iter()
    .any(|needle| text.contains(needle));

    if hard_negative {
        return false;
    }

    let explicit_analysis_marker = [
        "writeup",
        "write-up",
        "technical analysis",
        "deep dive",
        "root cause analysis",
        "postmortem",
        "case study",
        "research report",
        "threat report",
        "threat research",
        "malware analysis",
        "reverse engineering",
        "incident analysis",
        "intrusion analysis",
        "campaign analysis",
        "detection engineering",
        "hunting guide",
        "forensic analysis",
        "tradecraft",
        "ttps",
        "attack chain",
        "exploit chain",
        "patch diff",
        "vulnerability analysis",
        "we analyzed",
        "we found",
        "our research",
        "tracking ",
        "unpacking",
        "inside ",
    ]
    .iter()
    .any(|needle| text.contains(needle));

    let research_source_allows_depth = [
        "the dfir report",
        "portswigger research",
        "unit 42",
        "cisco talos",
        "securelist",
        "google cloud threat intelligence",
    ]
    .iter()
    .any(|needle| source.contains(needle));

    let technical_depth_signal = [
        "ioc",
        "yara",
        "sigma",
        "rule",
        "reverse engineer",
        "loader",
        "payload",
        "c2",
        "command and control",
        "ttp",
        "mitre",
        "kill chain",
        "attack chain",
        "exploit chain",
        "root cause",
        "patch diff",
        "code path",
        "proof-of-concept",
        "vulnerability analysis",
        "cve-",
        "apt",
        "threat actor",
        "malware",
        "ransomware",
        "phishing kit",
        "detection",
    ]
    .iter()
    .any(|needle| text.contains(needle));

    explicit_analysis_marker || (research_source_allows_depth && technical_depth_signal)
}

fn writeup_title_fa(kind: &str, title: &str) -> String {
    let focus = persian_focus_label(title);
    let text = match kind {
        "CVE Analysis" => format!("تحلیل فنی CVE درباره {focus}"),
        "Malware Writeup" => format!("تحلیل فنی بدافزار درباره {focus}"),
        "Phishing Analysis" => format!("تحلیل فنی فیشینگ درباره {focus}"),
        "Incident Analysis" => format!("تحلیل فنی رخداد درباره {focus}"),
        "Detection Engineering" => format!("یادداشت مهندسی تشخیص درباره {focus}"),
        "Cloud/SaaS Research" => format!("تحلیل فنی Cloud/SaaS درباره {focus}"),
        _ => format!("یادداشت پژوهشی درباره {focus}"),
    };
    truncate_chars(&text, 72)
}

fn writeup_kind(item: &FeedItem) -> &'static str {
    let text =
        format!("{} {} {}", item.title, item.summary, item.tags.join(" ")).to_ascii_lowercase();
    if text.contains("cve-")
        || text.contains("vulnerability")
        || text.contains("zero-day")
        || text.contains("exploit")
    {
        "CVE Analysis"
    } else if text.contains("malware")
        || text.contains("ransomware")
        || text.contains("trojan")
        || text.contains("stealer")
        || text.contains("backdoor")
    {
        "Malware Writeup"
    } else if text.contains("phishing")
        || text.contains("credential")
        || text.contains("microsoft 365")
    {
        "Phishing Analysis"
    } else if text.contains("incident")
        || text.contains("breach")
        || text.contains("campaign")
        || text.contains("threat actor")
        || text.contains("apt")
    {
        "Incident Analysis"
    } else if text.contains("detection")
        || text.contains("yara")
        || text.contains("sigma")
        || text.contains("rule")
    {
        "Detection Engineering"
    } else if text.contains("cloud")
        || text.contains("aws")
        || text.contains("azure")
        || text.contains("kubernetes")
        || text.contains("container")
    {
        "Cloud/SaaS Research"
    } else {
        "Research Note"
    }
}

fn writeup_kind_fa(kind: &str) -> &'static str {
    match kind {
        "CVE Analysis" => "تحلیل CVE",
        "Malware Writeup" => "تحلیل بدافزار",
        "Phishing Analysis" => "تحلیل فیشینگ",
        "Incident Analysis" => "تحلیل رخداد",
        "Detection Engineering" => "مهندسی تشخیص",
        "Cloud/SaaS Research" => "تحلیل Cloud/SaaS",
        _ => "یادداشت پژوهشی",
    }
}

fn writeup_note_fa(kind: &str) -> &'static str {
    match kind {
        "CVE Analysis" => "برای تطبیق با CVEها، EPSS/KEV و backlog وصله نگه داشته شود؛ این بخش exploit اجرا نمی‌کند.",
        "Malware Writeup" => "برای correlation با IOC، C2 و خانواده‌های بدافزار استفاده شود؛ نمونه یا payload نمایش داده نمی‌شود.",
        "Phishing Analysis" => "برای آگاهی ایمیل/هویت و تطبیق با Phishing Pulse استفاده شود؛ URLها عملیاتی نمی‌شوند.",
        "Incident Analysis" => "برای فهم روند حمله و اثر احتمالی روی کنترل‌های دفاعی مرور شود.",
        "Detection Engineering" => "برای ایده rule/detection قابل بررسی است، اما هیچ rule یا scan خودکار اجرا نمی‌شود.",
        "Cloud/SaaS Research" => "برای تطبیق با دارایی‌های Cloud/SaaS و کنترل exposure مرور شود.",
        _ => "برای زمینه‌سازی triage روزانه و خواندن تحلیل فنی نگه داشته شود.",
    }
}

fn writeup_tags(item: &FeedItem) -> Vec<String> {
    let mut tags = item.tags.iter().take(4).cloned().collect::<Vec<_>>();
    let kind = writeup_kind(item).to_string();
    if !tags.iter().any(|tag| tag == &kind) {
        tags.insert(0, kind);
    }
    tags.into_iter()
        .filter(|tag| !tag.trim().is_empty())
        .take(5)
        .collect()
}

fn writeup_score(item: &FeedItem) -> usize {
    let mut score = (item.risk_score.max(1) as usize * 9).clamp(12, 90);
    let text = format!("{} {}", item.title, item.summary).to_ascii_lowercase();
    if text.contains("cve-") || text.contains("zero-day") || text.contains("actively exploited") {
        score += 10;
    }
    if text.contains("ransomware") || text.contains("malware") || text.contains("phishing") {
        score += 7;
    }
    score.clamp(12, 100)
}

fn count_chart(mut counts: HashMap<String, usize>, limit: usize) -> Vec<Value> {
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
                "name": truncate_chars(&name, 42),
                "count": count,
                "bar_width": width.clamp(12, 100)
            })
        })
        .collect()
}

fn priority_from_item(item: &FeedItem) -> Value {
    json!({
        "title": item.title.clone(),
        "summary": item.summary.clone(),
        "source": item.source.clone(),
        "url": item.url.clone(),
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
    let greynoise_noise = stat_u64(brief, "greynoise_noise");
    let greynoise_malicious = stat_u64(brief, "greynoise_malicious");
    let phishing_urls = stat_u64(brief, "phishing_urls");
    let phishing_high = stat_u64(brief, "phishing_high");
    let poc_watch = stat_u64(brief, "poc_watch");
    let poc_watch_high = stat_u64(brief, "poc_watch_high");
    let ics_advisories = stat_u64(brief, "ics_advisories");
    let ics_high = stat_u64(brief, "ics_high");
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
        + greynoise_noise.min(20)
        + greynoise_malicious * 12
        + phishing_urls.min(20)
        + phishing_high * 6
        + poc_watch.min(18)
        + poc_watch_high * 10
        + ics_advisories.min(18)
        + ics_high * 8
        + infrastructure_hosts.min(25)
        + infra_high * 10
        + supply_critical * 12
        + supply_high * 4
        + ransomware_24h * 5
        + failed_rss * 4)
        .min(100);
    let level = snapshot_level(score);

    let cve_score =
        (critical_cves * 32 + kev * 28 + cves * 4 + poc_watch.min(20) + poc_watch_high * 12)
            .min(100)
            .max(12);
    let intel_score = (iocs.min(55)
        + botnet_c2.min(25)
        + malicious_tls.min(20)
        + greynoise_noise.min(20)
        + greynoise_malicious * 12
        + phishing_urls.min(20)
        + phishing_high * 6
        + poc_watch.min(18)
        + poc_watch_high * 10
        + ics_advisories.min(18)
        + ics_high * 8
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
    let top_phishing = first_chart_entry(brief, &["phishing_pulse", "brand_chart"])
        .unwrap_or_else(|| ("بدون phishing برجسته".to_string(), 0));
    let top_ransomware = first_chart_entry(brief, &["ransomware_pulse", "group_chart"])
        .unwrap_or_else(|| ("بدون گروه برجسته".to_string(), 0));
    let top_supply = first_chart_entry(brief, &["supply_chain_radar", "severity_chart"])
        .unwrap_or_else(|| ("بدون severity برجسته".to_string(), 0));

    let impact_a = cves + critical_cves + kev + poc_watch;
    let impact_b = iocs + infrastructure_hosts + botnet_c2 + malicious_tls + phishing_urls;
    let impact_c = supply_advisories + ransomware_victims;
    let impact_max = impact_a.max(impact_b).max(impact_c).max(1);

    json!({
        "title": "Static Executive Snapshot",
        "level": level,
        "score": score,
        "bar_width": score.max(12),
        "generated_at": brief.get("generated_at").cloned().unwrap_or(Value::Null),
        "summary_fa": format!(
            "خلاصه ۶۰ ثانیه‌ای: در این اجرا {} آیتم، {} CVE، {} PoC metadata، {} IOC، {} C2 botnet، {} URL فیشینگ، {} advisory ICS/OT، {} IP با context GreyNoise، {} advisory زنجیره تأمین و {} claim ransomware دیده شد.",
            total_items, cves, poc_watch, iocs, botnet_c2, phishing_urls, ics_advisories, greynoise_noise + greynoise_malicious, supply_advisories, ransomware_victims
        ),
        "risk_cards": [
            {
                "title": "ریسک آسیب‌پذیری‌ها",
                "metric": format!("{} critical / {} CVE / {} PoC", critical_cves, cves, poc_watch),
                "level": snapshot_level(cve_score),
                "bar_width": cve_score,
                "note_fa": if critical_cves > 0 { "CVEهای critical باید در اولویت patch و exposure review دیده شوند." } else { "در این اجرا CVE critical برجسته‌ای دیده نشده است." }
            },
            {
                "title": "IOC و زیرساخت مشکوک",
                "metric": format!("{} IOC / {} C2 / {} phish / {} ICS", iocs, botnet_c2, phishing_urls, ics_advisories),
                "level": snapshot_level(intel_score),
                "bar_width": intel_score,
                "note_fa": if ics_high > 0 { "Advisoryهای ICS/OT سطح بالا کنار IOC/C2 برای اولویت‌بندی دفاعی OT دیده شوند." } else if phishing_high > 0 { "URLهای فیشینگ defanged کنار IOC/C2 برای correlation دفاعی آمده‌اند." } else if greynoise_malicious > 0 { "GreyNoise برای برخی IPها classification بدخواه داده و با C2/IOC باید correlation شود." } else if botnet_c2 > 0 { "سیگنال‌های C2 و زیرساخت برای correlation دفاعی کنار هم دیده می‌شوند." } else if infra_high > 0 { "برخی hostها با exposure یا vulnerability hint بالاتر دیده شده‌اند." } else { "سیگنال‌های زیرساختی برای correlation دفاعی نگه داشته شده‌اند." }
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
                "metric": format!("{} · {} | {} · {}", top_ioc.0, top_ioc.1, top_phishing.0, top_phishing.1),
                "level": if phishing_high >= 4 || top_ioc.1 >= 5 { "high" } else if phishing_urls >= 10 || top_ioc.1 >= 2 { "medium" } else { "watch" },
                "bar_width": ((top_ioc.1 * 12 + phishing_high * 10 + phishing_urls.min(20)).min(100)).max(12),
                "note_fa": "بیشترین الگوی IOC و phishing برای triage و correlation دفاعی نمایش داده شده است."
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
                "name": "DShield + abuse.ch + SSLBL + OpenPhish + InternetDB + GreyNoise",
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

fn value_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

fn concise_text(input: &str, max_chars: usize) -> String {
    truncate_chars(input.trim(), max_chars)
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
    brief["version"] = json!("v0.4.28-nuclei-template-coverage");

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
    if brief.get("breaking_news").is_none() {
        brief["breaking_news"] = json!([]);
    }
    if brief.get("news_window").is_none() {
        let daily_news = brief
            .get("global_news")
            .and_then(|v| v.as_array())
            .map(|items| items.len())
            .unwrap_or(0)
            + brief
                .get("iran_radar")
                .and_then(|v| v.as_array())
                .map(|items| items.len())
                .unwrap_or(0)
            + brief
                .get("breaking_news")
                .and_then(|v| v.as_array())
                .map(|items| items.len())
                .unwrap_or(0);
        brief["news_window"] = json!({
            "mode": "local-day",
            "date": brief.get("date_en").and_then(|v| v.as_str()).unwrap_or(""),
            "start": "00:00",
            "end": "23:59",
            "timezone": Local::now().format("%:z").to_string(),
            "rss_items_fetched": daily_news,
            "daily_news": daily_news,
            "hidden_old_or_undated": 0
        });
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("breaking_news"))
        .is_none()
    {
        let count = brief
            .get("breaking_news")
            .and_then(|v| v.as_array())
            .map(|items| items.len())
            .unwrap_or(0);
        brief["stats"]["breaking_news"] = json!(count);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("daily_news"))
        .is_none()
    {
        let count = brief
            .get("news_window")
            .and_then(|v| v.get("daily_news"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        brief["stats"]["daily_news"] = json!(count);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("current_day_news"))
        .is_none()
    {
        let count = brief
            .get("news_window")
            .and_then(|v| v.get("current_day_news"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        brief["stats"]["current_day_news"] = json!(count);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("news_backfill"))
        .is_none()
    {
        let count = brief
            .get("news_window")
            .and_then(|v| v.get("backfill_news"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        brief["stats"]["news_backfill"] = json!(count);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("daily_news_hidden"))
        .is_none()
    {
        let count = brief
            .get("news_window")
            .and_then(|v| v.get("hidden_old_or_undated"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        brief["stats"]["daily_news_hidden"] = json!(count);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("rss_items_fetched"))
        .is_none()
    {
        let count = brief
            .get("news_window")
            .and_then(|v| v.get("rss_items_fetched"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        brief["stats"]["rss_items_fetched"] = json!(count);
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
    if brief.get("botnet_c2_pulse").is_none() {
        brief["botnet_c2_pulse"] = empty_botnet_c2_pulse("missing");
    }
    if brief.get("greynoise_context").is_none() {
        brief["greynoise_context"] = empty_greynoise_context("missing");
    }
    if brief.get("phishing_pulse").is_none() {
        brief["phishing_pulse"] = empty_phishing_pulse("missing");
    }
    if brief.get("ics_ot_pulse").is_none() {
        brief["ics_ot_pulse"] = empty_ics_ot_pulse("missing");
    }
    if brief.get("nuclei_coverage").is_none() {
        brief["nuclei_coverage"] = empty_nuclei_coverage("missing");
    }
    if brief.get("writeups_pulse").is_none() {
        brief["writeups_pulse"] = empty_writeups_pulse("missing");
    }
    if brief.get("poc_watch").is_none() {
        brief["poc_watch"] = empty_poc_watch("missing");
    }
    if brief.get("stats").and_then(|v| v.get("writeups")).is_none() {
        brief["stats"]["writeups"] =
            json!(path_u64(brief, &["writeups_pulse", "totals", "writeups"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("writeup_sources"))
        .is_none()
    {
        brief["stats"]["writeup_sources"] =
            json!(path_u64(brief, &["writeups_pulse", "totals", "sources"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("nuclei_covered_cves"))
        .is_none()
    {
        brief["stats"]["nuclei_covered_cves"] = json!(path_u64(
            brief,
            &["nuclei_coverage", "totals", "covered_cves"]
        ));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("nuclei_coverage_pct"))
        .is_none()
    {
        brief["stats"]["nuclei_coverage_pct"] = json!(path_u64(
            brief,
            &["nuclei_coverage", "totals", "coverage_pct"]
        ));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("poc_watch"))
        .is_none()
    {
        brief["stats"]["poc_watch"] = json!(path_u64(brief, &["poc_watch", "totals", "repos"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("poc_watch_high"))
        .is_none()
    {
        brief["stats"]["poc_watch_high"] = json!(path_u64(brief, &["poc_watch", "totals", "high"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("poc_watch_cves"))
        .is_none()
    {
        brief["stats"]["poc_watch_cves"] =
            json!(path_u64(brief, &["poc_watch", "totals", "cves_with_poc"]));
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
    if brief
        .get("stats")
        .and_then(|v| v.get("botnet_c2"))
        .is_none()
    {
        let botnet_total = path_u64(brief, &["botnet_c2_pulse", "totals", "c2"]);
        brief["stats"]["botnet_c2"] = json!(botnet_total);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("malicious_tls"))
        .is_none()
    {
        let tls_total = path_u64(brief, &["botnet_c2_pulse", "totals", "tls"]);
        brief["stats"]["malicious_tls"] = json!(tls_total);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("greynoise_noise"))
        .is_none()
    {
        brief["stats"]["greynoise_noise"] =
            json!(path_u64(brief, &["greynoise_context", "totals", "noise"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("greynoise_malicious"))
        .is_none()
    {
        brief["stats"]["greynoise_malicious"] = json!(path_u64(
            brief,
            &["greynoise_context", "totals", "malicious"]
        ));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("greynoise_riot"))
        .is_none()
    {
        brief["stats"]["greynoise_riot"] =
            json!(path_u64(brief, &["greynoise_context", "totals", "riot"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("phishing_urls"))
        .is_none()
    {
        brief["stats"]["phishing_urls"] =
            json!(path_u64(brief, &["phishing_pulse", "totals", "urls"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("phishing_high"))
        .is_none()
    {
        brief["stats"]["phishing_high"] =
            json!(path_u64(brief, &["phishing_pulse", "totals", "high"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("phishing_tlds"))
        .is_none()
    {
        brief["stats"]["phishing_tlds"] =
            json!(path_u64(brief, &["phishing_pulse", "totals", "tlds"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("ics_advisories"))
        .is_none()
    {
        brief["stats"]["ics_advisories"] =
            json!(path_u64(brief, &["ics_ot_pulse", "totals", "advisories"]));
    }
    if brief.get("stats").and_then(|v| v.get("ics_high")).is_none() {
        brief["stats"]["ics_high"] = json!(path_u64(brief, &["ics_ot_pulse", "totals", "high"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("ics_vendors"))
        .is_none()
    {
        brief["stats"]["ics_vendors"] =
            json!(path_u64(brief, &["ics_ot_pulse", "totals", "vendors"]));
    }

    polish_priority(brief);
    polish_array_items(brief, "breaking_news", 88, 240);
    polish_array_items(brief, "iran_radar", 88, 240);
    polish_array_items(brief, "global_news", 88, 240);
    polish_writeups_pulse(brief);
    polish_cves(brief);
    add_editorial_display_fields(brief);
    brief["brief_notes"] = json!(build_brief_notes(brief));

    let executive_snapshot = build_executive_snapshot(brief);
    brief["executive_snapshot"] = executive_snapshot;
}

fn build_triage_signals(brief: &Value) -> Value {
    let breaking_news = stat_u64(brief, "breaking_news");
    let daily_news = stat_u64(brief, "daily_news");
    let critical_cves = stat_u64(brief, "critical_cves");
    let cves = stat_u64(brief, "cves");
    let kev = stat_u64(brief, "kev");
    let epss_rising = stat_u64(brief, "epss_rising");
    let iocs = stat_u64(brief, "iocs");
    let botnet_c2 = stat_u64(brief, "botnet_c2");
    let malicious_tls = stat_u64(brief, "malicious_tls");
    let greynoise_malicious = stat_u64(brief, "greynoise_malicious");
    let greynoise_noise = stat_u64(brief, "greynoise_noise");
    let phishing_urls = stat_u64(brief, "phishing_urls");
    let phishing_high = stat_u64(brief, "phishing_high");
    let ics_advisories = stat_u64(brief, "ics_advisories");
    let ics_high = stat_u64(brief, "ics_high");
    let writeups = stat_u64(brief, "writeups");
    let writeup_sources = stat_u64(brief, "writeup_sources");
    let poc_watch = stat_u64(brief, "poc_watch");
    let poc_watch_high = stat_u64(brief, "poc_watch_high");
    let poc_watch_cves = stat_u64(brief, "poc_watch_cves");
    let history_changes = stat_u64(brief, "history_changes");
    let failed_rss = stat_u64(brief, "failed_rss_sources");
    let risk_score = path_u64(brief, &["executive_snapshot", "score"]);

    let mut signals: Vec<(u64, Value)> = Vec::new();

    signals.push((
        100 + risk_score,
        json!({
            "title": "تصمیم سریع امروز",
            "metric": format!("Risk {risk_score}"),
            "level": snapshot_level(risk_score),
            "anchor": "#executive-snapshot",
            "bar_width": risk_score.max(12),
            "note_fa": "ابتدا خلاصه مدیریتی و دلیل امتیاز ریسک را ببین."
        }),
    ));

    if breaking_news > 0 || daily_news > 0 {
        let score = (breaking_news * 18 + daily_news.min(40)).min(100).max(12);
        signals.push((
            95 + score,
            json!({
                "title": "Breaking / خبر تازه",
                "metric": format!("{breaking_news} breaking · {daily_news} امروز"),
                "level": if breaking_news > 0 { "high" } else { "watch" },
                "anchor": "#breaking-news",
                "bar_width": score,
                "note_fa": "خبرهای امروز با ترتیب زمان انتشار نمایش داده می‌شوند؛ خبرهای مهم جدا شده‌اند."
            }),
        ));
    }

    if writeups > 0 {
        let score = (writeups * 8 + writeup_sources * 12).min(100).max(12);
        signals.push((
            88 + score,
            json!({
                "title": "Writeup / تحلیل تازه",
                "metric": format!("{writeups} writeup · {writeup_sources} منبع"),
                "level": if score >= 70 { "medium" } else { "watch" },
                "anchor": "#writeups-pulse",
                "bar_width": score,
                "note_fa": "تحلیل‌های تازه را جدا از خبر خام ببین؛ خروجی فقط خلاصه و metadata است."
            }),
        ));
    }

    if critical_cves > 0 || kev > 0 || epss_rising > 0 || cves > 0 {
        let score = (critical_cves * 28 + kev * 32 + epss_rising * 18 + cves * 3)
            .min(100)
            .max(12);
        signals.push((
            90 + score,
            json!({
                "title": "آسیب‌پذیری قابل اقدام",
                "metric": format!("{critical_cves} critical · {kev} KEV · {epss_rising} EPSS↑"),
                "level": snapshot_level(score),
                "anchor": "#cves",
                "bar_width": score,
                "note_fa": if kev > 0 || critical_cves > 0 { "CVEهای critical/KEV را قبل از خبرهای عمومی مرور کن." } else { "CVEها برای تطبیق با asset inventory نگه داشته شده‌اند." }
            }),
        ));
    }

    if poc_watch > 0 {
        let score = (poc_watch_high * 30 + poc_watch_cves * 16 + poc_watch * 4)
            .min(100)
            .max(12);
        signals.push((
            89 + score,
            json!({
                "title": "PoC public metadata",
                "metric": format!("{poc_watch} repo · {poc_watch_cves} CVE"),
                "level": if poc_watch_high > 0 { "high" } else if score >= 55 { "medium" } else { "watch" },
                "anchor": "#poc-watch",
                "bar_width": score,
                "note_fa": "جدیدترین PoCهای عمومی ابتدا از جریان زمانی metadata استخراج و سپس بر اساس CVE گروه‌بندی می‌شوند؛ کد و لینک raw نمایش داده نمی‌شود."
            }),
        ));
    }

    if greynoise_malicious > 0 || greynoise_noise > 0 {
        let score = (greynoise_malicious * 42 + greynoise_noise * 6)
            .min(100)
            .max(12);
        signals.push((
            80 + score,
            json!({
                "title": "Context اسکنرها",
                "metric": format!("{greynoise_malicious} malicious · {greynoise_noise} noise"),
                "level": if greynoise_malicious > 0 { "high" } else { "watch" },
                "anchor": "#greynoise-context",
                "bar_width": score,
                "note_fa": "GreyNoise برای کاهش false positive و اولویت‌بندی IPها استفاده شود."
            }),
        ));
    }

    if botnet_c2 > 0 || malicious_tls > 0 || iocs > 0 {
        let score = (botnet_c2 * 12 + malicious_tls * 4 + iocs.min(45))
            .min(100)
            .max(12);
        signals.push((
            75 + score,
            json!({
                "title": "تهدید فعال و C2",
                "metric": format!("{iocs} IOC · {botnet_c2} C2 · {malicious_tls} TLS"),
                "level": if botnet_c2 > 0 { "high" } else if iocs > 0 { "medium" } else { "watch" },
                "anchor": "#ioc-radar",
                "bar_width": score,
                "note_fa": "IOC، C2 و TLS بدخواه را فقط برای correlation دفاعی ببین."
            }),
        ));
    }

    if phishing_urls > 0 {
        let score = (phishing_high * 16 + phishing_urls.min(40))
            .min(100)
            .max(12);
        signals.push((
            65 + score,
            json!({
                "title": "Phishing Pulse",
                "metric": format!("{phishing_urls} URL · {phishing_high} high"),
                "level": if phishing_high > 0 { "medium" } else { "watch" },
                "anchor": "#phishing-pulse",
                "bar_width": score,
                "note_fa": "نمایش فقط defanged و برای آگاهی/همبستگی دفاعی است."
            }),
        ));
    }

    if ics_advisories > 0 {
        let score = (ics_high * 20 + ics_advisories.min(30)).min(100).max(12);
        signals.push((
            60 + score,
            json!({
                "title": "ICS/OT Advisory",
                "metric": format!("{ics_advisories} advisory · {ics_high} high"),
                "level": if ics_high > 0 { "medium" } else { "watch" },
                "anchor": "#ics-ot-pulse",
                "bar_width": score,
                "note_fa": "Vendor و تجهیز را با موجودی OT/ICS تطبیق بده."
            }),
        ));
    }

    if history_changes > 0 {
        let score = (history_changes * 12).min(100).max(12);
        signals.push((
            55 + score,
            json!({
                "title": "تغییر نسبت به قبل",
                "metric": format!("{history_changes} شاخص تغییر کرد"),
                "level": "medium",
                "anchor": "#history-snapshot",
                "bar_width": score,
                "note_fa": "اول تغییرهای تازه را ببین، بعد وارد جزئیات پنل‌ها شو."
            }),
        ));
    }

    if failed_rss > 0 {
        let score = (failed_rss * 15).min(100).max(12);
        signals.push((
            45 + score,
            json!({
                "title": "سلامت منابع",
                "metric": format!("{failed_rss} RSS failed"),
                "level": "medium",
                "anchor": "#sources",
                "bar_width": score,
                "note_fa": "قبل از تصمیم‌گیری، محدودیت پوشش منبع را در نظر بگیر."
            }),
        ));
    }

    signals.sort_by(|a, b| b.0.cmp(&a.0));
    let values: Vec<Value> = signals
        .into_iter()
        .take(5)
        .map(|(_, value)| value)
        .collect();
    json!(values)
}

fn read_previous_latest_brief() -> Option<Value> {
    let raw = fs::read_to_string("data/latest_brief.json").ok()?;
    serde_json::from_str(&raw).ok()
}

fn attach_history_snapshot(brief: &mut Value, previous: Option<&Value>) {
    let generated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let previous_version = previous
        .and_then(|value| value.get("version"))
        .and_then(|value| value.as_str())
        .unwrap_or("none")
        .to_string();

    let metrics = history_metrics();
    let mut deltas: Vec<Value> = metrics
        .iter()
        .map(|metric| {
            let current = metric_value(brief, metric.path);
            let previous_value = previous
                .map(|value| metric_value(value, metric.path))
                .unwrap_or(0);
            let delta = current - previous_value;
            let direction = if delta > 0 {
                "up"
            } else if delta < 0 {
                "down"
            } else {
                "flat"
            };
            let level = history_delta_level(metric.key, delta);
            json!({
                "key": metric.key,
                "label_fa": metric.label_fa,
                "before": previous_value,
                "after": current,
                "delta": delta,
                "direction": direction,
                "level": level,
                "bar_width": relative_width(delta.unsigned_abs(), metric.baseline),
                "note_fa": history_delta_note(metric.label_fa, delta)
            })
        })
        .collect();

    deltas.sort_by(|a, b| {
        let ad = a.get("delta").and_then(|v| v.as_i64()).unwrap_or(0).abs();
        let bd = b.get("delta").and_then(|v| v.as_i64()).unwrap_or(0).abs();
        bd.cmp(&ad)
    });

    let changed = deltas
        .iter()
        .filter(|row| row.get("delta").and_then(|v| v.as_i64()).unwrap_or(0) != 0)
        .count() as u64;
    let increased = deltas
        .iter()
        .filter(|row| row.get("delta").and_then(|v| v.as_i64()).unwrap_or(0) > 0)
        .count() as u64;
    let decreased = deltas
        .iter()
        .filter(|row| row.get("delta").and_then(|v| v.as_i64()).unwrap_or(0) < 0)
        .count() as u64;
    let tracked = deltas.len() as u64;
    let unchanged = tracked.saturating_sub(changed);
    let changed_rows: Vec<Value> = deltas
        .iter()
        .filter(|row| row.get("delta").and_then(|v| v.as_i64()).unwrap_or(0) != 0)
        .cloned()
        .collect();
    let top_changes: Vec<Value> = if changed_rows.is_empty() {
        deltas.into_iter().take(5).collect()
    } else {
        changed_rows.into_iter().take(9).collect()
    };

    let summary_fa = if previous.is_none() {
        "برای مقایسه با اجرای قبل هنوز snapshot قبلی در دسترس نبود؛ از اجرای بعدی تغییرات روزانه نمایش داده می‌شود.".to_string()
    } else if changed == 0 {
        "در مقایسه با اجرای قبلی، تغییر معناداری در شاخص‌های اصلی دیده نشد.".to_string()
    } else {
        format!(
            "نسبت به اجرای قبلی، {changed} شاخص تغییر کرده؛ {increased} مورد افزایش و {decreased} مورد کاهش داشته است."
        )
    };

    brief["stats"]["history_changes"] = json!(changed);
    brief["history_snapshot"] = json!({
        "enabled": true,
        "generated_at": generated_at,
        "previous_available": previous.is_some(),
        "previous_version": previous_version,
        "current_version": brief.get("version").and_then(|v| v.as_str()).unwrap_or("unknown"),
        "summary_fa": summary_fa,
        "totals": {
            "tracked": tracked,
            "changed": changed,
            "increased": increased,
            "decreased": decreased,
            "unchanged": unchanged
        },
        "top_changes": top_changes,
        "storage": "snapshots/history"
    });
}

fn write_history_snapshot(brief: &Value) -> Result<()> {
    let history_dir = PathBuf::from("snapshots/history");
    fs::create_dir_all(&history_dir).context("failed to create snapshots/history")?;
    let generated_at = brief
        .get("history_snapshot")
        .and_then(|value| value.get("generated_at"))
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let safe_name = generated_at
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    let snapshot = json!({
        "version": brief.get("version").cloned().unwrap_or_else(|| json!("unknown")),
        "date_fa": brief.get("date_fa").cloned().unwrap_or_else(|| json!("")),
        "generated_at": generated_at,
        "stats": brief.get("stats").cloned().unwrap_or_else(|| json!({})),
        "executive_snapshot": brief.get("executive_snapshot").cloned().unwrap_or_else(|| json!({})),
        "history_snapshot": brief.get("history_snapshot").cloned().unwrap_or_else(|| json!({}))
    });
    let pretty = serde_json::to_string_pretty(&snapshot)?;
    fs::write(history_dir.join("latest_snapshot.json"), &pretty)
        .context("failed to write latest history snapshot")?;
    if !safe_name.is_empty() {
        fs::write(history_dir.join(format!("{safe_name}.json")), pretty)
            .context("failed to write timestamped history snapshot")?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct HistoryMetric {
    key: &'static str,
    label_fa: &'static str,
    path: &'static [&'static str],
    baseline: u64,
}

fn history_metrics() -> Vec<HistoryMetric> {
    vec![
        HistoryMetric {
            key: "risk_score",
            label_fa: "امتیاز ریسک",
            path: &["executive_snapshot", "score"],
            baseline: 100,
        },
        HistoryMetric {
            key: "global_news",
            label_fa: "خبر جهانی",
            path: &["stats", "global_news"],
            baseline: 30,
        },
        HistoryMetric {
            key: "writeups",
            label_fa: "Writeup امنیتی",
            path: &["stats", "writeups"],
            baseline: 20,
        },
        HistoryMetric {
            key: "poc_watch",
            label_fa: "PoC public metadata",
            path: &["stats", "poc_watch"],
            baseline: 20,
        },
        HistoryMetric {
            key: "cves",
            label_fa: "CVE",
            path: &["stats", "cves"],
            baseline: 20,
        },
        HistoryMetric {
            key: "critical_cves",
            label_fa: "CVE بحرانی",
            path: &["stats", "critical_cves"],
            baseline: 10,
        },
        HistoryMetric {
            key: "epss_rising",
            label_fa: "EPSS رو به رشد",
            path: &["stats", "epss_rising"],
            baseline: 10,
        },
        HistoryMetric {
            key: "iocs",
            label_fa: "IOC",
            path: &["stats", "iocs"],
            baseline: 50,
        },
        HistoryMetric {
            key: "botnet_c2",
            label_fa: "Botnet C2",
            path: &["stats", "botnet_c2"],
            baseline: 20,
        },
        HistoryMetric {
            key: "malicious_tls",
            label_fa: "TLS بدخواه",
            path: &["stats", "malicious_tls"],
            baseline: 30,
        },
        HistoryMetric {
            key: "greynoise_malicious",
            label_fa: "GreyNoise malicious",
            path: &["stats", "greynoise_malicious"],
            baseline: 10,
        },
        HistoryMetric {
            key: "phishing_urls",
            label_fa: "URL فیشینگ",
            path: &["stats", "phishing_urls"],
            baseline: 50,
        },
        HistoryMetric {
            key: "ics_advisories",
            label_fa: "ICS/OT advisory",
            path: &["stats", "ics_advisories"],
            baseline: 20,
        },
        HistoryMetric {
            key: "ics_high",
            label_fa: "ICS/OT سطح بالا",
            path: &["stats", "ics_high"],
            baseline: 10,
        },
        HistoryMetric {
            key: "supply_chain_advisories",
            label_fa: "زنجیره تأمین",
            path: &["stats", "supply_chain_advisories"],
            baseline: 30,
        },
        HistoryMetric {
            key: "ransomware_victims",
            label_fa: "Ransomware claim",
            path: &["stats", "ransomware_victims"],
            baseline: 40,
        },
        HistoryMetric {
            key: "failed_rss_sources",
            label_fa: "RSS خطادار",
            path: &["stats", "failed_rss_sources"],
            baseline: 10,
        },
    ]
}

fn metric_value(value: &Value, path: &[&str]) -> i64 {
    path_value(value, path)
        .and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_u64().and_then(|v| i64::try_from(v).ok()))
        })
        .unwrap_or(0)
}

fn history_delta_level(key: &str, delta: i64) -> &'static str {
    if delta == 0 {
        return "watch";
    }
    match key {
        "failed_rss_sources" if delta > 0 => "medium",
        "risk_score"
        | "critical_cves"
        | "epss_rising"
        | "poc_watch"
        | "poc_watch_high"
        | "botnet_c2"
        | "malicious_tls"
        | "greynoise_malicious"
        | "phishing_urls"
        | "ics_high"
        | "ransomware_victims"
            if delta > 0 =>
        {
            "high"
        }
        _ if delta > 0 => "medium",
        _ => "low",
    }
}

fn history_delta_note(label: &str, delta: i64) -> String {
    if delta > 0 {
        format!("{label} نسبت به اجرای قبل افزایش داشته است.")
    } else if delta < 0 {
        format!("{label} نسبت به اجرای قبل کاهش داشته است.")
    } else {
        format!("{label} نسبت به اجرای قبل ثابت مانده است.")
    }
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

fn polish_writeups_pulse(brief: &mut Value) {
    let Some(items) = brief
        .get_mut("writeups_pulse")
        .and_then(|value| value.get_mut("writeups"))
        .and_then(|value| value.as_array_mut())
    else {
        return;
    };

    for item in items {
        let Some(obj) = item.as_object_mut() else {
            continue;
        };
        if let Some(Value::String(title)) = obj.get_mut("title") {
            *title = concise_title(title, 92);
        }
        if let Some(Value::String(summary)) = obj.get_mut("summary") {
            *summary = non_empty_summary(summary, 260);
        }
        if let Some(Value::String(title_fa)) = obj.get_mut("title_fa") {
            *title_fa = truncate_chars(title_fa, 76);
        }
        if let Some(Value::String(summary_fa)) = obj.get_mut("summary_fa") {
            *summary_fa = truncate_chars(summary_fa, 210);
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
    enrich_news_fields(brief, "breaking_news", false);
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
        let published = obj
            .get("published")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let (published_date_local, published_time_local, freshness_label) =
            news_time_display_fields(&published);
        obj.insert(
            "published_date_local".to_string(),
            json!(published_date_local),
        );
        obj.insert(
            "published_time_local".to_string(),
            json!(published_time_local),
        );
        obj.insert("freshness_label".to_string(), json!(freshness_label));

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
    let botnet_ok = brief
        .get("botnet_c2_pulse")
        .and_then(|v| v.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let greynoise_ok = brief
        .get("greynoise_context")
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
        if botnet_ok {
            coverage
                .push_str(" Botnet C2 Pulse از Feodo و SSLBL به‌صورت metadata-only ساخته شده است.");
        }
        if greynoise_ok {
            coverage.push_str(
                " GreyNoise Context نیز برای IPهای منتخب به‌صورت passive lookup اضافه شده است.",
            );
        }
        if brief
            .get("ics_ot_pulse")
            .and_then(|v| v.get("ok"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            coverage.push_str(" ICS/OT Advisory Pulse هم از CISA ICS Advisories به‌صورت metadata-only ساخته شده است.");
        }
        if brief
            .get("poc_watch")
            .and_then(|v| v.get("ok"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            coverage.push_str(" Latest PoC Watch نیز از GitHub Search به‌صورت latest-first ساخته شده، CVE را از metadata استخراج می‌کند و کد exploit نمایش نمی‌دهد.");
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
