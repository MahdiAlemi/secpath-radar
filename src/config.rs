//! Configuration structures loaded from config.yaml.

use crate::prelude::*;

#[derive(Debug, Deserialize)]
pub(crate) struct Config {
    pub(crate) site: SiteConfig,
    pub(crate) fetch: FetchConfig,
    #[serde(default)]
    pub(crate) cache: CacheConfig,
    #[serde(default)]
    pub(crate) intel: IntelConfig,
    pub(crate) filters: FiltersConfig,
    pub(crate) limits: LimitsConfig,
    pub(crate) sources: Vec<SourceConfig>,
    #[serde(default)]
    pub(crate) writeup_sources: Vec<SourceConfig>,
    #[serde(default)]
    pub(crate) cve: CveConfig,
    #[serde(default)]
    pub(crate) gemini: GeminiConfig,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SiteConfig {
    pub(crate) title: String,
    #[allow(dead_code)]
    pub(crate) tagline: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FetchConfig {
    pub(crate) max_items_per_source: usize,
    pub(crate) max_total_items: usize,
    pub(crate) sleep_ms_between_sources: u64,
    pub(crate) user_agent: String,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct CacheConfig {
    #[serde(default = "default_cache_enabled")]
    pub(crate) enabled: bool,
    #[serde(default = "default_cache_dir")]
    pub(crate) dir: String,
    #[serde(default = "default_cache_ttl_minutes")]
    pub(crate) ttl_minutes: u64,
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

pub(crate) fn default_cache_enabled() -> bool {
    true
}

pub(crate) fn default_cache_dir() -> String {
    "data/cache/http".to_string()
}

pub(crate) fn default_cache_ttl_minutes() -> u64 {
    720
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct IntelConfig {
    #[serde(default = "default_intel_enabled")]
    pub(crate) enabled: bool,
    #[serde(default = "default_intel_cache_dir")]
    pub(crate) cache_dir: String,
    #[serde(default = "default_intel_refresh_hours")]
    pub(crate) refresh_hours: u64,
    #[serde(default = "default_intel_sleep_ms")]
    pub(crate) sleep_ms_between_sources: u64,
    #[serde(default)]
    pub(crate) attack_pressure: AttackPressureConfig,
    #[serde(default)]
    pub(crate) ioc_radar: IocRadarConfig,
    #[serde(default)]
    pub(crate) infrastructure: InfrastructureRadarConfig,
    #[serde(default)]
    pub(crate) supply_chain: SupplyChainConfig,
    #[serde(default)]
    pub(crate) ransomware: RansomwareConfig,
    #[serde(default)]
    pub(crate) botnet_c2: BotnetC2Config,
    #[serde(default)]
    pub(crate) greynoise: GreyNoiseConfig,
    #[serde(default)]
    pub(crate) phishing: PhishingPulseConfig,
    #[serde(default)]
    pub(crate) ics_ot: IcsOtConfig,
    #[serde(default)]
    pub(crate) nuclei_coverage: NucleiCoverageConfig,
    #[serde(default)]
    pub(crate) poc_watch: PocWatchConfig,
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

pub(crate) fn default_intel_enabled() -> bool {
    true
}

pub(crate) fn default_intel_cache_dir() -> String {
    "data/cache/intel".to_string()
}

pub(crate) fn default_intel_refresh_hours() -> u64 {
    1
}

pub(crate) fn default_intel_sleep_ms() -> u64 {
    350
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct AttackPressureConfig {
    #[serde(default = "default_attack_pressure_enabled")]
    pub(crate) enabled: bool,
    #[serde(default = "default_attack_pressure_max_ports")]
    pub(crate) max_ports: usize,
    #[serde(default = "default_top_ports_url")]
    pub(crate) top_ports_url: String,
    #[serde(default = "default_top_ports_source_url")]
    pub(crate) top_ports_source_url: String,
    #[serde(default = "default_top_ports_reports_url")]
    pub(crate) top_ports_reports_url: String,
    #[serde(default = "default_top_ports_targets_url")]
    pub(crate) top_ports_targets_url: String,
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

pub(crate) fn default_attack_pressure_enabled() -> bool {
    true
}

pub(crate) fn default_attack_pressure_max_ports() -> usize {
    10
}

pub(crate) fn default_top_ports_url() -> String {
    "https://feeds.dshield.org/feeds//topports.txt".to_string()
}

pub(crate) fn default_top_ports_source_url() -> String {
    "https://feeds.dshield.org/feeds//topports_source.txt".to_string()
}

pub(crate) fn default_top_ports_reports_url() -> String {
    "https://feeds.dshield.org/feeds//topports_reports.txt".to_string()
}

pub(crate) fn default_top_ports_targets_url() -> String {
    "https://feeds.dshield.org/feeds//topports_targets.txt".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct IocRadarConfig {
    #[serde(default = "default_ioc_radar_enabled")]
    pub(crate) enabled: bool,
    #[serde(default = "default_ioc_max_urlhaus")]
    pub(crate) max_urlhaus: usize,
    #[serde(default = "default_ioc_max_threatfox")]
    pub(crate) max_threatfox: usize,
    #[serde(default = "default_urlhaus_recent_csv_url")]
    pub(crate) urlhaus_recent_csv_url: String,
    #[serde(default = "default_threatfox_recent_csv_url")]
    pub(crate) threatfox_recent_csv_url: String,
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

pub(crate) fn default_ioc_radar_enabled() -> bool {
    true
}

pub(crate) fn default_ioc_max_urlhaus() -> usize {
    18
}

pub(crate) fn default_ioc_max_threatfox() -> usize {
    18
}

pub(crate) fn default_urlhaus_recent_csv_url() -> String {
    "https://urlhaus.abuse.ch/downloads/csv_recent/".to_string()
}

pub(crate) fn default_threatfox_recent_csv_url() -> String {
    "https://threatfox.abuse.ch/export/csv/recent/".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct InfrastructureRadarConfig {
    #[serde(default = "default_infrastructure_enabled")]
    pub(crate) enabled: bool,
    #[serde(default = "default_infrastructure_max_ips")]
    pub(crate) max_ips: usize,
    #[serde(default = "default_shodan_internetdb_base_url")]
    pub(crate) shodan_base_url: String,
    #[serde(default = "default_dshield_top_ips_url")]
    pub(crate) dshield_top_ips_url: String,
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

pub(crate) fn default_infrastructure_enabled() -> bool {
    true
}

pub(crate) fn default_infrastructure_max_ips() -> usize {
    12
}

pub(crate) fn default_shodan_internetdb_base_url() -> String {
    "https://internetdb.shodan.io".to_string()
}

pub(crate) fn default_dshield_top_ips_url() -> String {
    "https://feeds.dshield.org/feeds/topips.txt".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct SupplyChainConfig {
    #[serde(default = "default_supply_chain_enabled")]
    pub(crate) enabled: bool,
    #[serde(default = "default_supply_chain_max_advisories")]
    pub(crate) max_advisories: usize,
    #[serde(default = "default_github_advisories_url")]
    pub(crate) github_advisories_url: String,
    #[serde(default = "default_osv_base_url")]
    pub(crate) osv_base_url: String,
    #[serde(default = "default_supply_chain_ecosystems")]
    pub(crate) ecosystems: Vec<String>,
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

pub(crate) fn default_supply_chain_enabled() -> bool {
    true
}

pub(crate) fn default_supply_chain_max_advisories() -> usize {
    24
}

pub(crate) fn default_github_advisories_url() -> String {
    "https://api.github.com/advisories".to_string()
}

pub(crate) fn default_osv_base_url() -> String {
    "https://osv.dev/vulnerability".to_string()
}

pub(crate) fn default_supply_chain_ecosystems() -> Vec<String> {
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
pub(crate) struct RansomwareConfig {
    #[serde(default = "default_ransomware_enabled")]
    pub(crate) enabled: bool,
    #[serde(default = "default_ransomware_max_victims")]
    pub(crate) max_victims: usize,
    #[serde(default = "default_ransomware_recent_victims_url")]
    pub(crate) recent_victims_url: String,
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

pub(crate) fn default_ransomware_enabled() -> bool {
    true
}

pub(crate) fn default_ransomware_max_victims() -> usize {
    30
}

pub(crate) fn default_ransomware_recent_victims_url() -> String {
    "https://api.ransomware.live/v2/recentvictims".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct BotnetC2Config {
    #[serde(default = "default_botnet_enabled")]
    pub(crate) enabled: bool,
    #[serde(default = "default_botnet_max_c2")]
    pub(crate) max_c2: usize,
    #[serde(default = "default_botnet_max_tls")]
    pub(crate) max_tls: usize,
    #[serde(default = "default_feodo_ipblocklist_url")]
    pub(crate) feodo_ipblocklist_csv_url: String,
    #[serde(default = "default_sslbl_ja3_url")]
    pub(crate) sslbl_ja3_csv_url: String,
    #[serde(default = "default_sslbl_cert_url")]
    pub(crate) sslbl_cert_csv_url: String,
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

pub(crate) fn default_botnet_enabled() -> bool {
    true
}

pub(crate) fn default_botnet_max_c2() -> usize {
    18
}

pub(crate) fn default_botnet_max_tls() -> usize {
    16
}

pub(crate) fn default_feodo_ipblocklist_url() -> String {
    "https://feodotracker.abuse.ch/downloads/ipblocklist.csv".to_string()
}

pub(crate) fn default_sslbl_ja3_url() -> String {
    "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv".to_string()
}

pub(crate) fn default_sslbl_cert_url() -> String {
    "https://sslbl.abuse.ch/blacklist/sslblacklist.csv".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct GreyNoiseConfig {
    #[serde(default = "default_greynoise_enabled")]
    pub(crate) enabled: bool,
    #[serde(default = "default_greynoise_max_lookups")]
    pub(crate) max_lookups: usize,
    #[serde(default = "default_greynoise_community_api_url")]
    pub(crate) community_api_url: String,
    #[serde(default = "default_greynoise_api_key_env")]
    pub(crate) api_key_env: String,
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

pub(crate) fn default_greynoise_enabled() -> bool {
    true
}

pub(crate) fn default_greynoise_max_lookups() -> usize {
    8
}

pub(crate) fn default_greynoise_community_api_url() -> String {
    "https://api.greynoise.io/v3/community".to_string()
}

pub(crate) fn default_greynoise_api_key_env() -> String {
    "GREYNOISE_API_KEY".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct PhishingPulseConfig {
    #[serde(default = "default_phishing_enabled")]
    pub(crate) enabled: bool,
    #[serde(default = "default_phishing_max_urls")]
    pub(crate) max_urls: usize,
    #[serde(default = "default_openphish_feed_url")]
    pub(crate) openphish_feed_url: String,
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
pub(crate) struct IcsOtConfig {
    #[serde(default = "default_ics_ot_enabled")]
    pub(crate) enabled: bool,
    #[serde(default = "default_ics_ot_max_advisories")]
    pub(crate) max_advisories: usize,
    #[serde(default = "default_ics_ot_advisories_feed_url")]
    pub(crate) ics_advisories_feed_url: String,
}

pub(crate) fn default_ics_ot_enabled() -> bool {
    true
}

pub(crate) fn default_ics_ot_max_advisories() -> usize {
    12
}

pub(crate) fn default_ics_ot_advisories_feed_url() -> String {
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
pub(crate) struct NucleiCoverageConfig {
    #[serde(default = "default_nuclei_coverage_enabled")]
    pub(crate) enabled: bool,
    #[serde(default = "default_nuclei_coverage_max_templates")]
    pub(crate) max_templates: usize,
    #[serde(default = "default_nuclei_coverage_max_missing")]
    pub(crate) max_missing: usize,
    #[serde(default = "default_nuclei_templates_tree_url")]
    pub(crate) templates_tree_url: String,
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

pub(crate) fn default_nuclei_coverage_enabled() -> bool {
    true
}

pub(crate) fn default_nuclei_coverage_max_templates() -> usize {
    12
}

pub(crate) fn default_nuclei_coverage_max_missing() -> usize {
    8
}

pub(crate) fn default_nuclei_templates_tree_url() -> String {
    "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1"
        .to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct PocWatchConfig {
    #[serde(default = "default_poc_watch_enabled")]
    pub(crate) enabled: bool,
    #[serde(default = "default_poc_watch_recent_days")]
    pub(crate) recent_days: i64,
    #[serde(default = "default_poc_watch_max_repos_per_cve")]
    pub(crate) max_repos_per_cve: usize,
    #[serde(default = "default_poc_watch_max_results")]
    pub(crate) max_results: usize,
    #[serde(default = "default_poc_watch_max_search_results_per_query")]
    pub(crate) max_search_results_per_query: usize,
    #[serde(default = "default_github_search_repositories_url")]
    pub(crate) github_search_repositories_url: String,
    #[serde(default = "default_github_token_env")]
    pub(crate) github_token_env: String,
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

pub(crate) fn default_poc_watch_enabled() -> bool {
    true
}

pub(crate) fn default_poc_watch_recent_days() -> i64 {
    30
}

pub(crate) fn default_poc_watch_max_repos_per_cve() -> usize {
    1
}

pub(crate) fn default_poc_watch_max_results() -> usize {
    18
}

pub(crate) fn default_poc_watch_max_search_results_per_query() -> usize {
    30
}

pub(crate) fn default_github_search_repositories_url() -> String {
    "https://api.github.com/search/repositories".to_string()
}

pub(crate) fn default_github_token_env() -> String {
    "GITHUB_TOKEN".to_string()
}

pub(crate) fn default_phishing_enabled() -> bool {
    true
}

pub(crate) fn default_phishing_max_urls() -> usize {
    24
}

pub(crate) fn default_openphish_feed_url() -> String {
    "https://openphish.com/feed.txt".to_string()
}

#[derive(Debug, Deserialize)]
pub(crate) struct FiltersConfig {
    pub(crate) iran_keywords: Vec<String>,
    pub(crate) high_keywords: Vec<String>,
    pub(crate) low_keywords: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LimitsConfig {
    pub(crate) iran_radar: usize,
    pub(crate) global_news: usize,
    #[serde(default = "default_cve_limit")]
    pub(crate) cves: usize,
}

pub(crate) fn default_cve_limit() -> usize {
    8
}

#[derive(Debug, Deserialize)]
pub(crate) struct SourceConfig {
    pub(crate) name: String,
    pub(crate) url: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SourceFailure {
    pub(crate) name: String,
    pub(crate) url: String,
    pub(crate) error: String,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct CveConfig {
    #[serde(default = "default_max_cves")]
    pub(crate) max_cves: usize,
    #[serde(default = "default_lookback_days")]
    pub(crate) lookback_days: i64,
    #[serde(default = "default_sleep_ms")]
    pub(crate) sleep_ms_between_sources: u64,
    #[serde(default = "default_nvd_url")]
    pub(crate) nvd_url: String,
    #[serde(default = "default_kev_url")]
    pub(crate) kev_url: String,
    #[serde(default = "default_epss_url")]
    pub(crate) epss_url: String,
    #[serde(default)]
    pub(crate) include_epss: bool,
    #[serde(default)]
    pub(crate) include_epss_momentum: bool,
    #[serde(default = "default_epss_momentum_days")]
    pub(crate) epss_momentum_days: Vec<i64>,
    #[serde(default)]
    pub(crate) include_vulnrichment: bool,
    #[serde(default = "default_vulnrichment_base_url")]
    pub(crate) vulnrichment_base_url: String,
    #[serde(default = "default_max_vulnrichment")]
    pub(crate) max_vulnrichment: usize,
    #[serde(default = "default_include_fallback")]
    pub(crate) include_fallback: bool,
    #[serde(default = "default_fallback_delta_url")]
    pub(crate) fallback_delta_url: String,
    #[serde(default = "default_max_fallback_records")]
    pub(crate) max_fallback_records: usize,
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
            include_fallback: default_include_fallback(),
            fallback_delta_url: default_fallback_delta_url(),
            max_fallback_records: default_max_fallback_records(),
        }
    }
}

pub(crate) fn default_max_cves() -> usize {
    12
}

pub(crate) fn default_lookback_days() -> i64 {
    2
}

pub(crate) fn default_sleep_ms() -> u64 {
    1200
}

pub(crate) fn default_nvd_url() -> String {
    "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string()
}

pub(crate) fn default_kev_url() -> String {
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        .to_string()
}

pub(crate) fn default_epss_url() -> String {
    "https://api.first.org/data/v1/epss".to_string()
}

pub(crate) fn default_epss_momentum_days() -> Vec<i64> {
    vec![7, 30]
}

pub(crate) fn default_vulnrichment_base_url() -> String {
    "https://raw.githubusercontent.com/cisagov/vulnrichment/develop".to_string()
}

pub(crate) fn default_max_vulnrichment() -> usize {
    10
}

pub(crate) fn default_include_fallback() -> bool {
    true
}

pub(crate) fn default_fallback_delta_url() -> String {
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json".to_string()
}

pub(crate) fn default_max_fallback_records() -> usize {
    20
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct GeminiConfig {
    #[serde(default = "default_gemini_model")]
    pub(crate) model: String,
    #[serde(default = "default_gemini_api_url")]
    pub(crate) api_url: String,
    #[serde(default = "default_gemini_cache_dir")]
    pub(crate) cache_dir: String,
    #[serde(default = "default_gemini_temperature")]
    pub(crate) temperature: f64,
    #[serde(default = "default_gemini_max_iran")]
    pub(crate) max_iran_items: usize,
    #[serde(default = "default_gemini_max_global")]
    pub(crate) max_global_news: usize,
    #[serde(default = "default_gemini_max_cves")]
    pub(crate) max_cves: usize,
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

pub(crate) fn default_gemini_model() -> String {
    "gemini-2.5-flash".to_string()
}

pub(crate) fn default_gemini_api_url() -> String {
    "https://generativelanguage.googleapis.com/v1beta".to_string()
}

pub(crate) fn default_gemini_cache_dir() -> String {
    "data/cache/ai".to_string()
}

pub(crate) fn default_gemini_temperature() -> f64 {
    0.2
}

pub(crate) fn default_gemini_max_iran() -> usize {
    5
}

pub(crate) fn default_gemini_max_global() -> usize {
    7
}

pub(crate) fn default_gemini_max_cves() -> usize {
    8
}

pub(crate) fn load_config(path: &PathBuf) -> Result<Config> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config: {}", path.display()))?;
    serde_yaml::from_str(&raw).with_context(|| format!("invalid YAML in {}", path.display()))
}
