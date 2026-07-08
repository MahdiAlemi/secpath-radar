//! Core data structures shared across fetchers and the brief builder.

use crate::prelude::*;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FeedItem {
    pub(crate) title: String,
    pub(crate) summary: String,
    pub(crate) source: String,
    pub(crate) url: String,
    pub(crate) published: String,
    pub(crate) risk_score: i64,
    pub(crate) category: String,
    pub(crate) tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CveItem {
    pub(crate) cve_id: String,
    pub(crate) title: String,
    pub(crate) summary: String,
    pub(crate) severity: String,
    pub(crate) cvss: f64,
    pub(crate) epss: f64,
    pub(crate) epss_percentile: f64,
    pub(crate) epss_7d: f64,
    pub(crate) epss_30d: f64,
    pub(crate) epss_delta_7d: f64,
    pub(crate) epss_delta_30d: f64,
    pub(crate) epss_momentum: String,
    pub(crate) kev: bool,
    pub(crate) cisa_vulnrichment: bool,
    pub(crate) ssvc_exploitation: String,
    pub(crate) ssvc_automatable: String,
    pub(crate) ssvc_technical_impact: String,
    pub(crate) cisa_priority: String,
    pub(crate) cvss_version: String,
    pub(crate) kev_due_date: String,
    pub(crate) kev_ransomware: bool,
    pub(crate) published: String,
    pub(crate) url: String,
    pub(crate) recommended_action: String,
    pub(crate) risk_score: i64,
    pub(crate) tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct EpssSnapshot {
    pub(crate) epss: f64,
    pub(crate) percentile: f64,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct KevEntry {
    pub(crate) due_date: String,
    pub(crate) ransomware: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct CisaVulnrichment {
    pub(crate) found: bool,
    pub(crate) exploitation: String,
    pub(crate) automatable: String,
    pub(crate) technical_impact: String,
    pub(crate) priority: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AttackPort {
    pub(crate) rank: usize,
    pub(crate) port: u16,
    pub(crate) service: String,
    pub(crate) description: String,
    pub(crate) risk: String,
    pub(crate) pressure_score: usize,
    pub(crate) bar_width: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct IocIndicator {
    pub(crate) rank: usize,
    pub(crate) source: String,
    pub(crate) indicator_type: String,
    pub(crate) indicator: String,
    pub(crate) indicator_safe: String,
    pub(crate) threat_type: String,
    pub(crate) malware: String,
    pub(crate) first_seen: String,
    pub(crate) confidence: usize,
    pub(crate) risk: String,
    pub(crate) risk_score: usize,
    pub(crate) bar_width: usize,
    pub(crate) tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct InfraCandidate {
    pub(crate) ip: String,
    pub(crate) source: String,
    pub(crate) first_seen: String,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InfrastructureHost {
    pub(crate) rank: usize,
    pub(crate) ip: String,
    pub(crate) source: String,
    pub(crate) first_seen: String,
    pub(crate) reason: String,
    pub(crate) ports: Vec<u16>,
    pub(crate) port_count: usize,
    pub(crate) hostnames: Vec<String>,
    pub(crate) tags: Vec<String>,
    pub(crate) vulns: Vec<String>,
    pub(crate) vuln_count: usize,
    pub(crate) exposure_score: usize,
    pub(crate) bar_width: usize,
    pub(crate) risk: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RansomwareVictim {
    pub(crate) rank: usize,
    pub(crate) victim_safe: String,
    pub(crate) group: String,
    pub(crate) country: String,
    pub(crate) sector: String,
    pub(crate) claimed_date: String,
    pub(crate) recency_score: usize,
    pub(crate) risk: String,
    pub(crate) bar_width: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct BotnetC2Indicator {
    pub(crate) rank: usize,
    pub(crate) ip: String,
    pub(crate) ip_safe: String,
    pub(crate) port: u16,
    pub(crate) status: String,
    pub(crate) malware: String,
    pub(crate) first_seen: String,
    pub(crate) source: String,
    pub(crate) risk: String,
    pub(crate) score: usize,
    pub(crate) bar_width: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TlsThreatIndicator {
    pub(crate) rank: usize,
    pub(crate) indicator_type: String,
    pub(crate) fingerprint: String,
    pub(crate) fingerprint_safe: String,
    pub(crate) first_seen: String,
    pub(crate) last_seen: String,
    pub(crate) reason: String,
    pub(crate) source: String,
    pub(crate) risk: String,
    pub(crate) score: usize,
    pub(crate) bar_width: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct GreyNoiseContextRow {
    pub(crate) rank: usize,
    pub(crate) ip: String,
    pub(crate) ip_safe: String,
    pub(crate) source: String,
    pub(crate) reason: String,
    pub(crate) classification: String,
    pub(crate) noise: bool,
    pub(crate) riot: bool,
    pub(crate) name: String,
    pub(crate) last_seen: String,
    pub(crate) risk: String,
    pub(crate) score: usize,
    pub(crate) bar_width: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct GreyNoiseCandidate {
    pub(crate) ip: String,
    pub(crate) source: String,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PhishingUrlIndicator {
    pub(crate) rank: usize,
    pub(crate) url_safe: String,
    pub(crate) host_safe: String,
    pub(crate) host: String,
    pub(crate) tld: String,
    pub(crate) brand_hint: String,
    pub(crate) scheme: String,
    pub(crate) path_depth: usize,
    pub(crate) source: String,
    pub(crate) risk: String,
    pub(crate) score: usize,
    pub(crate) bar_width: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct IcsAdvisoryItem {
    pub(crate) rank: usize,
    pub(crate) advisory_id: String,
    pub(crate) title: String,
    pub(crate) vendor: String,
    pub(crate) equipment: String,
    pub(crate) sector: String,
    pub(crate) cves: Vec<String>,
    pub(crate) cve_count: usize,
    pub(crate) cvss: f64,
    pub(crate) published: String,
    pub(crate) risk: String,
    pub(crate) score: usize,
    pub(crate) bar_width: usize,
    pub(crate) source: String,
}
