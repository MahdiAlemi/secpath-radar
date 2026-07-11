//! Executive snapshot and triage signals.

use crate::prelude::*;

pub(crate) fn build_executive_snapshot(brief: &Value) -> Value {
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

    let infra_high = path_u64(brief, &["infrastructure_radar", "totals", "high"]);
    let supply_critical = path_u64(brief, &["supply_chain_radar", "totals", "critical"]);
    let supply_high = path_u64(brief, &["supply_chain_radar", "totals", "high"]);
    let ransomware_24h = path_u64(brief, &["ransomware_pulse", "totals", "recent_24h"]);
    let _attack_level = path_string(brief, &["attack_pressure", "level"], "Unknown");

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

    let score = ((cve_score * 45 + intel_score * 35 + ecosystem_score * 20) / 100).clamp(12, 100);
    let level = snapshot_level(score);
    let score_formula = format!(
        "Weighted blend: 45% Vulnerability ({cve_score}) + 35% Telemetry ({intel_score}) + 20% Ecosystem ({ecosystem_score})"
    );

    let top_port = top_attack_port(brief);
    let top_ioc = first_chart_entry(brief, &["ioc_radar", "malware_chart"])
        .or_else(|| first_chart_entry(brief, &["ioc_radar", "source_chart"]))
        .unwrap_or_else(|| ("No prominent IOC".to_string(), 0));
    let top_phishing = first_chart_entry(brief, &["phishing_pulse", "brand_chart"])
        .unwrap_or_else(|| ("No prominent phishing".to_string(), 0));
    let top_ransomware = first_chart_entry(brief, &["ransomware_pulse", "group_chart"])
        .unwrap_or_else(|| ("No prominent group".to_string(), 0));
    let top_supply = first_chart_entry(brief, &["supply_chain_radar", "severity_chart"])
        .unwrap_or_else(|| ("No prominent severity".to_string(), 0));

    let impact_a = cves + critical_cves + kev + poc_watch;
    let impact_b = iocs + infrastructure_hosts + botnet_c2 + malicious_tls + phishing_urls;
    let impact_c = supply_advisories + ransomware_victims;
    let impact_max = impact_a.max(impact_b).max(impact_c).max(1);

    json!({
        "title": "Static Executive Snapshot",
        "level": level,
        "score": score,
        "bar_width": score.max(12),
        "score_formula": score_formula,
        "generated_at": brief.get("generated_at").cloned().unwrap_or(Value::Null),
        "summary": format!(
            "60-second summary: This run saw {} items, {} CVEs, {} PoC metadata, {} IOCs, {} C2 botnets, {} phishing URLs, {} ICS/OT advisories, {} IPs with GreyNoise context, {} supply chain advisories, and {} ransomware claims.",
            total_items, cves, poc_watch, iocs, botnet_c2, phishing_urls, ics_advisories, greynoise_noise + greynoise_malicious, supply_advisories, ransomware_victims
        ),
        "risk_cards": [
            {
                "title": "Vulnerability Risk",
                "metric": format!("{} critical / {} CVE / {} PoC", critical_cves, cves, poc_watch),
                "level": snapshot_level(cve_score),
                "bar_width": cve_score
            },
            {
                "title": "IOC & Suspicious Infrastructure",
                "metric": format!("{} IOC / {} C2 / {} phish / {} ICS", iocs, botnet_c2, phishing_urls, ics_advisories),
                "level": snapshot_level(intel_score),
                "bar_width": intel_score
            },
            {
                "title": "Supply Chain & Ransomware",
                "metric": format!("{} advisory / {} claims", supply_advisories, ransomware_victims),
                "level": snapshot_level(ecosystem_score),
                "bar_width": ecosystem_score
            }
        ],
        "rising_signals": [
            {
                "title": "Attack Pressure",
                "metric": top_port.0,
                "level": top_port.2,
                "bar_width": top_port.1.max(12)
            },
            {
                "title": "IOC Pattern",
                "metric": format!("{} · {} | {} · {}", top_ioc.0, top_ioc.1, top_phishing.0, top_phishing.1),
                "level": if phishing_high >= 4 || top_ioc.1 >= 5 { "high" } else if phishing_urls >= 10 || top_ioc.1 >= 2 { "medium" } else { "watch" },
                "bar_width": ((top_ioc.1 * 12 + phishing_high * 10 + phishing_urls.min(20)).min(100)).max(12)
            },
            {
                "title": "Ransomware / Ecosystem",
                "metric": format!("{} · {} | {} · {}", top_ransomware.0, top_ransomware.1, top_supply.0, top_supply.1),
                "level": if ransomware_24h >= 8 || supply_critical >= 3 { "high" } else if ransomware_24h >= 3 || supply_high >= 5 { "medium" } else { "watch" },
                "bar_width": ((ransomware_24h * 10 + supply_critical * 15 + supply_high * 4).min(100)).max(12)
            }
        ],
        "impact_sources": [
            {
                "name": "NVD + CISA KEV + EPSS",
                "count": impact_a,
                "bar_width": relative_width(impact_a, impact_max)
            },
            {
                "name": "DShield + abuse.ch + SSLBL + OpenPhish + InternetDB + GreyNoise",
                "count": impact_b,
                "bar_width": relative_width(impact_b, impact_max)
            },
            {
                "name": "GitHub Advisories + OSV + Ransomware.live",
                "count": impact_c,
                "bar_width": relative_width(impact_c, impact_max)
            }
        ]
    })
}

pub(crate) fn stat_u64(brief: &Value, key: &str) -> u64 {
    path_u64(brief, &["stats", key])
}

pub(crate) fn path_value<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for part in path {
        current = current.get(*part)?;
    }
    Some(current)
}

pub(crate) fn path_u64(value: &Value, path: &[&str]) -> u64 {
    path_value(value, path)
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

pub(crate) fn path_string(value: &Value, path: &[&str], fallback: &str) -> String {
    path_value(value, path)
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| fallback.to_string())
}

pub(crate) fn value_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

pub(crate) fn concise_text(input: &str, max_chars: usize) -> String {
    truncate_chars(input.trim(), max_chars)
}

pub(crate) fn first_chart_entry(brief: &Value, path: &[&str]) -> Option<(String, u64)> {
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

pub(crate) fn top_attack_port(brief: &Value) -> (String, u64, &'static str) {
    let Some(row) = path_value(brief, &["attack_pressure", "top_ports"])
        .and_then(|v| v.as_array())
        .and_then(|items| items.first())
    else {
        return ("No prominent port".to_string(), 12, "watch");
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

pub(crate) fn relative_width(value: u64, max: u64) -> u64 {
    if max == 0 {
        return 12;
    }
    (((value as f64 / max as f64) * 100.0).round() as u64).clamp(12, 100)
}

pub(crate) fn snapshot_level(score: u64) -> &'static str {
    if score >= 70 {
        "high"
    } else if score >= 40 {
        "medium"
    } else {
        "watch"
    }
}

pub(crate) fn build_triage_signals(brief: &Value) -> Value {
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
    let stale_rss = stat_u64(brief, "stale_rss_sources");
    let degraded_rss = failed_rss.saturating_add(stale_rss);
    let risk_score = path_u64(brief, &["executive_snapshot", "score"]);

    let mut signals: Vec<(u64, Value)> = Vec::new();

    signals.push((
        100 + risk_score,
        json!({
            "title": "Quick Decision Today",
            "metric": format!("Risk {risk_score}"),
            "level": snapshot_level(risk_score),
            "anchor": "#executive-snapshot",
            "bar_width": risk_score.max(12)
        }),
    ));

    if breaking_news > 0 || daily_news > 0 {
        let score = (breaking_news * 18 + daily_news.min(40)).min(100).max(12);
        signals.push((
            95 + score,
            json!({
                "title": "Breaking / Latest News",
                "metric": format!("{breaking_news} breaking · {daily_news} today"),
                "level": if breaking_news > 0 { "high" } else { "watch" },
                "anchor": "#breaking-news",
                "bar_width": score
            }),
        ));
    }

    if writeups > 0 {
        let score = (writeups * 8 + writeup_sources * 12).min(100).max(12);
        signals.push((
            88 + score,
            json!({
                "title": "Writeup / Latest Analysis",
                "metric": format!("{writeups} writeup · {writeup_sources} sources"),
                "level": if score >= 70 { "medium" } else { "watch" },
                "anchor": "#writeups-pulse",
                "bar_width": score
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
                "title": "Actionable Vulnerabilities",
                "metric": format!("{critical_cves} critical · {kev} KEV · {epss_rising} EPSS↑"),
                "level": snapshot_level(score),
                "anchor": "#cves",
                "bar_width": score
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
                "bar_width": score
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
                "title": "Scanner Context",
                "metric": format!("{greynoise_malicious} malicious · {greynoise_noise} noise"),
                "level": if greynoise_malicious > 0 { "high" } else { "watch" },
                "anchor": "#greynoise-context",
                "bar_width": score
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
                "title": "Active Threats & C2",
                "metric": format!("{iocs} IOC · {botnet_c2} C2 · {malicious_tls} TLS"),
                "level": if botnet_c2 > 0 { "high" } else if iocs > 0 { "medium" } else { "watch" },
                "anchor": "#ioc-radar",
                "bar_width": score
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
                "bar_width": score
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
                "bar_width": score
            }),
        ));
    }

    if history_changes > 0 {
        let score = (history_changes * 12).min(100).max(12);
        signals.push((
            55 + score,
            json!({
                "title": "Changes From Previous",
                "metric": format!("{history_changes} indicators changed"),
                "level": "medium",
                "anchor": "#history-snapshot",
                "bar_width": score
            }),
        ));
    }

    if degraded_rss > 0 {
        let score = (degraded_rss * 8).min(100).max(12);
        signals.push((
            45 + score,
            json!({
                "title": "Source Health",
                "metric": format!("{failed_rss} failed · {stale_rss} stale"),
                "level": if failed_rss > 0 { "medium" } else { "low" },
                "anchor": "#sources",
                "bar_width": score
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
