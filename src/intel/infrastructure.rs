//! Shodan InternetDB / DShield infrastructure radar.

use crate::prelude::*;

pub(crate) fn fetch_infrastructure_radar_or_fallback(
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

pub(crate) fn fetch_infrastructure_radar(
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
            "summary": "No suitable public IPs found in IOC or DShield top IPs for infrastructure radar this run.",
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

    let summary = match level {
        "High" => "Several suspicious IPs have open ports or vulnerability indicators; this section is for exposure awareness.",
        "Medium" => "Some IOC-extracted IPs show observable exposure levels; useful for defensive correlation.",
        _ => "IOC-extracted infrastructure shows limited exposure in InternetDB.",
    };

    let port_chart = infrastructure_port_chart(&hosts, 10);
    let risk_chart = infrastructure_risk_chart(&hosts);

    Ok(json!({
        "enabled": true,
        "ok": true,
        "provider": "Shodan InternetDB + DShield top IPs",
        "source_url": "https://internetdb.shodan.io/",
        "level": level,
        "summary": summary,
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

pub(crate) fn fetch_shodan_internetdb_host(
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
    }))
}

pub(crate) fn infrastructure_candidates_from_sources(
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

pub(crate) fn fetch_dshield_top_ip_candidates(
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

pub(crate) fn parse_dshield_top_ip_candidates(text: &str, limit: usize) -> Vec<InfraCandidate> {
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

pub(crate) fn candidate_only_infrastructure_host(candidate: &InfraCandidate) -> InfrastructureHost {
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
    }
}

pub(crate) fn infrastructure_candidates_from_iocs(
    ioc_radar: &Value,
    limit: usize,
) -> Vec<InfraCandidate> {
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

pub(crate) fn extract_public_ips_from_indicator(value: &str) -> Vec<String> {
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

pub(crate) fn extract_host_from_url(value: &str) -> Option<String> {
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

pub(crate) fn parse_public_ip(value: &str) -> Option<String> {
    let ip = value.parse::<std::net::IpAddr>().ok()?;
    if is_public_ip(&ip) {
        Some(ip.to_string())
    } else {
        None
    }
}

pub(crate) fn is_public_ip(ip: &std::net::IpAddr) -> bool {
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

pub(crate) fn take_string_array(
    value: Option<&Value>,
    limit: usize,
    max_chars: usize,
) -> Vec<String> {
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

pub(crate) fn take_vulns(value: Option<&Value>, limit: usize) -> Vec<String> {
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

pub(crate) fn finalize_infrastructure_hosts(hosts: &mut [InfrastructureHost]) {
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

pub(crate) fn infrastructure_port_chart(hosts: &[InfrastructureHost], limit: usize) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for host in hosts {
        for port in &host.ports {
            *counts.entry(port.to_string()).or_insert(0) += 1;
        }
    }
    count_chart_from_counts(counts, limit)
}

pub(crate) fn infrastructure_risk_chart(hosts: &[InfrastructureHost]) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for host in hosts {
        *counts.entry(host.risk.clone()).or_insert(0) += 1;
    }
    count_chart_from_counts(counts, 4)
}

pub(crate) fn count_chart_from_counts(
    mut counts: HashMap<String, usize>,
    limit: usize,
) -> Vec<Value> {
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

pub(crate) fn is_risky_exposed_port(port: u16) -> bool {
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

pub(crate) fn is_exposure_tag(tag: &str) -> bool {
    let lower = tag.to_lowercase();
    lower.contains("vpn")
        || lower.contains("database")
        || lower.contains("ics")
        || lower.contains("industrial")
        || lower.contains("remote")
        || lower.contains("compromised")
}

pub(crate) fn empty_infrastructure_radar(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "Shodan InternetDB + DShield top IPs",
        "level": "Unknown",
        "summary": "Suspicious Infrastructure data was not available this run.",
        "last_updated": "",
        "refresh_hours": 1,
        "totals": {"candidates": 0, "hosts": 0, "high": 0, "vulns": 0, "ports": 0},
        "hosts": [],
        "port_chart": [],
        "risk_chart": []
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_public_ip_accepts_only_public_addresses() {
        assert_eq!(parse_public_ip("8.8.8.8"), Some("8.8.8.8".to_string()));
        assert_eq!(parse_public_ip("10.0.0.1"), None);
        assert_eq!(parse_public_ip("127.0.0.1"), None);
        assert_eq!(parse_public_ip("192.168.1.5"), None);
        assert_eq!(parse_public_ip("not-an-ip"), None);
    }
}
