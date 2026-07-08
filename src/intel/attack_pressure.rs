//! DShield top-ports attack pressure pulse.

use crate::prelude::*;

pub(crate) fn fetch_attack_pressure_or_fallback(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Value {
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

pub(crate) fn fetch_attack_pressure(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
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

    let summary = match level {
        "High" => "Multiple sensitive ports repeated in DShield feeds; high internet scan pressure assessed.",
        "Medium" => "Several high-risk services seen among targeted ports; notable for daily monitoring.",
        _ => "DShield data does not show extreme abnormal pressure, but common services remain under scan.",
    };

    Ok(json!({
        "enabled": true,
        "ok": true,
        "provider": "SANS ISC / DShield",
        "source_url": "https://www.dshield.org/feeds_doc.html",
        "level": level,
        "summary": summary,
        "last_updated": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "cache_dir": config.intel.cache_dir.clone(),
        "refresh_hours": config.intel.refresh_hours,
        "top_ports": headline,
        "scanning_ports": scanning,
        "reported_ports": reports,
        "targeted_ports": targets
    }))
}

pub(crate) fn fetch_dshield_port_feed(
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

pub(crate) fn annotate_attack_ports(ports: &mut [AttackPort]) {
    let total = ports.len().max(1);
    for (idx, port) in ports.iter_mut().enumerate() {
        let relative = (((total - idx) as f64 / total as f64) * 100.0).round() as usize;
        port.pressure_score = relative.max(10);
        port.bar_width = relative.clamp(10, 100);
    }
}

pub(crate) fn parse_dshield_ports(text: &str) -> Vec<AttackPort> {
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
            pressure_score: 0,
            bar_width: 0,
        });
    }

    out
}

pub(crate) fn normalize_port_service(service: &str) -> String {
    let cleaned = service.trim_matches('-').trim();
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned.to_string()
    }
}

pub(crate) fn attack_port_risk(port: u16) -> &'static str {
    match port {
        21 | 22 | 23 | 445 | 3389 | 5900 | 6379 | 9200 | 11211 | 27017 => "high",
        80 | 443 | 8080 | 8443 | 8000 | 2222 | 5060 | 53 | 853 => "medium",
        _ => "watch",
    }
}

pub(crate) fn empty_attack_pressure(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "SANS ISC / DShield",
        "level": "Unknown",
        "summary": "Attack Pressure data was not available this run.",
        "last_updated": "",
        "refresh_hours": 1,
        "top_ports": [],
        "scanning_ports": [],
        "reported_ports": [],
        "targeted_ports": []
    })
}
