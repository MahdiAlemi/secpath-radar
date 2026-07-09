//! Feodo Tracker / SSLBL botnet C2 pulse.

use crate::prelude::*;

pub(crate) fn fetch_botnet_c2_pulse_or_fallback(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Value {
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

pub(crate) fn fetch_botnet_c2_pulse(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
    let client = build_client(config)?;

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
    let online_count = c2
        .iter()
        .filter(|item| item.status.to_lowercase().contains("online"))
        .count();
    let web_port_count = c2
        .iter()
        .filter(|item| matches!(item.port, 80 | 443 | 8080 | 8443))
        .count();
    let ja3_count = tls
        .iter()
        .filter(|item| item.indicator_type == "JA3")
        .count();
    let cert_count = tls
        .iter()
        .filter(|item| item.indicator_type == "SSL cert")
        .count();
    let family_names = c2
        .iter()
        .map(|item| item.malware.clone())
        .collect::<Vec<_>>();
    let port_names = c2
        .iter()
        .map(|item| port_label(item.port))
        .collect::<Vec<_>>();
    let tls_reason_names = tls
        .iter()
        .map(|item| item.reason.clone())
        .collect::<Vec<_>>();
    let family_chart = count_chart_names(&family_names, 7);
    let port_chart = count_chart_names(&port_names, 6);
    let tls_chart = count_chart_names(&tls_reason_names, 6);
    let top_family = first_chart_name(&family_chart);
    let top_port = first_chart_name(&port_chart);
    let top_tls_reason = first_chart_name(&tls_chart);
    let spotlight_c2 = c2.first().cloned();
    let spotlight_tls = tls.first().cloned();

    let level = if c2_high >= 8 || tls_high >= 10 {
        "High"
    } else if c2.len() >= 8 || tls.len() >= 8 {
        "Medium"
    } else {
        "Low"
    };

    let summary = match level {
        "High" => "Several new malicious C2 and fingerprints seen from Feodo and SSLBL; this section displays only defensive, defanged metadata.",
        "Medium" => "Multiple botnet C2 and malicious TLS signals received; useful for IOC and suspicious infrastructure correlation.",
        _ => "Volume of botnet C2 and TLS signals is low in this run.",
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
        "summary": summary,
        "last_updated": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "metadata_only": true,
        "totals": {
            "c2": c2.len(),
            "tls": tls.len(),
            "high": c2_high + tls_high,
            "c2_high": c2_high,
            "tls_high": tls_high,
            "online": online_count,
            "web_ports": web_port_count,
            "ja3": ja3_count,
            "certs": cert_count,
            "families": family_chart.len(),
            "ports": port_chart.len()
        },
        "insights": {
            "top_family": top_family,
            "top_port": top_port,
            "top_tls_reason": top_tls_reason,
            "metadata_only": true,
            "passive_only": true
        },
        "spotlight_c2": spotlight_c2,
        "spotlight_tls": spotlight_tls,
        "c2": c2,
        "tls": tls,
        "family_chart": family_chart,
        "port_chart": port_chart,
        "tls_chart": tls_chart
    }))
}

pub(crate) fn parse_feodo_c2_csv(text: &str) -> Vec<BotnetC2Indicator> {
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
        let malware = botnet_family_from_fields(&fields, ip_index);

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
        });
    }
    out
}

pub(crate) fn parse_sslbl_ja3_csv(text: &str) -> Vec<TlsThreatIndicator> {
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
        let reason = tls_reason_from_fields(&fields, 3, "malicious JA3");
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
        });
    }
    out
}

pub(crate) fn parse_sslbl_cert_csv(text: &str) -> Vec<TlsThreatIndicator> {
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
        let reason = tls_reason_from_fields(&fields, 2, "malicious certificate");
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
        });
    }
    out
}

pub(crate) fn finalize_botnet_c2(items: &mut [BotnetC2Indicator]) {
    let total = items.len().max(1);
    for (idx, item) in items.iter_mut().enumerate() {
        item.rank = idx + 1;
        item.malware = clean_threat_label(&item.malware, "Unattributed C2");
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
    }
    items.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.malware.cmp(&b.malware))
    });
}

pub(crate) fn finalize_tls_threats(items: &mut [TlsThreatIndicator]) {
    let total = items.len().max(1);
    for (idx, item) in items.iter_mut().enumerate() {
        item.rank = idx + 1;
        item.reason = clean_threat_label(&item.reason, "malicious TLS");
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
    }
    items.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.indicator_type.cmp(&b.indicator_type))
    });
}

pub(crate) fn botnet_family_from_fields(fields: &[String], ip_index: usize) -> String {
    let mut candidate_indexes = Vec::new();
    // Feodo blocklist columns are usually:
    // first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware.
    // Prefer the malware column after last_online, then scan the tail defensively
    // because cached/community CSV variants can add columns.
    for idx in [ip_index + 4, ip_index + 3, fields.len().saturating_sub(1)] {
        if idx < fields.len() && !candidate_indexes.contains(&idx) {
            candidate_indexes.push(idx);
        }
    }
    for idx in (ip_index + 2)..fields.len() {
        if !candidate_indexes.contains(&idx) {
            candidate_indexes.push(idx);
        }
    }
    for idx in candidate_indexes {
        if let Some(value) = fields.get(idx) {
            let cleaned = clean_threat_label(value, "");
            if !cleaned.is_empty() {
                return cleaned;
            }
        }
    }
    "Unattributed C2".to_string()
}

pub(crate) fn tls_reason_from_fields(
    fields: &[String],
    preferred_idx: usize,
    fallback: &str,
) -> String {
    let mut candidate_indexes = Vec::new();
    if preferred_idx < fields.len() {
        candidate_indexes.push(preferred_idx);
    }
    for idx in 1..fields.len() {
        if !candidate_indexes.contains(&idx) {
            candidate_indexes.push(idx);
        }
    }
    for idx in candidate_indexes {
        if let Some(value) = fields.get(idx) {
            let cleaned = clean_threat_label(value, "");
            if !cleaned.is_empty() {
                return cleaned;
            }
        }
    }
    fallback.to_string()
}

pub(crate) fn clean_threat_label(value: &str, fallback: &str) -> String {
    let cleaned = normalize_family(value);
    if is_noise_threat_label(&cleaned) {
        fallback.to_string()
    } else {
        cleaned
    }
}

pub(crate) fn is_noise_threat_label(value: &str) -> bool {
    let lower = value.trim().trim_matches('.').to_lowercase();
    if lower.is_empty() {
        return true;
    }
    if looks_like_date_or_timestamp(&lower) || looks_like_ipv4(&lower) {
        return true;
    }
    let exact_noise = [
        "unknown",
        "-",
        "n/a",
        "na",
        "none",
        "online",
        "offline",
        "c2_status",
        "last_online",
        "first_seen",
        "first_seen_utc",
        "dst_ip",
        "dst_port",
        "malware",
        "botnet",
        "sslbl",
        "ja3",
        "ssl cert",
        "certificate",
        "malicious_tls",
        "malicious tls",
    ];
    exact_noise.iter().any(|noise| lower == *noise)
}

pub(crate) fn looks_like_date_or_timestamp(value: &str) -> bool {
    let trimmed = value.trim();
    let date_part = trimmed.split_whitespace().next().unwrap_or(trimmed);
    let parts = date_part.split('-').collect::<Vec<_>>();
    parts.len() == 3
        && parts[0].len() == 4
        && parts[1].len() == 2
        && parts[2].len() == 2
        && parts
            .iter()
            .all(|part| part.chars().all(|ch| ch.is_ascii_digit()))
}

pub(crate) fn is_named_malware_family(value: &str) -> bool {
    let lower = value.to_lowercase();
    [
        "emotet",
        "dridex",
        "trickbot",
        "qakbot",
        "qbot",
        "bazar",
        "icedid",
        "gozi",
        "ramnit",
        "lokibot",
        "redline",
        "formbook",
        "heodo",
        "pikabot",
        "smokeloader",
        "danabot",
    ]
    .iter()
    .any(|family| lower.contains(family))
}

pub(crate) fn looks_like_ipv4(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 4 && parts.iter().all(|part| part.parse::<u8>().is_ok())
}

pub(crate) fn truncate_middle(value: &str, keep: usize) -> String {
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

pub(crate) fn count_chart_names(names: &[String], limit: usize) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for name in names {
        let key = normalize_family(name);
        if !is_noise_threat_label(&key) {
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

pub(crate) fn first_chart_name(rows: &[Value]) -> String {
    rows.first()
        .and_then(|row| row.get("name"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("none")
        .to_string()
}

pub(crate) fn port_label(port: u16) -> String {
    match port {
        80 => "80 HTTP".to_string(),
        443 => "443 HTTPS".to_string(),
        8080 => "8080 HTTP-alt".to_string(),
        8443 => "8443 HTTPS-alt".to_string(),
        22 => "22 SSH".to_string(),
        25 => "25 SMTP".to_string(),
        53 => "53 DNS".to_string(),
        3389 => "3389 RDP".to_string(),
        0 => "unknown".to_string(),
        _ => port.to_string(),
    }
}

pub(crate) fn empty_botnet_c2_pulse(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "Feodo Tracker + SSLBL",
        "level": "Unknown",
        "summary": "Botnet C2 Pulse data was not available this run.",
        "last_updated": "",
        "metadata_only": true,
        "totals": {
            "c2": 0,
            "tls": 0,
            "high": 0,
            "c2_high": 0,
            "tls_high": 0,
            "online": 0,
            "web_ports": 0,
            "ja3": 0,
            "certs": 0,
            "families": 0,
            "ports": 0
        },
        "insights": {
            "top_family": "none",
            "top_port": "none",
            "top_tls_reason": "none",
            "metadata_only": true,
            "passive_only": true
        },
        "spotlight_c2": null,
        "spotlight_tls": null,
        "c2": [],
        "tls": [],
        "family_chart": [],
        "port_chart": [],
        "tls_chart": []
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feodo_parser_uses_malware_after_last_online_not_date() {
        let line = "2026-07-08 01:02:03,1.2.3.4,443,online,2026-02-18,Heodo";
        let rows = parse_feodo_c2_csv(line);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].malware, "Heodo");
    }

    #[test]
    fn tls_reason_falls_back_when_only_dates_are_present() {
        let fields = vec![
            "0123456789abcdef0123456789abcdef".to_string(),
            "2026-07-08".to_string(),
            "2026-07-09".to_string(),
        ];
        assert_eq!(
            tls_reason_from_fields(&fields, 3, "malicious JA3"),
            "malicious JA3"
        );
    }

    #[test]
    fn noise_threat_label_detects_dates_and_status_words() {
        assert!(is_noise_threat_label("2026-02-18"));
        assert!(is_noise_threat_label("online"));
        assert!(!is_noise_threat_label("Heodo"));
    }
}
