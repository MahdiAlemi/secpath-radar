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

pub(crate) fn finalize_botnet_c2(items: &mut [BotnetC2Indicator]) {
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

pub(crate) fn finalize_tls_threats(items: &mut [TlsThreatIndicator]) {
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

pub(crate) fn is_named_malware_family(value: &str) -> bool {
    let lower = value.to_lowercase();
    [
        "emotet", "dridex", "trickbot", "qakbot", "qbot", "bazar", "icedid", "gozi", "ramnit",
        "lokibot", "redline", "formbook",
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

pub(crate) fn empty_botnet_c2_pulse(status: &str) -> Value {
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
