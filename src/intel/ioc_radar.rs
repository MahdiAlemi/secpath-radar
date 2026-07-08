//! URLhaus / ThreatFox IOC radar.

use crate::prelude::*;

pub(crate) fn fetch_ioc_radar_or_fallback(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Value {
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

pub(crate) fn fetch_ioc_radar(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
    let client = build_client(config)?;

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

    let summary = match level {
        "High" => "Large volume of new IOCs and several notable malware families; this section is for situational awareness and defensive triage.",
        "Medium" => "New IOCs received from URLhaus and ThreatFox; several indicator types and malware families observed.",
        _ => "New IOCs received, but overall severity is assessed as low in this run.",
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
        "summary": summary,
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

pub(crate) fn parse_urlhaus_recent_csv(text: &str) -> Vec<IocIndicator> {
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
        });
    }
    out
}

pub(crate) fn parse_threatfox_recent_csv(text: &str) -> Vec<IocIndicator> {
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
        });
    }
    out
}

pub(crate) fn finalize_ioc_indicators(items: &mut [IocIndicator]) {
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
        item.tags = item
            .tags
            .iter()
            .filter(|tag| !tag.trim().is_empty())
            .take(4)
            .cloned()
            .collect();
    }
}

pub(crate) fn ioc_count_chart<F>(items: &[IocIndicator], key_fn: F, limit: usize) -> Vec<Value>
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

pub(crate) fn split_csv_line(line: &str) -> Vec<String> {
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

pub(crate) fn parse_tag_list(raw: &str) -> Vec<String> {
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

pub(crate) fn first_useful_tag(tags: &[String]) -> Option<String> {
    tags.iter()
        .find(|tag| {
            !matches!(
                tag.to_lowercase().as_str(),
                "elf" | "exe" | "payload" | "malware" | "download"
            )
        })
        .map(|tag| normalize_family(tag))
}

pub(crate) fn normalize_ioc_type(value: &str) -> String {
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

pub(crate) fn infer_indicator_type(value: &str) -> String {
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

pub(crate) fn normalize_family(value: &str) -> String {
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

pub(crate) fn non_empty_or(value: String, fallback: &str) -> String {
    if value.trim().is_empty() || value.trim() == "-" {
        fallback.to_string()
    } else {
        value
    }
}

pub(crate) fn defang_indicator(value: &str) -> String {
    let mut out = value.trim().to_string();
    out = out
        .replace("https://", "hxxps://")
        .replace("http://", "hxxp://");
    out = out.replace('.', "[.]");
    truncate_chars(&out, 96)
}

pub(crate) fn empty_ioc_radar(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "abuse.ch URLhaus + ThreatFox",
        "level": "Unknown",
        "summary": "IOC Radar data was not available this run.",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_csv_line_handles_quotes_and_commas() {
        assert_eq!(
            split_csv_line("a,\"b,c\",d"),
            vec!["a".to_string(), "b,c".to_string(), "d".to_string()]
        );
        assert_eq!(
            split_csv_line("\"url\", malware x ,tag"),
            vec![
                "url".to_string(),
                "malware x".to_string(),
                "tag".to_string()
            ]
        );
    }

    #[test]
    fn parse_tag_list_filters_noise() {
        assert_eq!(
            parse_tag_list("apt, null, -, botnet"),
            vec!["apt".to_string(), "botnet".to_string()]
        );
    }
}
