//! CISA ICS/OT advisories pulse.

use crate::prelude::*;

pub(crate) fn fetch_ics_ot_pulse_or_fallback(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Value {
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

pub(crate) fn fetch_ics_ot_pulse(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
    let client = build_client(config)?;

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
        .map(|value| clean_ics_sector_label(&value))
        .unwrap_or_else(|| infer_ics_sector(&detail));
        let deployment = extract_labeled_field(
            &detail,
            "COUNTRIES/AREAS DEPLOYED:",
            &[
                "COMPANY HEADQUARTERS LOCATION:",
                "RESEARCHER",
                "MITIGATIONS",
                "VULNERABILITY OVERVIEW",
            ],
        )
        .map(|value| first_list_value(&value))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "Not listed".to_string());
        let cves = extract_cve_ids(&detail);
        let cvss = extract_cvss_score(&detail);
        let remote_signal = has_ics_remote_signal(&detail);
        let critical_sector = is_ics_critical_sector(&sector);
        let (risk, score) = ics_risk_from_detail(cvss, &detail);
        let rank = advisories.len() + 1;
        advisories.push(IcsAdvisoryItem {
            rank,
            advisory_id,
            title: truncate_chars(&title, 90),
            vendor: truncate_chars(&vendor, 42),
            equipment: truncate_chars(&equipment, 58),
            sector: truncate_chars(&sector, 42),
            deployment: truncate_chars(&deployment, 42),
            cve_count: cves.len(),
            cves,
            cvss,
            published,
            risk,
            score,
            bar_width: score.max(12).min(100),
            source: "CISA ICS Advisories".to_string(),
            remote_signal,
            critical_sector,
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
    let medium = advisories
        .iter()
        .filter(|item| item.risk == "medium")
        .count();
    let remote = advisories.iter().filter(|item| item.remote_signal).count();
    let critical_sectors = advisories
        .iter()
        .filter(|item| item.critical_sector)
        .count();
    let with_cve = advisories.iter().filter(|item| item.cve_count > 0).count();
    let max_cvss = advisories
        .iter()
        .map(|item| item.cvss)
        .fold(0.0_f64, f64::max);
    let cves_total: usize = advisories.iter().map(|item| item.cve_count).sum();
    let top_vendor = top_count_key(&vendor_counts).unwrap_or_else(|| "Unknown vendor".to_string());
    let meaningful_sector_counts = filtered_ics_sector_counts(&sector_counts);
    let generic_sector_labels = sector_counts
        .iter()
        .filter(|(sector, _)| is_generic_ics_sector_label(sector))
        .map(|(_, count)| *count)
        .sum::<usize>();
    let top_sector =
        top_count_key(&meaningful_sector_counts).unwrap_or_else(|| "Sector not listed".to_string());
    let top_equipment = advisories
        .first()
        .map(|item| item.equipment.clone())
        .unwrap_or_else(|| "No equipment listed".to_string());
    let spotlight = advisories.first().cloned();
    let summary = if advisories.is_empty() {
        "No new ICS/OT advisories from CISA seen in the current cache this run.".to_string()
    } else if high > 0 {
        format!("{} industrial/OT advisories read from CISA; {} high-level and {} CVEs flagged for defensive triage.", advisories.len(), high, cves_total)
    } else {
        format!("{} industrial/OT advisories read from CISA; focus is on vendor, equipment, and CVEs for defensive review.", advisories.len())
    };

    Ok(json!({
        "ok": true,
        "provider": "CISA ICS Advisories",
        "source_url": config.intel.ics_ot.ics_advisories_feed_url,
        "summary": summary,
        "totals": {
            "advisories": advisories.len(),
            "high": high,
            "medium": medium,
            "remote": remote,
            "critical_sectors": critical_sectors,
            "with_cve": with_cve,
            "vendors": vendor_counts.len(),
            "sectors": meaningful_sector_counts.len(),
            "generic_sector_labels": generic_sector_labels,
            "cves": cves_total,
            "max_cvss": format!("{max_cvss:.1}")
        },
        "insights": {
            "top_vendor": top_vendor,
            "top_sector": top_sector,
            "top_equipment": top_equipment
        },
        "spotlight": spotlight,
        "advisories": advisories,
        "vendor_chart": count_chart_from_counts(vendor_counts, 6),
        "sector_chart": count_chart_from_counts(meaningful_sector_counts, 6),
        "risk_chart": count_chart_from_counts(severity_counts, 4),
        "safe_mode": "metadata only; no active scan; no exploit content"
    }))
}

pub(crate) fn clean_ics_description(raw: &str) -> String {
    let once = clean_text(raw);
    let twice = clean_text(&once);
    clean_text(&twice)
}

pub(crate) fn extract_labeled_field(
    text: &str,
    label: &str,
    next_labels: &[&str],
) -> Option<String> {
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

pub(crate) fn clean_ics_entity_value(value: &str) -> String {
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

pub(crate) fn extract_ics_advisory_id(title: &str, url: &str) -> String {
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

pub(crate) fn infer_vendor_from_title(title: &str) -> String {
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

pub(crate) fn infer_equipment_from_title(title: &str, vendor: &str) -> String {
    let value = title.replacen(vendor, "", 1).trim().to_string();
    if value.is_empty() {
        "Unknown equipment".to_string()
    } else {
        value
    }
}

pub(crate) fn first_list_value(value: &str) -> String {
    value
        .split(|ch| ch == ',' || ch == ';' || ch == '/')
        .next()
        .unwrap_or(value)
        .trim()
        .to_string()
}

pub(crate) fn clean_ics_sector_label(value: &str) -> String {
    let cleaned = first_list_value(value)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if is_generic_ics_sector_label(&cleaned) {
        "Sector not listed".to_string()
    } else {
        truncate_chars(&cleaned, 42)
    }
}

pub(crate) fn is_generic_ics_sector_label(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    lower.is_empty()
        || lower == "ics"
        || lower == "ot"
        || lower == "ics/ot"
        || lower == "industrial"
        || lower == "industrial control systems"
        || lower == "critical infrastructure"
        || lower == "multiple"
        || lower == "multiple sectors"
        || lower == "all sectors"
        || lower == "not listed"
        || lower == "sector not listed"
        || lower == "unknown"
        || lower == "unknown sector"
}

pub(crate) fn filtered_ics_sector_counts(
    counts: &HashMap<String, usize>,
) -> HashMap<String, usize> {
    counts
        .iter()
        .filter(|(sector, _)| !is_generic_ics_sector_label(sector))
        .map(|(sector, count)| (sector.clone(), *count))
        .collect()
}

pub(crate) fn infer_ics_sector(text: &str) -> String {
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
    "Sector not listed".to_string()
}

pub(crate) fn extract_cvss_score(text: &str) -> f64 {
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

pub(crate) fn has_ics_remote_signal(detail: &str) -> bool {
    let lower = detail.to_lowercase();
    lower.contains("exploitable remotely")
        || lower.contains("remotely exploitable")
        || lower.contains("remote attacker")
        || lower.contains("network access")
        || lower.contains("internet")
        || lower.contains("remote access")
}

pub(crate) fn is_ics_critical_sector(sector: &str) -> bool {
    let lower = sector.to_lowercase();
    lower.contains("energy")
        || lower.contains("water")
        || lower.contains("transport")
        || lower.contains("health")
        || lower.contains("chemical")
        || lower.contains("manufacturing")
        || lower.contains("communications")
}

pub(crate) fn top_count_key(counts: &HashMap<String, usize>) -> Option<String> {
    counts
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
        .map(|(key, _)| key.clone())
}

pub(crate) fn ics_risk_from_detail(cvss: f64, detail: &str) -> (String, usize) {
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

pub(crate) fn finalize_ics_advisories(items: &mut [IcsAdvisoryItem]) {
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

pub(crate) fn empty_ics_ot_pulse(reason: &str) -> Value {
    json!({
        "ok": false,
        "reason": reason,
        "provider": "CISA ICS Advisories",
        "summary": "ICS/OT Advisory Pulse data was not available this run.",
        "totals": {"advisories": 0, "high": 0, "medium": 0, "remote": 0, "critical_sectors": 0, "with_cve": 0, "vendors": 0, "sectors": 0, "generic_sector_labels": 0, "cves": 0, "max_cvss": "0.0"},
        "insights": {"top_vendor": "Unknown vendor", "top_sector": "Sector not listed", "top_equipment": "No equipment listed"},
        "spotlight": null,
        "advisories": [],
        "vendor_chart": [],
        "sector_chart": [],
        "risk_chart": [],
        "safe_mode": "metadata only; no active scan; no exploit content"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ics_sector_cleanup_drops_generic_labels() {
        assert_eq!(clean_ics_sector_label("ICS/OT"), "Sector not listed");
        assert_eq!(
            clean_ics_sector_label("Multiple Sectors"),
            "Sector not listed"
        );
        assert_eq!(clean_ics_sector_label("Energy, Water"), "Energy");
    }

    #[test]
    fn ics_inference_uses_real_sector_or_not_listed() {
        assert_eq!(
            infer_ics_sector("remote access in water facilities"),
            "Water/Wastewater"
        );
        assert_eq!(
            infer_ics_sector("generic advisory text"),
            "Sector not listed"
        );
    }
}
