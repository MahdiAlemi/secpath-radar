//! CSAF vendor advisory pulse (Red Hat CSAF v2, observation-only).

use crate::prelude::*;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CsafAdvisory {
    pub(crate) rank: usize,
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) severity: String,
    pub(crate) released: String,
    pub(crate) cve_count: usize,
    pub(crate) url: String,
    pub(crate) risk: String,
    pub(crate) score: usize,
    pub(crate) bar_width: usize,
    pub(crate) note_fa: String,
}

pub(crate) fn fetch_csaf_pulse_or_fallback(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Value {
    if !config.intel.enabled || !config.intel.csaf.enabled {
        return empty_csaf_pulse("disabled");
    }

    match fetch_csaf_pulse(config, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  CSAF Advisory Pulse skipped: {err:#}");
            empty_csaf_pulse("error")
        }
    }
}

pub(crate) fn fetch_csaf_pulse(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(26))
        .build()
        .context("failed to build HTTP client for CSAF Advisory Pulse")?;

    let cfg = &config.intel.csaf;
    eprintln!("→ fetching CSAF Advisory Pulse");
    let bytes = get_bytes_cached_intel(
        &client,
        config,
        &cfg.changes_csv_url,
        "CSAF changes index",
        offline,
        refresh_cache,
    )?;
    let text = String::from_utf8_lossy(&bytes);
    let mut entries = parse_csaf_changes_csv(&text);
    entries.truncate(cfg.max_advisories.max(1));

    let mut advisories = Vec::new();
    for (path, _date) in &entries {
        thread::sleep(Duration::from_millis(config.intel.sleep_ms_between_sources));
        let url = format!(
            "{}/{}",
            cfg.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let advisory_bytes = match get_bytes_cached_intel(
            &client,
            config,
            &url,
            &format!("CSAF advisory {path}"),
            offline,
            refresh_cache,
        ) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("⚠️  skipped CSAF advisory {path}: {err:#}");
                continue;
            }
        };
        let Ok(doc) = serde_json::from_slice::<Value>(&advisory_bytes) else {
            continue;
        };
        if let Some(item) = parse_csaf_document(&doc) {
            advisories.push(item);
        }
    }
    finalize_csaf_advisories(&mut advisories);

    let critical = advisories
        .iter()
        .filter(|item| item.severity == "critical")
        .count();
    let important = advisories
        .iter()
        .filter(|item| item.severity == "important")
        .count();
    let cves_total = advisories.iter().map(|item| item.cve_count).sum::<usize>();
    let severity_names = advisories
        .iter()
        .map(|item| item.severity.clone())
        .collect::<Vec<_>>();
    let severity_chart = count_chart_names(&severity_names, 5);

    let level = if critical > 0 {
        "High"
    } else if important > 0 {
        "Medium"
    } else if advisories.is_empty() {
        "Unknown"
    } else {
        "Watch"
    };
    let summary_fa = if advisories.is_empty() {
        "در این اجرا advisory تازه‌ای از فید CSAF دریافت نشد.".to_string()
    } else {
        format!(
            "{} advisory تازه از فید رسمی CSAF دریافت شد ({} بحرانی/مهم) و در مجموع {} CVE را پوشش می‌دهد.",
            advisories.len(),
            critical + important,
            cves_total
        )
    };

    Ok(json!({
        "enabled": true,
        "ok": true,
        "provider": "Red Hat CSAF v2",
        "level": level,
        "summary_fa": summary_fa,
        "last_updated": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "metadata_only": true,
        "totals": {
            "advisories": advisories.len(),
            "critical": critical,
            "important": important,
            "cves": cves_total
        },
        "advisories": advisories,
        "severity_chart": severity_chart
    }))
}

pub(crate) fn parse_csaf_changes_csv(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = split_csv_line(line);
        if fields.len() < 2 {
            continue;
        }
        let (path, date) = if fields[0].to_lowercase().ends_with(".json") {
            (fields[0].clone(), fields[1].clone())
        } else if fields[1].to_lowercase().ends_with(".json") {
            (fields[1].clone(), fields[0].clone())
        } else {
            continue;
        };
        out.push((path, date));
    }
    out.sort_by(|a, b| b.1.cmp(&a.1));
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

pub(crate) fn parse_csaf_document(doc: &Value) -> Option<CsafAdvisory> {
    let id = doc
        .pointer("/document/tracking/id")
        .and_then(|value| value.as_str())?
        .trim()
        .to_string();
    if id.is_empty() {
        return None;
    }
    let title = doc
        .pointer("/document/title")
        .and_then(|value| value.as_str())
        .map(clean_text)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| id.clone());
    let severity = doc
        .pointer("/document/aggregate_severity/text")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("unknown")
        .trim()
        .to_lowercase();
    let released = doc
        .pointer("/document/tracking/current_release_date")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .chars()
        .take(10)
        .collect::<String>();
    let cve_count = doc
        .get("vulnerabilities")
        .and_then(|value| value.as_array())
        .map(|arr| arr.len())
        .unwrap_or(0);
    let url = if id.starts_with("RH") {
        format!("https://access.redhat.com/errata/{id}")
    } else {
        String::new()
    };

    Some(CsafAdvisory {
        rank: 0,
        id,
        title: truncate_chars(&title, 96),
        severity,
        released,
        cve_count,
        url,
        risk: "watch".to_string(),
        score: 0,
        bar_width: 0,
        note_fa: String::new(),
    })
}

pub(crate) fn csaf_severity_score(severity: &str) -> usize {
    match severity {
        "critical" => 92,
        "important" => 74,
        "moderate" => 56,
        "low" => 40,
        _ => 35,
    }
}

pub(crate) fn finalize_csaf_advisories(items: &mut Vec<CsafAdvisory>) {
    for item in items.iter_mut() {
        let score = csaf_severity_score(&item.severity) + item.cve_count.min(8);
        item.score = score.clamp(10, 100);
        item.bar_width = item.score;
        item.risk = if item.score >= 78 {
            "high"
        } else if item.score >= 56 {
            "medium"
        } else {
            "watch"
        }
        .to_string();
        item.note_fa = "advisory رسمی CSAF است؛ برای تطبیق با سیستم‌های تحت مدیریت خودت استفاده کن."
            .to_string();
    }
    items.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
    for (idx, item) in items.iter_mut().enumerate() {
        item.rank = idx + 1;
    }
}

pub(crate) fn empty_csaf_pulse(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "Red Hat CSAF v2",
        "level": "Unknown",
        "summary_fa": "داده CSAF Advisory Pulse در این اجرا در دسترس نبود.",
        "last_updated": "",
        "metadata_only": true,
        "totals": {"advisories": 0, "critical": 0, "important": 0, "cves": 0},
        "advisories": [],
        "severity_chart": []
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_csaf_changes_csv_sorts_newest_first() {
        let text = [
            "\"2025/rhsa-2025_0001.json\",\"2026-07-01T10:00:00+00:00\"",
            "\"2026/rhsa-2026_9999.json\",\"2026-07-06T08:00:00+00:00\"",
        ]
        .join("\n");
        let entries = parse_csaf_changes_csv(&text);
        assert_eq!(entries.len(), 2);
        assert!(entries[0].0.contains("rhsa-2026_9999"));
    }

    #[test]
    fn csaf_severity_score_orders_levels() {
        assert!(csaf_severity_score("critical") > csaf_severity_score("important"));
        assert!(csaf_severity_score("important") > csaf_severity_score("moderate"));
        assert!(csaf_severity_score("unknown") < csaf_severity_score("low"));
    }
}
