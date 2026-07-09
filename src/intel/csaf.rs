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
    pub(crate) cves: Vec<String>,
    pub(crate) product_count: usize,
    pub(crate) products: Vec<String>,
    pub(crate) remediation_count: usize,
    pub(crate) fixed_count: usize,
    pub(crate) cwe_count: usize,
    pub(crate) max_cvss: f64,
    pub(crate) url: String,
    pub(crate) risk: String,
    pub(crate) score: usize,
    pub(crate) bar_width: usize,
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
    let client = build_client(config)?;

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
    let remediation_total = advisories
        .iter()
        .map(|item| item.remediation_count)
        .sum::<usize>();
    let fixed_total = advisories
        .iter()
        .map(|item| item.fixed_count)
        .sum::<usize>();
    let product_total = advisories
        .iter()
        .map(|item| item.product_count)
        .sum::<usize>();
    let cwe_total = advisories.iter().map(|item| item.cwe_count).sum::<usize>();
    let high_cvss = advisories
        .iter()
        .filter(|item| item.max_cvss >= 7.0)
        .count();
    let max_cvss = advisories
        .iter()
        .map(|item| item.max_cvss)
        .fold(0.0_f64, f64::max);
    let severity_names = advisories
        .iter()
        .map(|item| item.severity.clone())
        .collect::<Vec<_>>();
    let severity_chart = count_chart_names(&severity_names, 5);
    let mut product_names = Vec::new();
    let mut cve_names = Vec::new();
    for item in &advisories {
        product_names.extend(item.products.iter().cloned());
        cve_names.extend(item.cves.iter().cloned());
    }
    let product_chart = count_chart_names(&product_names, 6);
    let cve_chart = count_chart_names(&cve_names, 6);
    let spotlight = advisories.first().cloned();

    let level = if critical > 0 {
        "High"
    } else if important > 0 {
        "Medium"
    } else if advisories.is_empty() {
        "Unknown"
    } else {
        "Watch"
    };
    let summary = if advisories.is_empty() {
        "No new advisories received from the CSAF feed in this run.".to_string()
    } else {
        format!(
            "{} new advisories received from the official CSAF feed ({} critical/important), covering {} CVEs in total.",
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
        "summary": summary,
        "last_updated": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "metadata_only": true,
        "totals": {
            "advisories": advisories.len(),
            "critical": critical,
            "important": important,
            "important_plus": critical + important,
            "cves": cves_total,
            "remediations": remediation_total,
            "fixed_products": fixed_total,
            "products": product_total,
            "cwes": cwe_total,
            "high_cvss": high_cvss,
            "max_cvss": format!("{max_cvss:.1}")
        },
        "insights": {
            "top_product": product_chart.first().and_then(|row| row.get("name")).and_then(|value| value.as_str()).unwrap_or("Unknown product").to_string(),
            "top_cve": cve_chart.first().and_then(|row| row.get("name")).and_then(|value| value.as_str()).unwrap_or("No CVE listed").to_string(),
            "fix_signal": if fixed_total > 0 { "Fix metadata present" } else { "Fix metadata not listed" }
        },
        "spotlight": spotlight,
        "advisories": advisories,
        "severity_chart": severity_chart,
        "product_chart": product_chart,
        "cve_chart": cve_chart
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
    let vulnerabilities = doc
        .get("vulnerabilities")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let cves = extract_csaf_vulnerability_cves(&vulnerabilities);
    let cve_count = cves.len().max(vulnerabilities.len());
    let remediation_count = vulnerabilities
        .iter()
        .map(|vuln| {
            vuln.get("remediations")
                .and_then(|v| v.as_array())
                .map(|arr| arr.len())
                .unwrap_or(0)
        })
        .sum::<usize>();
    let fixed_count = vulnerabilities
        .iter()
        .map(count_csaf_fixed_products)
        .sum::<usize>();
    let cwe_count = vulnerabilities
        .iter()
        .map(|vuln| {
            vuln.get("cwes")
                .and_then(|v| v.as_array())
                .map(|arr| arr.len())
                .unwrap_or(0)
        })
        .sum::<usize>();
    let max_cvss = vulnerabilities
        .iter()
        .map(extract_csaf_max_cvss)
        .fold(0.0_f64, f64::max);
    let mut products = collect_csaf_product_names(doc);
    products.sort();
    products.dedup();
    let product_count = products.len();
    products.truncate(4);
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
        cves,
        product_count,
        products,
        remediation_count,
        fixed_count,
        cwe_count,
        max_cvss,
        url,
        risk: "watch".to_string(),
        score: 0,
        bar_width: 0,
    })
}

pub(crate) fn extract_csaf_vulnerability_cves(vulnerabilities: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for vuln in vulnerabilities {
        if let Some(cve) = vuln.get("cve").and_then(|value| value.as_str()) {
            let cve = cve.trim().to_ascii_uppercase();
            if cve.starts_with("CVE-") && seen.insert(cve.clone()) {
                out.push(cve);
            }
        }
    }
    out
}

pub(crate) fn count_csaf_fixed_products(vuln: &Value) -> usize {
    vuln.pointer("/product_status/fixed")
        .and_then(|value| value.as_array())
        .map(|arr| arr.len())
        .unwrap_or(0)
}

pub(crate) fn extract_csaf_max_cvss(vuln: &Value) -> f64 {
    let mut best = 0.0_f64;
    if let Some(scores) = vuln.get("scores").and_then(|value| value.as_array()) {
        for score in scores {
            for key in ["cvss_v4", "cvss_v3", "cvss_v2"] {
                if let Some(base) = score
                    .get(key)
                    .and_then(|value| value.get("baseScore"))
                    .and_then(|value| value.as_f64())
                {
                    best = best.max(base);
                }
            }
        }
    }
    best
}

pub(crate) fn collect_csaf_product_names(doc: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_csaf_product_names_inner(doc.get("product_tree").unwrap_or(&Value::Null), &mut out);
    out.into_iter()
        .map(|value| truncate_chars(&clean_text(&value), 46))
        .filter(|value| !value.is_empty())
        .collect()
}

fn collect_csaf_product_names_inner(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(name) = map.get("name").and_then(|value| value.as_str()) {
                let cleaned = clean_text(name);
                if !cleaned.is_empty() && !cleaned.eq_ignore_ascii_case("Red Hat") {
                    out.push(cleaned);
                }
            }
            for child in map.values() {
                collect_csaf_product_names_inner(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_csaf_product_names_inner(item, out);
            }
        }
        _ => {}
    }
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
        "summary": "CSAF Advisory Pulse data was not available this run.",
        "last_updated": "",
        "metadata_only": true,
        "totals": {"advisories": 0, "critical": 0, "important": 0, "important_plus": 0, "cves": 0, "remediations": 0, "fixed_products": 0, "products": 0, "cwes": 0, "high_cvss": 0, "max_cvss": "0.0"},
        "insights": {"top_product": "Unknown product", "top_cve": "No CVE listed", "fix_signal": "No CSAF data"},
        "spotlight": null,
        "advisories": [],
        "severity_chart": [],
        "product_chart": [],
        "cve_chart": []
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
