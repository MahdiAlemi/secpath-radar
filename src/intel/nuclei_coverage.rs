//! Nuclei template coverage (metadata-only).

use crate::prelude::*;

pub(crate) fn fetch_nuclei_coverage_or_fallback(
    config: &Config,
    cves: &Value,
    offline: bool,
    refresh_cache: bool,
) -> Value {
    if !config.intel.enabled || !config.intel.nuclei_coverage.enabled {
        return empty_nuclei_coverage("disabled");
    }

    match fetch_nuclei_coverage(config, cves, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  Nuclei Template Coverage skipped: {err:#}");
            let mut fallback = empty_nuclei_coverage("fetch_error");
            fallback["errors"] = json!([source_error_summary(&err.to_string())]);
            fallback
        }
    }
}

pub(crate) fn fetch_nuclei_coverage(
    config: &Config,
    cves: &Value,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
    let cfg = &config.intel.nuclei_coverage;
    let client = build_client(config)?;

    eprintln!("→ fetching Nuclei Template Coverage index");
    let label = "ProjectDiscovery nuclei-templates tree";
    let mut cache_misses = 0_u64;
    let mut errors = Vec::new();

    let tree_value = match get_bytes_cached_intel(
        &client,
        config,
        &cfg.templates_tree_url,
        label,
        offline,
        refresh_cache,
    ) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes)
            .context("ProjectDiscovery nuclei-templates tree was not valid JSON")?,
        Err(err) => {
            let err_text = err.to_string();
            if offline && is_offline_cache_miss_error(&err_text) {
                eprintln!("  ↳ cache miss: {label}");
                cache_misses = 1;
                Value::Null
            } else {
                errors.push(json!(source_error_summary(&err_text)));
                Value::Null
            }
        }
    };

    let dashboard_cves = dashboard_cve_metadata(cves);
    let dashboard_total = dashboard_cves.len();
    let mut cve_to_paths: HashMap<String, Vec<String>> = HashMap::new();
    let mut protocol_counts: HashMap<String, usize> = HashMap::new();
    let mut indexed_template_paths = 0usize;
    let tree_truncated = tree_value
        .get("truncated")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    if let Some(nodes) = tree_value.get("tree").and_then(|value| value.as_array()) {
        for node in nodes {
            if node.get("type").and_then(|value| value.as_str()) != Some("blob") {
                continue;
            }
            let Some(path) = node.get("path").and_then(|value| value.as_str()) else {
                continue;
            };
            let path_lower = path.to_ascii_lowercase();
            if !(path_lower.ends_with(".yaml") || path_lower.ends_with(".yml")) {
                continue;
            }
            let cve_ids = extract_cve_ids(path);
            if cve_ids.is_empty() {
                continue;
            }
            indexed_template_paths += 1;
            let protocol = nuclei_protocol_from_path(path);
            *protocol_counts.entry(protocol).or_insert(0) += 1;
            for cve_id in cve_ids {
                cve_to_paths
                    .entry(cve_id)
                    .or_insert_with(Vec::new)
                    .push(path.to_string());
            }
        }
    }

    let indexed_cves = cve_to_paths.len();
    let mut covered = Vec::new();
    let mut missing = Vec::new();
    let mut severity_counts: HashMap<String, usize> = HashMap::new();
    let mut missing_severity_counts: HashMap<String, usize> = HashMap::new();
    let mut covered_critical = 0usize;
    let mut covered_high = 0usize;
    let mut missing_critical = 0usize;
    let mut missing_high = 0usize;
    let mut covered_template_matches = 0usize;

    for row in &dashboard_cves {
        let cve_id = value_str(row, "cve_id").to_string();
        let severity = value_str(row, "severity").to_string();
        let title = value_str(row, "title").to_string();
        if let Some(paths) = cve_to_paths.get(&cve_id) {
            let first_path = paths.first().cloned().unwrap_or_default();
            *severity_counts.entry(severity.clone()).or_insert(0) += 1;
            covered_template_matches += paths.len();
            match severity.to_ascii_uppercase().as_str() {
                "CRITICAL" => covered_critical += 1,
                "HIGH" => covered_high += 1,
                _ => {}
            }
            let score = nuclei_coverage_score(&severity, paths.len());
            covered.push(json!({
                "cve_id": cve_id,
                "severity": severity,
                "title": title,
                "template_path": first_path,
                "template_path_safe": truncate_chars(&first_path, 82),
                "protocol": nuclei_protocol_from_path(&first_path),
                "template_count": paths.len(),
                "risk": nuclei_coverage_risk(&severity),
                "score": score,
                "bar_width": score.clamp(12, 100),
                "safe_mode": "metadata only; template path only; no nuclei execution; no scan target"
            }));
        } else {
            *missing_severity_counts.entry(severity.clone()).or_insert(0) += 1;
            match severity.to_ascii_uppercase().as_str() {
                "CRITICAL" => missing_critical += 1,
                "HIGH" => missing_high += 1,
                _ => {}
            }
            if missing.len() < cfg.max_missing {
                missing.push(json!({
                    "cve_id": cve_id,
                    "severity": severity,
                    "title": title,
                    "risk": nuclei_coverage_risk(&severity)
                }));
            }
        }
    }

    covered.sort_by(|a, b| {
        path_u64(b, &["score"])
            .cmp(&path_u64(a, &["score"]))
            .then_with(|| value_str(a, "cve_id").cmp(value_str(b, "cve_id")))
    });
    covered.truncate(cfg.max_templates);

    let covered_cves = dashboard_cves
        .iter()
        .filter(|row| {
            row.get("cve_id")
                .and_then(|value| value.as_str())
                .map(|cve_id| cve_to_paths.contains_key(cve_id))
                .unwrap_or(false)
        })
        .count();
    let missing_cves = dashboard_total.saturating_sub(covered_cves);
    let coverage_pct = if dashboard_total == 0 {
        0
    } else {
        ((covered_cves as f64 / dashboard_total as f64) * 100.0).round() as u64
    };

    let summary = if cache_misses > 0 {
        "Offline mode: no previous cache for public nuclei-templates index; run online once to populate the cache for coverage lookup.".to_string()
    } else if dashboard_total == 0 {
        "No current-day CVEs to assess against public nuclei-template metadata.".to_string()
    } else if covered_cves == 0 {
        format!("No template path matched today's {dashboard_total} CVEs; this may indicate coverage gaps or a limited index/cache.")
    } else {
        format!("{covered_cves}/{dashboard_total} current-day CVEs have public nuclei template metadata; {missing_cves} remain without a matched path.")
    };

    let coverage_level = if dashboard_total == 0 {
        "Idle"
    } else if missing_critical > 0 {
        "Critical gap"
    } else if missing_high > 0 {
        "High gap"
    } else if missing_cves > 0 {
        "Partial"
    } else {
        "Covered"
    };
    let coverage_risk = if missing_critical > 0 {
        "high"
    } else if missing_high > 0 || missing_cves > covered_cves {
        "medium"
    } else {
        "watch"
    };
    let top_protocol = top_count_entry(&protocol_counts, "No protocol");

    let mut coverage_counts = HashMap::new();
    coverage_counts.insert("covered".to_string(), covered_cves);
    coverage_counts.insert("missing".to_string(), missing_cves);
    let coverage_chart = count_chart(coverage_counts, 2);
    let severity_chart = count_chart(severity_counts, 5);
    let missing_severity_chart = count_chart(missing_severity_counts, 5);
    let protocol_chart = count_chart(protocol_counts, 6);

    Ok(json!({
        "enabled": true,
        "ok": errors.is_empty(),
        "provider": "ProjectDiscovery nuclei-templates Git tree",
        "source": "projectdiscovery/nuclei-templates path metadata",
        "mode": "template_path_coverage",
        "summary": summary,
        "level": coverage_level,
        "risk": coverage_risk,
        "top_protocol": top_protocol,
        "safe_mode": "metadata only; no nuclei execution; no active scan; no target input; no exploit content",
        "last_updated": tehran_now().format("%Y-%m-%d %H:%M").to_string(),
        "totals": {
            "dashboard_cves": dashboard_total,
            "covered_cves": covered_cves,
            "missing_cves": missing_cves,
            "coverage_pct": coverage_pct,
            "covered_critical": covered_critical,
            "covered_high": covered_high,
            "missing_critical": missing_critical,
            "missing_high": missing_high,
            "covered_template_matches": covered_template_matches,
            "indexed_cves": indexed_cves,
            "template_paths": indexed_template_paths,
            "tree_truncated": tree_truncated,
            "cache_misses": cache_misses,
            "errors": errors.len()
        },
        "covered": covered,
        "missing": missing,
        "coverage_chart": coverage_chart,
        "severity_chart": severity_chart,
        "missing_severity_chart": missing_severity_chart,
        "protocol_chart": protocol_chart,
        "errors": errors
    }))
}

pub(crate) fn top_count_entry(counts: &HashMap<String, usize>, fallback: &str) -> Value {
    counts
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
        .map(|(name, count)| json!({"name": truncate_chars(name, 36), "count": count}))
        .unwrap_or_else(|| json!({"name": fallback, "count": 0}))
}

pub(crate) fn dashboard_cve_metadata(cves: &Value) -> Vec<Value> {
    let mut seen = HashSet::new();
    let mut rows = Vec::new();
    let Some(items) = cves.as_array() else {
        return rows;
    };
    for item in items {
        let cve_id = item
            .get("cve_id")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .trim()
            .to_ascii_uppercase();
        if !is_cve_id(&cve_id) || !seen.insert(cve_id.clone()) {
            continue;
        }
        rows.push(json!({
            "cve_id": cve_id,
            "severity": item.get("severity").and_then(|value| value.as_str()).unwrap_or("UNKNOWN"),
            "title": item.get("title").and_then(|value| value.as_str()).unwrap_or("Current dashboard CVE")
        }));
    }
    rows
}

pub(crate) fn nuclei_protocol_from_path(path: &str) -> String {
    path.split('/')
        .next()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("templates")
        .to_string()
}

pub(crate) fn nuclei_coverage_risk(severity: &str) -> &'static str {
    match severity.to_ascii_uppercase().as_str() {
        "CRITICAL" => "high",
        "HIGH" => "high",
        "MEDIUM" => "medium",
        _ => "watch",
    }
}

pub(crate) fn nuclei_coverage_score(severity: &str, template_count: usize) -> usize {
    let base = match severity.to_ascii_uppercase().as_str() {
        "CRITICAL" => 84,
        "HIGH" => 72,
        "MEDIUM" => 54,
        _ => 36,
    };
    (base + template_count.saturating_sub(1).min(4) * 4).min(100)
}

pub(crate) fn empty_nuclei_coverage(reason: &str) -> Value {
    json!({
        "enabled": false,
        "ok": false,
        "reason": reason,
        "provider": "ProjectDiscovery nuclei-templates Git tree",
        "mode": "template_path_coverage",
        "summary": "Nuclei Template Coverage data was not available this run.",
        "safe_mode": "metadata only; no nuclei execution; no active scan; no target input; no exploit content",
        "totals": {
            "dashboard_cves": 0,
            "covered_cves": 0,
            "missing_cves": 0,
            "coverage_pct": 0,
            "indexed_cves": 0,
            "template_paths": 0,
            "tree_truncated": false,
            "cache_misses": 0,
            "errors": 0
        },
        "covered": [],
        "missing": [],
        "coverage_chart": [],
        "severity_chart": [],
        "protocol_chart": [],
        "errors": []
    })
}
