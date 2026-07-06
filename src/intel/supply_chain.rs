//! GitHub / OSV supply-chain advisories radar.

use crate::prelude::*;

pub(crate) fn fetch_supply_chain_radar_or_fallback(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Value {
    if !config.intel.enabled || !config.intel.supply_chain.enabled {
        return empty_supply_chain_radar("disabled");
    }

    match fetch_supply_chain_radar(config, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  Supply Chain Radar skipped: {err:#}");
            let mut fallback = empty_supply_chain_radar("error");
            fallback["error"] = json!(err.to_string());
            fallback
        }
    }
}

pub(crate) fn fetch_supply_chain_radar(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
    eprintln!("→ fetching Supply Chain radar");
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(45))
        .build()
        .context("failed to build HTTP client for Supply Chain radar")?;

    let sc = &config.intel.supply_chain;
    let per_ecosystem = (sc.max_advisories / sc.ecosystems.len().max(1)).clamp(3, 8);
    let mut seen = HashSet::new();
    let mut advisories = Vec::new();

    for ecosystem in &sc.ecosystems {
        let url = format!(
            "{}?type=reviewed&ecosystem={}&per_page={}&sort=published&direction=desc",
            sc.github_advisories_url.trim_end_matches('/'),
            ecosystem,
            per_ecosystem
        );
        let label = format!("GitHub Advisory {ecosystem}");
        match get_bytes_cached_intel(&client, config, &url, &label, offline, refresh_cache) {
            Ok(bytes) => {
                let rows: Value = serde_json::from_slice(&bytes).with_context(|| {
                    format!("GitHub advisory response was not valid JSON for {ecosystem}")
                })?;
                let Some(items) = rows.as_array() else {
                    continue;
                };
                for item in items {
                    if let Some(advisory) = map_github_advisory(
                        item,
                        ecosystem,
                        &config.intel.supply_chain.osv_base_url,
                    ) {
                        let key = advisory
                            .get("ghsa_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        if !key.is_empty() && seen.insert(key) {
                            advisories.push(advisory);
                        }
                    }
                }
            }
            Err(err) => eprintln!("⚠️  skipped GitHub Advisory {ecosystem}: {err:#}"),
        }
        thread::sleep(Duration::from_millis(config.intel.sleep_ms_between_sources));
    }

    advisories.sort_by(|a, b| {
        let ar = a.get("rank_score").and_then(|v| v.as_i64()).unwrap_or(0);
        let br = b.get("rank_score").and_then(|v| v.as_i64()).unwrap_or(0);
        br.cmp(&ar)
    });
    advisories.truncate(sc.max_advisories);
    annotate_supply_bars(&mut advisories);

    let mut ecosystem_counts = HashMap::new();
    let mut severity_counts = HashMap::new();
    let mut package_counts = HashMap::new();
    let mut fixed = 0usize;
    let mut critical = 0usize;
    let mut high = 0usize;

    for advisory in &advisories {
        let ecosystem = advisory
            .get("ecosystem")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let severity = advisory
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let package = advisory
            .get("package")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        *ecosystem_counts.entry(ecosystem).or_insert(0) += 1;
        *severity_counts.entry(severity.clone()).or_insert(0) += 1;
        if package != "unknown" {
            *package_counts.entry(package).or_insert(0) += 1;
        }
        if advisory
            .get("fix_available")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            fixed += 1;
        }
        match severity.as_str() {
            "critical" => critical += 1,
            "high" => high += 1,
            _ => {}
        }
    }

    let total = advisories.len();
    let level = if critical > 0 || high >= 5 {
        "High"
    } else if high > 0 || total >= 12 {
        "Medium"
    } else if total > 0 {
        "Watch"
    } else {
        "Low"
    };

    let summary_fa = if total == 0 {
        "در این اجرا advisory قابل نمایش برای supply chain دریافت نشد.".to_string()
    } else {
        format!("{total} advisory تازه/اخیر از اکوسیستم‌های open-source دیده شد؛ {high} مورد high و {critical} مورد critical است.")
    };

    Ok(json!({
        "enabled": true,
        "ok": total > 0,
        "provider": "GitHub Global Advisories + OSV references",
        "level": level,
        "summary_fa": summary_fa,
        "last_updated": tehran_now().format("%Y-%m-%d %H:%M").to_string(),
        "refresh_hours": config.intel.refresh_hours,
        "totals": {
            "advisories": total,
            "critical": critical,
            "high": high,
            "fixed": fixed,
            "ecosystems": ecosystem_counts.len()
        },
        "advisories": advisories,
        "ecosystem_chart": count_chart_from_counts(ecosystem_counts, 8),
        "severity_chart": count_chart_from_counts(severity_counts, 5),
        "package_chart": count_chart_from_counts(package_counts, 8),
        "source_health": {
            "cache_dir": config.intel.cache_dir.clone(),
            "refresh_hours": config.intel.refresh_hours,
            "sources": ["GitHub Global Advisories", "OSV vulnerability pages"]
        }
    }))
}

pub(crate) fn map_github_advisory(
    item: &Value,
    fallback_ecosystem: &str,
    osv_base_url: &str,
) -> Option<Value> {
    let ghsa_id = item.get("ghsa_id").and_then(|v| v.as_str())?.to_string();
    let cve_id = item
        .get("cve_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let summary = truncate_chars(
        item.get("summary").and_then(|v| v.as_str()).unwrap_or(""),
        180,
    );
    let severity = item
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_lowercase();
    let published = item
        .get("published_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let updated = item
        .get("updated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let html_url = item
        .get("html_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let cvss = item
        .get("cvss")
        .and_then(|v| v.get("score"))
        .and_then(|v| v.as_f64())
        .or_else(|| {
            item.get("cvss_severities")
                .and_then(|v| v.get("cvss_v4"))
                .and_then(|v| v.get("score"))
                .and_then(|v| v.as_f64())
        })
        .or_else(|| {
            item.get("cvss_severities")
                .and_then(|v| v.get("cvss_v3"))
                .and_then(|v| v.get("score"))
                .and_then(|v| v.as_f64())
        })
        .unwrap_or(0.0);
    let epss = item
        .get("epss")
        .and_then(|v| v.get("percentage"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let vuln = item
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first());
    let ecosystem = vuln
        .and_then(|v| v.get("package"))
        .and_then(|pkg| pkg.get("ecosystem"))
        .and_then(|v| v.as_str())
        .unwrap_or(fallback_ecosystem)
        .to_string();
    let package = vuln
        .and_then(|v| v.get("package"))
        .and_then(|pkg| pkg.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let vulnerable_range = vuln
        .and_then(|v| v.get("vulnerable_version_range"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let patched = vuln
        .and_then(|v| v.get("first_patched_version"))
        .and_then(|v| v.get("identifier"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let fix_available = !patched.trim().is_empty();

    let identifiers = item
        .get("identifiers")
        .and_then(|v| v.as_array())
        .map(|ids| {
            ids.iter()
                .filter_map(|id| {
                    id.get("value")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .take(4)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let risk = supply_chain_risk(&severity, cvss, epss);
    let rank_score = supply_chain_rank_score(&severity, cvss, epss, fix_available);
    let osv_id = if !ghsa_id.is_empty() {
        ghsa_id.as_str()
    } else {
        cve_id.as_str()
    };
    let osv_url = if osv_id.is_empty() {
        String::new()
    } else {
        format!("{}/{}", osv_base_url.trim_end_matches('/'), osv_id)
    };

    Some(json!({
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "summary": summary,
        "severity": severity,
        "ecosystem": ecosystem,
        "package": package,
        "vulnerable_range": vulnerable_range,
        "patched_version": patched,
        "fix_available": fix_available,
        "published": published,
        "updated": updated,
        "html_url": html_url,
        "osv_url": osv_url,
        "identifiers": identifiers,
        "cvss": cvss,
        "epss": epss,
        "risk": risk,
        "rank_score": rank_score,
        "bar_width": 0,
        "note_fa": supply_chain_note(&severity, fix_available, &package),
    }))
}

pub(crate) fn supply_chain_rank_score(
    severity: &str,
    cvss: f64,
    epss: f64,
    fix_available: bool,
) -> i64 {
    let sev = match severity {
        "critical" => 90,
        "high" => 72,
        "medium" => 48,
        "low" => 24,
        _ => 16,
    };
    let cvss_bonus = (cvss * 3.0).round() as i64;
    let epss_bonus = (epss * 100.0).round() as i64;
    let fix_bonus = if fix_available { 6 } else { 0 };
    sev + cvss_bonus + epss_bonus + fix_bonus
}

pub(crate) fn supply_chain_risk(severity: &str, cvss: f64, epss: f64) -> &'static str {
    if severity == "critical" || cvss >= 9.0 || epss >= 0.5 {
        "high"
    } else if severity == "high" || cvss >= 7.0 || epss >= 0.1 {
        "medium"
    } else {
        "watch"
    }
}

pub(crate) fn supply_chain_note(severity: &str, fix_available: bool, package: &str) -> String {
    if severity == "critical" || severity == "high" {
        if fix_available {
            return format!("برای package {package} نسخه patched وجود دارد؛ در SBOM و dependency inventory تطبیق شود.");
        }
        return format!("برای package {package} advisory پرریسک دیده شده؛ وضعیت patched version را در advisory رسمی بررسی کن.");
    }
    "برای آگاهی از ریسک supply chain نگه داشته شود؛ این رادار dependency scan انجام نمی‌دهد."
        .to_string()
}

pub(crate) fn annotate_supply_bars(advisories: &mut [Value]) {
    let max_score = advisories
        .iter()
        .filter_map(|row| row.get("rank_score").and_then(|v| v.as_i64()))
        .max()
        .unwrap_or(1)
        .max(1);
    for row in advisories {
        let score = row.get("rank_score").and_then(|v| v.as_i64()).unwrap_or(1);
        let width = ((score as f64 / max_score as f64) * 100.0).round() as usize;
        row["bar_width"] = json!(width.clamp(12, 100));
    }
}

pub(crate) fn empty_supply_chain_radar(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "GitHub Global Advisories + OSV references",
        "level": "Unknown",
        "summary_fa": "داده Supply Chain Radar در این اجرا در دسترس نبود.",
        "last_updated": "",
        "refresh_hours": 1,
        "totals": {"advisories": 0, "critical": 0, "high": 0, "fixed": 0, "ecosystems": 0},
        "advisories": [],
        "ecosystem_chart": [],
        "severity_chart": [],
        "package_chart": []
    })
}
