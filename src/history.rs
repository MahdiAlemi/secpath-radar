//! Local snapshot history and delta comparison.

use crate::prelude::*;

pub(crate) fn read_previous_latest_brief() -> Option<Value> {
    let raw = fs::read_to_string("data/latest_brief.json").ok()?;
    serde_json::from_str(&raw).ok()
}

pub(crate) fn attach_history_snapshot(brief: &mut Value, previous: Option<&Value>) {
    let generated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let previous_version = previous
        .and_then(|value| value.get("version"))
        .and_then(|value| value.as_str())
        .unwrap_or("none")
        .to_string();

    let metrics = history_metrics();
    let mut deltas: Vec<Value> = metrics
        .iter()
        .map(|metric| {
            let current = metric_value(brief, metric.path);
            let previous_value = previous
                .map(|value| metric_value(value, metric.path))
                .unwrap_or(0);
            let delta = current - previous_value;
            let direction = if delta > 0 {
                "up"
            } else if delta < 0 {
                "down"
            } else {
                "flat"
            };
            let level = history_delta_level(metric.key, delta);
            json!({
                "key": metric.key,
                "label": metric.label,
                "before": previous_value,
                "after": current,
                "delta": delta,
                "direction": direction,
                "level": level,
                "bar_width": relative_width(delta.unsigned_abs(), metric.baseline)
            })
        })
        .collect();

    deltas.sort_by(|a, b| {
        let ad = a.get("delta").and_then(|v| v.as_i64()).unwrap_or(0).abs();
        let bd = b.get("delta").and_then(|v| v.as_i64()).unwrap_or(0).abs();
        bd.cmp(&ad)
    });

    let changed = deltas
        .iter()
        .filter(|row| row.get("delta").and_then(|v| v.as_i64()).unwrap_or(0) != 0)
        .count() as u64;
    let increased = deltas
        .iter()
        .filter(|row| row.get("delta").and_then(|v| v.as_i64()).unwrap_or(0) > 0)
        .count() as u64;
    let decreased = deltas
        .iter()
        .filter(|row| row.get("delta").and_then(|v| v.as_i64()).unwrap_or(0) < 0)
        .count() as u64;
    let tracked = deltas.len() as u64;
    let unchanged = tracked.saturating_sub(changed);
    let changed_rows: Vec<Value> = deltas
        .iter()
        .filter(|row| row.get("delta").and_then(|v| v.as_i64()).unwrap_or(0) != 0)
        .cloned()
        .collect();
    let top_changes: Vec<Value> = if changed_rows.is_empty() {
        deltas.into_iter().take(5).collect()
    } else {
        changed_rows.into_iter().take(9).collect()
    };

    let summary = if previous.is_none() {
        "No previous snapshot available for comparison yet; daily changes will appear from the next run.".to_string()
    } else if changed == 0 {
        "Compared to the previous run, no significant changes in key indicators were observed."
            .to_string()
    } else {
        format!(
            "Compared to the previous run, {changed} indicators changed; {increased} increased and {decreased} decreased."
        )
    };

    brief["stats"]["history_changes"] = json!(changed);
    brief["history_snapshot"] = json!({
        "enabled": true,
        "generated_at": generated_at,
        "previous_available": previous.is_some(),
        "previous_version": previous_version,
        "current_version": brief.get("version").and_then(|v| v.as_str()).unwrap_or("unknown"),
        "summary": summary,
        "totals": {
            "tracked": tracked,
            "changed": changed,
            "increased": increased,
            "decreased": decreased,
            "unchanged": unchanged
        },
        "top_changes": top_changes,
        "storage": "snapshots/history"
    });
}

pub(crate) fn build_history_snapshot_value(brief: &Value) -> Value {
    let generated_at = brief
        .get("history_snapshot")
        .and_then(|value| value.get("generated_at"))
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    json!({
        "version": brief.get("version").cloned().unwrap_or_else(|| json!("unknown")),
        "generated_at": generated_at,
        "stats": brief.get("stats").cloned().unwrap_or_else(|| json!({})),
        "executive_snapshot": brief.get("executive_snapshot").cloned().unwrap_or_else(|| json!({})),
        "history_snapshot": brief.get("history_snapshot").cloned().unwrap_or_else(|| json!({}))
    })
}

pub(crate) fn write_history_snapshot(brief: &Value) -> Result<()> {
    let history_dir = PathBuf::from("snapshots/history");
    fs::create_dir_all(&history_dir).context("failed to create snapshots/history")?;
    let snapshot = build_history_snapshot_value(brief);
    let generated_at = snapshot
        .get("generated_at")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let safe_name = generated_at
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    let pretty = serde_json::to_string_pretty(&snapshot)?;
    fs::write(history_dir.join("latest_snapshot.json"), &pretty)
        .context("failed to write latest history snapshot")?;
    if !safe_name.is_empty() {
        fs::write(history_dir.join(format!("{safe_name}.json")), pretty)
            .context("failed to write timestamped history snapshot")?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) struct HistoryMetric {
    pub(crate) key: &'static str,
    pub(crate) label: &'static str,
    pub(crate) path: &'static [&'static str],
    pub(crate) baseline: u64,
}

pub(crate) fn history_metrics() -> Vec<HistoryMetric> {
    vec![
        HistoryMetric {
            key: "risk_score",
            label: "Risk Score",
            path: &["executive_snapshot", "score"],
            baseline: 100,
        },
        HistoryMetric {
            key: "global_news",
            label: "Global News",
            path: &["stats", "global_news"],
            baseline: 30,
        },
        HistoryMetric {
            key: "writeups",
            label: "Writeup",
            path: &["stats", "writeups"],
            baseline: 20,
        },
        HistoryMetric {
            key: "poc_watch",
            label: "PoC Public Metadata",
            path: &["stats", "poc_watch"],
            baseline: 20,
        },
        HistoryMetric {
            key: "cves",
            label: "CVE",
            path: &["stats", "cves"],
            baseline: 20,
        },
        HistoryMetric {
            key: "critical_cves",
            label: "Critical CVE",
            path: &["stats", "critical_cves"],
            baseline: 10,
        },
        HistoryMetric {
            key: "epss_rising",
            label: "EPSS Rising",
            path: &["stats", "epss_rising"],
            baseline: 10,
        },
        HistoryMetric {
            key: "iocs",
            label: "IOC",
            path: &["stats", "iocs"],
            baseline: 50,
        },
        HistoryMetric {
            key: "botnet_c2",
            label: "Botnet C2",
            path: &["stats", "botnet_c2"],
            baseline: 20,
        },
        HistoryMetric {
            key: "malicious_tls",
            label: "Malicious TLS",
            path: &["stats", "malicious_tls"],
            baseline: 30,
        },
        HistoryMetric {
            key: "greynoise_malicious",
            label: "GreyNoise Malicious",
            path: &["stats", "greynoise_malicious"],
            baseline: 10,
        },
        HistoryMetric {
            key: "phishing_urls",
            label: "Phishing URLs",
            path: &["stats", "phishing_urls"],
            baseline: 50,
        },
        HistoryMetric {
            key: "ics_advisories",
            label: "ICS/OT Advisory",
            path: &["stats", "ics_advisories"],
            baseline: 20,
        },
        HistoryMetric {
            key: "ics_high",
            label: "ICS/OT High",
            path: &["stats", "ics_high"],
            baseline: 10,
        },
        HistoryMetric {
            key: "supply_chain_advisories",
            label: "Supply Chain",
            path: &["stats", "supply_chain_advisories"],
            baseline: 30,
        },
        HistoryMetric {
            key: "ransomware_victims",
            label: "Ransomware Claim",
            path: &["stats", "ransomware_victims"],
            baseline: 40,
        },
        HistoryMetric {
            key: "failed_rss_sources",
            label: "Failed RSS",
            path: &["stats", "failed_rss_sources"],
            baseline: 10,
        },
    ]
}

pub(crate) fn metric_value(value: &Value, path: &[&str]) -> i64 {
    path_value(value, path)
        .and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_u64().and_then(|v| i64::try_from(v).ok()))
        })
        .unwrap_or(0)
}

pub(crate) fn history_delta_level(key: &str, delta: i64) -> &'static str {
    if delta == 0 {
        return "watch";
    }
    match key {
        "failed_rss_sources" if delta > 0 => "medium",
        "risk_score"
        | "critical_cves"
        | "epss_rising"
        | "poc_watch"
        | "poc_watch_high"
        | "botnet_c2"
        | "malicious_tls"
        | "greynoise_malicious"
        | "phishing_urls"
        | "ics_high"
        | "ransomware_victims"
            if delta > 0 =>
        {
            "high"
        }
        _ if delta > 0 => "medium",
        _ => "low",
    }
}
