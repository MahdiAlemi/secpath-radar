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
                "label_fa": metric.label_fa,
                "before": previous_value,
                "after": current,
                "delta": delta,
                "direction": direction,
                "level": level,
                "bar_width": relative_width(delta.unsigned_abs(), metric.baseline),
                "note_fa": history_delta_note(metric.label_fa, delta)
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

    let summary_fa = if previous.is_none() {
        "برای مقایسه با اجرای قبل هنوز snapshot قبلی در دسترس نبود؛ از اجرای بعدی تغییرات روزانه نمایش داده می‌شود.".to_string()
    } else if changed == 0 {
        "در مقایسه با اجرای قبلی، تغییر معناداری در شاخص‌های اصلی دیده نشد.".to_string()
    } else {
        format!(
            "نسبت به اجرای قبلی، {changed} شاخص تغییر کرده؛ {increased} مورد افزایش و {decreased} مورد کاهش داشته است."
        )
    };

    brief["stats"]["history_changes"] = json!(changed);
    brief["history_snapshot"] = json!({
        "enabled": true,
        "generated_at": generated_at,
        "previous_available": previous.is_some(),
        "previous_version": previous_version,
        "current_version": brief.get("version").and_then(|v| v.as_str()).unwrap_or("unknown"),
        "summary_fa": summary_fa,
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

pub(crate) fn write_history_snapshot(brief: &Value) -> Result<()> {
    let history_dir = PathBuf::from("snapshots/history");
    fs::create_dir_all(&history_dir).context("failed to create snapshots/history")?;
    let generated_at = brief
        .get("history_snapshot")
        .and_then(|value| value.get("generated_at"))
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let safe_name = generated_at
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    let snapshot = json!({
        "version": brief.get("version").cloned().unwrap_or_else(|| json!("unknown")),
        "date_fa": brief.get("date_fa").cloned().unwrap_or_else(|| json!("")),
        "generated_at": generated_at,
        "stats": brief.get("stats").cloned().unwrap_or_else(|| json!({})),
        "executive_snapshot": brief.get("executive_snapshot").cloned().unwrap_or_else(|| json!({})),
        "history_snapshot": brief.get("history_snapshot").cloned().unwrap_or_else(|| json!({}))
    });
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
    pub(crate) label_fa: &'static str,
    pub(crate) path: &'static [&'static str],
    pub(crate) baseline: u64,
}

pub(crate) fn history_metrics() -> Vec<HistoryMetric> {
    vec![
        HistoryMetric {
            key: "risk_score",
            label_fa: "امتیاز ریسک",
            path: &["executive_snapshot", "score"],
            baseline: 100,
        },
        HistoryMetric {
            key: "global_news",
            label_fa: "خبر جهانی",
            path: &["stats", "global_news"],
            baseline: 30,
        },
        HistoryMetric {
            key: "writeups",
            label_fa: "Writeup امنیتی",
            path: &["stats", "writeups"],
            baseline: 20,
        },
        HistoryMetric {
            key: "poc_watch",
            label_fa: "PoC public metadata",
            path: &["stats", "poc_watch"],
            baseline: 20,
        },
        HistoryMetric {
            key: "cves",
            label_fa: "CVE",
            path: &["stats", "cves"],
            baseline: 20,
        },
        HistoryMetric {
            key: "critical_cves",
            label_fa: "CVE بحرانی",
            path: &["stats", "critical_cves"],
            baseline: 10,
        },
        HistoryMetric {
            key: "epss_rising",
            label_fa: "EPSS رو به رشد",
            path: &["stats", "epss_rising"],
            baseline: 10,
        },
        HistoryMetric {
            key: "iocs",
            label_fa: "IOC",
            path: &["stats", "iocs"],
            baseline: 50,
        },
        HistoryMetric {
            key: "botnet_c2",
            label_fa: "Botnet C2",
            path: &["stats", "botnet_c2"],
            baseline: 20,
        },
        HistoryMetric {
            key: "malicious_tls",
            label_fa: "TLS بدخواه",
            path: &["stats", "malicious_tls"],
            baseline: 30,
        },
        HistoryMetric {
            key: "greynoise_malicious",
            label_fa: "GreyNoise malicious",
            path: &["stats", "greynoise_malicious"],
            baseline: 10,
        },
        HistoryMetric {
            key: "phishing_urls",
            label_fa: "URL فیشینگ",
            path: &["stats", "phishing_urls"],
            baseline: 50,
        },
        HistoryMetric {
            key: "ics_advisories",
            label_fa: "ICS/OT advisory",
            path: &["stats", "ics_advisories"],
            baseline: 20,
        },
        HistoryMetric {
            key: "ics_high",
            label_fa: "ICS/OT سطح بالا",
            path: &["stats", "ics_high"],
            baseline: 10,
        },
        HistoryMetric {
            key: "supply_chain_advisories",
            label_fa: "زنجیره تأمین",
            path: &["stats", "supply_chain_advisories"],
            baseline: 30,
        },
        HistoryMetric {
            key: "ransomware_victims",
            label_fa: "Ransomware claim",
            path: &["stats", "ransomware_victims"],
            baseline: 40,
        },
        HistoryMetric {
            key: "failed_rss_sources",
            label_fa: "RSS خطادار",
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

pub(crate) fn history_delta_note(label: &str, delta: i64) -> String {
    if delta > 0 {
        format!("{label} نسبت به اجرای قبل افزایش داشته است.")
    } else if delta < 0 {
        format!("{label} نسبت به اجرای قبل کاهش داشته است.")
    } else {
        format!("{label} نسبت به اجرای قبل ثابت مانده است.")
    }
}
