//! Trend Engine: multi-run metric trends built from local history snapshots.

use crate::prelude::*;

pub(crate) const TREND_MAX_RUNS: usize = 14;

pub(crate) fn build_trend_pulse(brief: &mut Value) {
    let mut snapshots = read_history_series("snapshots/history", TREND_MAX_RUNS);
    snapshots.push(build_history_snapshot_value(brief));
    snapshots.sort_by_key(snapshot_generated_at);
    if snapshots.len() > TREND_MAX_RUNS {
        let skip = snapshots.len() - TREND_MAX_RUNS;
        snapshots.drain(0..skip);
    }
    attach_trend_pulse(brief, &snapshots);
}

pub(crate) fn read_history_series(dir: &str, max_runs: usize) -> Vec<Value> {
    let mut snapshots: Vec<Value> = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return snapshots;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") || name == "latest_snapshot.json" {
            continue;
        }
        let Ok(raw) = fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        if value.get("generated_at").and_then(|v| v.as_str()).is_none() {
            continue;
        }
        snapshots.push(value);
    }
    snapshots.sort_by_key(snapshot_generated_at);
    if snapshots.len() > max_runs {
        let skip = snapshots.len() - max_runs;
        snapshots.drain(0..skip);
    }
    snapshots
}

pub(crate) fn snapshot_generated_at(snapshot: &Value) -> String {
    snapshot
        .get("generated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

pub(crate) fn snapshot_date(snapshot: &Value) -> String {
    snapshot_generated_at(snapshot).chars().take(10).collect()
}

pub(crate) fn attach_trend_pulse(brief: &mut Value, snapshots: &[Value]) {
    let runs = snapshots.len();
    brief["stats"]["trend_runs"] = json!(runs);
    if runs < 2 {
        brief["trend_pulse"] = json!({
            "enabled": true,
            "ok": false,
            "provider": "local history snapshots",
            "summary": "At least two runs are needed to plot trends; trends will appear from the next run.",
            "totals": { "runs": runs, "tracked": 0, "rising": 0, "falling": 0 }
        });
        return;
    }

    let mut rows: Vec<Value> = Vec::new();
    for metric in history_metrics() {
        let series: Vec<i64> = snapshots
            .iter()
            .map(|snapshot| metric_value(snapshot, metric.path))
            .collect();
        if series.iter().all(|value| *value == 0) {
            continue;
        }
        let first = *series.first().unwrap_or(&0);
        let last = *series.last().unwrap_or(&0);
        let peak = series.iter().copied().max().unwrap_or(0);
        let delta = last - first;
        let direction = if delta > 0 {
            "up"
        } else if delta < 0 {
            "down"
        } else {
            "flat"
        };
        rows.push(json!({
            "key": metric.key,
            "label": metric.label,
            "first": first,
            "last": last,
            "peak": peak,
            "delta": delta,
            "direction": direction,
            "level": history_delta_level(metric.key, delta),
            "spark": spark_points(&series),
            "bar_width": relative_width(delta.unsigned_abs(), metric.baseline)
        }));
    }

    rows.sort_by(|a, b| {
        let ad = a.get("delta").and_then(|v| v.as_i64()).unwrap_or(0).abs();
        let bd = b.get("delta").and_then(|v| v.as_i64()).unwrap_or(0).abs();
        bd.cmp(&ad)
    });

    let rising = rows
        .iter()
        .filter(|row| row.get("delta").and_then(|v| v.as_i64()).unwrap_or(0) > 0)
        .count() as u64;
    let falling = rows
        .iter()
        .filter(|row| row.get("delta").and_then(|v| v.as_i64()).unwrap_or(0) < 0)
        .count() as u64;
    let first_date = snapshot_date(&snapshots[0]);
    let last_date = snapshots.last().map(snapshot_date).unwrap_or_default();
    let span = if first_date == last_date {
        format!("Range: {first_date}")
    } else {
        format!("From {first_date} to {last_date}")
    };
    let summary = if rising == 0 && falling == 0 {
        format!("Across the last {runs} runs, key indicators remained largely stable.")
    } else {
        format!("Across the last {runs} runs, {rising} indicators showed an upward trend and {falling} showed a downward trend.")
    };

    brief["stats"]["trend_rising"] = json!(rising);
    brief["trend_pulse"] = json!({
        "enabled": true,
        "ok": true,
        "provider": "local history snapshots",
        "level": if rising >= 3 { "medium" } else { "info" },
        "summary": summary,
        "span": span,
        "totals": {
            "runs": runs,
            "tracked": rows.len(),
            "rising": rising,
            "falling": falling
        },
        "rows": rows
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(generated_at: &str, global_news: i64, cves: i64) -> Value {
        json!({
            "generated_at": generated_at,
            "stats": { "global_news": global_news, "cves": cves },
            "executive_snapshot": { "score": 0 }
        })
    }

    #[test]
    fn attach_trend_pulse_requires_two_snapshots() {
        let mut brief = json!({ "stats": {} });
        attach_trend_pulse(&mut brief, &[snapshot("2026-07-01T00:00:00Z", 3, 5)]);
        assert_eq!(brief["trend_pulse"]["ok"], json!(false));
        assert_eq!(brief["stats"]["trend_runs"], json!(1));
    }

    #[test]
    fn attach_trend_pulse_ranks_rows_by_absolute_delta() {
        let mut brief = json!({ "stats": {} });
        let snapshots = vec![
            snapshot("2026-07-01T00:00:00Z", 3, 5),
            snapshot("2026-07-02T00:00:00Z", 9, 4),
        ];
        attach_trend_pulse(&mut brief, &snapshots);
        assert_eq!(brief["trend_pulse"]["ok"], json!(true));
        let rows = brief["trend_pulse"]["rows"].as_array().expect("rows");
        assert_eq!(rows[0]["key"], json!("global_news"));
        assert_eq!(rows[0]["delta"], json!(6));
        assert_eq!(rows[0]["direction"], json!("up"));
        let cve_row = rows
            .iter()
            .find(|row| row.get("key") == Some(&json!("cves")))
            .expect("cve row");
        assert_eq!(cve_row["direction"], json!("down"));
    }
}

pub(crate) fn spark_points(series: &[i64]) -> String {
    let n = series.len();
    if n < 2 {
        return String::new();
    }
    let min = series.iter().copied().min().unwrap_or(0);
    let max = series.iter().copied().max().unwrap_or(0);
    let span = (max - min).max(1) as f64;
    let step = 100.0 / (n as f64 - 1.0);
    series
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let x = step * index as f64;
            let y = 25.0 - ((*value - min) as f64 / span) * 22.0;
            format!("{:.1},{:.1}", x, y)
        })
        .collect::<Vec<_>>()
        .join(" ")
}
