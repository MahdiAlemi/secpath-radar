//! Tehran-day accumulation state, run metadata, and top signals.

use crate::prelude::*;

pub(crate) const DAY_STATE_DIR: &str = "data/day_state";
pub(crate) const DAY_MAX_NEWS: usize = 60;
pub(crate) const DAY_MAX_CVES: usize = 2000;

pub(crate) fn tehran_offset() -> chrono::FixedOffset {
    chrono::FixedOffset::east_opt(3 * 3600 + 30 * 60).expect("tehran offset")
}

pub(crate) fn tehran_now() -> chrono::DateTime<chrono::FixedOffset> {
    Utc::now().with_timezone(&tehran_offset())
}

fn item_id(item: &Value, id_keys: &[&str]) -> Option<String> {
    for key in id_keys {
        if let Some(text) = item.get(*key).and_then(|v| v.as_str()) {
            let id = text.trim().to_lowercase();
            if !id.is_empty() {
                return Some(id);
            }
        }
    }
    None
}

pub(crate) fn merge_day_list(
    state: &Value,
    brief: &Value,
    list_key: &str,
    id_keys: &[&str],
    cap: usize,
    run_stamp: &str,
) -> Value {
    let empty: Vec<Value> = Vec::new();
    let old_items = state
        .get(list_key)
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let new_items = brief
        .get(list_key)
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let mut order: Vec<String> = Vec::new();
    let mut by_id: HashMap<String, Value> = HashMap::new();
    for item in old_items {
        if let Some(id) = item_id(item, id_keys) {
            if !by_id.contains_key(&id) {
                order.push(id.clone());
            }
            let mut kept = item.clone();
            kept["is_new"] = json!(false);
            by_id.insert(id, kept);
        }
    }
    for item in new_items {
        if let Some(id) = item_id(item, id_keys) {
            let mut fresh = item.clone();
            if let Some(previous) = by_id.get(&id) {
                fresh["first_seen"] = previous
                    .get("first_seen")
                    .cloned()
                    .unwrap_or_else(|| json!(run_stamp));
                fresh["is_new"] = json!(false);
            } else {
                order.push(id.clone());
                fresh["first_seen"] = json!(run_stamp);
                fresh["is_new"] = json!(true);
            }
            by_id.insert(id, fresh);
        }
    }
    let mut merged: Vec<Value> = order
        .into_iter()
        .filter_map(|id| by_id.remove(&id))
        .collect();
    merged.sort_by(|a, b| {
        let a_risk = a.get("risk_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let b_risk = b.get("risk_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        b_risk
            .partial_cmp(&a_risk)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    merged.truncate(cap);
    Value::Array(merged)
}

fn prune_state_cves_to_day(state: &mut Value, date: &str) {
    let Some(cves) = state.get_mut("cves").and_then(|v| v.as_array_mut()) else {
        return;
    };
    cves.retain(|cve| {
        cve.get("published")
            .and_then(|v| v.as_str())
            .and_then(|published| published.get(0..10))
            == Some(date)
    });
}

fn refresh_day_stats(brief: &mut Value) {
    let global = brief["global_news"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    let breaking = brief["breaking_news"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    let cves = brief["cves"].as_array().map(|a| a.len()).unwrap_or(0);
    let critical = brief["cves"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|c| {
                    c.get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_lowercase()
                        == "critical"
                })
                .count()
        })
        .unwrap_or(0);
    let kev = brief["cves"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|c| c.get("kev").and_then(|v| v.as_bool()).unwrap_or(false))
                .count()
        })
        .unwrap_or(0);
    if let Some(stats) = brief.get_mut("stats").and_then(|v| v.as_object_mut()) {
        stats.insert("global_news".to_string(), json!(global));
        stats.insert("breaking_news".to_string(), json!(breaking));
        stats.insert("daily_news".to_string(), json!(global + breaking));
        stats.insert("cves".to_string(), json!(cves));
        stats.insert("critical_cves".to_string(), json!(critical));
        stats.insert("kev".to_string(), json!(kev));
    }
}

pub(crate) fn apply_day_accumulation(brief: &mut Value) {
    let date = brief
        .get("date_en")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if date.len() != 10 {
        return;
    }
    let run_stamp = brief
        .get("generated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let state_path = std::path::Path::new(DAY_STATE_DIR).join(format!("{date}.json"));
    let mut state: Value = fs::read_to_string(&state_path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_else(|| json!({}));
    if state.get("date").and_then(|v| v.as_str()) != Some(date.as_str()) {
        state = json!({ "date": date.clone() });
    }
    prune_state_cves_to_day(&mut state, &date);
    let plans: [(&str, &[&str], usize); 3] = [
        ("breaking_news", &["url", "title"], DAY_MAX_NEWS),
        ("global_news", &["url", "title"], DAY_MAX_NEWS),
        ("cves", &["cve_id", "url"], DAY_MAX_CVES),
    ];
    for (list_key, id_keys, cap) in plans {
        let merged = merge_day_list(&state, brief, list_key, id_keys, cap, &run_stamp);
        state[list_key] = merged.clone();
        brief[list_key] = merged;
    }
    refresh_day_stats(brief);
    let runs = state.get("runs").and_then(|v| v.as_u64()).unwrap_or(0) + 1;
    state["runs"] = json!(runs);
    if state.get("first_run").is_none() {
        state["first_run"] = json!(run_stamp.clone());
    }
    state["updated_at"] = json!(run_stamp.clone());
    brief["day_runs"] = json!(runs);
    brief["day_first_run"] = state.get("first_run").cloned().unwrap_or(Value::Null);
    let _ = fs::create_dir_all(DAY_STATE_DIR);
    if let Ok(text) = serde_json::to_string(&state) {
        let _ = fs::write(&state_path, text);
    }
}

fn signal_level(risk: f64) -> &'static str {
    if risk >= 8.0 {
        "high"
    } else if risk >= 5.0 {
        "medium"
    } else {
        "watch"
    }
}

fn item_signal(item: &Value, fallback_title: &str, anchor: &str) -> Value {
    let risk = item
        .get("risk_score")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let title = item
        .get("cve_id")
        .or_else(|| item.get("title"))
        .and_then(|v| v.as_str())
        .unwrap_or(fallback_title);
    json!({
        "title": truncate_chars(title, 60),
        "metric": format!("risk {risk:.1}"),
        "level": signal_level(risk),
        "bar_width": ((risk * 10.0) as u64).clamp(8, 100),
        "anchor": anchor
    })
}

pub(crate) fn build_top_signals(brief: &Value) -> Value {
    let mut cards: Vec<Value> = Vec::new();
    if let Some(cve) = brief
        .get("cves")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        cards.push(item_signal(cve, "Top CVE", "#cves"));
    }
    if let Some(item) = brief
        .get("breaking_news")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        cards.push(item_signal(item, "Breaking News", "#breaking-news"));
    } else if let Some(item) = brief
        .get("global_news")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        cards.push(item_signal(item, "Top News", "#global-news"));
    }
    if let Some(row) = brief.pointer("/vendor_watchlist/rows/0") {
        let name = row
            .get("name")
            .or_else(|| row.get("vendor"))
            .and_then(|v| v.as_str())
            .unwrap_or("vendor");
        let cves_hits = row.get("cves").and_then(|v| v.as_u64()).unwrap_or(0);
        let news_hits = row.get("news").and_then(|v| v.as_u64()).unwrap_or(0);
        let metric = if cves_hits + news_hits > 0 {
            format!("{cves_hits} CVE · {news_hits} news")
        } else {
            row.get("count")
                .and_then(|v| v.as_str())
                .unwrap_or("—")
                .to_string()
        };
        cards.push(json!({
            "title": format!("Top Vendor: {name}"),
            "metric": metric,
            "level": row.get("level").and_then(|v| v.as_str()).unwrap_or("watch"),
            "bar_width": row.get("bar_width").cloned().unwrap_or(json!(40)),
            "anchor": "#vendor-watchlist"
        }));
    }
    if let Some(row) = brief.pointer("/attack_matrix/rows/0") {
        let technique = row.get("technique").and_then(|v| v.as_str()).unwrap_or("");
        let label = row.get("name").and_then(|v| v.as_str()).unwrap_or("ATT&CK");
        let hits = row.get("hits").and_then(|v| v.as_u64()).unwrap_or(0);
        let metric = if technique.is_empty() {
            format!("{hits} hits")
        } else {
            format!("{technique} · {hits} hits")
        };
        cards.push(json!({
            "title": format!("Dominant Attack Pattern: {label}"),
            "metric": metric,
            "level": "medium",
            "bar_width": row.get("bar_width").cloned().unwrap_or(json!(40)),
            "anchor": "#attack-matrix"
        }));
    }
    cards.truncate(5);
    Value::Array(cards)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_day_list_accumulates_and_marks_new_items() {
        let state = json!({
            "global_news": [
                { "url": "https://a.example/1", "title": "Old", "risk_score": 4.0, "first_seen": "2026-07-06 08:00", "is_new": true }
            ]
        });
        let brief = json!({
            "global_news": [
                { "url": "https://a.example/1", "title": "Old updated", "risk_score": 4.5 },
                { "url": "https://b.example/2", "title": "Brand new", "risk_score": 9.0 }
            ]
        });
        let merged = merge_day_list(
            &state,
            &brief,
            "global_news",
            &["url"],
            10,
            "2026-07-06 11:00",
        );
        let rows = merged.as_array().expect("array");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["url"], json!("https://b.example/2"));
        assert_eq!(rows[0]["is_new"], json!(true));
        assert_eq!(rows[0]["first_seen"], json!("2026-07-06 11:00"));
        assert_eq!(rows[1]["is_new"], json!(false));
        assert_eq!(rows[1]["first_seen"], json!("2026-07-06 08:00"));
        assert_eq!(rows[1]["title"], json!("Old updated"));
    }

    #[test]
    fn merge_day_list_respects_cap() {
        let state = json!({});
        let brief = json!({
            "cves": [
                { "cve_id": "CVE-1", "risk_score": 9.0 },
                { "cve_id": "CVE-2", "risk_score": 8.0 },
                { "cve_id": "CVE-3", "risk_score": 7.0 }
            ]
        });
        let merged = merge_day_list(&state, &brief, "cves", &["cve_id"], 2, "2026-07-06 08:00");
        assert_eq!(merged.as_array().map(|a| a.len()), Some(2));
    }

    #[test]
    fn build_top_signals_leads_with_top_cve() {
        let brief = json!({
            "cves": [ { "cve_id": "CVE-2026-1111", "title": "Example", "risk_score": 9.2 } ],
            "global_news": [ { "title": "Big news", "risk_score": 8.1 } ]
        });
        let cards = build_top_signals(&brief);
        let rows = cards.as_array().expect("array");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["title"], json!("CVE-2026-1111"));
        assert_eq!(rows[0]["anchor"], json!("#cves"));
        assert_eq!(rows[1]["anchor"], json!("#global-news"));
    }
}
