//! Tehran-day accumulation state, run metadata, and top signals.

use crate::prelude::*;

pub(crate) const DAY_STATE_DIR: &str = "data/day_state";
pub(crate) const DAY_MAX_NEWS: usize = 60;
pub(crate) const DAY_MAX_CVES: usize = 2000;

#[derive(Debug, Clone)]
pub(crate) struct PendingDayState {
    path: PathBuf,
    value: Value,
}

pub(crate) fn tehran_offset() -> chrono::FixedOffset {
    chrono::FixedOffset::east_opt(3 * 3600 + 30 * 60).expect("tehran offset")
}

pub(crate) fn tehran_now() -> chrono::DateTime<chrono::FixedOffset> {
    Utc::now().with_timezone(&tehran_offset())
}

pub(crate) fn tehran_date_for_timestamp(value: &str) -> Option<NaiveDate> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if let Ok(timestamp) = chrono::DateTime::parse_from_rfc3339(value) {
        return Some(timestamp.with_timezone(&tehran_offset()).date_naive());
    }

    value
        .get(0..10)
        .and_then(|date| NaiveDate::parse_from_str(date, "%Y-%m-%d").ok())
}

pub(crate) fn timestamp_is_tehran_day(value: &str, day: &str) -> bool {
    let Ok(day) = NaiveDate::parse_from_str(day, "%Y-%m-%d") else {
        return false;
    };
    tehran_date_for_timestamp(value) == Some(day)
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
            .map(|published| timestamp_is_tehran_day(published, date))
            .unwrap_or(false)
    });
}

fn prune_state_news_relevance(state: &mut Value, config: &Config) {
    for key in ["breaking_news", "global_news", "today_news"] {
        let Some(items) = state.get_mut(key).and_then(|value| value.as_array_mut()) else {
            continue;
        };
        items.retain(|item| {
            let source = item.get("source").and_then(Value::as_str).unwrap_or("");
            let topic_mode = config
                .sources
                .iter()
                .find(|candidate| candidate.name == source)
                .map(|candidate| candidate.topic_mode)
                .unwrap_or(TopicMode::Security);
            if topic_mode != TopicMode::Mixed {
                return true;
            }

            let title = item.get("title").and_then(Value::as_str).unwrap_or("");
            let summary = item.get("summary").and_then(Value::as_str).unwrap_or("");
            let category = item
                .get("category")
                .and_then(Value::as_str)
                .unwrap_or("general");
            is_security_relevant_fields(title, summary, category, config)
        });
    }
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
    let visible_news = brief["today_news"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(global + breaking);
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
        stats.insert("daily_news".to_string(), json!(visible_news));
        stats.insert("cves".to_string(), json!(cves));
        stats.insert("critical_cves".to_string(), json!(critical));
        stats.insert("kev".to_string(), json!(kev));
    }
    if brief
        .get("news_window")
        .and_then(|value| value.as_object())
        .is_some()
    {
        brief["news_window"]["daily_news"] = json!(visible_news);
        brief["news_window"]["current_day_news"] = json!(visible_news);
    }
}

pub(crate) fn apply_day_accumulation(
    brief: &mut Value,
    config: &Config,
) -> Result<Option<PendingDayState>> {
    let date = brief
        .get("date_en")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if date.len() != 10 {
        return Ok(None);
    }
    let run_stamp = brief
        .get("generated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let state_path = std::path::Path::new(DAY_STATE_DIR).join(format!("{date}.json"));
    let mut state: Value = match fs::read_to_string(&state_path) {
        Ok(text) => match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(err) => {
                eprintln!(
                    "⚠️  invalid day state {}; starting a clean state: {err}",
                    state_path.display()
                );
                json!({})
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to read day state: {}", state_path.display()))
        }
    };
    if state.get("date").and_then(|v| v.as_str()) != Some(date.as_str()) {
        state = json!({ "date": date.clone() });
    }
    prune_state_cves_to_day(&mut state, &date);
    prune_state_news_relevance(&mut state, config);

    let fallback_used = brief
        .get("news_window")
        .and_then(|value| value.get("fallback_used"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    if fallback_used {
        // Do not save older fallback stories as if they had been published today.
        // If this Tehran day already has accumulated same-day news, prefer that
        // state over an older rolling fallback from the current fetch.
        let saved_today = state
            .get("today_news")
            .and_then(|value| value.as_array())
            .map(|items| !items.is_empty())
            .unwrap_or(false);
        if saved_today {
            for key in ["breaking_news", "global_news", "today_news"] {
                if let Some(saved) = state.get(key).cloned() {
                    brief[key] = saved;
                }
            }
            brief["news_window"]["mode"] = json!("day-state-fallback");
            brief["news_window"]["date"] = json!(date.clone());
            brief["news_window"]["display_label"] = json!("Today's Accumulated News");
            brief["news_window"]["stale_fallback"] = json!(false);
        }
    } else {
        let news_plans: [(&str, &[&str], usize); 3] = [
            ("breaking_news", &["url", "title"], DAY_MAX_NEWS),
            ("global_news", &["url", "title"], DAY_MAX_NEWS),
            ("today_news", &["url", "title"], DAY_MAX_NEWS),
        ];
        for (list_key, id_keys, cap) in news_plans {
            let merged = merge_day_list(&state, brief, list_key, id_keys, cap, &run_stamp);
            state[list_key] = merged.clone();
            brief[list_key] = merged;
        }
    }

    let merged_cves = merge_day_list(
        &state,
        brief,
        "cves",
        &["cve_id", "url"],
        DAY_MAX_CVES,
        &run_stamp,
    );
    state["cves"] = merged_cves.clone();
    brief["cves"] = merged_cves;

    refresh_day_stats(brief);
    let runs = state.get("runs").and_then(|v| v.as_u64()).unwrap_or(0) + 1;
    state["runs"] = json!(runs);
    if state.get("first_run").is_none() {
        state["first_run"] = json!(run_stamp.clone());
    }
    state["updated_at"] = json!(run_stamp.clone());
    brief["day_runs"] = json!(runs);
    brief["day_first_run"] = state.get("first_run").cloned().unwrap_or(Value::Null);

    Ok(Some(PendingDayState {
        path: state_path,
        value: state,
    }))
}

pub(crate) fn persist_day_state(pending: &PendingDayState) -> Result<()> {
    fs::create_dir_all(DAY_STATE_DIR).context("failed to create day state directory")?;
    let text = serde_json::to_vec(&pending.value)?;
    let temp_path = pending
        .path
        .with_extension(format!("json.tmp-{}", std::process::id()));
    fs::write(&temp_path, text).with_context(|| {
        format!(
            "failed to write day state temp file: {}",
            temp_path.display()
        )
    })?;
    fs::rename(&temp_path, &pending.path).with_context(|| {
        format!(
            "failed to atomically replace day state: {}",
            pending.path.display()
        )
    })?;
    Ok(())
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
    #[test]
    fn day_state_prunes_irrelevant_items_from_mixed_sources() {
        let config = load_config(&PathBuf::from("config.yaml")).expect("valid config");
        let mut state = json!({
            "today_news": [
                {
                    "source": "gHacks",
                    "title": "Scientists solve mystery of unusual distant star",
                    "summary": "Astronomers published new observations.",
                    "category": "general"
                },
                {
                    "source": "gHacks",
                    "title": "Critical browser vulnerability fixed",
                    "summary": "Install the security update.",
                    "category": "vulnerability"
                }
            ]
        });

        prune_state_news_relevance(&mut state, &config);
        let items = state["today_news"].as_array().expect("news array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["title"], "Critical browser vulnerability fixed");
    }
}
