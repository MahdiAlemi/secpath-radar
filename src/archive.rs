//! Daily archive of compact brief digests used by the weekly summary page.

use crate::prelude::*;

pub(crate) const ARCHIVE_DIR: &str = "snapshots/archive";
pub(crate) const ARCHIVE_MAX_CVES: usize = 10;
pub(crate) const ARCHIVE_MAX_NEWS: usize = 12;

pub(crate) const CVE_ARCHIVE_KEYS: &[&str] = &[
    "cve_id",
    "title_fa",
    "title",
    "url",
    "severity",
    "cvss",
    "epss",
    "kev",
    "risk_score",
    "summary_fa",
    "recommended_action",
];

pub(crate) const NEWS_ARCHIVE_KEYS: &[&str] = &[
    "title_fa",
    "title",
    "url",
    "source",
    "risk_score",
    "published",
    "summary_fa",
    "iran_relevance",
    "category",
];

pub(crate) fn compact_item(item: &Value, keys: &[&str]) -> Value {
    let mut out = serde_json::Map::new();
    for key in keys {
        if let Some(value) = item.get(*key) {
            if !value.is_null() {
                out.insert((*key).to_string(), value.clone());
            }
        }
    }
    Value::Object(out)
}

pub(crate) fn compact_list(brief: &Value, key: &str, keys: &[&str], limit: usize) -> Value {
    let items = brief
        .get(key)
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .take(limit)
                .map(|item| compact_item(item, keys))
                .collect::<Vec<Value>>()
        })
        .unwrap_or_default();
    json!(items)
}

pub(crate) fn archive_date(brief: &Value) -> String {
    let raw = brief
        .get("generated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let date: String = raw.chars().take(10).collect();
    let dashes = date.chars().filter(|ch| *ch == '-').count();
    if date.len() == 10 && dashes == 2 {
        date
    } else {
        Utc::now().format("%Y-%m-%d").to_string()
    }
}

pub(crate) fn build_daily_archive(brief: &Value) -> Value {
    json!({
        "date": archive_date(brief),
        "version": brief.get("version").cloned().unwrap_or(Value::Null),
        "date_fa": brief.get("date_fa").cloned().unwrap_or(Value::Null),
        "generated_at": brief.get("generated_at").cloned().unwrap_or(Value::Null),
        "stats": brief.get("stats").cloned().unwrap_or_else(|| json!({})),
        "executive_snapshot": brief
            .get("executive_snapshot")
            .cloned()
            .unwrap_or_else(|| json!({})),
        "priority_alert": brief
            .get("priority_alert")
            .map(|alert| compact_item(alert, NEWS_ARCHIVE_KEYS))
            .unwrap_or(Value::Null),
        "cves": compact_list(brief, "cves", CVE_ARCHIVE_KEYS, ARCHIVE_MAX_CVES),
        "global_news": compact_list(brief, "global_news", NEWS_ARCHIVE_KEYS, ARCHIVE_MAX_NEWS),
        "iran_radar": compact_list(brief, "iran_radar", NEWS_ARCHIVE_KEYS, 6)
    })
}

pub(crate) fn write_daily_archive(brief: &Value) -> Result<()> {
    fs::create_dir_all(ARCHIVE_DIR).context("failed to create archive directory")?;
    let archive = build_daily_archive(brief);
    let date = archive
        .get("date")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let path = PathBuf::from(ARCHIVE_DIR).join(format!("{date}.json"));
    fs::write(&path, serde_json::to_string_pretty(&archive)?)
        .with_context(|| format!("failed to write daily archive: {}", path.display()))?;
    Ok(())
}

pub(crate) fn read_archive_series(dir: &str, max_days: usize) -> Vec<Value> {
    let mut archives: Vec<Value> = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return archives;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        let Ok(raw) = fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        if value.get("date").and_then(|v| v.as_str()).is_none() {
            continue;
        }
        archives.push(value);
    }
    archives.sort_by_key(|archive| {
        archive
            .get("date")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    });
    if archives.len() > max_days {
        let skip = archives.len() - max_days;
        archives.drain(0..skip);
    }
    archives
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_item_keeps_only_listed_keys() {
        let item = json!({
            "cve_id": "CVE-2026-0001",
            "url": "https://example.com/cve",
            "internal_debug": "drop me",
            "kev": true
        });
        let compact = compact_item(&item, CVE_ARCHIVE_KEYS);
        assert_eq!(compact["cve_id"], json!("CVE-2026-0001"));
        assert_eq!(compact["kev"], json!(true));
        assert!(compact.get("internal_debug").is_none());
    }

    #[test]
    fn archive_date_prefers_generated_at_prefix() {
        let brief = json!({ "generated_at": "2026-07-05 19:30" });
        assert_eq!(archive_date(&brief), "2026-07-05");
        let fallback = archive_date(&json!({ "generated_at": "garbage" }));
        assert_eq!(fallback.len(), 10);
    }
}
