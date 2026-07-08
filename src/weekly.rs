//! Weekly digest built from daily archives, rendered to site/weekly.html.

use crate::prelude::*;

pub(crate) const WEEKLY_MAX_DAYS: usize = 7;
pub(crate) const WEEKLY_TOP_CVES: usize = 10;
pub(crate) const WEEKLY_TOP_NEWS: usize = 12;

pub(crate) fn item_risk(item: &Value) -> f64 {
    item.get("risk_score")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0)
}

pub(crate) fn dedup_top_items(
    archives: &[Value],
    list_key: &str,
    id_keys: &[&str],
    limit: usize,
) -> Vec<Value> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut items: Vec<Value> = Vec::new();
    for archive in archives.iter().rev() {
        let Some(list) = archive.get(list_key).and_then(|v| v.as_array()) else {
            continue;
        };
        for item in list {
            let mut id = String::new();
            for key in id_keys {
                if let Some(text) = item.get(*key).and_then(|v| v.as_str()) {
                    if !text.trim().is_empty() {
                        id = text.trim().to_lowercase();
                        break;
                    }
                }
            }
            if id.is_empty() || !seen.insert(id) {
                continue;
            }
            let mut entry = item.clone();
            if let Some(date) = archive.get("date").and_then(|v| v.as_str()) {
                entry["archived_on"] = json!(date);
            }
            items.push(entry);
        }
    }
    items.sort_by(|a, b| {
        item_risk(b)
            .partial_cmp(&item_risk(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    items.truncate(limit);
    items
}

pub(crate) fn ensure_item_defaults(item: &mut Value, text_keys: &[&str], number_keys: &[&str]) {
    for key in text_keys {
        if item.get(*key).and_then(|v| v.as_str()).is_none() {
            item[*key] = json!("");
        }
    }
    for key in number_keys {
        if item.get(*key).and_then(|v| v.as_f64()).is_none() {
            item[*key] = json!(0);
        }
    }
}

pub(crate) fn build_daily_rows(archives: &[Value]) -> Vec<Value> {
    let counts: Vec<i64> = archives
        .iter()
        .map(|archive| metric_value(archive, &["stats", "cves"]))
        .collect();
    let peak = counts.iter().copied().max().unwrap_or(0).max(1);
    archives
        .iter()
        .zip(counts.iter())
        .map(|(archive, cves)| {
            let date = archive.get("date").and_then(|v| v.as_str()).unwrap_or("");
            let label: String = if date.len() == 10 {
                date.chars().skip(5).collect()
            } else {
                date.to_string()
            };
            json!({
                "date": date,
                "label": label,
                "cves": cves,
                "news": metric_value(archive, &["stats", "global_news"]),
                "score": metric_value(archive, &["executive_snapshot", "score"]),
                "bar_width": ((cves * 100) / peak).clamp(4, 100)
            })
        })
        .collect()
}

pub(crate) fn build_weekly_brief(archives: &[Value]) -> Value {
    let days = archives.len();
    let mut top_cves = dedup_top_items(archives, "cves", &["cve_id", "url"], WEEKLY_TOP_CVES);
    let mut top_news = dedup_top_items(archives, "global_news", &["url", "title"], WEEKLY_TOP_NEWS);
    for cve in top_cves.iter_mut() {
        ensure_item_defaults(
            cve,
            &[
                "cve_id",
                "title",
                "url",
                "severity",
                "summary",
                "archived_on",
            ],
            &["risk_score", "cvss", "epss"],
        );
        if cve.get("kev").and_then(|v| v.as_bool()).is_none() {
            cve["kev"] = json!(false);
        }
    }
    for item in top_news.iter_mut() {
        ensure_item_defaults(
            item,
            &[
                "title",
                "url",
                "source",
                "summary",
                "archived_on",
                "published",
            ],
            &["risk_score"],
        );
    }
    let kev_count = top_cves
        .iter()
        .filter(|cve| cve.get("kev").and_then(|v| v.as_bool()).unwrap_or(false))
        .count();
    let total_cves: i64 = archives
        .iter()
        .map(|archive| metric_value(archive, &["stats", "cves"]))
        .sum();
    let total_news: i64 = archives
        .iter()
        .map(|archive| metric_value(archive, &["stats", "global_news"]))
        .sum();
    let first_date = archives
        .first()
        .and_then(|a| a.get("date").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();
    let last_date = archives
        .last()
        .and_then(|a| a.get("date").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();
    let span = if days == 0 {
        String::new()
    } else if first_date == last_date {
        format!("Range: {first_date}")
    } else {
        format!("From {first_date} to {last_date}")
    };
    let summary = if days == 0 {
        "No daily archives recorded yet; weekly summaries will be built from the next run.".to_string()
    } else {
        format!("Over the last {days} days, {total_cves} vulnerabilities and {total_news} selected news items were tracked; {kev_count} of the selected CVEs are in the Known Exploited Vulnerabilities (KEV) list.")
    };
    json!({
        "ok": days > 0,
        "site_title": "SecPath Radar",
        "version": archives
            .last()
            .and_then(|a| a.get("version"))
            .cloned()
            .unwrap_or_else(|| json!("unknown")),
        "generated_at": archives
            .last()
            .and_then(|a| a.get("generated_at"))
            .cloned()
            .unwrap_or_else(|| json!("")),
        "span": span,
        "summary": summary,
        "totals": {
            "days": days,
            "cves": total_cves,
            "news": total_news,
            "kev": kev_count,
            "unique_cves": top_cves.len()
        },
        "daily_rows": build_daily_rows(archives),
        "top_cves": top_cves,
        "top_news": top_news
    })
}

pub(crate) fn render_weekly_page(template_path: &PathBuf, out_path: &PathBuf) -> Result<()> {
    let weekly_template = template_path.with_file_name("weekly.html.j2");
    if !weekly_template.exists() {
        anyhow::bail!("weekly template not found: {}", weekly_template.display());
    }
    let archives = read_archive_series(ARCHIVE_DIR, WEEKLY_MAX_DAYS);
    let weekly = build_weekly_brief(&archives);
    let out = site_output_dir(out_path).join("weekly.html");
    render_html(&weekly, &weekly_template, &out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(date: &str, cve_id: &str, risk: f64) -> Value {
        json!({
            "date": date,
            "stats": { "cves": 5, "global_news": 8 },
            "executive_snapshot": { "score": 40 },
            "cves": [{ "cve_id": cve_id, "url": "https://example.com/x", "risk_score": risk, "kev": true }],
            "global_news": [{ "url": "https://example.com/news", "title": "n", "risk_score": 3 }]
        })
    }

    #[test]
    fn dedup_top_items_dedups_across_days_and_ranks_by_risk() {
        let archives = vec![
            day("2026-07-01", "CVE-2026-0001", 6.0),
            day("2026-07-02", "CVE-2026-0001", 7.0),
            day("2026-07-03", "CVE-2026-0002", 9.0),
        ];
        let items = dedup_top_items(&archives, "cves", &["cve_id", "url"], 10);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["cve_id"], json!("CVE-2026-0002"));
        assert_eq!(items[1]["archived_on"], json!("2026-07-02"));
    }

    #[test]
    fn build_weekly_brief_reports_totals_and_empty_state() {
        let empty = build_weekly_brief(&[]);
        assert_eq!(empty["ok"], json!(false));
        let brief = build_weekly_brief(&[day("2026-07-01", "CVE-2026-0001", 6.0)]);
        assert_eq!(brief["ok"], json!(true));
        assert_eq!(brief["totals"]["days"], json!(1));
        assert_eq!(brief["totals"]["kev"], json!(1));
        assert_eq!(brief["totals"]["cves"], json!(5));
        assert_eq!(brief["daily_rows"][0]["bar_width"], json!(100));
    }
}
