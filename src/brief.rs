//! Brief assembly: news lanes, priority, and top-level JSON structure.

use crate::prelude::*;

pub(crate) fn build_brief(
    config: &Config,
    items: Vec<FeedItem>,
    writeup_items: Vec<FeedItem>,
    mut cves: Vec<CveItem>,
) -> Result<Value> {
    let now = tehran_now();
    let date_en = format!("{}-{:02}-{:02}", now.year(), now.month(), now.day());
    let generated_at = now.format("%Y-%m-%d %H:%M").to_string();

    let requested_news_day = now.date_naive();
    let mut current_day_items: Vec<_> = items
        .iter()
        .filter(|item| feed_item_is_local_day(item, requested_news_day))
        .cloned()
        .collect();
    sort_news_latest_first(&mut current_day_items);
    let current_day_news_total = current_day_items.len();

    let fallback_cutoff = now.timestamp().saturating_sub(
        config
            .fetch
            .news_fallback_hours
            .saturating_mul(60)
            .saturating_mul(60) as i64,
    );
    let (mut visible_news, news_window_mode, backfill_news_total, stale_news_fallback) =
        if !current_day_items.is_empty() {
            (current_day_items, "local-day-only", 0usize, false)
        } else {
            let mut recent: Vec<_> = items
                .iter()
                .filter(|item| {
                    let timestamp = feed_item_timestamp(item);
                    timestamp >= fallback_cutoff
                        && timestamp <= now.timestamp().saturating_add(7200)
                })
                .cloned()
                .collect();
            sort_news_latest_first(&mut recent);

            if !recent.is_empty() {
                let count = recent.len();
                (recent, "rolling-fallback", count, false)
            } else {
                let mut latest = items.clone();
                sort_news_latest_first(&mut latest);
                latest.truncate(config.fetch.max_total_items.min(50));
                let count = latest.len();
                (latest, "latest-available-fallback", count, count > 0)
            }
        };

    visible_news.truncate(config.fetch.max_total_items.min(100));
    let effective_news_date = visible_news
        .first()
        .and_then(parse_feed_item_local_time)
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| date_en.clone());

    let mut breaking_news: Vec<_> = visible_news
        .iter()
        .filter(|item| is_breaking_news_item(item))
        .cloned()
        .collect();
    sort_breaking_news(&mut breaking_news);
    breaking_news.truncate(5);
    let breaking_keys: HashSet<String> = breaking_news.iter().map(news_dedupe_key).collect();

    let mut global: Vec<_> = visible_news
        .iter()
        .filter(|item| !breaking_keys.contains(&news_dedupe_key(item)))
        .cloned()
        .collect();
    sort_news_latest_first(&mut global);
    let today_news = visible_news.clone();
    let daily_news_total = visible_news.len();
    let daily_news_hidden = items.len().saturating_sub(daily_news_total);
    let news_lanes = build_news_lanes(&global);
    let writeups_pulse = build_writeups_pulse(&writeup_items, requested_news_day, &date_en);
    let writeups_total = writeups_pulse
        .get("totals")
        .and_then(|value| value.get("writeups"))
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let writeup_sources = writeups_pulse
        .get("totals")
        .and_then(|value| value.get("sources"))
        .and_then(|value| value.as_u64())
        .unwrap_or(0);

    // The vulnerability panel is intentionally strict: show only CVEs published on the
    // dashboard date. Do not backfill older CVEs here; an empty current-day set should
    // render as an explicit empty state.
    let fetched_cve_count = cves.len();
    retain_cves_published_on_day(&mut cves, &date_en);
    let other_day_cve_count = fetched_cve_count.saturating_sub(cves.len());
    cves.sort_by(|a, b| {
        b.risk_score.cmp(&a.risk_score).then_with(|| {
            b.cvss
                .partial_cmp(&a.cvss)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });

    let news_priority = breaking_news
        .iter()
        .chain(global.iter())
        .max_by_key(|item| item.risk_score);
    let cve_priority = cves.iter().max_by_key(|c| c.risk_score);

    let priority = match (news_priority, cve_priority) {
        (Some(news), Some(cve)) if cve.risk_score >= news.risk_score => priority_from_cve(cve),
        (Some(news), _) => priority_from_item(news),
        (None, Some(cve)) => priority_from_cve(cve),
        (None, None) => empty_priority(),
    };

    let risk_level = match priority["risk_score"].as_i64().unwrap_or(1) {
        8..=10 => "High",
        5..=7 => "Medium",
        _ => "Low",
    };

    let cve_count = cves.len();
    let critical_count = cves
        .iter()
        .filter(|c| c.severity == "CRITICAL" || c.cvss >= 9.0)
        .count();
    let kev_count = cves.iter().filter(|c| c.kev).count();
    let epss_tracked = cves
        .iter()
        .filter(|c| c.epss > 0.0 || c.epss_percentile > 0.0)
        .count();
    let epss_rising_count = cves.iter().filter(|c| c.epss_momentum == "rising").count();
    let epss_stable_count = cves.iter().filter(|c| c.epss_momentum == "stable").count();
    let epss_falling_count = cves.iter().filter(|c| c.epss_momentum == "falling").count();
    let vulnrichment_checked = cve_count.min(config.cve.max_vulnrichment);
    let vulnrichment_hits = cves.iter().filter(|c| c.cisa_vulnrichment).count();
    let vulnrichment_missing = vulnrichment_checked.saturating_sub(vulnrichment_hits);

    Ok(json!({
        "site_title": config.site.title,
        "site_github": config.site.github.clone(),
        "date_en": date_en.clone(),
        "risk_level": risk_level,
        "generated_at": generated_at,
        "stats": {
            "total_items": items.len() + cve_count,
            "global_news": global.len(),
            "breaking_news": breaking_news.len(),
            "daily_news": daily_news_total,
            "current_day_news": current_day_news_total,
            "news_backfill": backfill_news_total,
            "daily_news_hidden": daily_news_hidden,
            "rss_items_fetched": items.len(),
            "writeups": writeups_total,
            "writeup_sources": writeup_sources,
            "poc_watch": 0,
            "poc_watch_high": 0,
            "poc_watch_cves": 0,
            "cves": cve_count,
            "critical_cves": critical_count,
            "kev": kev_count,
            "epss_tracked": epss_tracked,
            "epss_rising": epss_rising_count,
            "epss_stable": epss_stable_count,
            "epss_falling": epss_falling_count,
            "vulnrichment_checked": vulnrichment_checked,
            "vulnrichment_hits": vulnrichment_hits,
            "vulnrichment_missing": vulnrichment_missing,
            "cves_fetched_before_day_filter": fetched_cve_count,
            "cves_filtered_other_days": other_day_cve_count,
            "botnet_c2": 0,
            "malicious_tls": 0,
            "greynoise_noise": 0,
            "greynoise_malicious": 0,
            "greynoise_riot": 0,
            "phishing_urls": 0,
            "phishing_high": 0,
            "phishing_tlds": 0,
            "ics_advisories": 0,
            "ics_high": 0,
            "ics_vendors": 0,
            "nuclei_covered_cves": 0,
            "nuclei_coverage_pct": 0,
            "rss_sources": config.sources.len(),
            "intel_sources": intel_source_count(config)
        },
        "source_health": {
            "rss_sources": config.sources.len(),
            "source_names": config.sources.iter().map(|source| source.name.clone()).collect::<Vec<_>>(),
            "failed_rss_sources": 0,
            "rss_failures": [],
            "stale_rss_sources": 0,
            "rss_stale_fallbacks": [],
            "degraded_rss_sources": 0,
            "stale_writeup_sources": 0,
            "writeup_stale_fallbacks": [],
            "degraded_writeup_sources": 0,
            "http_cache": config.cache.enabled,
            "cache_ttl_minutes": config.cache.ttl_minutes,
            "ai_cache_dir": config.gemini.cache_dir.clone(),
            "intel_sources": intel_source_count(config),
            "intel_cache_dir": config.intel.cache_dir.clone()
        },
        "priority_alert": priority,
        "cve_window": {
            "mode": "published-day-only",
            "date": date_en.clone(),
            "fetched_before_day_filter": fetched_cve_count,
            "filtered_other_days": other_day_cve_count,
            "empty_message": format!("No CVEs were published for {date_en}.")
        },
        "news_window": {
            "mode": news_window_mode,
            "date": effective_news_date,
            "requested_date": date_en.clone(),
            "start": if news_window_mode == "local-day-only" { "00:00" } else { "rolling" },
            "end": if news_window_mode == "local-day-only" { "23:59" } else { "now" },
            "timezone": now.format("%:z").to_string(),
            "fallback_hours": config.fetch.news_fallback_hours,
            "fallback_used": news_window_mode != "local-day-only",
            "stale_fallback": stale_news_fallback,
            "display_label": if news_window_mode == "local-day-only" {
                "Today's News"
            } else if news_window_mode == "rolling-fallback" {
                "Latest News"
            } else {
                "Latest Available News"
            },
            "rss_items_fetched": items.len(),
            "daily_news": daily_news_total,
            "current_day_news": current_day_news_total,
            "backfill_news": backfill_news_total,
            "hidden_old_or_undated": daily_news_hidden
        },
        "breaking_news": breaking_news,
        "global_news": global,
        "today_news": today_news,
        "news_lanes": news_lanes,
        "writeups_pulse": writeups_pulse,
        "cves": cves
    }))
}

pub(crate) fn parse_feed_item_local_time(
    item: &FeedItem,
) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    if item.published.trim().is_empty() {
        return None;
    }

    chrono::DateTime::parse_from_rfc3339(&item.published)
        .map(|dt| dt.with_timezone(&tehran_offset()))
        .ok()
}

pub(crate) fn feed_item_is_local_day(item: &FeedItem, day: NaiveDate) -> bool {
    parse_feed_item_local_time(item)
        .map(|dt| dt.date_naive() == day)
        .unwrap_or(false)
}

pub(crate) fn feed_item_timestamp(item: &FeedItem) -> i64 {
    parse_feed_item_local_time(item)
        .map(|dt| dt.timestamp())
        .unwrap_or(0)
}

pub(crate) fn sort_news_latest_first(items: &mut [FeedItem]) {
    items.sort_by(|a, b| {
        feed_item_timestamp(b)
            .cmp(&feed_item_timestamp(a))
            .then_with(|| b.risk_score.cmp(&a.risk_score))
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.title.cmp(&b.title))
    });
}

pub(crate) fn sort_breaking_news(items: &mut [FeedItem]) {
    items.sort_by(|a, b| {
        b.risk_score
            .cmp(&a.risk_score)
            .then_with(|| feed_item_timestamp(b).cmp(&feed_item_timestamp(a)))
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.title.cmp(&b.title))
    });
}

pub(crate) fn news_dedupe_key(item: &FeedItem) -> String {
    if !item.url.trim().is_empty() {
        item.url.trim().to_ascii_lowercase()
    } else {
        format!(
            "{}::{}",
            item.source.to_ascii_lowercase(),
            item.title.to_ascii_lowercase()
        )
    }
}

pub(crate) fn is_breaking_news_item(item: &FeedItem) -> bool {
    if item.risk_score >= 8 {
        return true;
    }
    if matches!(
        item.category.as_str(),
        "active_exploitation" | "malware_incident"
    ) && item.risk_score >= 6
    {
        return true;
    }

    let haystack = format!(
        "{} {} {}",
        item.title.to_ascii_lowercase(),
        item.summary.to_ascii_lowercase(),
        item.tags.join(" ").to_ascii_lowercase()
    );
    [
        "zero-day",
        "0-day",
        "actively exploited",
        "exploited in the wild",
        "mass exploitation",
        "ransomware",
        "critical vulnerability",
        "emergency patch",
        "data breach",
    ]
    .iter()
    .any(|needle| haystack.contains(needle))
}

pub(crate) fn news_time_display_fields(published: &str) -> (String, String, String) {
    let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(published) else {
        return ("".to_string(), "".to_string(), "unknown time".to_string());
    };
    let local = parsed.with_timezone(&tehran_offset());
    let date = local.format("%Y-%m-%d").to_string();
    let time = local.format("%H:%M").to_string();
    let label = if local.date_naive() == tehran_now().date_naive() {
        format!("Today {time}")
    } else {
        format!("{date} {time}")
    };
    (date, time, label)
}

pub(crate) fn build_news_lanes(global: &[FeedItem]) -> Value {
    let mut active_exploitation = Vec::new();
    let mut vulnerabilities = Vec::new();
    let mut malware_incidents = Vec::new();
    let mut ai_security = Vec::new();
    let mut general = Vec::new();

    for item in global {
        match item.category.as_str() {
            "active_exploitation" => active_exploitation.push(item.clone()),
            "vulnerability" => vulnerabilities.push(item.clone()),
            "malware_incident" => malware_incidents.push(item.clone()),
            "ai_security" => ai_security.push(item.clone()),
            _ => general.push(item.clone()),
        }
    }

    json!({
        "active_exploitation": active_exploitation.into_iter().take(6).collect::<Vec<_>>(),
        "vulnerabilities": vulnerabilities.into_iter().take(6).collect::<Vec<_>>(),
        "malware_incidents": malware_incidents.into_iter().take(6).collect::<Vec<_>>(),
        "ai_security": ai_security.into_iter().take(6).collect::<Vec<_>>(),
        "general": general.into_iter().take(8).collect::<Vec<_>>()
    })
}

pub(crate) fn count_chart(mut counts: HashMap<String, usize>, limit: usize) -> Vec<Value> {
    let mut rows = counts.drain().collect::<Vec<_>>();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let max = rows
        .iter()
        .map(|(_, count)| *count)
        .max()
        .unwrap_or(1)
        .max(1);
    rows.into_iter()
        .take(limit)
        .map(|(name, count)| {
            let width = ((count as f64 / max as f64) * 100.0).round() as usize;
            json!({
                "name": truncate_chars(&name, 42),
                "count": count,
                "bar_width": width.clamp(12, 100)
            })
        })
        .collect()
}

pub(crate) fn priority_from_item(item: &FeedItem) -> Value {
    json!({
        "title": item.title.clone(),
        "summary": item.summary.clone(),
        "source": item.source.clone(),
        "url": item.url.clone(),
        "risk_score": item.risk_score,
        "tags": item.tags
    })
}

pub(crate) fn priority_from_cve(cve: &CveItem) -> Value {
    json!({
        "title": format!("{} — {}", cve.cve_id, cve.title),
        "summary": cve.summary,
        "source": "NVD / CISA KEV / EPSS",
        "url": cve.url,
        "risk_score": cve.risk_score,
        "tags": cve.tags
    })
}

pub(crate) fn empty_priority() -> Value {
    json!({
        "title": "No items available yet",
        "summary": "RSS feeds or internet were not available. Site output was generated, but no real data was received.",
        "source": "SecPath Radar Local",
        "url": "#",
        "risk_score": 1,
        "tags": ["No Data"]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_item(published: String) -> FeedItem {
        FeedItem {
            title: "Recent security advisory".to_string(),
            summary: "A defensive security update".to_string(),
            source: "Test Feed".to_string(),
            url: "https://example.test/advisory".to_string(),
            published,
            risk_score: 4,
            category: "vulnerability".to_string(),
            tags: vec!["Vulnerability".to_string()],
        }
    }

    #[test]
    fn previous_day_items_use_the_rolling_fallback_instead_of_empty_news() {
        let config = load_config(&PathBuf::from("config.yaml")).expect("config");
        let published = (tehran_now() - ChronoDuration::hours(25)).to_rfc3339();
        let brief = build_brief(&config, vec![feed_item(published)], Vec::new(), Vec::new())
            .expect("brief");

        assert_eq!(brief["news_window"]["mode"], json!("rolling-fallback"));
        assert_eq!(brief["news_window"]["fallback_used"], json!(true));
        assert_eq!(brief["today_news"].as_array().map(Vec::len), Some(1));
    }
}
