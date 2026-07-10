//! RSS/news fetching, scoring, and classification.

use crate::prelude::*;

pub(crate) fn fetch_and_score(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<(Vec<FeedItem>, Vec<SourceFailure>)> {
    let client = build_client(config)?;

    let mut seen = HashSet::new();
    let mut all = Vec::new();
    let mut failures = Vec::new();

    for source in &config.sources {
        eprintln!("→ fetching {}", source.name);

        match fetch_source(&client, source, config, offline, refresh_cache) {
            Ok(mut items) => all.append(&mut items),
            Err(err) => {
                eprintln!("⚠️  skipped {}: {err:#}", source.name);
                failures.push(SourceFailure {
                    name: source.name.clone(),
                    url: source.url.clone(),
                    error: source_error_summary(&err.to_string()),
                });
            }
        }

        thread::sleep(Duration::from_millis(config.fetch.sleep_ms_between_sources));
    }

    let mut deduped = Vec::new();
    for item in all {
        let key = normalize_key(&item.title, &item.url);
        if seen.insert(key) {
            deduped.push(item);
        }
    }

    let dashboard_day = tehran_now().date_naive();
    deduped = retain_current_day_before_cap(deduped, dashboard_day, config.fetch.max_total_items);
    let current_day_kept = deduped
        .iter()
        .filter(|item| feed_item_is_local_day(item, dashboard_day))
        .count();

    eprintln!(
        "✅ fetched+deduped RSS: {} items ({} for Tehran day {})",
        deduped.len(),
        current_day_kept,
        dashboard_day
    );
    Ok((deduped, failures))
}

/// Keep all available items for the current Tehran dashboard day before applying
/// the global RSS cap. Previously the feed pool was sorted only by risk and then
/// truncated, so fresh low-risk stories could be discarded in favor of older
/// high-risk stories before the daily filter ran.
pub(crate) fn retain_current_day_before_cap(
    items: Vec<FeedItem>,
    day: NaiveDate,
    cap: usize,
) -> Vec<FeedItem> {
    if cap == 0 {
        return Vec::new();
    }

    let (mut current_day, mut older_or_undated): (Vec<_>, Vec<_>) = items
        .into_iter()
        .partition(|item| feed_item_is_local_day(item, day));

    sort_news_latest_first(&mut current_day);
    older_or_undated.sort_by(|a, b| {
        b.risk_score
            .cmp(&a.risk_score)
            .then_with(|| feed_item_timestamp(b).cmp(&feed_item_timestamp(a)))
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.title.cmp(&b.title))
    });

    if current_day.len() >= cap {
        current_day.truncate(cap);
        return current_day;
    }

    let remaining = cap - current_day.len();
    current_day.extend(older_or_undated.into_iter().take(remaining));
    current_day
}

pub(crate) fn fetch_writeup_feeds(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<(Vec<FeedItem>, Vec<SourceFailure>)> {
    if config.writeup_sources.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let client = build_client(config)?;

    let mut seen = HashSet::new();
    let mut all = Vec::new();
    let mut failures = Vec::new();

    for source in &config.writeup_sources {
        eprintln!("→ fetching writeups {}", source.name);

        match fetch_source(&client, source, config, offline, refresh_cache) {
            Ok(mut items) => {
                for item in &mut items {
                    item.tags.push("Writeup Source".to_string());
                }
                all.append(&mut items)
            }
            Err(err) => {
                eprintln!("⚠️  skipped writeup source {}: {err:#}", source.name);
                failures.push(SourceFailure {
                    name: source.name.clone(),
                    url: source.url.clone(),
                    error: source_error_summary(&err.to_string()),
                });
            }
        }

        thread::sleep(Duration::from_millis(config.fetch.sleep_ms_between_sources));
    }

    let mut deduped = Vec::new();
    for item in all {
        let key = normalize_key(&item.title, &item.url);
        if seen.insert(key) {
            deduped.push(item);
        }
    }

    let deduped_before_quality_filter = deduped.len();
    deduped.retain(is_writeup_item);
    sort_news_latest_first(&mut deduped);

    let qualified_before_cap = deduped.len();
    let max_writeups = (config.fetch.max_total_items / 2).max(80).min(240);
    deduped.truncate(max_writeups);

    eprintln!(
        "✅ fetched+qualified writeup feeds: {} items ({} qualified before cap; {} deduped fetched) from {} sources",
        deduped.len(),
        qualified_before_cap,
        deduped_before_quality_filter,
        config.writeup_sources.len().saturating_sub(failures.len())
    );
    Ok((deduped, failures))
}

pub(crate) fn source_error_summary(error: &str) -> String {
    let compact = clean_text(error);
    truncate_chars(&compact, 160)
}

pub(crate) fn is_offline_cache_miss_error(error_text: &str) -> bool {
    error_text
        .to_ascii_lowercase()
        .contains("offline mode has no cached response")
}

pub(crate) fn fetch_source(
    client: &Client,
    source: &SourceConfig,
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<Vec<FeedItem>> {
    let bytes = get_bytes_cached(
        client,
        config,
        &source.url,
        &[],
        &format!("RSS {}", source.name),
        offline,
        refresh_cache,
    )?;

    let feed = parser::parse(&bytes[..]).context("failed to parse RSS/Atom feed")?;
    let mut out = Vec::new();

    for entry in feed.entries.iter().take(config.fetch.max_items_per_source) {
        let title = entry
            .title
            .as_ref()
            .map(|t| clean_text(&t.content))
            .unwrap_or_else(|| "Untitled".to_string());

        let url = entry
            .links
            .first()
            .map(|l| l.href.clone())
            .unwrap_or_else(|| source.url.clone());

        let summary = entry
            .summary
            .as_ref()
            .map(|s| clean_text(&s.content))
            .or_else(|| {
                entry
                    .content
                    .as_ref()
                    .and_then(|c| c.body.as_ref())
                    .map(|s| clean_text(s))
            })
            .unwrap_or_default();

        let published = entry
            .published
            .or(entry.updated)
            .map(|d| d.to_rfc3339())
            .unwrap_or_default();

        let mut item = FeedItem {
            title,
            summary: truncate_chars(&summary, 260),
            source: source.name.clone(),
            url,
            published,
            risk_score: 1,
            category: "general".to_string(),
            tags: Vec::new(),
        };

        classify_and_score(&mut item, config);
        out.push(item);
    }

    Ok(out)
}

pub(crate) fn classify_and_score(item: &mut FeedItem, config: &Config) {
    let haystack = format!("{} {} {}", item.title, item.summary, item.url).to_lowercase();

    let mut score = 1_i64;
    let mut tags = Vec::new();

    for kw in &config.filters.high_keywords {
        if haystack.contains(&kw.to_lowercase()) {
            score += 2;
            push_tag(&mut tags, keyword_tag(kw));
        }
    }

    for kw in &config.filters.low_keywords {
        if haystack.contains(&kw.to_lowercase()) {
            score -= 1;
        }
    }

    if haystack.contains("cve-") {
        score += 2;
        push_tag(&mut tags, "CVE".to_string());
    }
    if haystack.contains("zero-day") || haystack.contains("zeroday") {
        score += 3;
        push_tag(&mut tags, "Zero-day".to_string());
    }
    if haystack.contains("ransomware") {
        score += 3;
        push_tag(&mut tags, "Ransomware".to_string());
    }
    if haystack.contains("actively exploited") || haystack.contains("exploited in the wild") {
        score += 3;
        push_tag(&mut tags, "Active Exploit".to_string());
    }

    item.category = classify_news_category(&haystack).to_string();
    if item.category != "general" {
        push_tag(&mut tags, category_label(&item.category).to_string());
    }
    item.risk_score = score.clamp(1, 10);
    item.tags = tags.into_iter().take(5).collect();
}

pub(crate) fn classify_news_category(haystack: &str) -> &'static str {
    if haystack.contains("actively exploited")
        || haystack.contains("exploited in the wild")
        || haystack.contains("zero-day")
        || haystack.contains("zeroday")
        || haystack.contains("exploit")
    {
        "active_exploitation"
    } else if haystack.contains("cve-")
        || haystack.contains("vulnerability")
        || haystack.contains("patch")
        || haystack.contains("advisory")
    {
        "vulnerability"
    } else if haystack.contains("ransomware")
        || haystack.contains("malware")
        || haystack.contains("botnet")
        || haystack.contains("phishing")
        || haystack.contains("stealer")
    {
        "malware_incident"
    } else if haystack.contains(" ai ")
        || haystack.contains("artificial intelligence")
        || haystack.contains("llm")
        || haystack.contains("agentic")
    {
        "ai_security"
    } else {
        "general"
    }
}

pub(crate) fn category_label(category: &str) -> &'static str {
    match category {
        "active_exploitation" => "Active Exploit",
        "vulnerability" => "Vulnerability",
        "malware_incident" => "Malware/Incident",
        "ai_security" => "AI Security",
        _ => "General",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_item(title: &str, published: &str, risk_score: i64) -> FeedItem {
        FeedItem {
            title: title.to_string(),
            summary: String::new(),
            source: "test".to_string(),
            url: format!("https://example.test/{title}"),
            published: published.to_string(),
            risk_score,
            category: "general".to_string(),
            tags: Vec::new(),
        }
    }

    #[test]
    fn current_day_items_survive_global_cap_even_with_lower_risk() {
        let day = NaiveDate::from_ymd_opt(2026, 7, 10).expect("valid date");
        let items = vec![
            feed_item("old-critical", "2026-07-09T12:00:00+00:00", 10),
            feed_item("old-high", "2026-07-09T11:00:00+00:00", 9),
            feed_item("today-low", "2026-07-10T04:00:00+00:00", 1),
        ];

        let kept = retain_current_day_before_cap(items, day, 2);

        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].title, "today-low");
        assert!(kept.iter().any(|item| item.title == "old-critical"));
    }

    #[test]
    fn current_day_overflow_keeps_latest_items() {
        let day = NaiveDate::from_ymd_opt(2026, 7, 10).expect("valid date");
        let items = vec![
            feed_item("today-oldest", "2026-07-09T20:31:00+00:00", 10),
            feed_item("today-middle", "2026-07-10T01:00:00+00:00", 1),
            feed_item("today-latest", "2026-07-10T06:00:00+00:00", 1),
        ];

        let kept = retain_current_day_before_cap(items, day, 2);

        assert_eq!(
            kept.iter()
                .map(|item| item.title.as_str())
                .collect::<Vec<_>>(),
            vec!["today-latest", "today-middle"]
        );
    }
}
