//! RSS/news fetching, scoring, and classification.

use crate::prelude::*;

pub(crate) fn fetch_and_score(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<(Vec<FeedItem>, Vec<SourceFailure>, Vec<SourceFailure>)> {
    let (all, failures, stale_fallbacks) =
        fetch_source_group(config, &config.sources, offline, refresh_cache, false)?;

    let mut seen = HashSet::new();
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
    Ok((deduped, failures, stale_fallbacks))
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
) -> Result<(Vec<FeedItem>, Vec<SourceFailure>, Vec<SourceFailure>)> {
    if config.writeup_sources.is_empty() {
        return Ok((Vec::new(), Vec::new(), Vec::new()));
    }

    let (all, failures, stale_fallbacks) = fetch_source_group(
        config,
        &config.writeup_sources,
        offline,
        refresh_cache,
        true,
    )?;

    let mut seen = HashSet::new();
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
    Ok((deduped, failures, stale_fallbacks))
}

fn fetch_source_group(
    config: &Config,
    sources: &[SourceConfig],
    offline: bool,
    refresh_cache: bool,
    writeup_mode: bool,
) -> Result<(Vec<FeedItem>, Vec<SourceFailure>, Vec<SourceFailure>)> {
    let client = build_client(config)?;
    let mut all = Vec::new();
    let mut failures = Vec::new();
    let mut stale_fallbacks = Vec::new();
    let concurrency = config.fetch.max_concurrent_sources.max(1);

    for chunk in sources.chunks(concurrency) {
        let mut batch_results = Vec::with_capacity(chunk.len());

        thread::scope(|scope| {
            let mut handles = Vec::with_capacity(chunk.len());
            for source in chunk {
                if writeup_mode {
                    eprintln!("→ fetching writeups {}", source.name);
                } else {
                    eprintln!("→ fetching {}", source.name);
                }

                let worker_client = client.clone();
                handles.push((
                    source,
                    scope.spawn(move || {
                        fetch_source(&worker_client, source, config, offline, refresh_cache)
                    }),
                ));
            }

            for (source, handle) in handles {
                let result = match handle.join() {
                    Ok(result) => result,
                    Err(_) => Err(anyhow::anyhow!("source worker panicked")),
                };
                batch_results.push((source, result));
            }
        });

        for (source, result) in batch_results {
            match result {
                Ok((mut items, stale_fallback)) => {
                    if let Some(issue) = stale_fallback {
                        stale_fallbacks.push(issue);
                    }
                    if items.is_empty() {
                        if !writeup_mode && source.topic_mode == TopicMode::Mixed {
                            eprintln!(
                                "  ↳ no cybersecurity-relevant items in mixed feed {}",
                                source.name
                            );
                            continue;
                        }
                        failures.push(SourceFailure {
                            name: source.name.clone(),
                            url: source.url.clone(),
                            error: "feed parsed but contained no usable titled entries".to_string(),
                        });
                        continue;
                    }
                    if writeup_mode {
                        for item in &mut items {
                            push_tag(&mut item.tags, "Writeup Source".to_string());
                        }
                    }
                    all.append(&mut items);
                }
                Err(err) => {
                    let label = if writeup_mode {
                        "writeup source"
                    } else {
                        "source"
                    };
                    eprintln!("⚠️  skipped {label} {}: {err:#}", source.name);
                    failures.push(SourceFailure {
                        name: source.name.clone(),
                        url: source.url.clone(),
                        error: source_error_summary(&format!("{err:#}")),
                    });
                }
            }
        }

        if config.fetch.sleep_ms_between_sources > 0 {
            thread::sleep(Duration::from_millis(config.fetch.sleep_ms_between_sources));
        }
    }

    Ok((all, failures, stale_fallbacks))
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

fn validate_feed_payload(bytes: &[u8]) -> Result<()> {
    let feed = parser::parse(bytes).context("failed to parse RSS/Atom feed")?;
    let has_titled_entry = feed.entries.iter().any(|entry| {
        entry
            .title
            .as_ref()
            .map(|title| !clean_text(&title.content).is_empty())
            .unwrap_or(false)
    });

    if !has_titled_entry {
        anyhow::bail!("feed contained no usable titled entries");
    }

    Ok(())
}

pub(crate) fn fetch_source(
    client: &Client,
    source: &SourceConfig,
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<(Vec<FeedItem>, Option<SourceFailure>)> {
    let cached = get_bytes_cached_validated(
        client,
        config,
        &source.url,
        &[],
        &format!("RSS {}", source.name),
        offline,
        refresh_cache,
        validate_feed_payload,
    )?;

    let stale_fallback = cached.stale_fallback_reason.map(|error| SourceFailure {
        name: source.name.clone(),
        url: source.url.clone(),
        error: source_error_summary(&error),
    });

    let feed = parser::parse(&cached.bytes[..]).context("failed to parse RSS/Atom feed")?;
    let mut out = Vec::new();
    let mut filtered_irrelevant = 0usize;

    for entry in feed.entries.iter().take(config.fetch.max_items_per_source) {
        let title = entry
            .title
            .as_ref()
            .map(|title| clean_text(&title.content))
            .unwrap_or_default();
        if title.is_empty() {
            continue;
        }

        let url = entry
            .links
            .iter()
            .find_map(|link| validated_http_url(&link.href))
            .or_else(|| validated_http_url(&source.url))
            .unwrap_or_default();

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
        if source.topic_mode == TopicMode::Mixed && !is_security_relevant(&item, config) {
            filtered_irrelevant += 1;
            continue;
        }
        out.push(item);
    }

    if filtered_irrelevant > 0 {
        eprintln!(
            "  ↳ filtered {filtered_irrelevant} non-security item(s) from mixed feed {}",
            source.name
        );
    }

    Ok((out, stale_fallback))
}

pub(crate) fn is_security_relevant(item: &FeedItem, config: &Config) -> bool {
    is_security_relevant_fields(&item.title, &item.summary, &item.category, config)
}

pub(crate) fn is_security_relevant_fields(
    title: &str,
    summary: &str,
    _category: &str,
    config: &Config,
) -> bool {
    let haystack = format!("{title} {summary}").to_lowercase();
    config
        .filters
        .relevance_keywords
        .iter()
        .any(|keyword| contains_relevance_keyword(&haystack, keyword))
}

fn contains_relevance_keyword(haystack: &str, keyword: &str) -> bool {
    let keyword = keyword.trim().to_lowercase();
    if keyword.is_empty() {
        return false;
    }

    if keyword.chars().all(|ch| ch.is_ascii_alphanumeric()) && keyword.len() <= 3 {
        return haystack.match_indices(&keyword).any(|(start, _)| {
            let before = haystack[..start].chars().next_back();
            let end = start + keyword.len();
            let after = haystack[end..].chars().next();

            before.is_none_or(|ch| !ch.is_ascii_alphanumeric())
                && after.is_none_or(|ch| !ch.is_ascii_alphanumeric())
        });
    }

    haystack.contains(&keyword)
}

pub(crate) fn validated_http_url(raw: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(raw.trim()).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return None;
    }
    Some(parsed.to_string())
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
    fn feed_validation_rejects_html_and_empty_feeds() {
        assert!(validate_feed_payload(b"<html><body>challenge</body></html>").is_err());
        assert!(validate_feed_payload(
            br#"<?xml version="1.0"?><rss version="2.0"><channel><title>Empty</title></channel></rss>"#,
        )
        .is_err());
    }

    #[test]
    fn feed_validation_accepts_a_titled_rss_item() {
        let feed = br#"<?xml version="1.0" encoding="UTF-8"?>
            <rss version="2.0">
              <channel>
                <title>Example</title>
                <link>https://example.test/</link>
                <description>Example feed</description>
                <item>
                  <title>Security update</title>
                  <link>https://example.test/security-update</link>
                  <description>Details</description>
                </item>
              </channel>
            </rss>"#;
        assert!(validate_feed_payload(feed).is_ok());
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
    #[test]
    fn mixed_feed_relevance_rejects_general_technology_and_keeps_security() {
        let config = load_config(&PathBuf::from("config.yaml")).expect("valid config");

        let mut general = feed_item(
            "Scientists solve mystery of unusual distant star",
            "2026-07-11T10:00:00+00:00",
            1,
        );
        general.summary = "Astronomers published new observations.".to_string();
        classify_and_score(&mut general, &config);
        assert!(!is_security_relevant(&general, &config));

        let mut legal = feed_item(
            "Apple sues AI company over alleged trade secrets",
            "2026-07-11T10:00:00+00:00",
            1,
        );
        legal.summary = "The companies are involved in an employment dispute.".to_string();
        classify_and_score(&mut legal, &config);
        assert!(!is_security_relevant(&legal, &config));

        let mut security = feed_item(
            "Critical browser vulnerability enables remote code execution",
            "2026-07-11T10:00:00+00:00",
            1,
        );
        security.summary = "Users should install the security update.".to_string();
        classify_and_score(&mut security, &config);
        assert!(is_security_relevant(&security, &config));

        let mut ai_security = feed_item(
            "Prompt injection lets attackers compromise AI agents",
            "2026-07-11T10:00:00+00:00",
            1,
        );
        ai_security.summary = "The exploit can expose credentials.".to_string();
        classify_and_score(&mut ai_security, &config);
        assert!(is_security_relevant(&ai_security, &config));
    }

    #[test]
    fn short_relevance_keywords_require_word_boundaries() {
        assert!(contains_relevance_keyword(
            "apt campaign targets routers",
            "apt"
        ));
        assert!(!contains_relevance_keyword(
            "company adapts its strategy",
            "apt"
        ));
        assert!(contains_relevance_keyword(
            "stored xss vulnerability",
            "xss"
        ));
        assert!(!contains_relevance_keyword("css update released", "xss"));
    }
}
