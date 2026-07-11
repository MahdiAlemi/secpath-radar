//! Publication quality gates.
//!
//! A scheduled run must fail before the publish step when collection or output
//! is unusable. This preserves the last known-good radar-output branch instead
//! of replacing it with an empty but green build.

use crate::prelude::*;

fn array_len(value: &Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(|entry| entry.as_array())
        .map(|items| items.len())
        .unwrap_or(0)
}

pub(crate) fn validate_collected_brief(brief: &Value, config: &Config) -> Result<()> {
    let rss_items = path_u64(brief, &["stats", "rss_items_fetched"]) as usize;
    let visible_news = array_len(brief, "today_news");
    let source_count = config.sources.len();
    let failed_sources = path_u64(brief, &["source_health", "failed_rss_sources"]) as usize;
    let failure_percent = failed_sources
        .saturating_mul(100)
        .saturating_add(source_count.saturating_sub(1))
        / source_count.max(1);

    if rss_items < config.fetch.min_news_items_for_publish {
        anyhow::bail!(
            "quality gate: only {rss_items} RSS items were collected; minimum is {}",
            config.fetch.min_news_items_for_publish
        );
    }
    if visible_news < config.fetch.min_news_items_for_publish {
        anyhow::bail!(
            "quality gate: only {visible_news} usable news items are visible; minimum is {}",
            config.fetch.min_news_items_for_publish
        );
    }
    if failed_sources.saturating_mul(100)
        > config
            .fetch
            .max_source_failure_percent
            .saturating_mul(source_count.max(1))
    {
        anyhow::bail!(
            "quality gate: {failed_sources}/{source_count} RSS sources failed ({failure_percent}%); maximum is {}%",
            config.fetch.max_source_failure_percent
        );
    }

    let Some(items) = brief.get("today_news").and_then(|value| value.as_array()) else {
        anyhow::bail!("quality gate: today_news is missing or not an array");
    };
    for (index, item) in items.iter().enumerate() {
        let title = item
            .get("title")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .trim();
        let url = item
            .get("url")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .trim();
        if title.is_empty() {
            anyhow::bail!("quality gate: news item {index} has an empty title");
        }
        if validated_http_url(url).is_none() {
            anyhow::bail!("quality gate: news item {index} has an unsafe or invalid URL");
        }
    }

    let generated_at = brief
        .get("generated_at")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let generated = chrono::NaiveDateTime::parse_from_str(generated_at, "%Y-%m-%d %H:%M")
        .with_context(|| format!("quality gate: invalid generated_at {generated_at:?}"))?;
    let now = tehran_now().naive_local();
    let age_minutes = now.signed_duration_since(generated).num_minutes().abs();
    if age_minutes > 60 {
        anyhow::bail!(
            "quality gate: generated_at is {age_minutes} minutes away from current Tehran time"
        );
    }

    let expected_date = tehran_now().format("%Y-%m-%d").to_string();
    let brief_date = brief
        .get("date_en")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if brief_date != expected_date {
        anyhow::bail!(
            "quality gate: brief date {brief_date:?} does not match Tehran date {expected_date}"
        );
    }

    if let Some(cves) = brief.get("cves").and_then(|value| value.as_array()) {
        for (index, cve) in cves.iter().enumerate() {
            let published = cve
                .get("published")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            if !timestamp_is_tehran_day(published, brief_date) {
                anyhow::bail!(
                    "quality gate: CVE item {index} publication timestamp {published:?} is outside Tehran day {brief_date}"
                );
            }
        }
    }

    if let Some(repos) = brief
        .pointer("/poc_watch/repos")
        .and_then(|value| value.as_array())
    {
        for (index, repo) in repos.iter().enumerate() {
            let published = repo
                .get("published_at")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            if !timestamp_is_tehran_day(published, brief_date) {
                anyhow::bail!(
                    "quality gate: PoC item {index} publication timestamp {published:?} is outside Tehran day {brief_date}"
                );
            }
        }
    }

    Ok(())
}

fn require_nonempty_file(path: &PathBuf, minimum_bytes: u64) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("quality gate: missing output {}", path.display()))?;
    if metadata.len() < minimum_bytes {
        anyhow::bail!(
            "quality gate: output {} is too small ({} bytes; expected at least {minimum_bytes})",
            path.display(),
            metadata.len()
        );
    }
    Ok(())
}

pub(crate) fn validate_rendered_outputs(out_path: &PathBuf, config: &Config) -> Result<()> {
    let site_dir = site_output_dir(out_path);
    require_nonempty_file(out_path, 1024)?;
    require_nonempty_file(&site_dir.join("feed.xml"), 128)?;
    require_nonempty_file(&site_dir.join("api/brief.json"), 512)?;
    require_nonempty_file(&site_dir.join("api/summary.json"), 128)?;

    let raw = fs::read_to_string(site_dir.join("api/brief.json"))
        .context("quality gate: failed to read generated api/brief.json")?;
    let generated: Value = serde_json::from_str(&raw)
        .context("quality gate: generated api/brief.json is invalid JSON")?;
    validate_collected_brief(&generated, config)?;

    let html = fs::read_to_string(out_path)
        .with_context(|| format!("quality gate: failed to read {}", out_path.display()))?;
    if html.contains("Publication quality checks should block this output") {
        anyhow::bail!("quality gate: rendered HTML contains the empty-news failure state");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tehran_day_helper_handles_utc_midnight_boundary() {
        assert!(timestamp_is_tehran_day(
            "2026-07-10T20:30:00Z",
            "2026-07-11"
        ));
        assert!(!timestamp_is_tehran_day(
            "2026-07-11T20:30:00Z",
            "2026-07-11"
        ));
    }

    #[test]
    fn unsafe_news_url_is_rejected() {
        assert!(validated_http_url("javascript:alert(1)").is_none());
        assert!(validated_http_url("https://example.test/news").is_some());
    }
}
