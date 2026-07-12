//! Publication quality gates.
//!
//! A scheduled run must fail before the publish step when collection or output
//! is unusable. This preserves the last known-good deployment instead of
//! replacing it with an empty or structurally broken build.

use crate::prelude::*;

fn array_len(value: &Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

fn nested_array_len(value: &Value, pointer: &str) -> usize {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

fn panel_failure_reason(brief: &Value, panel_name: &str) -> Option<String> {
    let Some(panel) = brief.get(panel_name) else {
        return Some("panel is missing".to_string());
    };
    let Some(object) = panel.as_object() else {
        return Some("panel is not an object".to_string());
    };

    if object
        .get("enabled")
        .and_then(Value::as_bool)
        .is_some_and(|enabled| !enabled)
    {
        return None;
    }

    match object.get("ok").and_then(Value::as_bool) {
        Some(true) => None,
        Some(false) => {
            let detail = object
                .get("error")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .or_else(|| {
                    object
                        .get("summary")
                        .and_then(Value::as_str)
                        .filter(|value| !value.trim().is_empty())
                })
                .or_else(|| {
                    object
                        .get("errors")
                        .and_then(Value::as_array)
                        .and_then(|errors| errors.first())
                        .and_then(Value::as_str)
                        .filter(|value| !value.trim().is_empty())
                })
                .unwrap_or("panel reported ok=false");
            Some(detail.to_string())
        }
        None => Some("panel is missing a boolean ok field".to_string()),
    }
}

fn validate_cve_engine(brief: &Value, config: &Config) -> Result<()> {
    if !config.quality.require_cve_engine {
        return Ok(());
    }

    let enabled = brief
        .pointer("/source_health/cve_engine_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !enabled {
        anyhow::bail!("quality gate: CVE engine is required but was not enabled");
    }

    let ok = brief
        .pointer("/source_health/cve_engine_ok")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !ok {
        let error = brief
            .pointer("/source_health/cve_error")
            .and_then(Value::as_str)
            .unwrap_or("unknown CVE engine error");
        anyhow::bail!("quality gate: CVE engine failed: {error}");
    }

    if !brief.get("cves").is_some_and(Value::is_array) {
        anyhow::bail!("quality gate: cves is missing or not an array");
    }

    Ok(())
}

fn validate_writeups(brief: &Value, config: &Config) -> Result<()> {
    if config.writeup_sources.is_empty() {
        return Ok(());
    }

    let visible = nested_array_len(brief, "/writeups_pulse/writeups");
    if visible < config.quality.min_writeups_for_publish {
        anyhow::bail!(
            "quality gate: only {visible} usable writeups are visible; minimum is {}",
            config.quality.min_writeups_for_publish
        );
    }

    let source_count = path_u64(brief, &["source_health", "writeup_sources"]) as usize;
    let failed = path_u64(brief, &["source_health", "failed_writeup_sources"]) as usize;
    if source_count == 0 {
        anyhow::bail!("quality gate: writeup sources are configured but source count is zero");
    }

    let failure_percent = failed
        .saturating_mul(100)
        .saturating_add(source_count.saturating_sub(1))
        / source_count;
    if failed.saturating_mul(100)
        > config
            .quality
            .max_writeup_source_failure_percent
            .saturating_mul(source_count)
    {
        anyhow::bail!(
            "quality gate: {failed}/{source_count} writeup sources failed ({failure_percent}%); maximum is {}%",
            config.quality.max_writeup_source_failure_percent
        );
    }

    Ok(())
}

fn validate_intel_panels(brief: &Value, config: &Config) -> Result<()> {
    if !config.intel.enabled {
        return Ok(());
    }

    let required_failures: Vec<String> = config
        .quality
        .required_panels
        .iter()
        .filter_map(|name| {
            panel_failure_reason(brief, name).map(|reason| format!("{name}: {reason}"))
        })
        .collect();
    if !required_failures.is_empty() {
        anyhow::bail!(
            "quality gate: required Intel panel failure(s): {}",
            required_failures.join("; ")
        );
    }

    let degradable_failures: Vec<String> = config
        .quality
        .degradable_panels
        .iter()
        .filter_map(|name| {
            panel_failure_reason(brief, name).map(|reason| format!("{name}: {reason}"))
        })
        .collect();
    if degradable_failures.len() > config.quality.max_degradable_panel_failures {
        anyhow::bail!(
            "quality gate: {} degradable Intel panels failed; maximum is {}: {}",
            degradable_failures.len(),
            config.quality.max_degradable_panel_failures,
            degradable_failures.join("; ")
        );
    }

    Ok(())
}

fn validate_intel_freshness(brief: &Value, config: &Config) -> Result<()> {
    if !config.intel.enabled {
        return Ok(());
    }

    let freshness = brief
        .pointer("/source_health/intel_cache")
        .with_context(|| "quality gate: source_health.intel_cache is missing")?;
    let tracked = freshness
        .get("tracked_sources")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let stale = freshness
        .get("stale_sources")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if stale > tracked {
        anyhow::bail!(
            "quality gate: Intel stale source count {stale} exceeds tracked source count {tracked}"
        );
    }

    let status = freshness
        .get("cache_status")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !matches!(status, "fresh" | "stale" | "untracked") {
        anyhow::bail!("quality gate: invalid Intel cache_status {status:?}");
    }

    let max_age_minutes = config.intel.max_stale_hours.saturating_mul(60);
    if let Some(age) = freshness.get("cache_age_minutes").and_then(Value::as_u64) {
        if age > max_age_minutes {
            anyhow::bail!(
                "quality gate: Intel cache age {age} minutes exceeds configured maximum {max_age_minutes}"
            );
        }
    }

    if tracked > 0 {
        let fetched_at = freshness
            .get("source_fetched_at")
            .and_then(Value::as_str)
            .unwrap_or("");
        if fetched_at.is_empty() {
            anyhow::bail!(
                "quality gate: Intel sources were tracked but source_fetched_at is empty"
            );
        }
        chrono::DateTime::parse_from_rfc3339(fetched_at).with_context(|| {
            format!("quality gate: invalid Intel source_fetched_at {fetched_at:?}")
        })?;
    }

    if let Some(sources) = freshness.get("sources").and_then(Value::as_array) {
        for (index, source) in sources.iter().enumerate() {
            let age = source
                .get("age_minutes")
                .and_then(Value::as_u64)
                .unwrap_or(max_age_minutes.saturating_add(1));
            if age > max_age_minutes {
                anyhow::bail!(
                    "quality gate: Intel source {index} cache age {age} minutes exceeds configured maximum {max_age_minutes}"
                );
            }
            let fetched_at = source
                .get("fetched_at")
                .and_then(Value::as_str)
                .unwrap_or("");
            chrono::DateTime::parse_from_rfc3339(fetched_at).with_context(|| {
                format!("quality gate: invalid fetched_at for Intel source {index}: {fetched_at:?}")
            })?;
        }
    }

    Ok(())
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
    if config.quality.min_visible_news_for_publish > 0
        && visible_news < config.quality.min_visible_news_for_publish
    {
        anyhow::bail!(
            "quality gate: only {visible_news} usable news items are visible; minimum is {}",
            config.quality.min_visible_news_for_publish
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

    let Some(items) = brief.get("today_news").and_then(Value::as_array) else {
        anyhow::bail!("quality gate: today_news is missing or not an array");
    };
    for (index, item) in items.iter().enumerate() {
        let title = item
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let url = item.get("url").and_then(Value::as_str).unwrap_or("").trim();
        if title.is_empty() {
            anyhow::bail!("quality gate: news item {index} has an empty title");
        }
        if validated_http_url(url).is_none() {
            anyhow::bail!("quality gate: news item {index} has an unsafe or invalid URL");
        }
    }

    let generated_at = brief
        .get("generated_at")
        .and_then(Value::as_str)
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
    let brief_date = brief.get("date_en").and_then(Value::as_str).unwrap_or("");
    if brief_date != expected_date {
        anyhow::bail!(
            "quality gate: brief date {brief_date:?} does not match Tehran date {expected_date}"
        );
    }

    validate_cve_engine(brief, config)?;
    validate_writeups(brief, config)?;
    validate_intel_panels(brief, config)?;

    if let Some(cves) = brief.get("cves").and_then(Value::as_array) {
        for (index, cve) in cves.iter().enumerate() {
            let published = cve.get("published").and_then(Value::as_str).unwrap_or("");
            if !timestamp_is_tehran_day(published, brief_date) {
                anyhow::bail!(
                    "quality gate: CVE item {index} publication timestamp {published:?} is outside Tehran day {brief_date}"
                );
            }
        }
    }

    if let Some(repos) = brief.pointer("/poc_watch/repos").and_then(Value::as_array) {
        for (index, repo) in repos.iter().enumerate() {
            let published = repo
                .get("published_at")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !timestamp_is_tehran_day(published, brief_date) {
                anyhow::bail!(
                    "quality gate: PoC item {index} publication timestamp {published:?} is outside Tehran day {brief_date}"
                );
            }
        }
    }

    validate_intel_freshness(brief, config)?;

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
    let feed_path = site_dir.join("feed.xml");
    let brief_path = site_dir.join("api/brief.json");
    let summary_path = site_dir.join("api/summary.json");

    require_nonempty_file(out_path, 1024)?;
    require_nonempty_file(&feed_path, 128)?;
    require_nonempty_file(&brief_path, 512)?;
    require_nonempty_file(&summary_path, 128)?;

    let raw = fs::read_to_string(&brief_path)
        .context("quality gate: failed to read generated api/brief.json")?;
    let generated: Value = serde_json::from_str(&raw)
        .context("quality gate: generated api/brief.json is invalid JSON")?;
    validate_collected_brief(&generated, config)?;

    let summary_raw = fs::read_to_string(&summary_path)
        .context("quality gate: failed to read generated api/summary.json")?;
    let summary: Value = serde_json::from_str(&summary_raw)
        .context("quality gate: generated api/summary.json is invalid JSON")?;
    for key in ["generated_at", "date_en"] {
        if summary.get(key) != generated.get(key) {
            anyhow::bail!(
                "quality gate: api/summary.json field {key:?} does not match api/brief.json"
            );
        }
    }

    let feed_raw = fs::read(&feed_path)
        .with_context(|| format!("quality gate: failed to read {}", feed_path.display()))?;
    let feed = parser::parse(feed_raw.as_slice())
        .context("quality gate: generated feed.xml is not valid RSS/Atom")?;
    if feed.entries.is_empty() {
        anyhow::bail!(
            "quality gate: generated feed.xml contains no usable CVE, alert, or news entries"
        );
    }

    let html = fs::read_to_string(out_path)
        .with_context(|| format!("quality gate: failed to read {}", out_path.display()))?;
    if html.contains("Publication quality checks should block this output") {
        anyhow::bail!("quality gate: rendered HTML contains the empty-news failure state");
    }
    if html.contains("href=\"javascript:") || html.contains("href=\"data:") {
        anyhow::bail!("quality gate: rendered HTML contains an unsafe link scheme");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        load_config(&PathBuf::from("config.yaml")).expect("test config should load")
    }

    fn healthy_brief(config: &Config) -> Value {
        let now = tehran_now();
        let date = now.format("%Y-%m-%d").to_string();
        let generated_at = now.format("%Y-%m-%d %H:%M").to_string();
        let news: Vec<Value> = (0..config.quality.min_visible_news_for_publish)
            .map(|index| {
                json!({
                    "title": format!("Security item {index}"),
                    "url": format!("https://example.test/security/{index}")
                })
            })
            .collect();

        let mut brief = json!({
            "date_en": date,
            "generated_at": generated_at,
            "today_news": news,
            "cves": [],
            "stats": {"rss_items_fetched": config.fetch.min_news_items_for_publish},
            "source_health": {
                "failed_rss_sources": 0,
                "cve_engine_enabled": true,
                "cve_engine_ok": true,
                "cve_error": null,
                "writeup_sources": config.writeup_sources.len(),
                "failed_writeup_sources": 0,
                "intel_cache": {
                    "tracked_sources": 0,
                    "stale_sources": 0,
                    "cache_status": "untracked",
                    "sources": []
                }
            },
            "writeups_pulse": {
                "writeups": [{"title": "Writeup"}],
                "totals": {"writeups": 1}
            }
        });

        for panel in known_quality_panels() {
            brief[*panel] = json!({
                "enabled": true,
                "ok": true,
                "summary": "healthy"
            });
        }
        brief["poc_watch"]["repos"] = json!([]);
        brief
    }

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

    #[test]
    fn zero_visible_news_passes_when_collection_is_healthy() {
        let config = test_config();
        assert_eq!(config.quality.min_visible_news_for_publish, 0);

        let mut brief = healthy_brief(&config);
        brief["today_news"] = json!([]);

        validate_collected_brief(&brief, &config)
            .expect("same-day news volume must not block an otherwise healthy publication");
    }

    #[test]
    fn configured_visible_news_minimum_still_blocks_publication() {
        let mut config = test_config();
        config.quality.min_visible_news_for_publish = 3;

        let mut brief = healthy_brief(&config);
        brief["today_news"] = json!([
            {"title": "Security item 1", "url": "https://example.test/security/1"},
            {"title": "Security item 2", "url": "https://example.test/security/2"}
        ]);

        let error = validate_collected_brief(&brief, &config)
            .expect_err("an explicitly configured visible-news minimum must be enforced")
            .to_string();
        assert!(error.contains("usable news items are visible"));
    }

    #[test]
    fn required_panel_failure_blocks_publication() {
        let config = test_config();
        let mut brief = healthy_brief(&config);
        brief["ioc_radar"]["ok"] = json!(false);
        brief["ioc_radar"]["error"] = json!("IOC provider unavailable");

        let error = validate_collected_brief(&brief, &config)
            .expect_err("required panel failure must block publication")
            .to_string();
        assert!(error.contains("required Intel panel"));
        assert!(error.contains("ioc_radar"));
    }

    #[test]
    fn degradable_panel_failures_respect_configured_budget() {
        let config = test_config();
        let mut brief = healthy_brief(&config);
        for panel in config
            .quality
            .degradable_panels
            .iter()
            .take(config.quality.max_degradable_panel_failures)
        {
            brief[panel.as_str()]["ok"] = json!(false);
        }
        validate_collected_brief(&brief, &config)
            .expect("failures inside degradable budget should be accepted");

        let extra = &config.quality.degradable_panels[config.quality.max_degradable_panel_failures];
        brief[extra.as_str()]["ok"] = json!(false);
        let error = validate_collected_brief(&brief, &config)
            .expect_err("exceeding degradable budget must block publication")
            .to_string();
        assert!(error.contains("degradable Intel panels failed"));
    }

    #[test]
    fn cve_engine_failure_blocks_publication_when_required() {
        let config = test_config();
        let mut brief = healthy_brief(&config);
        brief["source_health"]["cve_engine_ok"] = json!(false);
        brief["source_health"]["cve_error"] = json!("NVD and fallback failed");

        let error = validate_collected_brief(&brief, &config)
            .expect_err("required CVE engine failure must block publication")
            .to_string();
        assert!(error.contains("CVE engine failed"));
    }

    #[test]
    fn missing_writeups_block_publication() {
        let config = test_config();
        let mut brief = healthy_brief(&config);
        brief["writeups_pulse"]["writeups"] = json!([]);
        brief["writeups_pulse"]["totals"]["writeups"] = json!(0);

        let error = validate_collected_brief(&brief, &config)
            .expect_err("missing writeups must block publication")
            .to_string();
        assert!(error.contains("usable writeups"));
    }
}
