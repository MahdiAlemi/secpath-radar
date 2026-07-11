//! HTTP and intel caches on disk.
//!
//! Freshness is recorded in an explicit sidecar metadata file. Git does not
//! preserve file mtimes, so using filesystem modification time makes restored
//! caches look fresh on every CI run and can keep stale feeds alive forever.

use crate::prelude::*;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheMetadata {
    fetched_at_unix: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct IntelCacheEntry {
    pub(crate) bytes: Vec<u8>,
    pub(crate) fetched_at_unix: i64,
    pub(crate) age_minutes: u64,
    pub(crate) is_fresh: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct IntelCacheEvent {
    pub(crate) label: String,
    pub(crate) status: String,
    pub(crate) fetched_at: String,
    pub(crate) age_minutes: u64,
    pub(crate) stale_reason: Option<String>,
}

static INTEL_CACHE_EVENTS: OnceLock<Mutex<Vec<IntelCacheEvent>>> = OnceLock::new();

fn intel_cache_events() -> &'static Mutex<Vec<IntelCacheEvent>> {
    INTEL_CACHE_EVENTS.get_or_init(|| Mutex::new(Vec::new()))
}

pub(crate) fn begin_intel_freshness_scope() -> usize {
    intel_cache_events()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .len()
}

fn unix_to_rfc3339(timestamp: i64) -> String {
    chrono::DateTime::<Utc>::from_timestamp(timestamp, 0)
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_default()
}

pub(crate) fn record_intel_cache_event(
    label: &str,
    status: &str,
    fetched_at_unix: i64,
    age_minutes: u64,
    stale_reason: Option<String>,
) {
    let event = IntelCacheEvent {
        label: label.to_string(),
        status: status.to_string(),
        fetched_at: unix_to_rfc3339(fetched_at_unix),
        age_minutes,
        stale_reason,
    };
    intel_cache_events()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(event);
}

pub(crate) fn intel_freshness_summary_since(start: usize) -> Value {
    let events = intel_cache_events()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let scoped = events.iter().skip(start).cloned().collect::<Vec<_>>();

    if scoped.is_empty() {
        return json!({
            "cache_status": "untracked",
            "tracked_sources": 0,
            "stale_sources": 0,
            "cache_age_minutes": null,
            "source_fetched_at": "",
            "newest_source_fetched_at": "",
            "sources": []
        });
    }

    let stale_sources = scoped
        .iter()
        .filter(|event| event.status.contains("stale"))
        .count();
    let max_age = scoped
        .iter()
        .map(|event| event.age_minutes)
        .max()
        .unwrap_or(0);
    let oldest = scoped
        .iter()
        .filter_map(|event| chrono::DateTime::parse_from_rfc3339(&event.fetched_at).ok())
        .min()
        .map(|value| {
            value
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Secs, true)
        })
        .unwrap_or_default();
    let newest = scoped
        .iter()
        .filter_map(|event| chrono::DateTime::parse_from_rfc3339(&event.fetched_at).ok())
        .max()
        .map(|value| {
            value
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Secs, true)
        })
        .unwrap_or_default();

    json!({
        "cache_status": if stale_sources > 0 { "stale" } else { "fresh" },
        "tracked_sources": scoped.len(),
        "stale_sources": stale_sources,
        "cache_age_minutes": max_age,
        "source_fetched_at": oldest,
        "newest_source_fetched_at": newest,
        "sources": scoped
    })
}

pub(crate) fn apply_intel_freshness(
    mut panel: Value,
    scope_start: usize,
    config: &Config,
) -> Value {
    let summary = intel_freshness_summary_since(scope_start);
    let generated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let tracked_sources = summary
        .get("tracked_sources")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let Some(object) = panel.as_object_mut() else {
        return panel;
    };
    object.insert("generated_at".to_string(), json!(generated_at));
    object.insert(
        "cache_status".to_string(),
        summary
            .get("cache_status")
            .cloned()
            .unwrap_or(json!("untracked")),
    );
    object.insert(
        "cache_age_minutes".to_string(),
        summary
            .get("cache_age_minutes")
            .cloned()
            .unwrap_or(Value::Null),
    );
    object.insert(
        "stale_sources".to_string(),
        summary.get("stale_sources").cloned().unwrap_or(json!(0)),
    );
    object.insert(
        "tracked_sources".to_string(),
        summary.get("tracked_sources").cloned().unwrap_or(json!(0)),
    );
    object.insert(
        "source_fetched_at".to_string(),
        summary
            .get("source_fetched_at")
            .cloned()
            .unwrap_or(json!("")),
    );
    object.insert("freshness".to_string(), summary.clone());

    if tracked_sources > 0 {
        if let Some(source_fetched_at) = summary
            .get("source_fetched_at")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            object.insert("last_updated".to_string(), json!(source_fetched_at));
        }
    }

    let source_health = object
        .entry("source_health".to_string())
        .or_insert_with(|| json!({}));
    if let Some(health) = source_health.as_object_mut() {
        health.insert(
            "cache_status".to_string(),
            summary
                .get("cache_status")
                .cloned()
                .unwrap_or(json!("untracked")),
        );
        health.insert(
            "cache_age_minutes".to_string(),
            summary
                .get("cache_age_minutes")
                .cloned()
                .unwrap_or(Value::Null),
        );
        health.insert(
            "stale_sources".to_string(),
            summary.get("stale_sources").cloned().unwrap_or(json!(0)),
        );
        health.insert(
            "tracked_sources".to_string(),
            summary.get("tracked_sources").cloned().unwrap_or(json!(0)),
        );
        health.insert(
            "source_fetched_at".to_string(),
            summary
                .get("source_fetched_at")
                .cloned()
                .unwrap_or(json!("")),
        );
        health.insert(
            "max_stale_hours".to_string(),
            json!(config.intel.max_stale_hours),
        );
    }

    panel
}

#[derive(Debug, Clone)]
pub(crate) struct ValidatedCacheBytes {
    pub(crate) bytes: Vec<u8>,
    pub(crate) stale_fallback_reason: Option<String>,
}

pub(crate) fn get_bytes_cached_intel(
    client: &Client,
    config: &Config,
    url: &str,
    label: &str,
    offline: bool,
    refresh_cache: bool,
) -> Result<Vec<u8>> {
    let cache_key = cache_key(url, &[]);

    if !refresh_cache {
        if let Some(entry) = read_intel_cache_entry(config, &cache_key, false)? {
            eprintln!("  ↳ cache hit: {label}");
            record_intel_cache_event(
                label,
                "fresh-cache",
                entry.fetched_at_unix,
                entry.age_minutes,
                None,
            );
            return Ok(entry.bytes);
        }
    }

    if offline {
        let entry = read_intel_cache_entry(config, &cache_key, true)?
            .with_context(|| format!("offline mode has no bounded cached response for {label}"))?;
        let status = if entry.is_fresh {
            "offline-fresh-cache"
        } else {
            "offline-stale-cache"
        };
        record_intel_cache_event(
            label,
            status,
            entry.fetched_at_unix,
            entry.age_minutes,
            Some("offline mode used cached response".to_string()),
        );
        return Ok(entry.bytes);
    }

    match client
        .get(url)
        .send()
        .and_then(|response| response.error_for_status())
    {
        Ok(response) => {
            let bytes = response
                .bytes()
                .with_context(|| format!("failed to read response body for {label}"))?
                .to_vec();
            write_cache_to_dir(&config.intel.cache_dir, &cache_key, &bytes)?;
            record_intel_cache_event(label, "network", Utc::now().timestamp(), 0, None);
            Ok(bytes)
        }
        Err(err) => match read_intel_cache_entry(config, &cache_key, true) {
            Ok(Some(entry)) => {
                let reason = format!("{err:#}");
                eprintln!(
                    "⚠️  using stale intel cache for {label} ({} min old): {reason}",
                    entry.age_minutes
                );
                record_intel_cache_event(
                    label,
                    "stale-cache",
                    entry.fetched_at_unix,
                    entry.age_minutes,
                    Some(reason),
                );
                Ok(entry.bytes)
            }
            Ok(None) => Err(err).with_context(|| format!("request failed for {label}: {url}")),
            Err(cache_err) => Err(err).with_context(|| {
                format!("request failed for {label}: {url}; stale fallback rejected: {cache_err:#}")
            }),
        },
    }
}

pub(crate) fn cache_path_in_dir(cache_dir: &str, cache_key: &str) -> PathBuf {
    let mut hasher = DefaultHasher::new();
    cache_key.hash(&mut hasher);
    let hash = hasher.finish();
    PathBuf::from(cache_dir).join(format!("{hash:016x}.bin"))
}

pub(crate) fn cache_meta_path_in_dir(cache_dir: &str, cache_key: &str) -> PathBuf {
    let mut hasher = DefaultHasher::new();
    cache_key.hash(&mut hasher);
    let hash = hasher.finish();
    PathBuf::from(cache_dir).join(format!("{hash:016x}.meta.json"))
}

fn read_cache_metadata(cache_dir: &str, cache_key: &str) -> Option<CacheMetadata> {
    let path = cache_meta_path_in_dir(cache_dir, cache_key);
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn cache_is_fresh(cache_dir: &str, cache_key: &str, ttl_minutes: u64) -> bool {
    let Some(metadata) = read_cache_metadata(cache_dir, cache_key) else {
        // Legacy cache files have no trustworthy timestamp. Force one network
        // refresh; stale fallback remains available if that request fails.
        return false;
    };

    let age_seconds = Utc::now()
        .timestamp()
        .saturating_sub(metadata.fetched_at_unix)
        .max(0) as u64;
    age_seconds <= ttl_minutes.saturating_mul(60)
}

pub(crate) fn read_intel_cache_entry(
    config: &Config,
    cache_key: &str,
    allow_stale: bool,
) -> Result<Option<IntelCacheEntry>> {
    let path = cache_path_in_dir(&config.intel.cache_dir, cache_key);
    if !path.exists() {
        return Ok(None);
    }

    let Some(metadata) = read_cache_metadata(&config.intel.cache_dir, cache_key) else {
        // A cache restored without explicit metadata has no trustworthy age.
        // Reject it for Intel so stale data cannot live forever.
        return Ok(None);
    };

    let age_seconds = Utc::now()
        .timestamp()
        .saturating_sub(metadata.fetched_at_unix)
        .max(0) as u64;
    let age_minutes = age_seconds.saturating_add(59) / 60;
    let ttl_minutes = config.intel.refresh_hours.saturating_mul(60).max(60);
    let max_stale_minutes = config
        .intel
        .max_stale_hours
        .saturating_mul(60)
        .max(ttl_minutes);
    let is_fresh = age_seconds <= ttl_minutes.saturating_mul(60);

    if !allow_stale && !is_fresh {
        return Ok(None);
    }
    if allow_stale && age_seconds > max_stale_minutes.saturating_mul(60) {
        anyhow::bail!(
            "cached Intel response is {age_minutes} minutes old; maximum allowed is {max_stale_minutes} minutes"
        );
    }

    let bytes = fs::read(&path)
        .with_context(|| format!("failed to read Intel cache file: {}", path.display()))?;
    Ok(Some(IntelCacheEntry {
        bytes,
        fetched_at_unix: metadata.fetched_at_unix,
        age_minutes,
        is_fresh,
    }))
}

pub(crate) fn read_cache_from_dir(
    cache_dir: &str,
    cache_key: &str,
    ttl_minutes: u64,
    allow_stale: bool,
) -> Result<Option<Vec<u8>>> {
    let path = cache_path_in_dir(cache_dir, cache_key);
    if !path.exists() {
        return Ok(None);
    }

    if !allow_stale && !cache_is_fresh(cache_dir, cache_key, ttl_minutes) {
        return Ok(None);
    }

    fs::read(&path)
        .map(Some)
        .with_context(|| format!("failed to read cache file: {}", path.display()))
}

fn atomic_write(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create cache directory: {}", parent.display()))?;
    }

    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("cache");
    let temp = path.with_extension(format!("{extension}.tmp-{}", std::process::id()));
    fs::write(&temp, bytes)
        .with_context(|| format!("failed to write temporary cache file: {}", temp.display()))?;
    fs::rename(&temp, path).with_context(|| {
        format!(
            "failed to atomically replace cache file {} with {}",
            path.display(),
            temp.display()
        )
    })?;
    Ok(())
}

pub(crate) fn write_cache_to_dir(cache_dir: &str, cache_key: &str, bytes: &[u8]) -> Result<()> {
    let path = cache_path_in_dir(cache_dir, cache_key);
    atomic_write(&path, bytes)?;

    let metadata = CacheMetadata {
        fetched_at_unix: Utc::now().timestamp(),
    };
    let metadata_bytes = serde_json::to_vec(&metadata)?;
    let metadata_path = cache_meta_path_in_dir(cache_dir, cache_key);
    atomic_write(&metadata_path, &metadata_bytes)
}

pub(crate) fn get_bytes_cached(
    client: &Client,
    config: &Config,
    url: &str,
    query: &[(&str, &str)],
    label: &str,
    offline: bool,
    refresh_cache: bool,
) -> Result<Vec<u8>> {
    let cache_key = cache_key(url, query);

    if !refresh_cache {
        if let Some(bytes) = read_cache(config, &cache_key, false)? {
            eprintln!("  ↳ cache hit: {label}");
            return Ok(bytes);
        }
    }

    if offline {
        return read_cache(config, &cache_key, true)?
            .with_context(|| format!("offline mode has no cached response for {label}"));
    }

    let mut request = client.get(url);
    if !query.is_empty() {
        request = request.query(query);
    }

    match request
        .send()
        .and_then(|response| response.error_for_status())
    {
        Ok(response) => {
            let bytes = response
                .bytes()
                .with_context(|| format!("failed to read response body for {label}"))?
                .to_vec();
            write_cache(config, &cache_key, &bytes)?;
            Ok(bytes)
        }
        Err(err) => {
            if let Some(bytes) = read_cache(config, &cache_key, true)? {
                eprintln!("⚠️  using stale cache for {label}: {err}");
                Ok(bytes)
            } else {
                Err(err).with_context(|| format!("request failed for {label}: {url}"))
            }
        }
    }
}

pub(crate) fn get_bytes_cached_validated<F>(
    client: &Client,
    config: &Config,
    url: &str,
    query: &[(&str, &str)],
    label: &str,
    offline: bool,
    refresh_cache: bool,
    validate: F,
) -> Result<ValidatedCacheBytes>
where
    F: Fn(&[u8]) -> Result<()>,
{
    let cache_key = cache_key(url, query);

    if !refresh_cache {
        if let Some(bytes) = read_cache(config, &cache_key, false)? {
            match validate(&bytes) {
                Ok(()) => {
                    eprintln!("  ↳ cache hit: {label}");
                    return Ok(ValidatedCacheBytes {
                        bytes,
                        stale_fallback_reason: None,
                    });
                }
                Err(err) => {
                    eprintln!("⚠️  ignoring invalid fresh cache for {label}: {err:#}");
                }
            }
        }
    }

    if offline {
        let bytes = read_cache(config, &cache_key, true)?
            .with_context(|| format!("offline mode has no cached response for {label}"))?;
        validate(&bytes)
            .with_context(|| format!("offline cached response is invalid for {label}"))?;
        return Ok(ValidatedCacheBytes {
            bytes,
            stale_fallback_reason: Some("offline mode used cached response".to_string()),
        });
    }

    let mut request = client
        .get(url)
        .header(
            reqwest::header::ACCEPT,
            "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.1",
        )
        .header(reqwest::header::ACCEPT_LANGUAGE, "en-US,en;q=0.8");
    if !query.is_empty() {
        request = request.query(query);
    }

    let network_result: Result<Vec<u8>> = (|| {
        let response = request
            .send()
            .with_context(|| format!("failed to send request for {label}"))?
            .error_for_status()
            .with_context(|| format!("HTTP error for {label}"))?;
        let bytes = response
            .bytes()
            .with_context(|| format!("failed to read response body for {label}"))?
            .to_vec();
        validate(&bytes).with_context(|| format!("response validation failed for {label}"))?;
        Ok(bytes)
    })();

    match network_result {
        Ok(bytes) => {
            write_cache(config, &cache_key, &bytes)?;
            Ok(ValidatedCacheBytes {
                bytes,
                stale_fallback_reason: None,
            })
        }
        Err(err) => {
            if let Some(bytes) = read_cache(config, &cache_key, true)? {
                if validate(&bytes).is_ok() {
                    let reason = format!("{err:#}");
                    eprintln!("⚠️  using stale cache for {label}: {reason}");
                    return Ok(ValidatedCacheBytes {
                        bytes,
                        stale_fallback_reason: Some(reason),
                    });
                }
            }

            Err(err).with_context(|| format!("request failed for {label}: {url}"))
        }
    }
}

pub(crate) fn cache_key(url: &str, query: &[(&str, &str)]) -> String {
    let mut key = url.to_string();
    if !query.is_empty() {
        let parts = query
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        key.push('?');
        key.push_str(&parts);
    }
    key
}

pub(crate) fn read_cache(
    config: &Config,
    cache_key: &str,
    allow_stale: bool,
) -> Result<Option<Vec<u8>>> {
    if !config.cache.enabled {
        return Ok(None);
    }

    read_cache_from_dir(
        &config.cache.dir,
        cache_key,
        config.cache.ttl_minutes,
        allow_stale,
    )
}

pub(crate) fn write_cache(config: &Config, cache_key: &str, bytes: &[u8]) -> Result<()> {
    if !config.cache.enabled {
        return Ok(());
    }

    write_cache_to_dir(&config.cache.dir, cache_key, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_cache_dir(name: &str) -> String {
        let path = env::temp_dir().join(format!(
            "secpath-radar-cache-{name}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        path.to_string_lossy().to_string()
    }

    #[test]
    fn legacy_cache_without_metadata_is_stale_but_still_available_as_fallback() {
        let dir = temp_cache_dir("legacy");
        let key = "https://example.test/feed";
        let path = cache_path_in_dir(&dir, key);
        fs::create_dir_all(&dir).expect("create cache dir");
        fs::write(&path, b"legacy").expect("write legacy cache");

        assert!(read_cache_from_dir(&dir, key, 120, false)
            .expect("fresh read")
            .is_none());
        assert_eq!(
            read_cache_from_dir(&dir, key, 120, true)
                .expect("stale read")
                .expect("stale bytes"),
            b"legacy"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn expired_metadata_rejects_fresh_reads_but_preserves_stale_fallback() {
        let dir = temp_cache_dir("expired");
        let key = "https://example.test/feed";
        let path = cache_path_in_dir(&dir, key);
        let meta_path = cache_meta_path_in_dir(&dir, key);
        fs::create_dir_all(&dir).expect("create cache dir");
        fs::write(&path, b"old").expect("write cache");
        fs::write(
            &meta_path,
            serde_json::to_vec(&CacheMetadata {
                fetched_at_unix: Utc::now().timestamp() - 7_200,
            })
            .expect("metadata JSON"),
        )
        .expect("write metadata");

        assert!(read_cache_from_dir(&dir, key, 90, false)
            .expect("fresh read")
            .is_none());
        assert_eq!(
            read_cache_from_dir(&dir, key, 90, true)
                .expect("stale read")
                .expect("stale bytes"),
            b"old"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn explicit_metadata_keeps_cache_fresh_across_file_timestamp_changes() {
        let dir = temp_cache_dir("metadata");
        let key = "https://example.test/feed";
        write_cache_to_dir(&dir, key, b"fresh").expect("write cache");

        assert_eq!(
            read_cache_from_dir(&dir, key, 120, false)
                .expect("read cache")
                .expect("fresh bytes"),
            b"fresh"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn stale_intel_cache_is_rejected_after_configured_max_age() {
        let dir = temp_cache_dir("intel-max-stale");
        let key = "https://example.test/intel";
        let mut config = load_config(&PathBuf::from("config.yaml")).expect("load config");
        config.intel.cache_dir = dir.clone();
        config.intel.refresh_hours = 1;
        config.intel.max_stale_hours = 2;

        write_cache_to_dir(&dir, key, b"old-intel").expect("write cache");
        let meta_path = cache_meta_path_in_dir(&dir, key);
        fs::write(
            &meta_path,
            serde_json::to_vec(&CacheMetadata {
                fetched_at_unix: Utc::now().timestamp() - 3 * 60 * 60,
            })
            .expect("metadata JSON"),
        )
        .expect("write metadata");

        let err = read_intel_cache_entry(&config, key, true)
            .expect_err("cache older than max_stale_hours must be rejected");
        assert!(err.to_string().contains("maximum allowed"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn intel_freshness_summary_reports_stale_sources_and_oldest_fetch() {
        let start = begin_intel_freshness_scope();
        let now = Utc::now().timestamp();
        record_intel_cache_event("fresh-source", "network", now, 0, None);
        record_intel_cache_event(
            "stale-source",
            "stale-cache",
            now - 7_200,
            120,
            Some("timeout".to_string()),
        );

        let summary = intel_freshness_summary_since(start);
        assert_eq!(summary["cache_status"], json!("stale"));
        assert_eq!(summary["tracked_sources"], json!(2));
        assert_eq!(summary["stale_sources"], json!(1));
        assert_eq!(summary["cache_age_minutes"], json!(120));
        assert_eq!(
            summary["source_fetched_at"],
            json!(unix_to_rfc3339(now - 7_200))
        );
    }
}
