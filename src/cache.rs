//! HTTP and intel caches on disk.
//!
//! Freshness is recorded in an explicit sidecar metadata file. Git does not
//! preserve file mtimes, so using filesystem modification time makes restored
//! caches look fresh on every CI run and can keep stale feeds alive forever.

use crate::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheMetadata {
    fetched_at_unix: i64,
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
    let ttl_minutes = config.intel.refresh_hours.saturating_mul(60).max(60);

    if !refresh_cache {
        if let Some(bytes) =
            read_cache_from_dir(&config.intel.cache_dir, &cache_key, ttl_minutes, false)?
        {
            eprintln!("  ↳ cache hit: {label}");
            return Ok(bytes);
        }
    }

    if offline {
        return read_cache_from_dir(&config.intel.cache_dir, &cache_key, ttl_minutes, true)?
            .with_context(|| format!("offline mode has no cached response for {label}"));
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
            Ok(bytes)
        }
        Err(err) => {
            if let Some(bytes) =
                read_cache_from_dir(&config.intel.cache_dir, &cache_key, ttl_minutes, true)?
            {
                eprintln!("⚠️  using stale intel cache for {label}: {err}");
                Ok(bytes)
            } else {
                Err(err).with_context(|| format!("request failed for {label}: {url}"))
            }
        }
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
}
