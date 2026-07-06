//! HTTP and intel caches on disk.

use crate::prelude::*;

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

    if !allow_stale {
        let metadata = fs::metadata(&path)
            .with_context(|| format!("failed to read cache metadata: {}", path.display()))?;
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or_else(|_| Duration::from_secs(0));
        let ttl = Duration::from_secs(ttl_minutes.saturating_mul(60));

        if age > ttl {
            return Ok(None);
        }
    }

    fs::read(&path)
        .map(Some)
        .with_context(|| format!("failed to read cache file: {}", path.display()))
}

pub(crate) fn write_cache_to_dir(cache_dir: &str, cache_key: &str, bytes: &[u8]) -> Result<()> {
    let path = cache_path_in_dir(cache_dir, cache_key);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create cache directory: {}", parent.display()))?;
    }
    fs::write(&path, bytes)
        .with_context(|| format!("failed to write cache file: {}", path.display()))?;
    Ok(())
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

pub(crate) fn cache_path(config: &Config, cache_key: &str) -> PathBuf {
    let mut hasher = DefaultHasher::new();
    cache_key.hash(&mut hasher);
    let hash = hasher.finish();
    PathBuf::from(&config.cache.dir).join(format!("{hash:016x}.bin"))
}

pub(crate) fn read_cache(
    config: &Config,
    cache_key: &str,
    allow_stale: bool,
) -> Result<Option<Vec<u8>>> {
    if !config.cache.enabled {
        return Ok(None);
    }

    let path = cache_path(config, cache_key);
    if !path.exists() {
        return Ok(None);
    }

    if !allow_stale {
        let metadata = fs::metadata(&path)
            .with_context(|| format!("failed to read cache metadata: {}", path.display()))?;
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or_else(|_| Duration::from_secs(0));
        let ttl = Duration::from_secs(config.cache.ttl_minutes.saturating_mul(60));

        if age > ttl {
            return Ok(None);
        }
    }

    fs::read(&path)
        .map(Some)
        .with_context(|| format!("failed to read cache file: {}", path.display()))
}

pub(crate) fn write_cache(config: &Config, cache_key: &str, bytes: &[u8]) -> Result<()> {
    if !config.cache.enabled {
        return Ok(());
    }

    let path = cache_path(config, cache_key);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create cache directory: {}", parent.display()))?;
    }

    fs::write(&path, bytes)
        .with_context(|| format!("failed to write cache file: {}", path.display()))?;
    Ok(())
}
