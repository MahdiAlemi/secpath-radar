//! GitHub PoC metadata watch (defensive triage signal).

use crate::prelude::*;

pub(crate) fn fetch_poc_watch_or_fallback(
    config: &Config,
    _cves: &Value,
    offline: bool,
    refresh_cache: bool,
) -> Value {
    if !config.intel.enabled || !config.intel.poc_watch.enabled {
        return empty_poc_watch("disabled");
    }

    match fetch_poc_watch(config, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  Latest PoC Watch skipped: {err:#}");
            empty_poc_watch("fetch_error")
        }
    }
}

pub(crate) fn fetch_poc_watch(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
    let cfg = &config.intel.poc_watch;
    let client = build_client(config)?;

    let recent_days = cfg.recent_days.max(1);
    let target_date = tehran_now().date_naive().format("%Y-%m-%d").to_string();
    let queries = latest_poc_search_queries(&target_date);

    eprintln!("→ fetching Latest PoC Watch metadata");

    let mut candidates = Vec::new();
    let mut errors = Vec::new();
    let mut cache_misses = 0_u64;

    for (index, query) in queries.iter().enumerate() {
        let label = format!("Latest GitHub PoC metadata query {}", index + 1);
        match fetch_github_repository_search(
            &client,
            config,
            cfg,
            query,
            &label,
            offline,
            refresh_cache,
        ) {
            Ok(value) => {
                if let Some(items) = value.get("items").and_then(|v| v.as_array()) {
                    for repo in items {
                        candidates.extend(map_github_latest_poc_candidates(repo));
                    }
                }
            }
            Err(err) => {
                let err_text = err.to_string();
                if offline && is_offline_cache_miss_error(&err_text) {
                    eprintln!(
                        "  ↳ cache miss: Latest GitHub PoC metadata query {}",
                        index + 1
                    );
                    cache_misses += 1;
                } else {
                    eprintln!(
                        "⚠️  skipped Latest GitHub PoC metadata query {}: {err:#}",
                        index + 1
                    );
                    errors.push(json!({
                        "query": index + 1,
                        "error": source_error_summary(&err_text)
                    }));
                }
            }
        }
        thread::sleep(Duration::from_millis(config.intel.sleep_ms_between_sources));
    }

    let raw_candidates = candidates.len() as u64;
    let candidates_before_day_filter = candidates.len();
    retain_pocs_published_on_day(&mut candidates, &target_date);
    let filtered_other_days = candidates_before_day_filter.saturating_sub(candidates.len()) as u64;
    let today_candidates = candidates.len() as u64;

    let mut seen_repo_cve = HashSet::new();
    candidates.retain(|item| {
        let key = format!(
            "{}::{}",
            item.get("cve_id").and_then(|v| v.as_str()).unwrap_or(""),
            item.get("repo").and_then(|v| v.as_str()).unwrap_or("")
        );
        seen_repo_cve.insert(key)
    });

    candidates.sort_by(|a, b| {
        path_u64(b, &["published_ts"])
            .cmp(&path_u64(a, &["published_ts"]))
            .then_with(|| path_u64(b, &["score"]).cmp(&path_u64(a, &["score"])))
            .then_with(|| value_str(a, "repo").cmp(value_str(b, "repo")))
    });

    let mut cve_seen_counts: HashMap<String, usize> = HashMap::new();
    let per_cve_limit = cfg.max_repos_per_cve.max(1);
    let mut grouped = Vec::new();
    for item in candidates {
        let cve_id = item
            .get("cve_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let count = cve_seen_counts.entry(cve_id).or_insert(0);
        if *count < per_cve_limit {
            grouped.push(item);
            *count += 1;
        }
        if grouped.len() >= cfg.max_results {
            break;
        }
    }

    let repos = grouped.len() as u64;
    let high = grouped
        .iter()
        .filter(|item| item.get("risk").and_then(|v| v.as_str()) == Some("high"))
        .count() as u64;
    let cves_with_poc = grouped
        .iter()
        .filter_map(|item| item.get("cve_id").and_then(|v| v.as_str()))
        .collect::<HashSet<_>>()
        .len() as u64;
    let fresh = grouped
        .iter()
        .filter(|item| path_u64(item, &["age_days"]) <= 7)
        .count() as u64;

    let mut cve_counts: HashMap<String, usize> = HashMap::new();
    let mut risk_counts: HashMap<String, usize> = HashMap::new();
    for item in &grouped {
        if let Some(cve_id) = item.get("cve_id").and_then(|v| v.as_str()) {
            *cve_counts.entry(cve_id.to_string()).or_insert(0) += 1;
        }
        if let Some(risk) = item.get("risk").and_then(|v| v.as_str()) {
            *risk_counts.entry(risk.to_string()).or_insert(0) += 1;
        }
    }

    let summary = if repos == 0 && offline && cache_misses == queries.len() as u64 {
        format!("In offline mode, no previous cache was available for today's PoC queries; with an online run, the current-day PoC timeline will be populated and then cached for offline use.")
    } else if repos == 0 {
        format!("No public PoC repository metadata was published for {target_date}.")
    } else {
        format!("{repos} public PoC metadata entries for {cves_with_poc} CVEs were published on {target_date}; the basis is repository publish time, not CVE dashboard searches.")
    };

    Ok(json!({
        "enabled": true,
        "ok": errors.is_empty(),
        "provider": "GitHub Repository Search API",
        "source": "GitHub latest repository metadata only",
        "mode": "current_day_poc_stream",
        "window_mode": "published-day-only",
        "date": target_date.clone(),
        "window_days": recent_days,
        "empty_message": format!("No public PoC repositories were published for {target_date}."),
        "safe_mode": "metadata only; no exploit code; no raw links; no clone/download commands; repository links are rendered for triage",
        "summary": summary,
        "totals": {
            "cves_checked": 0,
            "cves_with_poc": cves_with_poc,
            "repos": repos,
            "high": high,
            "fresh": fresh,
            "raw_candidates": raw_candidates,
            "today_candidates": today_candidates,
            "filtered_other_days": filtered_other_days,
            "kev_related": 0,
            "epss_rising_related": 0,
            "queries": queries.len(),
            "cache_misses": cache_misses,
            "errors": errors.len()
        },
        "repos": grouped,
        "cve_chart": count_chart(cve_counts, 8),
        "risk_chart": count_chart(risk_counts, 4),
        "errors": errors
    }))
}

pub(crate) fn latest_poc_search_queries(day: &str) -> Vec<String> {
    let Ok(local_day) = NaiveDate::parse_from_str(day, "%Y-%m-%d") else {
        return Vec::new();
    };
    let previous_utc_day = local_day
        .pred_opt()
        .unwrap_or(local_day)
        .format("%Y-%m-%d")
        .to_string();
    let current_utc_day = local_day.format("%Y-%m-%d").to_string();
    let terms = ["PoC", "exploit", "proof-of-concept", "reproducer"];

    [previous_utc_day, current_utc_day]
        .into_iter()
        .flat_map(|utc_day| {
            terms
                .iter()
                .map(move |term| format!("CVE {term} in:name,description,readme created:{utc_day}"))
        })
        .collect()
}

pub(crate) fn fetch_github_repository_search(
    client: &Client,
    config: &Config,
    cfg: &PocWatchConfig,
    query: &str,
    label: &str,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
    let per_page = cfg.max_search_results_per_query.clamp(8, 50).to_string();
    let query_params = [
        ("q", query),
        ("sort", "updated"),
        ("order", "desc"),
        ("per_page", per_page.as_str()),
    ];
    let cache_key = cache_key(&cfg.github_search_repositories_url, &query_params);

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
            return serde_json::from_slice(&entry.bytes)
                .with_context(|| format!("cached GitHub search was not valid JSON for {label}"));
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
        return serde_json::from_slice(&entry.bytes)
            .with_context(|| format!("cached GitHub search was not valid JSON for {label}"));
    }

    let mut request = client
        .get(&cfg.github_search_repositories_url)
        .query(&query_params)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28");

    if let Ok(token) = env::var(&cfg.github_token_env) {
        let token = token.trim();
        if !token.is_empty() {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
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
            write_cache_to_dir(&config.intel.cache_dir, &cache_key, &bytes)?;
            record_intel_cache_event(label, "network", Utc::now().timestamp(), 0, None);
            serde_json::from_slice(&bytes)
                .with_context(|| format!("GitHub search response was not valid JSON for {label}"))
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
                serde_json::from_slice(&entry.bytes)
                    .with_context(|| format!("cached GitHub search was not valid JSON for {label}"))
            }
            Ok(None) => Err(err).with_context(|| {
                format!(
                    "request failed for {label}: {}",
                    cfg.github_search_repositories_url
                )
            }),
            Err(cache_err) => Err(err).with_context(|| {
                format!(
                    "request failed for {label}: {}; stale fallback rejected: {cache_err:#}",
                    cfg.github_search_repositories_url
                )
            }),
        },
    }
}

pub(crate) fn is_cve_id(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();
    parts.len() == 3
        && parts[0].eq_ignore_ascii_case("CVE")
        && parts[1].len() == 4
        && parts[1].chars().all(|ch| ch.is_ascii_digit())
        && parts[2].len() >= 4
        && parts[2].chars().all(|ch| ch.is_ascii_digit())
}

pub(crate) fn map_github_latest_poc_candidates(repo: &Value) -> Vec<Value> {
    let full_name = match repo.get("full_name").and_then(|v| v.as_str()) {
        Some(value) => value.trim(),
        None => return Vec::new(),
    };
    let description = repo
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let topics = repo
        .get("topics")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let text = format!(
        "{} {} {}",
        full_name.to_ascii_lowercase(),
        description.to_ascii_lowercase(),
        topics.to_ascii_lowercase()
    );

    if github_poc_negative_match(&text) || !github_latest_poc_positive_signal(&text) {
        return Vec::new();
    }

    let cve_ids = extract_cve_ids(&text);
    if cve_ids.is_empty() {
        return Vec::new();
    }

    let stars = repo
        .get("stargazers_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let forks = repo
        .get("forks_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let updated_at = repo
        .get("updated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let created_at = repo
        .get("created_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let pushed_at = repo
        .get("pushed_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let language = repo
        .get("language")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let published_ts = parse_rfc3339_timestamp(&created_at).unwrap_or(0).max(0) as u64;
    let updated_ts = parse_rfc3339_timestamp(&updated_at).unwrap_or(0).max(0) as u64;
    let score = github_poc_score(stars, forks, &created_at, &updated_at, &text);
    let risk = if score >= 78 {
        "high"
    } else if score >= 50 {
        "medium"
    } else {
        "watch"
    };
    let repo_type = github_poc_repo_type(&text);
    let repo_type_label = github_poc_repo_type_label(repo_type);
    let age_days = poc_age_days(&created_at);
    let (author, repo_name) = full_name
        .split_once('/')
        .map(|(owner, name)| (owner.to_string(), name.to_string()))
        .unwrap_or_else(|| (full_name.to_string(), full_name.to_string()));
    let repo_url = repo
        .get("html_url")
        .and_then(|v| v.as_str())
        .map(|value| value.to_string())
        .unwrap_or_else(|| format!("https://github.com/{full_name}"));
    cve_ids
        .into_iter()
        .map(|cve_id| {
            let title = format!("{} latest public PoC metadata", cve_id);
            json!({
                "cve_id": cve_id,
                "repo": full_name,
                "repo_safe": full_name,
                "author": author.clone(),
                "repo_name": repo_name.clone(),
                "repo_url": repo_url.clone(),
                "github_path": format!("github.com/{full_name}"),
                "url_rendered": true,
                "title": title,
                "description": concise_text(description, 180),
                "stars": stars,
                "forks": forks,
                "language": language.clone(),
                "created_at": created_at.clone(),
                "published_at": created_at.clone(),
                "published_date": tehran_date_for_timestamp(&created_at)
                    .map(|date| date.format("%Y-%m-%d").to_string())
                    .unwrap_or_default(),
                "published_date_utc": iso_date_prefix(&created_at).unwrap_or("").to_string(),
                "published_ts": published_ts,
                "updated_at": updated_at.clone(),
                "updated_ts": updated_ts,
                "pushed_at": pushed_at.clone(),
                "age_days": age_days,
                "repo_type": repo_type,
                "repo_type_label": repo_type_label,
                "risk": risk,
                "score": score,
                "bar_width": score,
                "safe_mode": "metadata only; no code, no raw URL, no clone/download command",
                "tags": github_poc_tags(repo_type, risk, age_days)
            })
        })
        .collect()
}

pub(crate) fn retain_pocs_published_on_day(items: &mut Vec<Value>, target_date: &str) {
    items.retain(|item| {
        item.get("published_at")
            .and_then(|value| value.as_str())
            .map(|published_at| timestamp_is_tehran_day(published_at, target_date))
            .unwrap_or(false)
    });
}

pub(crate) fn iso_date_prefix(value: &str) -> Option<&str> {
    if value.len() < 10 {
        return None;
    }
    let prefix = &value[..10];
    let bytes = prefix.as_bytes();
    let is_yyyy_mm_dd = bytes[0].is_ascii_digit()
        && bytes[1].is_ascii_digit()
        && bytes[2].is_ascii_digit()
        && bytes[3].is_ascii_digit()
        && bytes[4] == b'-'
        && bytes[5].is_ascii_digit()
        && bytes[6].is_ascii_digit()
        && bytes[7] == b'-'
        && bytes[8].is_ascii_digit()
        && bytes[9].is_ascii_digit();
    if is_yyyy_mm_dd {
        Some(prefix)
    } else {
        None
    }
}

pub(crate) fn extract_cve_ids(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut values = Vec::new();
    let mut seen = HashSet::new();
    let mut index = 0usize;

    while index + 9 <= bytes.len() {
        let has_cve_prefix = index + 4 <= bytes.len()
            && bytes[index].eq_ignore_ascii_case(&b'c')
            && bytes[index + 1].eq_ignore_ascii_case(&b'v')
            && bytes[index + 2].eq_ignore_ascii_case(&b'e')
            && bytes[index + 3] == b'-';
        if has_cve_prefix {
            let mut end = index + 4;
            let year_start = end;
            while end < bytes.len() && bytes[end].is_ascii_digit() && end - year_start < 4 {
                end += 1;
            }
            if end - year_start == 4 && end < bytes.len() && bytes[end] == b'-' {
                end += 1;
                let id_start = end;
                while end < bytes.len() && bytes[end].is_ascii_digit() {
                    end += 1;
                }
                if end - id_start >= 4 {
                    let cve_id = String::from_utf8_lossy(&bytes[index..end]).to_ascii_uppercase();
                    if is_cve_id(&cve_id) && seen.insert(cve_id.clone()) {
                        values.push(cve_id);
                    }
                    index = end;
                    continue;
                }
            }
        }
        index += 1;
    }

    values
}

pub(crate) fn github_poc_negative_match(text: &str) -> bool {
    [
        "advisory-database",
        "cvelist",
        "cve-list",
        "cve database",
        "cve dictionary",
        "nvd mirror",
        "vulnerability database",
        "vuldb",
        "oval definitions",
        "nessus plugin",
        "scanner collection",
        "awesome-cve",
        "poc-in-github",
        "nomi-sec",
        "trickest",
        "nuclei-templates",
        "template collection",
        "exploitdb mirror",
        "packetstorm mirror",
        "weekly roundup",
        "monthly roundup",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

pub(crate) fn github_latest_poc_positive_signal(text: &str) -> bool {
    [
        "poc",
        "proof-of-concept",
        "proof of concept",
        "exploit",
        "exp",
        "rce",
        "privilege escalation",
        "local privilege escalation",
        "lpe",
        "weaponized",
        "reproducer",
        "trigger",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

pub(crate) fn github_poc_repo_type(text: &str) -> &'static str {
    if text.contains("proof-of-concept")
        || text.contains("proof of concept")
        || text.contains("poc")
    {
        "poc"
    } else if text.contains("exploit")
        || text.contains("rce")
        || text.contains("privilege escalation")
    {
        "exploit-metadata"
    } else if text.contains("reproducer") || text.contains("trigger") {
        "reproducer"
    } else {
        "public-reference"
    }
}

pub(crate) fn github_poc_repo_type_label(repo_type: &str) -> &'static str {
    match repo_type {
        "poc" => "PoC",
        "exploit-metadata" => "EXP",
        "reproducer" => "REPRO",
        _ => "REF",
    }
}

pub(crate) fn github_poc_score(
    stars: u64,
    forks: u64,
    created_at: &str,
    updated_at: &str,
    text: &str,
) -> u64 {
    let mut score = 24_u64;
    score += stars.min(80) / 4;
    score += forks.min(40) / 4;
    if text.contains("exploit") || text.contains("rce") {
        score += 16;
    } else if text.contains("poc")
        || text.contains("proof-of-concept")
        || text.contains("proof of concept")
    {
        score += 12;
    }
    if text.contains("weaponized") {
        score += 10;
    }
    if text.contains("reproducer") || text.contains("trigger") {
        score += 6;
    }

    let age_days = poc_age_days(created_at);
    if age_days <= 1 {
        score += 24;
    } else if age_days <= 3 {
        score += 18;
    } else if age_days <= 7 {
        score += 12;
    } else if age_days <= 30 {
        score += 6;
    }

    let updated_ts = parse_rfc3339_timestamp(updated_at).unwrap_or(0);
    let created_ts = parse_rfc3339_timestamp(created_at).unwrap_or(0);
    if created_ts > 0 && updated_ts >= created_ts && updated_ts - created_ts <= 604_800 {
        score += 4;
    }

    score.clamp(12, 100)
}

pub(crate) fn poc_age_days(timestamp: &str) -> u64 {
    let event_ts = parse_rfc3339_timestamp(timestamp).unwrap_or(0);
    if event_ts <= 0 {
        return 365;
    }
    ((Utc::now().timestamp() - event_ts).max(0) / 86_400) as u64
}

pub(crate) fn parse_rfc3339_timestamp(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.timestamp())
}

pub(crate) fn github_poc_tags(repo_type: &str, risk: &str, age_days: u64) -> Vec<String> {
    let mut tags = vec![
        "latest-first".to_string(),
        repo_type.to_string(),
        risk.to_string(),
    ];
    if age_days <= 7 {
        tags.push("fresh".to_string());
    }
    tags
}

pub(crate) fn empty_poc_watch(reason: &str) -> Value {
    json!({
        "enabled": reason != "disabled",
        "ok": false,
        "provider": "GitHub Repository Search API",
        "source": reason,
        "mode": "current_day_poc_stream",
        "window_mode": "published-day-only",
        "date": tehran_now().date_naive().format("%Y-%m-%d").to_string(),
        "window_days": 0,
        "empty_message": "No public PoC repositories were published for today's dashboard date.",
        "safe_mode": "metadata only; no exploit code; no raw links; no clone/download commands; repository links are rendered for triage",
        "summary": "PoC Watch has no data for this run.",
        "totals": {
            "cves_checked": 0,
            "cves_with_poc": 0,
            "repos": 0,
            "high": 0,
            "fresh": 0,
            "raw_candidates": 0,
            "today_candidates": 0,
            "filtered_other_days": 0,
            "kev_related": 0,
            "epss_rising_related": 0,
            "queries": 0,
            "cache_misses": 0,
            "errors": 0
        },
        "repos": [],
        "cve_chart": [],
        "risk_chart": [],
        "errors": []
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_cve_id_validates_shape() {
        assert!(is_cve_id("CVE-2026-1234"));
        assert!(is_cve_id("cve-2026-123456"));
        assert!(!is_cve_id("CVE-26-1234"));
        assert!(!is_cve_id("CVE-2026-123"));
        assert!(!is_cve_id("CVE-2026-12a4"));
        assert!(!is_cve_id("not-a-cve"));
    }

    #[test]
    fn extract_cve_ids_uppercases_and_deduplicates() {
        let text = "Fixes cve-2026-1234 and CVE-2026-1234, also CVE-2025-99999.";
        assert_eq!(
            extract_cve_ids(text),
            vec!["CVE-2026-1234".to_string(), "CVE-2025-99999".to_string()]
        );
        assert!(extract_cve_ids("no identifiers here").is_empty());
        assert!(extract_cve_ids("CVE-2026-12").is_empty());
    }

    #[test]
    fn retain_pocs_published_on_day_uses_tehran_boundaries() {
        let mut repos = vec![
            json!({"repo": "before/start", "published_at": "2026-07-07T20:29:59Z"}),
            json!({"repo": "at/start", "published_at": "2026-07-07T20:30:00Z"}),
            json!({"repo": "before/end", "published_at": "2026-07-08T20:29:59Z"}),
            json!({"repo": "at/end", "published_at": "2026-07-08T20:30:00Z"}),
            json!({"repo": "missing/time", "published_at": ""}),
        ];
        retain_pocs_published_on_day(&mut repos, "2026-07-08");
        let names: Vec<&str> = repos
            .iter()
            .filter_map(|repo| repo.get("repo").and_then(|value| value.as_str()))
            .collect();
        assert_eq!(names, vec!["at/start", "before/end"]);
    }

    #[test]
    fn latest_poc_search_queries_cover_both_utc_dates_for_tehran_day() {
        let queries = latest_poc_search_queries("2026-07-08");
        assert_eq!(queries.len(), 8);
        assert_eq!(
            queries
                .iter()
                .filter(|query| query.contains("created:2026-07-07"))
                .count(),
            4
        );
        assert_eq!(
            queries
                .iter()
                .filter(|query| query.contains("created:2026-07-08"))
                .count(),
            4
        );
        assert!(queries.iter().all(|query| !query.contains("created:>=")));
    }
}
