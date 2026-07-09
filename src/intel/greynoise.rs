//! GreyNoise community context.

use crate::prelude::*;

pub(crate) fn fetch_greynoise_context_or_fallback(
    config: &Config,
    infrastructure_radar: &Value,
    botnet_c2_pulse: &Value,
    offline: bool,
    refresh_cache: bool,
) -> Value {
    if !config.intel.enabled || !config.intel.greynoise.enabled {
        return empty_greynoise_context("disabled");
    }

    match fetch_greynoise_context(
        config,
        infrastructure_radar,
        botnet_c2_pulse,
        offline,
        refresh_cache,
    ) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  GreyNoise Context skipped: {err:#}");
            let mut fallback = empty_greynoise_context("error");
            fallback["error"] = json!(err.to_string());
            fallback
        }
    }
}

pub(crate) fn fetch_greynoise_context(
    config: &Config,
    infrastructure_radar: &Value,
    botnet_c2_pulse: &Value,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
    let cfg = &config.intel.greynoise;
    eprintln!("→ fetching GreyNoise Infrastructure Context");

    if offline {
        if let Some(value) = read_greynoise_context_aggregate(config)? {
            eprintln!("  ↳ cache hit: GreyNoise Context aggregate");
            return Ok(value);
        }
    }

    let client = build_client(config)?;

    let candidates =
        greynoise_candidates_from_signals(infrastructure_radar, botnet_c2_pulse, cfg.max_lookups);
    if candidates.is_empty() {
        return Ok(json!({
            "enabled": true,
            "ok": true,
            "provider": "GreyNoise Community API",
            "source_url": cfg.community_api_url.clone(),
            "level": "Low",
            "summary": "No suitable IPs selected for GreyNoise context lookup in this run.",
            "last_updated": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            "passive_lookup": true,
            "totals": {"checked": 0, "noise": 0, "malicious": 0, "riot": 0, "no_data": 0, "errors": 0, "actionable": 0, "quiet": 0},
            "verdict": "No lookup candidates",
            "spotlight": null,
            "contexts": [],
            "classification_chart": [],
            "noise_chart": [],
            "risk_chart": [],
            "source_chart": []
        }));
    }

    let mut rows = Vec::new();
    let mut no_data = 0usize;
    let mut errors = 0usize;
    for (idx, candidate) in candidates.iter().enumerate() {
        if idx > 0 {
            thread::sleep(Duration::from_millis(config.intel.sleep_ms_between_sources));
        }
        match fetch_greynoise_candidate(&client, config, candidate, offline, refresh_cache) {
            Ok(row) => {
                if row.classification == "unknown" && !row.noise && !row.riot {
                    no_data += 1;
                }
                rows.push(row);
            }
            Err(err) => {
                let text = err.to_string();
                if text.contains("429") || text.to_lowercase().contains("rate") {
                    eprintln!("  ↳ GreyNoise rate limit reached after {} lookup(s); keeping collected context", rows.len());
                    errors += 1;
                    break;
                }
                if !offline {
                    eprintln!("⚠️  skipped GreyNoise {}: {err:#}", candidate.ip);
                }
                errors += 1;
            }
        }
    }

    finalize_greynoise_rows(&mut rows);
    let noise_count = rows.iter().filter(|row| row.noise).count();
    let riot_count = rows.iter().filter(|row| row.riot).count();
    let malicious_count = rows
        .iter()
        .filter(|row| row.classification == "malicious")
        .count();
    let checked = rows.len();
    let actionable_count = rows
        .iter()
        .filter(|row| row.classification == "malicious" || row.noise)
        .count();
    let quiet_count = rows
        .iter()
        .filter(|row| !row.noise && !row.riot && row.classification != "malicious")
        .count();
    let spotlight = rows.first().cloned();
    let verdict = greynoise_verdict(malicious_count, noise_count, riot_count, no_data, checked);

    let level = if malicious_count > 0 || noise_count >= 4 {
        "High"
    } else if noise_count >= 1 || checked >= 4 {
        "Medium"
    } else {
        "Low"
    };

    let summary = match level {
        "High" => "Some infrastructure or C2 IPs flagged as noise or malicious in GreyNoise; this is defensive context only.",
        "Medium" => "Several IPs have observable GreyNoise context; useful for reducing false positives and prioritization.",
        _ => "GreyNoise does not show notable high-risk signals for the selected IPs.",
    };

    let value = json!({
        "enabled": true,
        "ok": errors == 0 || !rows.is_empty(),
        "provider": "GreyNoise Community API",
        "source_url": cfg.community_api_url.clone(),
        "level": level,
        "summary": summary,
        "last_updated": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "passive_lookup": true,
        "rate_limited_possible": true,
        "cached": false,
        "offline_cache": false,
        "totals": {
            "checked": checked,
            "noise": noise_count,
            "malicious": malicious_count,
            "riot": riot_count,
            "no_data": no_data,
            "errors": errors,
            "actionable": actionable_count,
            "quiet": quiet_count
        },
        "verdict": verdict,
        "spotlight": spotlight,
        "contexts": rows,
        "classification_chart": greynoise_classification_chart(&rows),
        "noise_chart": greynoise_noise_chart(&rows),
        "risk_chart": greynoise_risk_chart(&rows),
        "source_chart": greynoise_source_chart(&rows)
    });

    if checked > 0 || errors == 0 {
        if let Err(err) = write_greynoise_context_aggregate(config, &value) {
            eprintln!("⚠️  failed to write GreyNoise aggregate cache: {err:#}");
        }
    }

    Ok(value)
}

pub(crate) fn greynoise_candidates_from_signals(
    infrastructure_radar: &Value,
    botnet_c2_pulse: &Value,
    limit: usize,
) -> Vec<GreyNoiseCandidate> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    if let Some(hosts) = infrastructure_radar
        .get("hosts")
        .and_then(|value| value.as_array())
    {
        for host in hosts {
            let Some(ip) = host.get("ip").and_then(|value| value.as_str()) else {
                continue;
            };
            if !looks_like_ipv4(ip) || !seen.insert(ip.to_string()) {
                continue;
            }
            out.push(GreyNoiseCandidate {
                ip: ip.to_string(),
                source: host
                    .get("source")
                    .and_then(|value| value.as_str())
                    .unwrap_or("Infrastructure")
                    .to_string(),
                reason: host
                    .get("reason")
                    .and_then(|value| value.as_str())
                    .unwrap_or("suspicious infrastructure")
                    .to_string(),
            });
            if out.len() >= limit {
                return out;
            }
        }
    }

    if let Some(items) = botnet_c2_pulse.get("c2").and_then(|value| value.as_array()) {
        for item in items {
            let Some(ip) = item.get("ip").and_then(|value| value.as_str()) else {
                continue;
            };
            if !looks_like_ipv4(ip) || !seen.insert(ip.to_string()) {
                continue;
            }
            out.push(GreyNoiseCandidate {
                ip: ip.to_string(),
                source: item
                    .get("source")
                    .and_then(|value| value.as_str())
                    .unwrap_or("Botnet C2")
                    .to_string(),
                reason: item
                    .get("malware")
                    .and_then(|value| value.as_str())
                    .unwrap_or("botnet c2")
                    .to_string(),
            });
            if out.len() >= limit {
                return out;
            }
        }
    }

    out
}

pub(crate) fn fetch_greynoise_candidate(
    client: &Client,
    config: &Config,
    candidate: &GreyNoiseCandidate,
    offline: bool,
    refresh_cache: bool,
) -> Result<GreyNoiseContextRow> {
    let bytes =
        get_greynoise_context_cached(client, config, &candidate.ip, offline, refresh_cache)?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("GreyNoise response was not JSON for {}", candidate.ip))?;

    let noise = value
        .get("noise")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let riot = value
        .get("riot")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let mut classification = value
        .get("classification")
        .and_then(|value| value.as_str())
        .unwrap_or(if riot { "benign" } else { "unknown" })
        .to_lowercase();
    if classification.trim().is_empty() {
        classification = "unknown".to_string();
    }
    let name = value
        .get("name")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("unknown")
        .to_string();
    let last_seen = value
        .get("last_seen")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();

    let (risk, score) = greynoise_risk_score(&classification, noise, riot);
    Ok(GreyNoiseContextRow {
        rank: 0,
        ip: candidate.ip.clone(),
        ip_safe: defang_indicator(&candidate.ip),
        source: candidate.source.clone(),
        reason: candidate.reason.clone(),
        classification,
        noise,
        riot,
        name: truncate_chars(&name, 48),
        last_seen,
        risk: risk.to_string(),
        score,
        bar_width: score.clamp(12, 100),
    })
}

pub(crate) fn greynoise_context_aggregate_cache_key() -> String {
    cache_key("greynoise://community-context/aggregate-v1", &[])
}

pub(crate) fn read_greynoise_context_aggregate(config: &Config) -> Result<Option<Value>> {
    let cache_key = greynoise_context_aggregate_cache_key();
    let ttl_minutes = config.intel.refresh_hours.saturating_mul(60).max(60);
    let Some(bytes) = read_cache_from_dir(&config.intel.cache_dir, &cache_key, ttl_minutes, true)?
    else {
        return Ok(None);
    };
    let mut value: Value = serde_json::from_slice(&bytes)
        .context("cached GreyNoise Context aggregate was not valid JSON")?;
    value["cached"] = json!(true);
    value["offline_cache"] = json!(true);
    Ok(Some(value))
}

pub(crate) fn write_greynoise_context_aggregate(config: &Config, value: &Value) -> Result<()> {
    let cache_key = greynoise_context_aggregate_cache_key();
    let bytes =
        serde_json::to_vec(value).context("failed to serialize GreyNoise Context aggregate")?;
    write_cache_to_dir(&config.intel.cache_dir, &cache_key, &bytes)
}

pub(crate) fn get_greynoise_context_cached(
    client: &Client,
    config: &Config,
    ip: &str,
    offline: bool,
    refresh_cache: bool,
) -> Result<Vec<u8>> {
    let cfg = &config.intel.greynoise;
    let url = format!("{}/{}", cfg.community_api_url.trim_end_matches('/'), ip);
    let label = format!("GreyNoise Community {}", ip);
    let cache_key = cache_key(&url, &[]);
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

    let mut request = client.get(&url);
    if let Ok(api_key) = env::var(&cfg.api_key_env) {
        if !api_key.trim().is_empty() {
            request = request.header("key", api_key.trim().to_string());
        }
    }

    let response = request
        .send()
        .with_context(|| format!("request failed for {label}: {url}"))?;
    let status = response.status().as_u16();
    let bytes = response
        .bytes()
        .with_context(|| format!("failed to read response body for {label}"))?
        .to_vec();

    if status == 200 || status == 404 {
        write_cache_to_dir(&config.intel.cache_dir, &cache_key, &bytes)?;
        Ok(bytes)
    } else if let Some(cached) =
        read_cache_from_dir(&config.intel.cache_dir, &cache_key, ttl_minutes, true)?
    {
        eprintln!("⚠️  using stale intel cache for {label}: HTTP {status}");
        Ok(cached)
    } else {
        anyhow::bail!("GreyNoise Community API returned HTTP {status} for {ip}");
    }
}

pub(crate) fn finalize_greynoise_rows(rows: &mut [GreyNoiseContextRow]) {
    rows.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.ip.cmp(&b.ip)));
    let max_score = rows.iter().map(|row| row.score).max().unwrap_or(1).max(1);
    for (idx, row) in rows.iter_mut().enumerate() {
        row.rank = idx + 1;
        row.ip_safe = defang_indicator(&row.ip);
        row.bar_width =
            (((row.score as f64 / max_score as f64) * 100.0).round() as usize).clamp(12, 100);
    }
}

pub(crate) fn greynoise_risk_score(
    classification: &str,
    noise: bool,
    riot: bool,
) -> (&'static str, usize) {
    if classification == "malicious" {
        ("high", 92)
    } else if noise {
        ("medium", 68)
    } else if riot || classification == "benign" {
        ("low", 18)
    } else {
        ("watch", 32)
    }
}

pub(crate) fn greynoise_verdict(
    malicious_count: usize,
    noise_count: usize,
    riot_count: usize,
    no_data: usize,
    checked: usize,
) -> String {
    if malicious_count > 0 {
        format!(
            "{} malicious IP(s) in selected infrastructure",
            malicious_count
        )
    } else if noise_count > 0 {
        format!("{} scanner/noise IP(s) observed", noise_count)
    } else if riot_count > 0 {
        format!("{} benign RIOT IP(s) identified", riot_count)
    } else if checked == 0 {
        "No lookup candidates".to_string()
    } else if no_data >= checked {
        "No GreyNoise context for selected IPs".to_string()
    } else {
        "No malicious GreyNoise classification in this run".to_string()
    }
}

pub(crate) fn greynoise_classification_chart(rows: &[GreyNoiseContextRow]) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for row in rows {
        *counts.entry(row.classification.clone()).or_insert(0) += 1;
    }
    count_chart_from_counts(counts, 5)
}

pub(crate) fn greynoise_risk_chart(rows: &[GreyNoiseContextRow]) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for row in rows {
        *counts.entry(row.risk.clone()).or_insert(0) += 1;
    }
    count_chart_from_counts(counts, 4)
}

pub(crate) fn greynoise_source_chart(rows: &[GreyNoiseContextRow]) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for row in rows {
        *counts.entry(row.source.clone()).or_insert(0) += 1;
    }
    count_chart_from_counts(counts, 5)
}

pub(crate) fn greynoise_noise_chart(rows: &[GreyNoiseContextRow]) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for row in rows {
        let key = if row.noise {
            "noise"
        } else if row.riot {
            "riot"
        } else {
            "quiet"
        };
        *counts.entry(key.to_string()).or_insert(0) += 1;
    }
    count_chart_from_counts(counts, 4)
}

pub(crate) fn empty_greynoise_context(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "GreyNoise Community API",
        "level": "Unknown",
        "summary": "GreyNoise Context data was not available this run.",
        "last_updated": "",
        "passive_lookup": true,
        "totals": {"checked": 0, "noise": 0, "malicious": 0, "riot": 0, "no_data": 0, "errors": 0, "actionable": 0, "quiet": 0},
        "verdict": "GreyNoise Context data was not available this run.",
        "spotlight": null,
        "contexts": [],
        "classification_chart": [],
        "noise_chart": [],
        "risk_chart": [],
        "source_chart": []
    })
}
