//! Ransomware.live victims pulse.

use crate::prelude::*;

pub(crate) fn fetch_ransomware_pulse_or_fallback(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Value {
    if !config.intel.enabled || !config.intel.ransomware.enabled {
        return empty_ransomware_pulse("disabled");
    }

    match fetch_ransomware_pulse(config, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  Ransomware Pulse skipped: {err:#}");
            let mut fallback = empty_ransomware_pulse("error");
            fallback["error"] = json!(err.to_string());
            fallback
        }
    }
}

pub(crate) fn fetch_ransomware_pulse(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
    eprintln!("→ fetching Ransomware Pulse");
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(45))
        .build()
        .context("failed to build HTTP client for Ransomware Pulse")?;

    let rw = &config.intel.ransomware;
    let mut urls = Vec::new();
    let configured = rw.recent_victims_url.trim_end_matches('/').to_string();
    if configured.contains('?') {
        urls.push(format!("{}&limit={}", configured, rw.max_victims.max(1)));
    } else {
        urls.push(format!("{}?limit={}", configured, rw.max_victims.max(1)));
        urls.push(configured.clone());
    }
    let base = "https://api.ransomware.live/v2";
    urls.push(format!(
        "{base}/victims/recent?limit={}",
        rw.max_victims.max(1)
    ));
    urls.push(format!("{base}/recentvictims/{}", rw.max_victims.max(1)));

    let mut last_error: Option<anyhow::Error> = None;
    let mut body = None;
    for (idx, url) in urls.into_iter().enumerate() {
        let label = if idx == 0 {
            "Ransomware.live recent victims".to_string()
        } else {
            format!("Ransomware.live fallback endpoint {idx}")
        };
        match get_bytes_cached_intel(&client, config, &url, &label, offline, refresh_cache) {
            Ok(bytes) => {
                body = Some(bytes);
                break;
            }
            Err(err) => {
                last_error = Some(err);
            }
        }
    }

    let bytes = body.ok_or_else(|| {
        last_error.unwrap_or_else(|| anyhow::anyhow!("no Ransomware.live endpoint returned data"))
    })?;
    let raw: Value =
        serde_json::from_slice(&bytes).context("Ransomware.live response was not valid JSON")?;
    let rows = extract_ransomware_rows(&raw);

    let mut seen = HashSet::new();
    let mut victims = Vec::new();
    for row in rows {
        if let Some(victim) = map_ransomware_victim(row) {
            let key = format!(
                "{}:{}",
                victim.group.to_lowercase(),
                victim.victim_safe.to_lowercase()
            );
            if seen.insert(key) {
                victims.push(victim);
            }
        }
    }

    victims.sort_by(|a, b| {
        b.recency_score
            .cmp(&a.recency_score)
            .then_with(|| a.group.cmp(&b.group))
    });
    victims.truncate(rw.max_victims);
    finalize_ransomware_victims(&mut victims);

    let mut group_counts = HashMap::new();
    let mut country_counts = HashMap::new();
    let mut sector_counts = HashMap::new();
    let mut activity_counts = HashMap::new();
    let mut recent_24h = 0usize;
    let mut recent_7d = 0usize;

    for victim in &victims {
        *group_counts.entry(victim.group.clone()).or_insert(0) += 1;
        if victim.country != "unknown" {
            *country_counts.entry(victim.country.clone()).or_insert(0) += 1;
        }
        if victim.sector != "unknown" {
            *sector_counts.entry(victim.sector.clone()).or_insert(0) += 1;
        }
        if !victim.claimed_date.is_empty() && victim.claimed_date != "unknown" {
            *activity_counts
                .entry(victim.claimed_date.clone())
                .or_insert(0) += 1;
        }
        if victim.recency_score >= 90 {
            recent_24h += 1;
        }
        if victim.recency_score >= 55 {
            recent_7d += 1;
        }
    }

    let total = victims.len();
    let level = if recent_24h >= 3 || total >= 20 {
        "High"
    } else if recent_7d >= 6 || total >= 10 {
        "Medium"
    } else if total > 0 {
        "Watch"
    } else {
        "Low"
    };
    let summary_fa = if total == 0 {
        "در این اجرا claim تازه قابل نمایش از Ransomware.live دریافت نشد.".to_string()
    } else {
        format!("{total} claim عمومی ransomware از Ransomware.live وارد رادار شد؛ {recent_7d} مورد در بازه نزدیک به ۷ روز اخیر دیده می‌شود.")
    };

    Ok(json!({
        "enabled": true,
        "ok": total > 0,
        "provider": "Ransomware.live public API",
        "level": level,
        "summary_fa": summary_fa,
        "last_updated": Local::now().format("%Y-%m-%d %H:%M").to_string(),
        "refresh_hours": config.intel.refresh_hours,
        "totals": {
            "victims": total,
            "groups": group_counts.len(),
            "countries": country_counts.len(),
            "sectors": sector_counts.len(),
            "recent_24h": recent_24h,
            "recent_7d": recent_7d
        },
        "victims": victims,
        "group_chart": count_chart_from_counts(group_counts, 8),
        "country_chart": count_chart_from_counts(country_counts, 8),
        "sector_chart": count_chart_from_counts(sector_counts, 8),
        "activity_chart": count_chart_from_counts(activity_counts, 10),
        "source_health": {
            "cache_dir": config.intel.cache_dir.clone(),
            "refresh_hours": config.intel.refresh_hours,
            "sources": ["Ransomware.live recent victims"]
        }
    }))
}

pub(crate) fn extract_ransomware_rows(value: &Value) -> Vec<&Value> {
    if let Some(items) = value.as_array() {
        return items.iter().collect();
    }
    for key in ["victims", "data", "results", "items", "recent", "posts"] {
        if let Some(items) = value.get(key).and_then(|v| v.as_array()) {
            return items.iter().collect();
        }
    }
    Vec::new()
}

pub(crate) fn map_ransomware_victim(row: &Value) -> Option<RansomwareVictim> {
    let victim_name = first_text(row, &["victim", "name", "post_title", "title", "company"])?;
    let group = first_text(
        row,
        &["group", "group_name", "ransomware", "actor", "family"],
    )
    .unwrap_or_else(|| "unknown".to_string());
    let country = first_text(
        row,
        &["country", "country_code", "countrycode", "country_name"],
    )
    .unwrap_or_else(|| "unknown".to_string());
    let sector = first_text(row, &["sector", "activity", "industry", "business_sector"])
        .unwrap_or_else(|| "unknown".to_string());
    let raw_date = first_text(
        row,
        &[
            "attackdate",
            "date",
            "discovered",
            "published",
            "published_at",
            "created_at",
            "updated",
            "updated_at",
        ],
    )
    .unwrap_or_default();
    let claimed_date = normalize_claim_date(&raw_date).unwrap_or_else(|| {
        if raw_date.is_empty() {
            "unknown".to_string()
        } else {
            truncate_chars(&raw_date, 20)
        }
    });
    let recency_score = ransomware_recency_score(&claimed_date);
    let critical_sector = is_critical_ransomware_sector(&sector);
    let risk = if recency_score >= 90 || critical_sector {
        "high"
    } else if recency_score >= 55 {
        "medium"
    } else {
        "watch"
    }
    .to_string();
    let note_fa = ransomware_note(&group, &country, &sector, &claimed_date);

    Some(RansomwareVictim {
        rank: 0,
        victim_safe: sanitize_victim_label(&victim_name),
        group: truncate_chars(&clean_text(&group), 48),
        country: normalize_short_value(&country),
        sector: truncate_chars(&normalize_short_value(&sector), 44),
        claimed_date,
        recency_score,
        risk,
        bar_width: 12,
        note_fa,
    })
}

pub(crate) fn first_text(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(raw) = value.get(*key) {
            if let Some(text) = raw.as_str() {
                let cleaned = clean_text(text);
                if !cleaned.is_empty() {
                    return Some(cleaned);
                }
            } else if raw.is_number() || raw.is_boolean() {
                return Some(raw.to_string());
            }
        }
    }
    None
}

pub(crate) fn sanitize_victim_label(input: &str) -> String {
    let cleaned = clean_text(input);
    let without_url = cleaned
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("www.")
        .to_string();
    truncate_chars(&without_url, 72)
}

pub(crate) fn normalize_short_value(input: &str) -> String {
    let cleaned = clean_text(input);
    if cleaned.is_empty() || cleaned == "-" || cleaned.eq_ignore_ascii_case("null") {
        "unknown".to_string()
    } else {
        truncate_chars(&cleaned, 42)
    }
}

pub(crate) fn normalize_claim_date(raw: &str) -> Option<String> {
    let cleaned = clean_text(raw);
    if cleaned.len() >= 10 {
        let first = &cleaned[..10.min(cleaned.len())];
        if NaiveDate::parse_from_str(first, "%Y-%m-%d").is_ok() {
            return Some(first.to_string());
        }
    }
    for fmt in ["%d/%m/%Y", "%m/%d/%Y", "%Y/%m/%d"] {
        if let Ok(date) = NaiveDate::parse_from_str(&cleaned, fmt) {
            return Some(date.format("%Y-%m-%d").to_string());
        }
    }
    None
}

pub(crate) fn ransomware_recency_score(claimed_date: &str) -> usize {
    let Ok(date) = NaiveDate::parse_from_str(claimed_date, "%Y-%m-%d") else {
        return 30;
    };
    let today = Local::now().date_naive();
    let days = today.signed_duration_since(date).num_days();
    if days <= 1 {
        100
    } else if days <= 3 {
        82
    } else if days <= 7 {
        62
    } else if days <= 14 {
        44
    } else {
        28
    }
}

pub(crate) fn is_critical_ransomware_sector(sector: &str) -> bool {
    let lower = sector.to_lowercase();
    lower.contains("health")
        || lower.contains("hospital")
        || lower.contains("government")
        || lower.contains("education")
        || lower.contains("energy")
        || lower.contains("transport")
        || lower.contains("finance")
        || lower.contains("manufacturing")
}

pub(crate) fn ransomware_note(
    group: &str,
    country: &str,
    sector: &str,
    claimed_date: &str,
) -> String {
    let mut parts = Vec::new();
    if group != "unknown" {
        parts.push(format!("گروه {group}"));
    }
    if country != "unknown" {
        parts.push(format!("کشور {country}"));
    }
    if sector != "unknown" {
        parts.push(format!("بخش {sector}"));
    }
    if claimed_date != "unknown" && !claimed_date.is_empty() {
        parts.push(format!("تاریخ claim {claimed_date}"));
    }
    if parts.is_empty() {
        "claim عمومی ransomware برای آگاهی موقعیتی ثبت شده؛ لینک leak یا محتوای حساس نمایش داده نمی‌شود.".to_string()
    } else {
        format!(
            "{}؛ فقط برای آگاهی موقعیتی و بدون لینک leak نمایش داده شده است.",
            parts.join(" · ")
        )
    }
}

pub(crate) fn finalize_ransomware_victims(victims: &mut [RansomwareVictim]) {
    victims.sort_by(|a, b| {
        b.recency_score
            .cmp(&a.recency_score)
            .then_with(|| a.group.cmp(&b.group))
    });
    let max_score = victims
        .iter()
        .map(|v| v.recency_score)
        .max()
        .unwrap_or(1)
        .max(1);
    for (idx, victim) in victims.iter_mut().enumerate() {
        victim.rank = idx + 1;
        victim.bar_width = (((victim.recency_score as f64 / max_score as f64) * 100.0).round()
            as usize)
            .clamp(12, 100);
    }
}

pub(crate) fn empty_ransomware_pulse(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "Ransomware.live public API",
        "level": "Unknown",
        "summary_fa": "داده Ransomware Pulse در این اجرا در دسترس نبود.",
        "last_updated": "",
        "refresh_hours": 1,
        "totals": {"victims": 0, "groups": 0, "countries": 0, "sectors": 0, "recent_24h": 0, "recent_7d": 0},
        "victims": [],
        "group_chart": [],
        "country_chart": [],
        "sector_chart": [],
        "activity_chart": []
    })
}
