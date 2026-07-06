//! OpenPhish passive phishing pulse.

use crate::prelude::*;

pub(crate) fn fetch_phishing_pulse_or_fallback(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Value {
    if !config.intel.enabled || !config.intel.phishing.enabled {
        return empty_phishing_pulse("disabled");
    }

    match fetch_phishing_pulse(config, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  Phishing Pulse skipped: {err:#}");
            empty_phishing_pulse("error")
        }
    }
}

pub(crate) fn fetch_phishing_pulse(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
    let client = Client::builder()
        .timeout(Duration::from_secs(22))
        .user_agent(&config.fetch.user_agent)
        .build()
        .context("failed to build HTTP client for Phishing Pulse")?;

    let cfg = &config.intel.phishing;
    eprintln!("→ fetching Phishing Pulse");
    let bytes = get_bytes_cached_intel(
        &client,
        config,
        &cfg.openphish_feed_url,
        "OpenPhish community feed",
        offline,
        refresh_cache,
    )?;
    let text = String::from_utf8_lossy(&bytes);
    let mut indicators = parse_openphish_feed(&text, cfg.max_urls);
    finalize_phishing_indicators(&mut indicators);

    let high = indicators.iter().filter(|item| item.risk == "high").count();
    let tlds = indicators
        .iter()
        .map(|item| item.tld.clone())
        .collect::<HashSet<_>>()
        .len();
    let brands = indicators
        .iter()
        .map(|item| item.brand_hint.clone())
        .collect::<HashSet<_>>()
        .len();
    let tld_chart = phishing_tld_chart(&indicators, 8);
    let brand_chart = phishing_brand_chart(&indicators, 8);
    let risk_chart = phishing_risk_chart(&indicators);
    let level = if high >= 6 {
        "High"
    } else if indicators.len() >= 10 {
        "Medium"
    } else if indicators.is_empty() {
        "Unknown"
    } else {
        "Watch"
    };
    let summary_fa = if indicators.is_empty() {
        "در این اجرا URL فیشینگ تازه‌ای از feed عمومی دریافت نشد.".to_string()
    } else if high > 0 {
        format!("{} URL فیشینگ فعال از OpenPhish دریافت شد؛ {} مورد پرریسک lexical/host دیده می‌شود. همه URLها defanged هستند.", indicators.len(), high)
    } else {
        format!("{} URL فیشینگ فعال از OpenPhish دریافت شد؛ خروجی فقط برای آگاهی و correlation دفاعی است.", indicators.len())
    };

    Ok(json!({
        "enabled": true,
        "ok": true,
        "provider": "OpenPhish Community Feed",
        "level": level,
        "summary_fa": summary_fa,
        "last_updated": tehran_now().format("%Y-%m-%d %H:%M").to_string(),
        "metadata_only": true,
        "defanged": true,
        "totals": {
            "urls": indicators.len(),
            "high": high,
            "tlds": tlds,
            "brands": brands
        },
        "urls": indicators,
        "tld_chart": tld_chart,
        "brand_chart": brand_chart,
        "risk_chart": risk_chart,
    }))
}

pub(crate) fn parse_openphish_feed(text: &str, limit: usize) -> Vec<PhishingUrlIndicator> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines() {
        let url = line.trim().trim_matches('"').trim_matches('\'');
        if url.is_empty() || url.starts_with('#') || !url.contains('.') {
            continue;
        }
        let Some(host) = phishing_host(url) else {
            continue;
        };
        if !seen.insert(url.to_string()) {
            continue;
        }
        let tld = phishing_tld(&host);
        let brand_hint = phishing_brand_hint(url, &host);
        let scheme = if url.to_lowercase().starts_with("https://") {
            "https"
        } else if url.to_lowercase().starts_with("http://") {
            "http"
        } else {
            "unknown"
        };
        let path_depth = phishing_path_depth(url);
        let score = phishing_score(url, &host, scheme, path_depth, &brand_hint);
        let risk = if score >= 76 {
            "high"
        } else if score >= 52 {
            "medium"
        } else {
            "watch"
        };
        out.push(PhishingUrlIndicator {
            rank: 0,
            url_safe: defang_indicator(url),
            host_safe: defang_indicator(&host),
            host,
            tld,
            brand_hint,
            scheme: scheme.to_string(),
            path_depth,
            source: "OpenPhish".to_string(),
            risk: risk.to_string(),
            score,
            bar_width: score.clamp(12, 100),
            note_fa: "URL فیشینگ به‌صورت defanged نمایش داده شده؛ آن را باز نکن و فقط برای correlation دفاعی استفاده کن.".to_string(),
        });
        if out.len() >= limit.max(1) {
            break;
        }
    }
    out
}

pub(crate) fn phishing_host(url: &str) -> Option<String> {
    let mut rest = url.trim();
    if let Some(idx) = rest.find("://") {
        rest = &rest[idx + 3..];
    }
    if let Some(idx) = rest.find('@') {
        rest = &rest[idx + 1..];
    }
    let host_port = rest
        .split(|ch| ch == '/' || ch == '?' || ch == '#')
        .next()
        .unwrap_or("");
    let host = host_port
        .trim_matches('[')
        .trim_matches(']')
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .trim_start_matches("www.")
        .to_lowercase();
    if host.is_empty() || !host.contains('.') {
        None
    } else {
        Some(truncate_chars(&host, 80))
    }
}

pub(crate) fn phishing_tld(host: &str) -> String {
    host.rsplit('.')
        .next()
        .filter(|part| !part.is_empty())
        .map(|part| truncate_chars(part, 16))
        .unwrap_or_else(|| "unknown".to_string())
}

pub(crate) fn phishing_path_depth(url: &str) -> usize {
    let rest = if let Some(idx) = url.find("://") {
        &url[idx + 3..]
    } else {
        url
    };
    let path = rest.splitn(2, '/').nth(1).unwrap_or("");
    path.split('/')
        .filter(|part| !part.trim().is_empty())
        .count()
}

pub(crate) fn phishing_brand_hint(url: &str, host: &str) -> String {
    let lower = format!("{} {}", url.to_lowercase(), host.to_lowercase());
    let pairs = [
        ("microsoft", "Microsoft/Cloud"),
        ("office", "Microsoft/Cloud"),
        ("outlook", "Microsoft/Cloud"),
        ("onedrive", "Microsoft/Cloud"),
        ("paypal", "Payments"),
        ("bank", "Banking"),
        ("wallet", "Crypto/Wallet"),
        ("crypto", "Crypto/Wallet"),
        ("facebook", "Meta/Social"),
        ("instagram", "Meta/Social"),
        ("meta", "Meta/Social"),
        ("google", "Google/Cloud"),
        ("apple", "Apple"),
        ("amazon", "Amazon/Retail"),
        ("netflix", "Streaming"),
        ("telegram", "Messaging"),
        ("whatsapp", "Messaging"),
        ("login", "Credential Harvest"),
        ("verify", "Credential Harvest"),
        ("account", "Credential Harvest"),
    ];
    for (needle, label) in pairs {
        if lower.contains(needle) {
            return label.to_string();
        }
    }
    "Unknown target".to_string()
}

pub(crate) fn phishing_score(
    url: &str,
    host: &str,
    scheme: &str,
    path_depth: usize,
    brand_hint: &str,
) -> usize {
    let mut score = 42_usize;
    let lower = url.to_lowercase();
    if scheme == "http" {
        score += 10;
    }
    if host.chars().filter(|ch| *ch == '.').count() >= 3 {
        score += 8;
    }
    if host.split('.').any(|part| part.parse::<u8>().is_ok()) {
        score += 10;
    }
    if path_depth >= 4 {
        score += 10;
    }
    if lower.len() > 120 {
        score += 8;
    }
    for needle in [
        "login", "verify", "account", "secure", "update", "wallet", "password", "invoice",
    ] {
        if lower.contains(needle) {
            score += 6;
            break;
        }
    }
    if brand_hint != "Unknown target" {
        score += 8;
    }
    score.min(100).max(12)
}

pub(crate) fn finalize_phishing_indicators(items: &mut [PhishingUrlIndicator]) {
    items.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.host.cmp(&b.host)));
    let max_score = items
        .iter()
        .map(|item| item.score)
        .max()
        .unwrap_or(1)
        .max(1);
    for (idx, item) in items.iter_mut().enumerate() {
        item.rank = idx + 1;
        item.url_safe = defang_indicator(
            &item
                .url_safe
                .replace("hxxps://", "https://")
                .replace("hxxp://", "http://")
                .replace("[.]", "."),
        );
        item.host_safe = defang_indicator(&item.host);
        item.bar_width =
            (((item.score as f64 / max_score as f64) * 100.0).round() as usize).clamp(12, 100);
    }
}

pub(crate) fn phishing_tld_chart(items: &[PhishingUrlIndicator], limit: usize) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for item in items {
        *counts.entry(item.tld.clone()).or_insert(0) += 1;
    }
    count_chart_from_counts(counts, limit)
}

pub(crate) fn phishing_brand_chart(items: &[PhishingUrlIndicator], limit: usize) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for item in items {
        *counts.entry(item.brand_hint.clone()).or_insert(0) += 1;
    }
    count_chart_from_counts(counts, limit)
}

pub(crate) fn phishing_risk_chart(items: &[PhishingUrlIndicator]) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for item in items {
        *counts.entry(item.risk.clone()).or_insert(0) += 1;
    }
    count_chart_from_counts(counts, 4)
}

pub(crate) fn empty_phishing_pulse(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "OpenPhish Community Feed",
        "level": "Unknown",
        "summary_fa": "داده Phishing Pulse در این اجرا در دسترس نبود.",
        "last_updated": "",
        "metadata_only": true,
        "defanged": true,
        "totals": {"urls": 0, "high": 0, "tlds": 0, "brands": 0},
        "urls": [],
        "tld_chart": [],
        "brand_chart": [],
        "risk_chart": []
    })
}
