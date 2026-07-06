//! Spamhaus DROP hostile netblock pulse (observation-only).

use crate::prelude::*;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DropRange {
    pub(crate) rank: usize,
    pub(crate) cidr: String,
    pub(crate) cidr_safe: String,
    pub(crate) sblid: String,
    pub(crate) rir: String,
    pub(crate) prefix_len: u32,
    pub(crate) est_ips: u64,
    pub(crate) risk: String,
    pub(crate) score: usize,
    pub(crate) bar_width: usize,
    pub(crate) note_fa: String,
}

pub(crate) fn fetch_drop_pulse_or_fallback(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Value {
    if !config.intel.enabled || !config.intel.spamhaus_drop.enabled {
        return empty_drop_pulse("disabled");
    }

    match fetch_drop_pulse(config, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  DROP Pulse skipped: {err:#}");
            empty_drop_pulse("error")
        }
    }
}

pub(crate) fn fetch_drop_pulse(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(24))
        .build()
        .context("failed to build HTTP client for DROP Pulse")?;

    let cfg = &config.intel.spamhaus_drop;
    eprintln!("→ fetching Spamhaus DROP Pulse");
    let bytes = get_bytes_cached_intel(
        &client,
        config,
        &cfg.drop_v4_url,
        "Spamhaus DROP v4 list",
        offline,
        refresh_cache,
    )?;
    let text = String::from_utf8_lossy(&bytes);
    let mut ranges = parse_drop_v4_jsonl(&text);
    finalize_drop_ranges(&mut ranges);

    let total_ranges = ranges.len();
    let total_ips = ranges.iter().map(|item| item.est_ips).sum::<u64>();
    let rir_names = ranges
        .iter()
        .map(|item| item.rir.clone())
        .collect::<Vec<_>>();
    let rir_chart = count_chart_names(&rir_names, 6);
    let rirs = rir_names.iter().collect::<HashSet<_>>().len();
    let big_ranges = ranges.iter().filter(|item| item.prefix_len <= 18).count();
    ranges.truncate(cfg.max_ranges.max(1));

    let level = if total_ranges >= 900 || big_ranges >= 40 {
        "High"
    } else if total_ranges >= 200 {
        "Medium"
    } else if total_ranges == 0 {
        "Unknown"
    } else {
        "Watch"
    };
    let summary_fa = if total_ranges == 0 {
        "در این اجرا داده‌ای از فهرست Spamhaus DROP دریافت نشد.".to_string()
    } else {
        format!(
            "{} رنج IP خصمانه (حدود {} میلیون آدرس) در فهرست DROP است؛ بزرگ‌ترین رنج‌ها نمایش داده شده‌اند؛ در شبکه سالم نباید ترافیکی به/از آنها دیده شود.",
            total_ranges,
            (total_ips / 1_000_000).max(1)
        )
    };

    Ok(json!({
        "enabled": true,
        "ok": true,
        "provider": "Spamhaus DROP v4",
        "level": level,
        "summary_fa": summary_fa,
        "last_updated": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "metadata_only": true,
        "totals": {
            "ranges": total_ranges,
            "shown": ranges.len(),
            "rirs": rirs,
            "big_ranges": big_ranges,
            "est_ips": total_ips
        },
        "ranges": ranges,
        "rir_chart": rir_chart
    }))
}

pub(crate) fn parse_drop_v4_jsonl(text: &str) -> Vec<DropRange> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(row) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if row.get("type").is_some() {
            continue;
        }
        let Some(cidr) = row.get("cidr").and_then(|value| value.as_str()) else {
            continue;
        };
        if !cidr.contains('/') || !seen.insert(cidr.to_string()) {
            continue;
        }
        let sblid = row
            .get("sblid")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let rir = row
            .get("rir")
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("unknown")
            .to_uppercase();
        let prefix_len = cidr
            .rsplit('/')
            .next()
            .and_then(|part| part.parse::<u32>().ok())
            .unwrap_or(32)
            .min(32);
        let est_ips = 1u64 << (32 - prefix_len);

        out.push(DropRange {
            rank: out.len() + 1,
            cidr_safe: defang_indicator(cidr),
            cidr: cidr.to_string(),
            sblid,
            rir,
            prefix_len,
            est_ips,
            risk: "watch".to_string(),
            score: 0,
            bar_width: 0,
            note_fa: String::new(),
        });
    }
    out
}

pub(crate) fn finalize_drop_ranges(items: &mut Vec<DropRange>) {
    items.sort_by(|a, b| b.est_ips.cmp(&a.est_ips).then_with(|| a.cidr.cmp(&b.cidr)));
    for (idx, item) in items.iter_mut().enumerate() {
        item.rank = idx + 1;
        let spread = 32u32.saturating_sub(item.prefix_len) as usize;
        let mut score = 40 + spread * 4;
        if item.prefix_len <= 16 {
            score += 10;
        }
        item.score = score.clamp(10, 100);
        item.bar_width = item.score;
        item.risk = if item.score >= 78 {
            "high"
        } else if item.score >= 58 {
            "medium"
        } else {
            "watch"
        }
        .to_string();
        item.note_fa = format!(
            "رنج {} در فهرست DROP است؛ فقط برای آگاهی و مسدودسازی دفاعی داخلی استفاده شود.",
            item.cidr_safe
        );
    }
}

pub(crate) fn empty_drop_pulse(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "Spamhaus DROP v4",
        "level": "Unknown",
        "summary_fa": "داده Spamhaus DROP در این اجرا در دسترس نبود.",
        "last_updated": "",
        "metadata_only": true,
        "totals": {"ranges": 0, "shown": 0, "rirs": 0, "big_ranges": 0, "est_ips": 0},
        "ranges": [],
        "rir_chart": []
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_drop_v4_jsonl_skips_metadata_and_ranks_by_size() {
        let lines = [
            "{\"type\":\"metadata\",\"timestamp\":1720000000}",
            "{\"cidr\":\"5.188.10.0/23\",\"sblid\":\"SBL111\",\"rir\":\"ripe\"}",
            "{\"cidr\":\"223.254.0.0/16\",\"sblid\":\"SBL222\",\"rir\":\"apnic\"}",
        ]
        .join("\n");
        let mut ranges = parse_drop_v4_jsonl(&lines);
        assert_eq!(ranges.len(), 2);
        finalize_drop_ranges(&mut ranges);
        assert_eq!(ranges[0].cidr, "223.254.0.0/16");
        assert_eq!(ranges[0].rir, "APNIC");
        assert_eq!(ranges[0].est_ips, 65536);
        assert!(ranges[0].score >= ranges[1].score);
    }
}
