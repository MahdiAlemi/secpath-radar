//! Research write-ups pulse.

use crate::prelude::*;

const WRITEUP_VISIBLE_LIMIT: usize = 20;
const WRITEUP_FALLBACK_DAYS: i64 = 7;

pub(crate) fn build_writeups_pulse(items: &[FeedItem], day: NaiveDate, date_label: &str) -> Value {
    let qualified_candidates: Vec<FeedItem> = items
        .iter()
        .filter(|item| is_writeup_item(item))
        .cloned()
        .collect();
    let total_candidates_all_days = qualified_candidates.len();

    let mut candidates: Vec<FeedItem> = qualified_candidates
        .iter()
        .filter(|item| feed_item_is_local_day(item, day))
        .cloned()
        .collect();
    sort_news_latest_first(&mut candidates);

    let total_candidates = candidates.len();
    let filtered_other_days = total_candidates_all_days.saturating_sub(total_candidates);

    // Phase 472: research blogs publish sporadically, so an empty same-day set is
    // common. On quiet days, fall back to the most recent writeups from the past
    // 7 local days, clearly labeled as recent instead of same-day content.
    let mut fallback_used = false;
    if candidates.is_empty() {
        let mut recent: Vec<FeedItem> = qualified_candidates
            .iter()
            .filter(|item| {
                parse_feed_item_local_time(item)
                    .map(|dt| {
                        let age = day.signed_duration_since(dt.date_naive()).num_days();
                        (1..=WRITEUP_FALLBACK_DAYS).contains(&age)
                    })
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        sort_news_latest_first(&mut recent);
        recent.truncate(WRITEUP_VISIBLE_LIMIT);
        if !recent.is_empty() {
            fallback_used = true;
            candidates = recent;
        }
    }
    let mut source_counts: HashMap<String, usize> = HashMap::new();
    let mut kind_counts: HashMap<String, usize> = HashMap::new();
    for item in &candidates {
        *source_counts.entry(item.source.clone()).or_insert(0) += 1;
        *kind_counts
            .entry(writeup_kind(item).to_string())
            .or_insert(0) += 1;
    }

    let writeups: Vec<Value> = candidates
        .iter()
        .take(WRITEUP_VISIBLE_LIMIT)
        .enumerate()
        .map(|(idx, item)| writeup_item_value(idx + 1, item))
        .collect();
    let visible = writeups.len();
    let hidden = total_candidates.saturating_sub(visible);
    let sources = source_counts.len();
    let kinds = kind_counts.len();
    let source_chart = count_chart(source_counts, 6);
    let kind_chart = count_chart(kind_counts, 6);

    let summary = if visible == 0 {
        format!("No public writeups were published for {date_label} or the preceding {WRITEUP_FALLBACK_DAYS} days.")
    } else if fallback_used {
        format!(
            "No writeups were published on {date_label}; the {visible} most recent from the past {WRITEUP_FALLBACK_DAYS} days are shown instead."
        )
    } else if hidden > 0 {
        format!("{visible} writeups published on {date_label} are shown and {hidden} lower-priority same-day items are hidden for conciseness.")
    } else {
        format!("{visible} writeups from {sources} sources were published on {date_label}; no older-day writeups are backfilled.")
    };

    let window_mode = if fallback_used {
        "recent-7d-fallback"
    } else {
        "local-day-only"
    };
    let count_label = if fallback_used {
        format!("{visible} recent")
    } else {
        format!("{visible} today")
    };

    json!({
        "enabled": true,
        "date": date_label,
        "window_mode": window_mode,
        "fallback": fallback_used,
        "count_label": count_label,
        "source": "Dedicated writeup RSS feeds",
        "safe_mode": "summary and metadata only; no exploit steps; no code execution",
        "summary": summary,
        "totals": {
            "writeups": visible,
            "candidates": total_candidates,
            "all_day_candidates": total_candidates_all_days,
            "filtered_other_days": filtered_other_days,
            "hidden": hidden,
            "sources": sources,
            "kinds": kinds
        },
        "writeups": writeups,
        "source_chart": source_chart,
        "kind_chart": kind_chart
    })
}

pub(crate) fn empty_writeups_pulse(reason: &str) -> Value {
    json!({
        "enabled": false,
        "source": reason,
        "date": "",
        "window_mode": "local-day-only",
        "safe_mode": "summary and metadata only; no exploit steps; no code execution",
        "summary": "Writeups Pulse has no data for this run.",
        "totals": {
            "writeups": 0,
            "candidates": 0,
            "all_day_candidates": 0,
            "filtered_other_days": 0,
            "hidden": 0,
            "sources": 0,
            "kinds": 0
        },
        "writeups": [],
        "source_chart": [],
        "kind_chart": []
    })
}

pub(crate) fn writeup_item_value(rank: usize, item: &FeedItem) -> Value {
    let (published_date_local, published_time_local, freshness_label) =
        news_time_display_fields(&item.published);
    let kind = writeup_kind(item);
    let score = writeup_score(item).clamp(12, 100);
    let risk = if score >= 78 {
        "high"
    } else if score >= 52 {
        "medium"
    } else {
        "watch"
    };

    json!({
        "rank": rank,
        "title": item.title.clone(),
        "summary": item.summary.clone(),
        "source": item.source.clone(),
        "url": item.url.clone(),
        "published": item.published.clone(),
        "published_date_local": published_date_local,
        "published_time_local": published_time_local,
        "freshness_label": freshness_label,
        "kind": kind,
        "risk": risk,
        "risk_score": score,
        "bar_width": score,
        "tags": writeup_tags(item),
        "safe_mode": "metadata only"
    })
}

pub(crate) fn is_writeup_item(item: &FeedItem) -> bool {
    let source = item.source.to_ascii_lowercase();
    let title = item.title.to_ascii_lowercase();
    let summary = item.summary.to_ascii_lowercase();
    let content_tags = item
        .tags
        .iter()
        .filter(|tag| !tag.eq_ignore_ascii_case("Writeup Source"))
        .map(|tag| tag.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    let text = format!("{title} {summary} {content_tags}");

    // Every entry fetched through `writeup_sources` is tagged at ingestion time.
    // Trust that dedicated pipeline instead of maintaining a second, incomplete
    // source allow-list that silently rejected most configured feeds.
    let dedicated_writeup_source = item
        .tags
        .iter()
        .any(|tag| tag.eq_ignore_ascii_case("Writeup Source"));
    if !dedicated_writeup_source {
        return false;
    }

    let hard_negative = [
        "weekly metasploit update",
        "metasploit update",
        "weekly wrap",
        "wrap-up",
        "roundup",
        "in other news",
        "noteworthy stories",
        "podcast",
        "webinar",
        "newsletter",
        "patch tuesday",
        "security update review",
        "release notes",
        "product update",
        "advisory released",
        "continues with community help",
        "conference",
        "event recap",
        "hiring",
        "job",
    ]
    .iter()
    .any(|needle| text.contains(needle));

    if hard_negative {
        return false;
    }

    let explicit_analysis_marker = [
        "writeup",
        "write-up",
        "technical analysis",
        "deep dive",
        "root cause analysis",
        "postmortem",
        "case study",
        "research report",
        "threat report",
        "threat research",
        "malware analysis",
        "reverse engineering",
        "incident analysis",
        "intrusion analysis",
        "campaign analysis",
        "detection engineering",
        "hunting guide",
        "forensic analysis",
        "tradecraft",
        "ttps",
        "attack chain",
        "exploit chain",
        "patch diff",
        "vulnerability analysis",
        "we analyzed",
        "we found",
        "our research",
        "tracking ",
        "unpacking",
        "inside ",
    ]
    .iter()
    .any(|needle| text.contains(needle));

    let technical_depth_signal = [
        "ioc",
        "yara",
        "sigma",
        "reverse engineer",
        "loader",
        "payload",
        "c2",
        "command and control",
        "ttp",
        "mitre",
        "kill chain",
        "attack chain",
        "exploit chain",
        "root cause",
        "patch diff",
        "code path",
        "proof-of-concept",
        "vulnerability analysis",
        "cve-",
        "zero-day",
        "apt",
        "threat actor",
        "malware",
        "ransomware",
        "phishing kit",
        "detection",
        "bug bounty",
        "hackerone",
        "bugcrowd",
        "responsible disclosure",
        "vulnerability disclosure",
        "idor",
        "ssrf",
        "xss",
        "sql injection",
        "account takeover",
        "subdomain takeover",
        "oauth",
        "cors",
        "request smuggling",
        "race condition",
        "business logic",
        "graphql",
        "jwt",
        "postmessage",
        "prototype pollution",
        "cache poisoning",
        "cache deception",
        "immunefi",
    ]
    .iter()
    .any(|needle| text.contains(needle));

    // A few feeds intentionally mix research with corporate/product content.
    // Keep those high precision. The remaining entries originate from the
    // explicitly curated writeup source list and are accepted by default.
    let mixed_content_source = source.starts_with("medium ")
        || [
            "microsoft security blog",
            "cloudflare security research",
            "projectdiscovery research",
            "projectdiscovery blog",
            "github bug bounty",
        ]
        .iter()
        .any(|needle| source.contains(needle));

    let topical_feed_name = [
        "bug bounty",
        "hackerone",
        "bugcrowd",
        "vulnerability disclosure",
        "responsible disclosure",
        "idor",
        "ssrf",
        "subdomain takeover",
        "information disclosure",
        "web cache poisoning",
        "account takeover",
        "prototype pollution",
        "postmessage",
        "request smuggling",
        "web cache deception",
        "oauth",
        "graphql",
        "jwt",
        "cors",
        "dom xss",
        "blind xss",
        "race condition",
        "business logic",
        "immunefi",
    ]
    .iter()
    .any(|needle| source.contains(needle));

    if mixed_content_source {
        explicit_analysis_marker || technical_depth_signal || topical_feed_name
    } else {
        true
    }
}

pub(crate) fn writeup_kind(item: &FeedItem) -> &'static str {
    let text =
        format!("{} {} {}", item.title, item.summary, item.tags.join(" ")).to_ascii_lowercase();
    if text.contains("cve-")
        || text.contains("vulnerability")
        || text.contains("zero-day")
        || text.contains("exploit")
    {
        "CVE Analysis"
    } else if text.contains("malware")
        || text.contains("ransomware")
        || text.contains("trojan")
        || text.contains("stealer")
        || text.contains("backdoor")
    {
        "Malware Writeup"
    } else if text.contains("phishing")
        || text.contains("credential")
        || text.contains("microsoft 365")
    {
        "Phishing Analysis"
    } else if text.contains("incident")
        || text.contains("breach")
        || text.contains("campaign")
        || text.contains("threat actor")
        || text.contains("apt")
    {
        "Incident Analysis"
    } else if text.contains("detection")
        || text.contains("yara")
        || text.contains("sigma")
        || text.contains("rule")
    {
        "Detection Engineering"
    } else if text.contains("cloud")
        || text.contains("aws")
        || text.contains("azure")
        || text.contains("kubernetes")
        || text.contains("container")
    {
        "Cloud/SaaS Research"
    } else {
        "Research Note"
    }
}

pub(crate) fn writeup_tags(item: &FeedItem) -> Vec<String> {
    let mut tags = item.tags.iter().take(4).cloned().collect::<Vec<_>>();
    let kind = writeup_kind(item).to_string();
    if !tags.iter().any(|tag| tag == &kind) {
        tags.insert(0, kind);
    }
    tags.into_iter()
        .filter(|tag| !tag.trim().is_empty())
        .take(5)
        .collect()
}

pub(crate) fn writeup_score(item: &FeedItem) -> usize {
    let mut score = (item.risk_score.max(1) as usize * 9).clamp(12, 90);
    let text = format!("{} {}", item.title, item.summary).to_ascii_lowercase();
    if text.contains("cve-") || text.contains("zero-day") || text.contains("actively exploited") {
        score += 10;
    }
    if text.contains("ransomware") || text.contains("malware") || text.contains("phishing") {
        score += 7;
    }
    score.clamp(12, 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_item(source: &str, title: &str, summary: &str, published: &str) -> FeedItem {
        FeedItem {
            title: title.to_string(),
            summary: summary.to_string(),
            source: source.to_string(),
            url: format!(
                "https://example.test/{}/{}",
                source.replace(' ', "-"),
                title.replace(' ', "-")
            ),
            published: published.to_string(),
            risk_score: 3,
            category: "general".to_string(),
            tags: vec!["Writeup Source".to_string()],
        }
    }

    #[test]
    fn curated_writeup_source_is_not_blocked_by_old_allow_list() {
        let item = feed_item(
            "Assetnote Research",
            "A new path through a complex application",
            "Detailed security research from the team.",
            "2026-07-10T08:00:00+00:00",
        );

        assert!(is_writeup_item(&item));
    }

    #[test]
    fn normal_news_item_without_writeup_pipeline_tag_is_rejected() {
        let mut item = feed_item(
            "Assetnote Research",
            "Technical analysis",
            "Detailed findings.",
            "2026-07-10T08:00:00+00:00",
        );
        item.tags.clear();

        assert!(!is_writeup_item(&item));
    }

    #[test]
    fn generic_mixed_feed_post_is_rejected() {
        let item = feed_item(
            "Cloudflare Security Research",
            "Cloudflare joins a public resilience pledge",
            "An organizational announcement.",
            "2026-07-10T08:00:00+00:00",
        );

        assert!(!is_writeup_item(&item));
    }

    #[test]
    fn topical_medium_feed_is_accepted() {
        let item = feed_item(
            "Medium IDOR",
            "How I found access to another tenant",
            "A bug bounty finding with impact and remediation details.",
            "2026-07-10T08:00:00+00:00",
        );

        assert!(is_writeup_item(&item));
    }

    #[test]
    fn writeups_panel_uses_all_twenty_supported_cards() {
        let day = NaiveDate::from_ymd_opt(2026, 7, 10).expect("valid date");
        let items = (0..25)
            .map(|idx| {
                feed_item(
                    "watchTowr Labs",
                    &format!("Research item {idx}"),
                    "Technical research details.",
                    &format!("2026-07-10T{:02}:00:00+00:00", idx % 20),
                )
            })
            .collect::<Vec<_>>();

        let pulse = build_writeups_pulse(&items, day, "2026-07-10");

        assert_eq!(
            pulse["totals"]["writeups"].as_u64(),
            Some(WRITEUP_VISIBLE_LIMIT as u64)
        );
        assert_eq!(pulse["writeups"].as_array().map(Vec::len), Some(20));
    }
}
