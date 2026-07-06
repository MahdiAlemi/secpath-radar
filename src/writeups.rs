//! Research write-ups pulse.

use crate::prelude::*;

pub(crate) fn build_writeups_pulse(items: &[FeedItem]) -> Value {
    let mut candidates: Vec<FeedItem> = items
        .iter()
        .filter(|item| is_writeup_item(item))
        .cloned()
        .collect();
    sort_news_latest_first(&mut candidates);

    let total_candidates = candidates.len();
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
        .take(12)
        .enumerate()
        .map(|(idx, item)| writeup_item_value(idx + 1, item))
        .collect();
    let visible = writeups.len();
    let hidden = total_candidates.saturating_sub(visible);
    let sources = source_counts.len();
    let kinds = kind_counts.len();
    let source_chart = count_chart(source_counts, 6);
    let kind_chart = count_chart(kind_counts, 6);

    let summary_fa = if visible == 0 {
        "در پنجره خبری فعلی writeup تحلیلی تازه‌ای از منابع موجود دیده نشد.".to_string()
    } else if hidden > 0 {
        format!("{visible} writeup تحلیلی تازه نمایش داده شد و {hidden} مورد کم‌اولویت‌تر برای فشردگی پنهان شد؛ جدیدترین تحلیل‌ها بالاتر هستند.")
    } else {
        format!("{visible} writeup تحلیلی تازه از {sources} منبع جدا شد؛ این بخش خبر خام را از تحلیل فنی جدا می‌کند.")
    };

    json!({
        "enabled": true,
        "source": "Dedicated research/writeup RSS feeds",
        "safe_mode": "summary and metadata only; no exploit steps; no code execution",
        "summary_fa": summary_fa,
        "totals": {
            "writeups": visible,
            "candidates": total_candidates,
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
        "safe_mode": "summary and metadata only; no exploit steps; no code execution",
        "summary_fa": "Writeups Pulse در این اجرا داده‌ای ندارد.",
        "totals": {
            "writeups": 0,
            "candidates": 0,
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
        "title_fa": writeup_title_fa(kind, &item.title),
        "summary": item.summary.clone(),
        "summary_fa": fallback_persian_summary(&item.summary, "این writeup برای تحلیل فنی روز قابل توجه است"),
        "source": item.source.clone(),
        "url": item.url.clone(),
        "published": item.published.clone(),
        "published_date_local": published_date_local,
        "published_time_local": published_time_local,
        "freshness_label": freshness_label,
        "kind": kind,
        "kind_fa": writeup_kind_fa(kind),
        "risk": risk,
        "risk_score": score,
        "bar_width": score,
        "tags": writeup_tags(item),
        "note_fa": writeup_note_fa(kind),
        "safe_mode": "metadata only"
    })
}

pub(crate) fn is_writeup_item(item: &FeedItem) -> bool {
    let source = item.source.to_ascii_lowercase();
    let title = item.title.to_ascii_lowercase();
    let summary = item.summary.to_ascii_lowercase();
    let text = format!(
        "{title} {summary} {}",
        item.tags.join(" ").to_ascii_lowercase()
    );

    // Writeups now come from a dedicated source list, not from the Daily News feed.
    // This guard keeps the panel focused on analysis/research and prevents normal
    // news, newsletters, patch roundups, and product updates from leaking in.
    let dedicated_writeup_source = [
        "the dfir report",
        "portswigger research",
        "unit 42",
        "cisco talos",
        "projectdiscovery research",
        "projectdiscovery blog",
        "zero day initiative research",
        "securelist",
        "google cloud threat intelligence",
        "microsoft security blog",
        "cloudflare security research",
        "rapid7 research",
    ];
    let dedicated_writeup_source = dedicated_writeup_source
        .iter()
        .any(|needle| source.contains(needle));

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

    let research_source_allows_depth = [
        "the dfir report",
        "portswigger research",
        "unit 42",
        "cisco talos",
        "securelist",
        "google cloud threat intelligence",
    ]
    .iter()
    .any(|needle| source.contains(needle));

    let technical_depth_signal = [
        "ioc",
        "yara",
        "sigma",
        "rule",
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
        "apt",
        "threat actor",
        "malware",
        "ransomware",
        "phishing kit",
        "detection",
    ]
    .iter()
    .any(|needle| text.contains(needle));

    explicit_analysis_marker || (research_source_allows_depth && technical_depth_signal)
}

pub(crate) fn writeup_title_fa(kind: &str, title: &str) -> String {
    let focus = persian_focus_label(title);
    let text = match kind {
        "CVE Analysis" => format!("تحلیل فنی CVE درباره {focus}"),
        "Malware Writeup" => format!("تحلیل فنی بدافزار درباره {focus}"),
        "Phishing Analysis" => format!("تحلیل فنی فیشینگ درباره {focus}"),
        "Incident Analysis" => format!("تحلیل فنی رخداد درباره {focus}"),
        "Detection Engineering" => format!("یادداشت مهندسی تشخیص درباره {focus}"),
        "Cloud/SaaS Research" => format!("تحلیل فنی Cloud/SaaS درباره {focus}"),
        _ => format!("یادداشت پژوهشی درباره {focus}"),
    };
    truncate_chars(&text, 72)
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

pub(crate) fn writeup_kind_fa(kind: &str) -> &'static str {
    match kind {
        "CVE Analysis" => "تحلیل CVE",
        "Malware Writeup" => "تحلیل بدافزار",
        "Phishing Analysis" => "تحلیل فیشینگ",
        "Incident Analysis" => "تحلیل رخداد",
        "Detection Engineering" => "مهندسی تشخیص",
        "Cloud/SaaS Research" => "تحلیل Cloud/SaaS",
        _ => "یادداشت پژوهشی",
    }
}

pub(crate) fn writeup_note_fa(kind: &str) -> &'static str {
    match kind {
        "CVE Analysis" => "برای تطبیق با CVEها، EPSS/KEV و backlog وصله نگه داشته شود؛ این بخش exploit اجرا نمی‌کند.",
        "Malware Writeup" => "برای correlation با IOC، C2 و خانواده‌های بدافزار استفاده شود؛ نمونه یا payload نمایش داده نمی‌شود.",
        "Phishing Analysis" => "برای آگاهی ایمیل/هویت و تطبیق با Phishing Pulse استفاده شود؛ URLها عملیاتی نمی‌شوند.",
        "Incident Analysis" => "برای فهم روند حمله و اثر احتمالی روی کنترل‌های دفاعی مرور شود.",
        "Detection Engineering" => "برای ایده rule/detection قابل بررسی است، اما هیچ rule یا scan خودکار اجرا نمی‌شود.",
        "Cloud/SaaS Research" => "برای تطبیق با دارایی‌های Cloud/SaaS و کنترل exposure مرور شود.",
        _ => "برای زمینه‌سازی triage روزانه و خواندن تحلیل فنی نگه داشته شود.",
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
