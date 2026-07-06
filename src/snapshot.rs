//! Executive snapshot and triage signals.

use crate::prelude::*;

pub(crate) fn build_executive_snapshot(brief: &Value) -> Value {
    let total_items = stat_u64(brief, "total_items");
    let cves = stat_u64(brief, "cves");
    let critical_cves = stat_u64(brief, "critical_cves");
    let kev = stat_u64(brief, "kev");
    let iocs = stat_u64(brief, "iocs");
    let botnet_c2 = stat_u64(brief, "botnet_c2");
    let malicious_tls = stat_u64(brief, "malicious_tls");
    let greynoise_noise = stat_u64(brief, "greynoise_noise");
    let greynoise_malicious = stat_u64(brief, "greynoise_malicious");
    let phishing_urls = stat_u64(brief, "phishing_urls");
    let phishing_high = stat_u64(brief, "phishing_high");
    let poc_watch = stat_u64(brief, "poc_watch");
    let poc_watch_high = stat_u64(brief, "poc_watch_high");
    let ics_advisories = stat_u64(brief, "ics_advisories");
    let ics_high = stat_u64(brief, "ics_high");
    let infrastructure_hosts = stat_u64(brief, "infrastructure_hosts");
    let supply_advisories = stat_u64(brief, "supply_chain_advisories");
    let ransomware_victims = stat_u64(brief, "ransomware_victims");
    let failed_rss = stat_u64(brief, "failed_rss_sources");

    let infra_high = path_u64(brief, &["infrastructure_radar", "totals", "high"]);
    let supply_critical = path_u64(brief, &["supply_chain_radar", "totals", "critical"]);
    let supply_high = path_u64(brief, &["supply_chain_radar", "totals", "high"]);
    let ransomware_24h = path_u64(brief, &["ransomware_pulse", "totals", "recent_24h"]);
    let attack_level = path_string(brief, &["attack_pressure", "level"], "Unknown");

    let score = (critical_cves * 18
        + kev * 20
        + iocs.min(60)
        + botnet_c2.min(25)
        + malicious_tls.min(20)
        + greynoise_noise.min(20)
        + greynoise_malicious * 12
        + phishing_urls.min(20)
        + phishing_high * 6
        + poc_watch.min(18)
        + poc_watch_high * 10
        + ics_advisories.min(18)
        + ics_high * 8
        + infrastructure_hosts.min(25)
        + infra_high * 10
        + supply_critical * 12
        + supply_high * 4
        + ransomware_24h * 5
        + failed_rss * 4)
        .min(100);
    let level = snapshot_level(score);

    let cve_score =
        (critical_cves * 32 + kev * 28 + cves * 4 + poc_watch.min(20) + poc_watch_high * 12)
            .min(100)
            .max(12);
    let intel_score = (iocs.min(55)
        + botnet_c2.min(25)
        + malicious_tls.min(20)
        + greynoise_noise.min(20)
        + greynoise_malicious * 12
        + phishing_urls.min(20)
        + phishing_high * 6
        + poc_watch.min(18)
        + poc_watch_high * 10
        + ics_advisories.min(18)
        + ics_high * 8
        + infrastructure_hosts.min(25)
        + infra_high * 10)
        .min(100)
        .max(12);
    let ecosystem_score =
        (supply_critical * 18 + supply_high * 8 + ransomware_24h * 7 + ransomware_victims.min(25))
            .min(100)
            .max(12);

    let top_port = top_attack_port(brief);
    let top_ioc = first_chart_entry(brief, &["ioc_radar", "malware_chart"])
        .or_else(|| first_chart_entry(brief, &["ioc_radar", "source_chart"]))
        .unwrap_or_else(|| ("بدون IOC برجسته".to_string(), 0));
    let top_phishing = first_chart_entry(brief, &["phishing_pulse", "brand_chart"])
        .unwrap_or_else(|| ("بدون phishing برجسته".to_string(), 0));
    let top_ransomware = first_chart_entry(brief, &["ransomware_pulse", "group_chart"])
        .unwrap_or_else(|| ("بدون گروه برجسته".to_string(), 0));
    let top_supply = first_chart_entry(brief, &["supply_chain_radar", "severity_chart"])
        .unwrap_or_else(|| ("بدون severity برجسته".to_string(), 0));

    let impact_a = cves + critical_cves + kev + poc_watch;
    let impact_b = iocs + infrastructure_hosts + botnet_c2 + malicious_tls + phishing_urls;
    let impact_c = supply_advisories + ransomware_victims;
    let impact_max = impact_a.max(impact_b).max(impact_c).max(1);

    json!({
        "title": "Static Executive Snapshot",
        "level": level,
        "score": score,
        "bar_width": score.max(12),
        "generated_at": brief.get("generated_at").cloned().unwrap_or(Value::Null),
        "summary_fa": format!(
            "خلاصه ۶۰ ثانیه‌ای: در این اجرا {} آیتم، {} CVE، {} PoC metadata، {} IOC، {} C2 botnet، {} URL فیشینگ، {} advisory ICS/OT، {} IP با context GreyNoise، {} advisory زنجیره تأمین و {} claim ransomware دیده شد.",
            total_items, cves, poc_watch, iocs, botnet_c2, phishing_urls, ics_advisories, greynoise_noise + greynoise_malicious, supply_advisories, ransomware_victims
        ),
        "risk_cards": [
            {
                "title": "ریسک آسیب‌پذیری‌ها",
                "metric": format!("{} critical / {} CVE / {} PoC", critical_cves, cves, poc_watch),
                "level": snapshot_level(cve_score),
                "bar_width": cve_score,
                "note_fa": if critical_cves > 0 { "CVEهای critical باید در اولویت patch و exposure review دیده شوند." } else { "در این اجرا CVE critical برجسته‌ای دیده نشده است." }
            },
            {
                "title": "IOC و زیرساخت مشکوک",
                "metric": format!("{} IOC / {} C2 / {} phish / {} ICS", iocs, botnet_c2, phishing_urls, ics_advisories),
                "level": snapshot_level(intel_score),
                "bar_width": intel_score,
                "note_fa": if ics_high > 0 { "Advisoryهای ICS/OT سطح بالا کنار IOC/C2 برای اولویت‌بندی دفاعی OT دیده شوند." } else if phishing_high > 0 { "URLهای فیشینگ defanged کنار IOC/C2 برای correlation دفاعی آمده‌اند." } else if greynoise_malicious > 0 { "GreyNoise برای برخی IPها classification بدخواه داده و با C2/IOC باید correlation شود." } else if botnet_c2 > 0 { "سیگنال‌های C2 و زیرساخت برای correlation دفاعی کنار هم دیده می‌شوند." } else if infra_high > 0 { "برخی hostها با exposure یا vulnerability hint بالاتر دیده شده‌اند." } else { "سیگنال‌های زیرساختی برای correlation دفاعی نگه داشته شده‌اند." }
            },
            {
                "title": "Supply Chain و Ransomware",
                "metric": format!("{} advisory / {} claims", supply_advisories, ransomware_victims),
                "level": snapshot_level(ecosystem_score),
                "bar_width": ecosystem_score,
                "note_fa": "این بخش فشار اکوسیستم نرم‌افزار و claimهای عمومی ransomware را در یک نگاه ترکیب می‌کند."
            }
        ],
        "rising_signals": [
            {
                "title": "Attack Pressure",
                "metric": top_port.0,
                "level": top_port.2,
                "bar_width": top_port.1.max(12),
                "note_fa": format!("سطح کلی DShield در این اجرا {} گزارش شده است.", attack_level)
            },
            {
                "title": "IOC Pattern",
                "metric": format!("{} · {} | {} · {}", top_ioc.0, top_ioc.1, top_phishing.0, top_phishing.1),
                "level": if phishing_high >= 4 || top_ioc.1 >= 5 { "high" } else if phishing_urls >= 10 || top_ioc.1 >= 2 { "medium" } else { "watch" },
                "bar_width": ((top_ioc.1 * 12 + phishing_high * 10 + phishing_urls.min(20)).min(100)).max(12),
                "note_fa": "بیشترین الگوی IOC و phishing برای triage و correlation دفاعی نمایش داده شده است."
            },
            {
                "title": "Ransomware / Ecosystem",
                "metric": format!("{} · {} | {} · {}", top_ransomware.0, top_ransomware.1, top_supply.0, top_supply.1),
                "level": if ransomware_24h >= 8 || supply_critical >= 3 { "high" } else if ransomware_24h >= 3 || supply_high >= 5 { "medium" } else { "watch" },
                "bar_width": ((ransomware_24h * 10 + supply_critical * 15 + supply_high * 4).min(100)).max(12),
                "note_fa": "Claimهای عمومی ransomware و advisoryهای package در یک سیگنال فشرده آمده‌اند."
            }
        ],
        "impact_sources": [
            {
                "name": "NVD + CISA KEV + EPSS",
                "count": impact_a,
                "bar_width": relative_width(impact_a, impact_max),
                "note_fa": "هسته اولویت‌بندی CVE و exploitability."
            },
            {
                "name": "DShield + abuse.ch + SSLBL + OpenPhish + InternetDB + GreyNoise",
                "count": impact_b,
                "bar_width": relative_width(impact_b, impact_max),
                "note_fa": "فشار حمله، IOC و زیرساخت قابل مشاهده."
            },
            {
                "name": "GitHub Advisories + OSV + Ransomware.live",
                "count": impact_c,
                "bar_width": relative_width(impact_c, impact_max),
                "note_fa": "ریسک اکوسیستم نرم‌افزار و claimهای عمومی."
            }
        ]
    })
}

pub(crate) fn stat_u64(brief: &Value, key: &str) -> u64 {
    path_u64(brief, &["stats", key])
}

pub(crate) fn path_value<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for part in path {
        current = current.get(*part)?;
    }
    Some(current)
}

pub(crate) fn path_u64(value: &Value, path: &[&str]) -> u64 {
    path_value(value, path)
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

pub(crate) fn path_string(value: &Value, path: &[&str], fallback: &str) -> String {
    path_value(value, path)
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| fallback.to_string())
}

pub(crate) fn value_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

pub(crate) fn concise_text(input: &str, max_chars: usize) -> String {
    truncate_chars(input.trim(), max_chars)
}

pub(crate) fn first_chart_entry(brief: &Value, path: &[&str]) -> Option<(String, u64)> {
    let row = path_value(brief, path)?.as_array()?.first()?;
    let name = row.get("name")?.as_str()?.trim();
    if name.is_empty() {
        return None;
    }
    Some((
        truncate_chars(name, 36),
        row.get("count").and_then(|v| v.as_u64()).unwrap_or(0),
    ))
}

pub(crate) fn top_attack_port(brief: &Value) -> (String, u64, &'static str) {
    let Some(row) = path_value(brief, &["attack_pressure", "top_ports"])
        .and_then(|v| v.as_array())
        .and_then(|items| items.first())
    else {
        return ("بدون پورت برجسته".to_string(), 12, "watch");
    };
    let port = row
        .get("port")
        .and_then(|v| v.as_u64())
        .map(|p| p.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    let service = row
        .get("service")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let pressure = row
        .get("pressure_score")
        .and_then(|v| v.as_u64())
        .unwrap_or(12)
        .max(12)
        .min(100);
    let risk = row.get("risk").and_then(|v| v.as_str()).unwrap_or("watch");
    let level = match risk {
        "high" => "high",
        "medium" => "medium",
        _ => "watch",
    };
    (
        format!("port {} · {}", port, truncate_chars(service, 20)),
        pressure,
        level,
    )
}

pub(crate) fn relative_width(value: u64, max: u64) -> u64 {
    if max == 0 {
        return 12;
    }
    (((value as f64 / max as f64) * 100.0).round() as u64).clamp(12, 100)
}

pub(crate) fn snapshot_level(score: u64) -> &'static str {
    if score >= 70 {
        "high"
    } else if score >= 40 {
        "medium"
    } else {
        "watch"
    }
}

pub(crate) fn build_triage_signals(brief: &Value) -> Value {
    let breaking_news = stat_u64(brief, "breaking_news");
    let daily_news = stat_u64(brief, "daily_news");
    let critical_cves = stat_u64(brief, "critical_cves");
    let cves = stat_u64(brief, "cves");
    let kev = stat_u64(brief, "kev");
    let epss_rising = stat_u64(brief, "epss_rising");
    let iocs = stat_u64(brief, "iocs");
    let botnet_c2 = stat_u64(brief, "botnet_c2");
    let malicious_tls = stat_u64(brief, "malicious_tls");
    let greynoise_malicious = stat_u64(brief, "greynoise_malicious");
    let greynoise_noise = stat_u64(brief, "greynoise_noise");
    let phishing_urls = stat_u64(brief, "phishing_urls");
    let phishing_high = stat_u64(brief, "phishing_high");
    let ics_advisories = stat_u64(brief, "ics_advisories");
    let ics_high = stat_u64(brief, "ics_high");
    let writeups = stat_u64(brief, "writeups");
    let writeup_sources = stat_u64(brief, "writeup_sources");
    let poc_watch = stat_u64(brief, "poc_watch");
    let poc_watch_high = stat_u64(brief, "poc_watch_high");
    let poc_watch_cves = stat_u64(brief, "poc_watch_cves");
    let history_changes = stat_u64(brief, "history_changes");
    let failed_rss = stat_u64(brief, "failed_rss_sources");
    let risk_score = path_u64(brief, &["executive_snapshot", "score"]);

    let mut signals: Vec<(u64, Value)> = Vec::new();

    signals.push((
        100 + risk_score,
        json!({
            "title": "تصمیم سریع امروز",
            "metric": format!("Risk {risk_score}"),
            "level": snapshot_level(risk_score),
            "anchor": "#executive-snapshot",
            "bar_width": risk_score.max(12),
            "note_fa": "ابتدا خلاصه مدیریتی و دلیل امتیاز ریسک را ببین."
        }),
    ));

    if breaking_news > 0 || daily_news > 0 {
        let score = (breaking_news * 18 + daily_news.min(40)).min(100).max(12);
        signals.push((
            95 + score,
            json!({
                "title": "Breaking / خبر تازه",
                "metric": format!("{breaking_news} breaking · {daily_news} امروز"),
                "level": if breaking_news > 0 { "high" } else { "watch" },
                "anchor": "#breaking-news",
                "bar_width": score,
                "note_fa": "خبرهای امروز با ترتیب زمان انتشار نمایش داده می‌شوند؛ خبرهای مهم جدا شده‌اند."
            }),
        ));
    }

    if writeups > 0 {
        let score = (writeups * 8 + writeup_sources * 12).min(100).max(12);
        signals.push((
            88 + score,
            json!({
                "title": "Writeup / تحلیل تازه",
                "metric": format!("{writeups} writeup · {writeup_sources} منبع"),
                "level": if score >= 70 { "medium" } else { "watch" },
                "anchor": "#writeups-pulse",
                "bar_width": score,
                "note_fa": "تحلیل‌های تازه را جدا از خبر خام ببین؛ خروجی فقط خلاصه و metadata است."
            }),
        ));
    }

    if critical_cves > 0 || kev > 0 || epss_rising > 0 || cves > 0 {
        let score = (critical_cves * 28 + kev * 32 + epss_rising * 18 + cves * 3)
            .min(100)
            .max(12);
        signals.push((
            90 + score,
            json!({
                "title": "آسیب‌پذیری قابل اقدام",
                "metric": format!("{critical_cves} critical · {kev} KEV · {epss_rising} EPSS↑"),
                "level": snapshot_level(score),
                "anchor": "#cves",
                "bar_width": score,
                "note_fa": if kev > 0 || critical_cves > 0 { "CVEهای critical/KEV را قبل از خبرهای عمومی مرور کن." } else { "CVEها برای تطبیق با asset inventory نگه داشته شده‌اند." }
            }),
        ));
    }

    if poc_watch > 0 {
        let score = (poc_watch_high * 30 + poc_watch_cves * 16 + poc_watch * 4)
            .min(100)
            .max(12);
        signals.push((
            89 + score,
            json!({
                "title": "PoC public metadata",
                "metric": format!("{poc_watch} repo · {poc_watch_cves} CVE"),
                "level": if poc_watch_high > 0 { "high" } else if score >= 55 { "medium" } else { "watch" },
                "anchor": "#poc-watch",
                "bar_width": score,
                "note_fa": "جدیدترین PoCهای عمومی ابتدا از جریان زمانی metadata استخراج و سپس بر اساس CVE گروه‌بندی می‌شوند؛ کد و لینک raw نمایش داده نمی‌شود."
            }),
        ));
    }

    if greynoise_malicious > 0 || greynoise_noise > 0 {
        let score = (greynoise_malicious * 42 + greynoise_noise * 6)
            .min(100)
            .max(12);
        signals.push((
            80 + score,
            json!({
                "title": "Context اسکنرها",
                "metric": format!("{greynoise_malicious} malicious · {greynoise_noise} noise"),
                "level": if greynoise_malicious > 0 { "high" } else { "watch" },
                "anchor": "#greynoise-context",
                "bar_width": score,
                "note_fa": "GreyNoise برای کاهش false positive و اولویت‌بندی IPها استفاده شود."
            }),
        ));
    }

    if botnet_c2 > 0 || malicious_tls > 0 || iocs > 0 {
        let score = (botnet_c2 * 12 + malicious_tls * 4 + iocs.min(45))
            .min(100)
            .max(12);
        signals.push((
            75 + score,
            json!({
                "title": "تهدید فعال و C2",
                "metric": format!("{iocs} IOC · {botnet_c2} C2 · {malicious_tls} TLS"),
                "level": if botnet_c2 > 0 { "high" } else if iocs > 0 { "medium" } else { "watch" },
                "anchor": "#ioc-radar",
                "bar_width": score,
                "note_fa": "IOC، C2 و TLS بدخواه را فقط برای correlation دفاعی ببین."
            }),
        ));
    }

    if phishing_urls > 0 {
        let score = (phishing_high * 16 + phishing_urls.min(40))
            .min(100)
            .max(12);
        signals.push((
            65 + score,
            json!({
                "title": "Phishing Pulse",
                "metric": format!("{phishing_urls} URL · {phishing_high} high"),
                "level": if phishing_high > 0 { "medium" } else { "watch" },
                "anchor": "#phishing-pulse",
                "bar_width": score,
                "note_fa": "نمایش فقط defanged و برای آگاهی/همبستگی دفاعی است."
            }),
        ));
    }

    if ics_advisories > 0 {
        let score = (ics_high * 20 + ics_advisories.min(30)).min(100).max(12);
        signals.push((
            60 + score,
            json!({
                "title": "ICS/OT Advisory",
                "metric": format!("{ics_advisories} advisory · {ics_high} high"),
                "level": if ics_high > 0 { "medium" } else { "watch" },
                "anchor": "#ics-ot-pulse",
                "bar_width": score,
                "note_fa": "Vendor و تجهیز را با موجودی OT/ICS تطبیق بده."
            }),
        ));
    }

    if history_changes > 0 {
        let score = (history_changes * 12).min(100).max(12);
        signals.push((
            55 + score,
            json!({
                "title": "تغییر نسبت به قبل",
                "metric": format!("{history_changes} شاخص تغییر کرد"),
                "level": "medium",
                "anchor": "#history-snapshot",
                "bar_width": score,
                "note_fa": "اول تغییرهای تازه را ببین، بعد وارد جزئیات پنل‌ها شو."
            }),
        ));
    }

    if failed_rss > 0 {
        let score = (failed_rss * 15).min(100).max(12);
        signals.push((
            45 + score,
            json!({
                "title": "سلامت منابع",
                "metric": format!("{failed_rss} RSS failed"),
                "level": "medium",
                "anchor": "#sources",
                "bar_width": score,
                "note_fa": "قبل از تصمیم‌گیری، محدودیت پوشش منبع را در نظر بگیر."
            }),
        ));
    }

    signals.sort_by(|a, b| b.0.cmp(&a.0));
    let values: Vec<Value> = signals
        .into_iter()
        .take(5)
        .map(|(_, value)| value)
        .collect();
    json!(values)
}
