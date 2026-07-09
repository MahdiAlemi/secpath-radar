use crate::prelude::*;

pub(crate) const VENDOR_WATCHLIST: &[(&str, &[&str])] = &[
    (
        "Microsoft",
        &[
            "microsoft",
            "windows",
            "azure",
            "exchange server",
            "sharepoint",
            "outlook",
            "active directory",
        ],
    ),
    ("Cisco", &["cisco", "ios xe", "anyconnect", "webex"]),
    (
        "Fortinet",
        &["fortinet", "fortigate", "fortios", "fortimanager"],
    ),
    ("Palo Alto", &["palo alto", "pan-os", "globalprotect"]),
    ("VMware", &["vmware", "vcenter", "esxi", "vsphere"]),
    ("Citrix", &["citrix", "netscaler"]),
    ("Ivanti", &["ivanti", "pulse secure", "connect secure"]),
    ("Oracle", &["oracle", "weblogic"]),
    (
        "Apache",
        &["apache", "tomcat", "struts", "log4j", "activemq"],
    ),
    (
        "Atlassian",
        &["atlassian", "confluence", "jira", "bitbucket"],
    ),
    ("SAP", &["sap netweaver", "sap security note"]),
    ("Google", &["google chrome", "chromium", "android"]),
    (
        "Linux",
        &["linux kernel", "openssh", "glibc", "systemd", "sudo"],
    ),
    (
        "Edge devices",
        &[
            "zyxel", "mikrotik", "routeros", "d-link", "tp-link", "qnap", "synology",
        ],
    ),
];

pub(crate) fn item_blob(item: &Value) -> String {
    let mut parts: Vec<String> = Vec::new();
    for key in [
        "title",
        "summary",
        "source",
        "cve_id",
        "vendor",
        "product",
        "repo",
        "repo_name",
        "description",
        "author",
    ] {
        if let Some(text) = item.get(key).and_then(|v| v.as_str()) {
            parts.push(text.to_lowercase());
        }
    }
    if let Some(tags) = item.get("tags").and_then(|v| v.as_array()) {
        for tag in tags {
            if let Some(text) = tag.as_str() {
                parts.push(text.to_lowercase());
            }
        }
    }
    parts.join(" ")
}

pub(crate) fn count_hits(brief: &Value, list_key: &str, needles: &[&str]) -> u64 {
    let Some(items) = brief.get(list_key).and_then(|v| v.as_array()) else {
        return 0;
    };
    items
        .iter()
        .filter(|item| {
            let blob = item_blob(item);
            needles.iter().any(|needle| blob.contains(*needle))
        })
        .count() as u64
}

pub(crate) fn item_matches_vendor(item: &Value, needles: &[&str]) -> bool {
    let blob = item_blob(item);
    needles.iter().any(|needle| blob.contains(*needle))
}

pub(crate) fn count_nested_hits(brief: &Value, path: &[&str], needles: &[&str]) -> u64 {
    let Some(items) = brief
        .pointer(&format!("/{}", path.join("/")))
        .and_then(|v| v.as_array())
    else {
        return 0;
    };
    items
        .iter()
        .filter(|item| item_matches_vendor(item, needles))
        .count() as u64
}

fn cve_is_critical(item: &Value) -> bool {
    item.get("severity")
        .and_then(|v| v.as_str())
        .map(|severity| severity.eq_ignore_ascii_case("critical"))
        .unwrap_or(false)
        || item.get("cvss").and_then(|v| v.as_f64()).unwrap_or(0.0) >= 9.0
}

fn cve_is_high(item: &Value) -> bool {
    item.get("severity")
        .and_then(|v| v.as_str())
        .map(|severity| severity.eq_ignore_ascii_case("high"))
        .unwrap_or(false)
        || item.get("cvss").and_then(|v| v.as_f64()).unwrap_or(0.0) >= 7.0
}

fn vendor_cve_counts(brief: &Value, needles: &[&str]) -> (u64, u64, u64, u64) {
    let Some(items) = brief.get("cves").and_then(|v| v.as_array()) else {
        return (0, 0, 0, 0);
    };
    let mut cves = 0u64;
    let mut critical = 0u64;
    let mut high = 0u64;
    let mut kev = 0u64;
    for item in items
        .iter()
        .filter(|item| item_matches_vendor(item, needles))
    {
        cves += 1;
        if cve_is_critical(item) {
            critical += 1;
        }
        if cve_is_high(item) {
            high += 1;
        }
        if item.get("kev").and_then(|v| v.as_bool()).unwrap_or(false) {
            kev += 1;
        }
    }
    (cves, critical, high, kev)
}

fn pct(part: u64, total: u64) -> u64 {
    if total == 0 {
        0
    } else {
        ((part * 100) / total).min(100)
    }
}

fn vendor_level(signal: u64, critical: u64, kev: u64, cves: u64, pocs: u64) -> &'static str {
    if kev > 0 || critical > 0 || signal >= 18 {
        "high"
    } else if cves > 0 || pocs > 0 || signal >= 6 {
        "medium"
    } else {
        "watch"
    }
}

fn vendor_primary_driver(critical: u64, kev: u64, cves: u64, pocs: u64, news: u64) -> &'static str {
    if kev > 0 {
        "KEV"
    } else if critical > 0 {
        "Critical"
    } else if cves > 0 {
        "CVE"
    } else if pocs > 0 {
        "PoC"
    } else if news > 0 {
        "News"
    } else {
        "Watch"
    }
}

fn vendor_footprint(cves: u64, critical: u64, kev: u64, pocs: u64, news: u64) -> String {
    let mut parts = Vec::new();
    if cves > 0 {
        parts.push(format!("{cves} CVE"));
    }
    if critical > 0 {
        parts.push(format!("{critical} critical"));
    }
    if kev > 0 {
        parts.push(format!("{kev} KEV"));
    }
    if pocs > 0 {
        parts.push(format!("{pocs} PoC"));
    }
    if news > 0 {
        parts.push(format!("{news} news"));
    }
    if parts.is_empty() {
        "No direct signal".to_string()
    } else {
        parts.join(" · ")
    }
}

pub(crate) fn build_vendor_watchlist(brief: &mut Value) {
    let mut rows: Vec<Value> = Vec::new();
    let mut total_cves = 0u64;
    let mut total_news = 0u64;
    let mut total_pocs = 0u64;
    let mut total_critical = 0u64;
    let mut total_high = 0u64;
    let mut total_kev = 0u64;

    for (vendor, needles) in VENDOR_WATCHLIST {
        let (cves, critical, high, kev) = vendor_cve_counts(brief, needles);
        let news = if brief.get("today_news").and_then(|v| v.as_array()).is_some() {
            count_hits(brief, "today_news", needles)
        } else {
            count_hits(brief, "global_news", needles)
        };
        let pocs = count_nested_hits(brief, &["poc_watch", "repos"], needles);
        let total = cves + news + pocs;
        if total == 0 {
            continue;
        }

        total_cves += cves;
        total_news += news;
        total_pocs += pocs;
        total_critical += critical;
        total_high += high;
        total_kev += kev;

        let signal = cves * 5 + critical * 4 + kev * 6 + pocs * 4 + news;
        let level = vendor_level(signal, critical, kev, cves, pocs);
        let primary_driver = vendor_primary_driver(critical, kev, cves, pocs, news);
        let mix_total = (cves + pocs + news).max(1);
        let footprint = vendor_footprint(cves, critical, kev, pocs, news);
        let level_label = match level {
            "high" => "High focus",
            "medium" => "Medium",
            _ => "Watch",
        };

        rows.push(json!({
            "name": vendor,
            "vendor": vendor,
            "cves": cves,
            "critical": critical,
            "high": high,
            "kev": kev,
            "pocs": pocs,
            "news": news,
            "total": total,
            "signal": signal,
            "count": footprint,
            "footprint": footprint,
            "level": level,
            "level_label": level_label,
            "primary_driver": primary_driver,
            "cve_width": pct(cves, mix_total),
            "poc_width": pct(pocs, mix_total),
            "news_width": pct(news, mix_total),
            "bar_width": 0
        }));
    }

    rows.sort_by(|a, b| {
        let asig = a["signal"].as_u64().unwrap_or(0);
        let bsig = b["signal"].as_u64().unwrap_or(0);
        bsig.cmp(&asig)
            .then_with(|| {
                let ac = a["critical"].as_u64().unwrap_or(0);
                let bc = b["critical"].as_u64().unwrap_or(0);
                bc.cmp(&ac)
            })
            .then_with(|| {
                let at = a["total"].as_u64().unwrap_or(0);
                let bt = b["total"].as_u64().unwrap_or(0);
                bt.cmp(&at)
            })
    });
    rows.truncate(8);

    let peak = rows
        .iter()
        .map(|row| row["signal"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(0)
        .max(1);
    for row in rows.iter_mut() {
        let signal = row["signal"].as_u64().unwrap_or(0);
        row["bar_width"] = json!(((signal * 100) / peak).clamp(4, 100));
    }

    let vendors_hit = rows.len();
    let spotlight = rows.first().map(|row| {
        let vendor = row["vendor"].as_str().unwrap_or("-");
        let driver = row["primary_driver"].as_str().unwrap_or("Watch");
        let level = row["level"].as_str().unwrap_or("watch");
        json!({ "vendor": vendor, "driver": driver, "level": level })
    });
    let summary = if rows.is_empty() {
        "No direct mention of watchlist vendors was observed in this run.".to_string()
    } else {
        let top = rows[0]["vendor"].as_str().unwrap_or("-").to_string();
        format!("{vendors_hit} watchlist vendors appeared across today's CVEs, PoCs, and news; strongest signal is {top}.")
    };

    brief["vendor_watchlist"] = json!({
        "ok": vendors_hit > 0,
        "rows": rows,
        "spotlight": spotlight,
        "totals": {
            "vendors": vendors_hit,
            "cves": total_cves,
            "critical": total_critical,
            "high": total_high,
            "kev": total_kev,
            "pocs": total_pocs,
            "news": total_news
        },
        "summary": summary,
        "provider": "Local keyword scan"
    });
    if let Some(stats) = brief.get_mut("stats").and_then(|v| v.as_object_mut()) {
        stats.insert(
            "vendor_hits".to_string(),
            json!(total_cves + total_news + total_pocs),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_vendor_watchlist_counts_cves_and_news() {
        let mut brief = json!({
            "stats": {},
            "cves": [
                { "title": "Fortinet FortiGate flaw exploited", "summary": "patch now", "tags": [] },
                { "title": "Unrelated advisory", "summary": "misc", "tags": [] }
            ],
            "global_news": [
                { "title": "New FortiOS bug under active attack", "summary": "", "tags": [] }
            ]
        });
        build_vendor_watchlist(&mut brief);
        let pulse = &brief["vendor_watchlist"];
        assert_eq!(pulse["ok"], json!(true));
        let rows = pulse["rows"].as_array().expect("rows");
        assert_eq!(rows[0]["vendor"], json!("Fortinet"));
        assert_eq!(rows[0]["cves"], json!(1));
        assert_eq!(rows[0]["news"], json!(1));
        assert_eq!(rows[0]["bar_width"], json!(100));
    }

    #[test]
    fn build_vendor_watchlist_reports_empty_state() {
        let mut brief = json!({ "stats": {}, "cves": [], "global_news": [] });
        build_vendor_watchlist(&mut brief);
        assert_eq!(brief["vendor_watchlist"]["ok"], json!(false));
        assert!(brief["vendor_watchlist"]["summary"]
            .as_str()
            .unwrap_or("")
            .contains("No direct mention"));
    }
}
