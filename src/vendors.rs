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
    for key in ["title", "summary", "source", "cve_id"] {
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

pub(crate) fn build_vendor_watchlist(brief: &mut Value) {
    let mut rows: Vec<Value> = Vec::new();
    let mut total_cves = 0u64;
    let mut total_news = 0u64;
    for (vendor, needles) in VENDOR_WATCHLIST {
        let cves = count_hits(brief, "cves", needles);
        let news = count_hits(brief, "global_news", needles);
        let total = cves + news;
        if total == 0 {
            continue;
        }
        total_cves += cves;
        total_news += news;
        let level = if cves >= 3 {
            "high"
        } else if cves >= 1 {
            "medium"
        } else {
            "watch"
        };
        rows.push(json!({
            "name": vendor,
            "vendor": vendor,
            "cves": cves,
            "news": news,
            "total": total,
            "count": format!("{cves} CVE · {news} news"),
            "level": level
        }));
    }
    rows.sort_by(|a, b| {
        let ac = a["cves"].as_u64().unwrap_or(0);
        let bc = b["cves"].as_u64().unwrap_or(0);
        bc.cmp(&ac).then_with(|| {
            let at = a["total"].as_u64().unwrap_or(0);
            let bt = b["total"].as_u64().unwrap_or(0);
            bt.cmp(&at)
        })
    });
    rows.truncate(8);
    let peak = rows
        .iter()
        .map(|row| row["total"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(0)
        .max(1);
    for row in rows.iter_mut() {
        let total = row["total"].as_u64().unwrap_or(0);
        row["bar_width"] = json!(((total * 100) / peak).clamp(4, 100));
    }
    let vendors_hit = rows.len();
    let summary = if rows.is_empty() {
        "No direct mention of watchlist vendors was observed in this run.".to_string()
    } else {
        let top = rows[0]["vendor"].as_str().unwrap_or("-").to_string();
        format!("{vendors_hit} watchlist vendors seen in CVEs and news this run; highest focus on {top}.")
    };
    brief["vendor_watchlist"] = json!({
        "ok": vendors_hit > 0,
        "rows": rows,
        "totals": { "vendors": vendors_hit, "cves": total_cves, "news": total_news },
        "summary": summary,
        "provider": "Local keyword scan"
    });
    if let Some(stats) = brief.get_mut("stats").and_then(|v| v.as_object_mut()) {
        stats.insert("vendor_hits".to_string(), json!(total_cves + total_news));
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
