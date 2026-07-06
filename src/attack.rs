use crate::prelude::*;

pub(crate) const ATTACK_TECHNIQUES: &[(&str, &str, &[&str])] = &[
    (
        "T1190",
        "بهره‌برداری از سرویس عمومی",
        &[
            "exploit",
            "remote code execution",
            " rce",
            "zero-day",
            "0-day",
        ],
    ),
    (
        "T1566",
        "فیشینگ",
        &["phishing", "spearphishing", "smishing", "quishing"],
    ),
    (
        "T1486",
        "باج‌افزار و رمزگذاری داده",
        &["ransomware", "extortion"],
    ),
    (
        "T1078",
        "سوءاستفاده از حساب معتبر",
        &["credential", "account takeover", "stolen password"],
    ),
    (
        "T1195",
        "زنجیره تأمین",
        &["supply chain", "malicious package", "typosquat"],
    ),
    (
        "T1059",
        "اجرای فرمان و اسکریپت",
        &["powershell", "command injection", "web shell", "webshell"],
    ),
    (
        "T1041",
        "سرقت و افشای داده",
        &["data breach", "data leak", "exfiltration", "stolen data"],
    ),
    (
        "T1498",
        "منع سرویس",
        &["ddos", "denial of service", "denial-of-service"],
    ),
    (
        "T1110",
        "حمله به گذرواژه",
        &[
            "brute force",
            "brute-force",
            "password spraying",
            "credential stuffing",
        ],
    ),
    (
        "T1189",
        "آلوده‌سازی مرورگری",
        &["watering hole", "malvertising", "drive-by"],
    ),
];

pub(crate) fn build_attack_matrix(brief: &mut Value) {
    let mut rows: Vec<Value> = Vec::new();
    let mut total_hits = 0u64;
    for (technique, label_fa, needles) in ATTACK_TECHNIQUES {
        let mut hits = 0u64;
        for list_key in ["cves", "global_news", "iran_radar"] {
            hits += count_hits(brief, list_key, needles);
        }
        if hits == 0 {
            continue;
        }
        total_hits += hits;
        rows.push(json!({
            "name": format!("{technique} · {label_fa}"),
            "technique": technique,
            "label_fa": label_fa,
            "hits": hits,
            "count": hits
        }));
    }
    rows.sort_by(|a, b| {
        let ah = a["hits"].as_u64().unwrap_or(0);
        let bh = b["hits"].as_u64().unwrap_or(0);
        bh.cmp(&ah)
    });
    rows.truncate(8);
    let peak = rows
        .iter()
        .map(|row| row["hits"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(0)
        .max(1);
    for row in rows.iter_mut() {
        let hits = row["hits"].as_u64().unwrap_or(0);
        row["bar_width"] = json!(((hits * 100) / peak).clamp(4, 100));
    }
    let techniques = rows.len();
    let summary_fa = if rows.is_empty() {
        "در این اجرا الگوی حمله شاخصی از محتوای رصدشده استخراج نشد.".to_string()
    } else {
        let top_name = rows[0]["name"].as_str().unwrap_or("-").to_string();
        format!("محتوای این اجرا به {techniques} تکنیک MITRE ATT&CK نگاشت شد؛ پرتکرارترین الگو: {top_name}.")
    };
    brief["attack_matrix"] = json!({
        "ok": techniques > 0,
        "rows": rows,
        "totals": { "techniques": techniques, "hits": total_hits },
        "summary_fa": summary_fa,
        "provider": "نگاشت کلیدواژه‌ای به MITRE ATT&CK"
    });
    if let Some(stats) = brief.get_mut("stats").and_then(|v| v.as_object_mut()) {
        stats.insert("attack_techniques".to_string(), json!(techniques));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_attack_matrix_ranks_techniques_by_hits() {
        let mut brief = json!({
            "stats": {},
            "cves": [],
            "global_news": [
                { "title": "Large phishing campaign hits banks", "summary": "", "tags": [] },
                { "title": "Phishing kit abuses QR codes", "summary": "", "tags": [] },
                { "title": "Ransomware gang claims new victim", "summary": "", "tags": [] }
            ],
            "iran_radar": []
        });
        build_attack_matrix(&mut brief);
        let pulse = &brief["attack_matrix"];
        assert_eq!(pulse["ok"], json!(true));
        let rows = pulse["rows"].as_array().expect("rows");
        assert_eq!(rows[0]["technique"], json!("T1566"));
        assert_eq!(rows[0]["hits"], json!(2));
        assert_eq!(rows[0]["bar_width"], json!(100));
    }

    #[test]
    fn build_attack_matrix_reports_empty_state() {
        let mut brief = json!({ "stats": {}, "cves": [], "global_news": [], "iran_radar": [] });
        build_attack_matrix(&mut brief);
        assert_eq!(brief["attack_matrix"]["ok"], json!(false));
    }
}
