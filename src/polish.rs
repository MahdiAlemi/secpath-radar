//! Local Persian editorial polish applied without AI.

use crate::prelude::*;

pub(crate) fn apply_local_polish(brief: &mut Value) {
    brief["version"] = json!("v0.4.34-day-machine");

    if brief.get("source_health").is_none() {
        brief["source_health"] = json!({
            "rss_sources": 0,
            "source_names": [],
            "http_cache": true,
            "cache_ttl_minutes": 0,
            "ai_cache_dir": "data/cache/ai",
            "intel_sources": 0,
            "intel_cache_dir": "data/cache/intel"
        });
    }
    if brief["source_health"].get("source_names").is_none() {
        brief["source_health"]["source_names"] = json!([]);
    }
    if brief["source_health"].get("intel_sources").is_none() {
        brief["source_health"]["intel_sources"] = json!(0);
    }
    if brief["source_health"].get("failed_rss_sources").is_none() {
        brief["source_health"]["failed_rss_sources"] = json!(0);
    }
    if brief["source_health"].get("rss_failures").is_none() {
        brief["source_health"]["rss_failures"] = json!([]);
    }
    if brief.get("breaking_news").is_none() {
        brief["breaking_news"] = json!([]);
    }
    if brief.get("news_window").is_none() {
        let daily_news = brief
            .get("global_news")
            .and_then(|v| v.as_array())
            .map(|items| items.len())
            .unwrap_or(0)
            + brief
                .get("iran_radar")
                .and_then(|v| v.as_array())
                .map(|items| items.len())
                .unwrap_or(0)
            + brief
                .get("breaking_news")
                .and_then(|v| v.as_array())
                .map(|items| items.len())
                .unwrap_or(0);
        brief["news_window"] = json!({
            "mode": "local-day",
            "date": brief.get("date_en").and_then(|v| v.as_str()).unwrap_or(""),
            "start": "00:00",
            "end": "23:59",
            "timezone": tehran_now().format("%:z").to_string(),
            "rss_items_fetched": daily_news,
            "daily_news": daily_news,
            "hidden_old_or_undated": 0
        });
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("breaking_news"))
        .is_none()
    {
        let count = brief
            .get("breaking_news")
            .and_then(|v| v.as_array())
            .map(|items| items.len())
            .unwrap_or(0);
        brief["stats"]["breaking_news"] = json!(count);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("daily_news"))
        .is_none()
    {
        let count = brief
            .get("news_window")
            .and_then(|v| v.get("daily_news"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        brief["stats"]["daily_news"] = json!(count);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("current_day_news"))
        .is_none()
    {
        let count = brief
            .get("news_window")
            .and_then(|v| v.get("current_day_news"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        brief["stats"]["current_day_news"] = json!(count);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("news_backfill"))
        .is_none()
    {
        let count = brief
            .get("news_window")
            .and_then(|v| v.get("backfill_news"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        brief["stats"]["news_backfill"] = json!(count);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("daily_news_hidden"))
        .is_none()
    {
        let count = brief
            .get("news_window")
            .and_then(|v| v.get("hidden_old_or_undated"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        brief["stats"]["daily_news_hidden"] = json!(count);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("rss_items_fetched"))
        .is_none()
    {
        let count = brief
            .get("news_window")
            .and_then(|v| v.get("rss_items_fetched"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        brief["stats"]["rss_items_fetched"] = json!(count);
    }
    if brief.get("attack_pressure").is_none() {
        brief["attack_pressure"] = empty_attack_pressure("missing");
    }
    if brief.get("ioc_radar").is_none() {
        brief["ioc_radar"] = empty_ioc_radar("missing");
    }
    if brief.get("infrastructure_radar").is_none() {
        brief["infrastructure_radar"] = empty_infrastructure_radar("missing");
    }
    if brief.get("supply_chain_radar").is_none() {
        brief["supply_chain_radar"] = empty_supply_chain_radar("missing");
    }
    if brief.get("ransomware_pulse").is_none() {
        brief["ransomware_pulse"] = empty_ransomware_pulse("missing");
    }
    if brief.get("botnet_c2_pulse").is_none() {
        brief["botnet_c2_pulse"] = empty_botnet_c2_pulse("missing");
    }
    if brief.get("greynoise_context").is_none() {
        brief["greynoise_context"] = empty_greynoise_context("missing");
    }
    if brief.get("phishing_pulse").is_none() {
        brief["phishing_pulse"] = empty_phishing_pulse("missing");
    }
    if brief.get("ics_ot_pulse").is_none() {
        brief["ics_ot_pulse"] = empty_ics_ot_pulse("missing");
    }
    if brief.get("nuclei_coverage").is_none() {
        brief["nuclei_coverage"] = empty_nuclei_coverage("missing");
    }
    if brief.get("writeups_pulse").is_none() {
        brief["writeups_pulse"] = empty_writeups_pulse("missing");
    }
    if brief.get("poc_watch").is_none() {
        brief["poc_watch"] = empty_poc_watch("missing");
    }
    if brief.get("stats").and_then(|v| v.get("writeups")).is_none() {
        brief["stats"]["writeups"] =
            json!(path_u64(brief, &["writeups_pulse", "totals", "writeups"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("writeup_sources"))
        .is_none()
    {
        brief["stats"]["writeup_sources"] =
            json!(path_u64(brief, &["writeups_pulse", "totals", "sources"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("nuclei_covered_cves"))
        .is_none()
    {
        brief["stats"]["nuclei_covered_cves"] = json!(path_u64(
            brief,
            &["nuclei_coverage", "totals", "covered_cves"]
        ));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("nuclei_coverage_pct"))
        .is_none()
    {
        brief["stats"]["nuclei_coverage_pct"] = json!(path_u64(
            brief,
            &["nuclei_coverage", "totals", "coverage_pct"]
        ));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("poc_watch"))
        .is_none()
    {
        brief["stats"]["poc_watch"] = json!(path_u64(brief, &["poc_watch", "totals", "repos"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("poc_watch_high"))
        .is_none()
    {
        brief["stats"]["poc_watch_high"] = json!(path_u64(brief, &["poc_watch", "totals", "high"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("poc_watch_cves"))
        .is_none()
    {
        brief["stats"]["poc_watch_cves"] =
            json!(path_u64(brief, &["poc_watch", "totals", "cves_with_poc"]));
    }
    if brief.get("executive_snapshot").is_none() {
        brief["executive_snapshot"] = json!({});
    }
    if brief.get("stats").and_then(|v| v.get("iocs")).is_none() {
        let ioc_total = brief
            .get("ioc_radar")
            .and_then(|radar| radar.get("totals"))
            .and_then(|totals| totals.get("total"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["iocs"] = json!(ioc_total);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("infrastructure_hosts"))
        .is_none()
    {
        let infra_total = brief
            .get("infrastructure_radar")
            .and_then(|radar| radar.get("totals"))
            .and_then(|totals| totals.get("hosts"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["infrastructure_hosts"] = json!(infra_total);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("supply_chain_advisories"))
        .is_none()
    {
        let supply_total = brief
            .get("supply_chain_radar")
            .and_then(|radar| radar.get("totals"))
            .and_then(|totals| totals.get("advisories"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["supply_chain_advisories"] = json!(supply_total);
    }
    let cve_items = brief
        .get("cves")
        .and_then(|items| items.as_array())
        .cloned()
        .unwrap_or_default();
    if brief
        .get("stats")
        .and_then(|v| v.get("epss_tracked"))
        .is_none()
    {
        let tracked = cve_items
            .iter()
            .filter(|cve| {
                cve.get("epss").and_then(|v| v.as_f64()).unwrap_or(0.0) > 0.0
                    || cve
                        .get("epss_percentile")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0)
                        > 0.0
            })
            .count();
        brief["stats"]["epss_tracked"] = json!(tracked);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("epss_rising"))
        .is_none()
    {
        let rising = cve_items
            .iter()
            .filter(|cve| cve.get("epss_momentum").and_then(|v| v.as_str()) == Some("rising"))
            .count();
        brief["stats"]["epss_rising"] = json!(rising);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("epss_stable"))
        .is_none()
    {
        let stable = cve_items
            .iter()
            .filter(|cve| cve.get("epss_momentum").and_then(|v| v.as_str()) == Some("stable"))
            .count();
        brief["stats"]["epss_stable"] = json!(stable);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("epss_falling"))
        .is_none()
    {
        let falling = cve_items
            .iter()
            .filter(|cve| cve.get("epss_momentum").and_then(|v| v.as_str()) == Some("falling"))
            .count();
        brief["stats"]["epss_falling"] = json!(falling);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("vulnrichment_hits"))
        .is_none()
    {
        let hits = cve_items
            .iter()
            .filter(|cve| {
                cve.get("cisa_vulnrichment")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            })
            .count();
        brief["stats"]["vulnrichment_hits"] = json!(hits);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("vulnrichment_checked"))
        .is_none()
    {
        let checked = cve_items.len().min(10);
        brief["stats"]["vulnrichment_checked"] = json!(checked);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("vulnrichment_missing"))
        .is_none()
    {
        let checked = brief["stats"]["vulnrichment_checked"].as_u64().unwrap_or(0);
        let hits = brief["stats"]["vulnrichment_hits"].as_u64().unwrap_or(0);
        brief["stats"]["vulnrichment_missing"] = json!(checked.saturating_sub(hits));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("ransomware_victims"))
        .is_none()
    {
        let ransomware_total = brief
            .get("ransomware_pulse")
            .and_then(|radar| radar.get("totals"))
            .and_then(|totals| totals.get("victims"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["ransomware_victims"] = json!(ransomware_total);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("botnet_c2"))
        .is_none()
    {
        let botnet_total = path_u64(brief, &["botnet_c2_pulse", "totals", "c2"]);
        brief["stats"]["botnet_c2"] = json!(botnet_total);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("malicious_tls"))
        .is_none()
    {
        let tls_total = path_u64(brief, &["botnet_c2_pulse", "totals", "tls"]);
        brief["stats"]["malicious_tls"] = json!(tls_total);
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("greynoise_noise"))
        .is_none()
    {
        brief["stats"]["greynoise_noise"] =
            json!(path_u64(brief, &["greynoise_context", "totals", "noise"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("greynoise_malicious"))
        .is_none()
    {
        brief["stats"]["greynoise_malicious"] = json!(path_u64(
            brief,
            &["greynoise_context", "totals", "malicious"]
        ));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("greynoise_riot"))
        .is_none()
    {
        brief["stats"]["greynoise_riot"] =
            json!(path_u64(brief, &["greynoise_context", "totals", "riot"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("phishing_urls"))
        .is_none()
    {
        brief["stats"]["phishing_urls"] =
            json!(path_u64(brief, &["phishing_pulse", "totals", "urls"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("phishing_high"))
        .is_none()
    {
        brief["stats"]["phishing_high"] =
            json!(path_u64(brief, &["phishing_pulse", "totals", "high"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("phishing_tlds"))
        .is_none()
    {
        brief["stats"]["phishing_tlds"] =
            json!(path_u64(brief, &["phishing_pulse", "totals", "tlds"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("ics_advisories"))
        .is_none()
    {
        brief["stats"]["ics_advisories"] =
            json!(path_u64(brief, &["ics_ot_pulse", "totals", "advisories"]));
    }
    if brief.get("stats").and_then(|v| v.get("ics_high")).is_none() {
        brief["stats"]["ics_high"] = json!(path_u64(brief, &["ics_ot_pulse", "totals", "high"]));
    }
    if brief
        .get("stats")
        .and_then(|v| v.get("ics_vendors"))
        .is_none()
    {
        brief["stats"]["ics_vendors"] =
            json!(path_u64(brief, &["ics_ot_pulse", "totals", "vendors"]));
    }

    polish_priority(brief);
    polish_array_items(brief, "breaking_news", 88, 240);
    polish_array_items(brief, "iran_radar", 88, 240);
    polish_array_items(brief, "global_news", 88, 240);
    polish_writeups_pulse(brief);
    polish_cves(brief);
    add_editorial_display_fields(brief);
    brief["brief_notes"] = json!(build_brief_notes(brief));

    let executive_snapshot = build_executive_snapshot(brief);
    brief["executive_snapshot"] = executive_snapshot;
    let synced_level = match brief["executive_snapshot"]["level"].as_str() {
        Some("high") => "High",
        Some("medium") => "Medium",
        _ => "Watch",
    };
    brief["risk_level"] = json!(synced_level);
}

pub(crate) fn polish_priority(brief: &mut Value) {
    let Some(priority) = brief
        .get_mut("priority_alert")
        .and_then(|v| v.as_object_mut())
    else {
        return;
    };

    if let Some(Value::String(title)) = priority.get_mut("title") {
        *title = concise_title(title, 92);
    }
    if let Some(Value::String(summary)) = priority.get_mut("summary") {
        *summary = non_empty_summary(summary, 260);
    }
}

pub(crate) fn polish_array_items(brief: &mut Value, key: &str, title_max: usize, summary_max: usize) {
    let Some(items) = brief.get_mut(key).and_then(|v| v.as_array_mut()) else {
        return;
    };

    for item in items {
        let Some(obj) = item.as_object_mut() else {
            continue;
        };
        if let Some(Value::String(title)) = obj.get_mut("title") {
            *title = concise_title(title, title_max);
        }
        if let Some(Value::String(summary)) = obj.get_mut("summary") {
            *summary = non_empty_summary(summary, summary_max);
        }
    }
}

pub(crate) fn polish_writeups_pulse(brief: &mut Value) {
    let Some(items) = brief
        .get_mut("writeups_pulse")
        .and_then(|value| value.get_mut("writeups"))
        .and_then(|value| value.as_array_mut())
    else {
        return;
    };

    for item in items {
        let Some(obj) = item.as_object_mut() else {
            continue;
        };
        if let Some(Value::String(title)) = obj.get_mut("title") {
            *title = concise_title(title, 92);
        }
        if let Some(Value::String(summary)) = obj.get_mut("summary") {
            *summary = non_empty_summary(summary, 260);
        }
        if let Some(Value::String(title_fa)) = obj.get_mut("title_fa") {
            *title_fa = truncate_chars(title_fa, 160);
        }
        if let Some(Value::String(summary_fa)) = obj.get_mut("summary_fa") {
            *summary_fa = truncate_chars(summary_fa, 210);
        }
    }
}

pub(crate) fn polish_cves(brief: &mut Value) {
    let Some(items) = brief.get_mut("cves").and_then(|v| v.as_array_mut()) else {
        return;
    };

    for item in items {
        let Some(obj) = item.as_object_mut() else {
            continue;
        };
        if let Some(Value::String(title)) = obj.get_mut("title") {
            *title = concise_title(title, 84);
        }
        if let Some(Value::String(summary)) = obj.get_mut("summary") {
            *summary = non_empty_summary(summary, 260);
        }
        if let Some(Value::String(action)) = obj.get_mut("recommended_action") {
            *action = non_empty_summary(action, 170);
        }
    }
}

pub(crate) fn add_editorial_display_fields(brief: &mut Value) {
    enrich_priority_fields(brief);
    enrich_news_fields(brief, "breaking_news", false);
    enrich_news_fields(brief, "iran_radar", true);
    enrich_news_fields(brief, "global_news", false);
    enrich_cve_fields(brief);
}

pub(crate) fn enrich_priority_fields(brief: &mut Value) {
    let Some(obj) = brief
        .get_mut("priority_alert")
        .and_then(|value| value.as_object_mut())
    else {
        return;
    };

    let title = obj
        .get("title")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    let summary = obj
        .get("summary")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    let risk_score = obj
        .get("risk_score")
        .and_then(|value| value.as_i64())
        .unwrap_or(1);

    insert_string_if_missing(obj, "title_fa", &fallback_persian_title(&title));
    insert_string_if_missing(
        obj,
        "summary_fa",
        &fallback_persian_summary(&summary, "این هشدار مهم‌ترین آیتم امروز است"),
    );
    insert_string_if_missing(
        obj,
        "why_it_matters",
        &fallback_why_it_matters(risk_score, &summary),
    );
    insert_string_if_missing(
        obj,
        "ops_note",
        "اول exposure و دارایی‌های مرتبط را مشخص کن، سپس وضعیت patch یا mitigation را ثبت کن.",
    );
}

pub(crate) fn enrich_news_fields(brief: &mut Value, key: &str, iran_section: bool) {
    let Some(items) = brief.get_mut(key).and_then(|value| value.as_array_mut()) else {
        return;
    };

    for item in items {
        let Some(obj) = item.as_object_mut() else {
            continue;
        };
        let title = obj
            .get("title")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let summary = obj
            .get("summary")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let risk_score = obj
            .get("risk_score")
            .and_then(|value| value.as_i64())
            .unwrap_or(1);
        let published = obj
            .get("published")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let (published_date_local, published_time_local, freshness_label) =
            news_time_display_fields(&published);
        obj.insert(
            "published_date_local".to_string(),
            json!(published_date_local),
        );
        obj.insert(
            "published_time_local".to_string(),
            json!(published_time_local),
        );
        obj.insert("freshness_label".to_string(), json!(freshness_label));

        insert_string_if_missing(obj, "title_fa", &fallback_persian_title(&title));
        insert_string_if_missing(
            obj,
            "summary_fa",
            &fallback_persian_summary(&summary, "این خبر برای پایش امروز قابل توجه است"),
        );
        insert_string_if_missing(
            obj,
            "why_it_matters",
            &fallback_why_it_matters(risk_score, &summary),
        );
        let note = if iran_section {
            "ارتباط این آیتم با ایران را با دامنه، برند، vendor و زیرساخت خودت جداگانه triage کن."
        } else if risk_score >= 8 {
            "برای دارایی‌های public-facing مرتبط، وضعیت exposure و لاگ‌های ۲۴ تا ۴۸ ساعت اخیر را بررسی کن."
        } else {
            "نام vendor یا محصول را با inventory و backlog patch مقایسه کن."
        };
        insert_string_if_missing(obj, "ops_note", note);
    }
}

pub(crate) fn enrich_cve_fields(brief: &mut Value) {
    let Some(items) = brief.get_mut("cves").and_then(|value| value.as_array_mut()) else {
        return;
    };

    for item in items {
        let Some(obj) = item.as_object_mut() else {
            continue;
        };
        let title = obj
            .get("title")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let summary = obj
            .get("summary")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let risk_score = obj
            .get("risk_score")
            .and_then(|value| value.as_i64())
            .unwrap_or(1);
        let kev = obj
            .get("kev")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let severity = obj
            .get("severity")
            .and_then(|value| value.as_str())
            .unwrap_or("UNKNOWN")
            .to_string();

        insert_string_if_missing(obj, "title_fa", &fallback_persian_title(&title));
        insert_string_if_missing(
            obj,
            "summary_fa",
            &fallback_persian_summary(&summary, "این CVE باید با موجودی دارایی‌ها تطبیق داده شود"),
        );
        insert_string_if_missing(
            obj,
            "why_it_matters",
            &fallback_why_it_matters(risk_score, &summary),
        );

        let note = if kev {
            "چون در KEV دیده شده، وضعیت affected/not affected را همان‌روز مشخص و mitigation را پیگیری کن."
        } else if severity == "CRITICAL" || risk_score >= 8 {
            "ابتدا assetهای اینترنتی و سرویس‌های حساس مرتبط را بررسی و برای patch اولویت بالا تعیین کن."
        } else {
            "با inventory تطبیق بده و در چرخه patch عادی یا accelerated پیگیری کن."
        };
        insert_string_if_missing(obj, "ops_note", note);
    }
}

pub(crate) fn insert_string_if_missing(obj: &mut serde_json::Map<String, Value>, key: &str, value: &str) {
    let has_good_value = obj
        .get(key)
        .and_then(|existing| existing.as_str())
        .is_some_and(|existing| !existing.trim().is_empty());

    if !has_good_value && !value.trim().is_empty() {
        obj.insert(key.to_string(), Value::String(value.to_string()));
    }
}

pub(crate) fn fallback_persian_title(title: &str) -> String {
    // Non-AI runs must NOT rewrite headlines: keep the original title text as-is.
    // A faithful Persian translation is added only by the AI editorial layer.
    let cleaned = concise_title(title, 160);
    if cleaned.trim().is_empty() {
        return "سیگنال امنیتی قابل بررسی".to_string();
    }
    truncate_chars(&cleaned, 160)
}

pub(crate) fn fallback_persian_summary(summary: &str, fallback_prefix: &str) -> String {
    let cleaned = non_empty_summary(summary, 220);
    if contains_persian(&cleaned) {
        return truncate_chars(&cleaned, 190);
    }

    let lower = cleaned.to_lowercase();
    let focus = persian_focus_label(&cleaned);
    let text = if lower.contains("actively exploited")
        || lower.contains("exploited in the wild")
        || lower.contains("mass exploitation")
    {
        format!("این سیگنال نشانه بهره‌برداری فعال پیرامون {focus} دارد؛ exposure دارایی‌های مرتبط باید سریع بررسی شود.")
    } else if lower.contains("cve-")
        || lower.contains("vulnerability")
        || lower.contains("vulnerabilities")
        || lower.contains("flaw")
        || lower.contains("bug")
    {
        format!("این آیتم به آسیب‌پذیری در {focus} اشاره دارد و باید با موجودی دارایی‌ها و برنامه وصله تطبیق داده شود.")
    } else if lower.contains("ransomware") {
        format!("این گزارش به فعالیت باج‌افزاری مرتبط با {focus} اشاره دارد و برای پایش ریسک تداوم سرویس مهم است.")
    } else if lower.contains("malware")
        || lower.contains("trojan")
        || lower.contains("botnet")
        || lower.contains("backdoor")
    {
        format!("این سیگنال به بدافزار یا زیرساخت مخرب مرتبط با {focus} اشاره دارد و برای correlation دفاعی قابل استفاده است.")
    } else if lower.contains("supply chain")
        || lower.contains("package")
        || lower.contains("dependency")
    {
        format!("این آیتم به ریسک زنجیره تأمین نرم‌افزار پیرامون {focus} اشاره دارد و باید با وابستگی‌های واقعی مقایسه شود.")
    } else if lower.contains("phishing") || lower.contains("credential") {
        format!("این سیگنال به فیشینگ یا سرقت اعتبار مرتبط با {focus} اشاره دارد و برای پایش هویت و ایمیل مهم است.")
    } else if !fallback_prefix.trim().is_empty() {
        format!("{fallback_prefix}؛ موضوع اصلی برای پایش امروز {focus} است.")
    } else {
        format!(
            "این خبر امنیتی درباره {focus} برای آگاهی موقعیتی و اولویت‌بندی روزانه قابل بررسی است."
        )
    };

    truncate_chars(&text, 190)
}

pub(crate) fn persian_focus_label(text: &str) -> String {
    if let Some(cve) = first_cve_id(text) {
        return cve;
    }

    let lower = text.to_lowercase();
    let known = [
        ("microsoft", "Microsoft"),
        ("windows", "Windows"),
        ("exchange", "Exchange"),
        ("office", "Office"),
        ("azure", "Azure"),
        ("github", "GitHub"),
        ("gitlab", "GitLab"),
        ("gitea", "Gitea"),
        ("google chrome", "Chrome"),
        ("chrome", "Chrome"),
        ("android", "Android"),
        ("apple", "Apple"),
        ("ios", "iOS"),
        ("macos", "macOS"),
        ("linux", "Linux"),
        ("kernel", "Linux Kernel"),
        ("cisco", "Cisco"),
        ("fortinet", "Fortinet"),
        ("fortigate", "FortiGate"),
        ("palo alto", "Palo Alto"),
        ("ivanti", "Ivanti"),
        ("vmware", "VMware"),
        ("citrix", "Citrix"),
        ("apache", "Apache"),
        ("nginx", "Nginx"),
        ("wordpress", "WordPress"),
        ("drupal", "Drupal"),
        ("kubernetes", "Kubernetes"),
        ("docker", "Docker"),
        ("jenkins", "Jenkins"),
        ("npm", "npm"),
        ("pypi", "PyPI"),
        ("maven", "Maven"),
        ("rust", "Rust"),
        ("golang", "Go"),
        ("go ", "Go"),
        ("ransomware", "باج‌افزار"),
        ("malware", "بدافزار"),
        ("phishing", "فیشینگ"),
        ("botnet", "بات‌نت"),
        ("zero-day", "روز-صفر"),
    ];

    let mut hits: Vec<&str> = Vec::new();
    for (needle, label) in known {
        if lower.contains(needle) && !hits.contains(&label) {
            hits.push(label);
        }
        if hits.len() >= 2 {
            break;
        }
    }
    if !hits.is_empty() {
        return hits.join(" / ");
    }

    let mut tokens: Vec<String> = Vec::new();
    for raw in text.split_whitespace() {
        let token = raw.trim_matches(|ch: char| {
            !(ch.is_alphanumeric() || ch == '-' || ch == '_' || ch == '.' || ch == '/')
        });
        if token.len() < 3 || token.len() > 32 || is_noise_token(token) {
            continue;
        }
        let has_signal_case = token.chars().any(|ch| ch.is_ascii_uppercase())
            || token.contains('-')
            || token.contains('.')
            || token.contains('/');
        if has_signal_case && !tokens.iter().any(|existing| existing == token) {
            tokens.push(token.to_string());
        }
        if tokens.len() >= 2 {
            break;
        }
    }

    if tokens.is_empty() {
        "دارایی یا سرویس مهم".to_string()
    } else {
        tokens.join(" / ")
    }
}

pub(crate) fn first_cve_id(text: &str) -> Option<String> {
    for raw in text.split_whitespace() {
        let token = raw
            .trim_matches(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-'))
            .to_ascii_uppercase();
        if token.starts_with("CVE-") && token.len() >= 13 {
            return Some(token);
        }
    }
    None
}

pub(crate) fn is_noise_token(token: &str) -> bool {
    let lower = token.to_lowercase();
    matches!(
        lower.as_str(),
        "the"
            | "and"
            | "for"
            | "from"
            | "with"
            | "that"
            | "this"
            | "into"
            | "after"
            | "before"
            | "over"
            | "under"
            | "new"
            | "old"
            | "security"
            | "cyber"
            | "hackers"
            | "attacks"
            | "attack"
            | "vulnerability"
            | "vulnerabilities"
            | "critical"
            | "high"
            | "medium"
            | "low"
            | "warning"
            | "alert"
            | "update"
            | "updates"
            | "patch"
            | "patches"
            | "users"
            | "companies"
            | "researchers"
    )
}

pub(crate) fn fallback_why_it_matters(risk_score: i64, text: &str) -> String {
    let lower = text.to_lowercase();
    if lower.contains("ransomware") {
        "احتمال اثر مستقیم روی تداوم کسب‌وکار و بازیابی سرویس‌ها وجود دارد.".to_string()
    } else if lower.contains("actively exploited") || lower.contains("exploited in the wild") {
        "نشانه بهره‌برداری فعال دیده شده و باید از backlog عادی جدا شود.".to_string()
    } else if lower.contains("cve-") || risk_score >= 8 {
        "اگر محصول مرتبط در محیط وجود داشته باشد، اولویت patch و کنترل exposure بالاست.".to_string()
    } else {
        "برای تصمیم روزانه SOC و تیم زیرساخت، ارزش triage و ثبت وضعیت دارد.".to_string()
    }
}

pub(crate) fn contains_persian(text: &str) -> bool {
    text.chars()
        .any(|ch| ('\u{0600}'..='\u{06FF}').contains(&ch))
}

pub(crate) fn build_brief_notes(brief: &Value) -> Vec<String> {
    let mut notes = Vec::new();
    let ai = brief.get("ai_status").unwrap_or(&Value::Null);
    let ai_enabled = ai.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let ai_ok = ai.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    let ai_cache = ai
        .get("cache_hit")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let sources = brief
        .get("source_health")
        .and_then(|v| v.get("rss_sources"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let failed_sources = brief
        .get("source_health")
        .and_then(|v| v.get("failed_rss_sources"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let attack_pressure_ok = brief
        .get("attack_pressure")
        .and_then(|v| v.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ioc_radar_ok = brief
        .get("ioc_radar")
        .and_then(|v| v.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let infrastructure_ok = brief
        .get("infrastructure_radar")
        .and_then(|v| v.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let supply_chain_ok = brief
        .get("supply_chain_radar")
        .and_then(|v| v.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ransomware_ok = brief
        .get("ransomware_pulse")
        .and_then(|v| v.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let botnet_ok = brief
        .get("botnet_c2_pulse")
        .and_then(|v| v.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let greynoise_ok = brief
        .get("greynoise_context")
        .and_then(|v| v.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if ai_enabled && ai_ok && ai_cache {
        notes.push(
            "نسخه فارسی این رادار از cache هوش مصنوعی آماده شده و داده خام منابع حفظ شده است."
                .to_string(),
        );
    } else if ai_enabled && ai_ok {
        notes.push(
            "نسخه فارسی این رادار با یک ویرایش هوش مصنوعی ساخته و برای اجرای بعدی cache شد."
                .to_string(),
        );
    } else if ai_enabled {
        notes.push(
            "لایه فارسی‌سازی هوش مصنوعی در این اجرا کامل نشد؛ خروجی با fallback محلی ساخته شده است."
                .to_string(),
        );
    } else {
        notes.push(
            "این خروجی بدون هوش مصنوعی ساخته شده و فقط از ruleهای محلی استفاده می‌کند.".to_string(),
        );
    }

    if sources > 0 {
        let mut coverage = format!(
            "پوشش خبری این نسخه از {sources} منبع RSS به‌همراه NVD، CISA KEV و EPSS ساخته شده است."
        );
        if attack_pressure_ok {
            coverage.push_str(" لایه Attack Pressure نیز از DShield/SANS اضافه شده است.");
        }
        if ioc_radar_ok {
            coverage.push_str(" IOC Radar هم از URLhaus و ThreatFox ساخته شده است.");
        }
        if infrastructure_ok {
            coverage
                .push_str(" Suspicious Infrastructure نیز با Shodan InternetDB enrich شده است.");
        }
        if supply_chain_ok {
            coverage.push_str(
                " Supply Chain Radar نیز از GitHub Advisories و OSV reference ساخته شده است.",
            );
        }
        if ransomware_ok {
            coverage.push_str(" Ransomware Pulse هم از Ransomware.live به صورت آماری و بدون لینک leak ساخته شده است.");
        }
        if botnet_ok {
            coverage
                .push_str(" Botnet C2 Pulse از Feodo و SSLBL به‌صورت metadata-only ساخته شده است.");
        }
        if greynoise_ok {
            coverage.push_str(
                " GreyNoise Context نیز برای IPهای منتخب به‌صورت passive lookup اضافه شده است.",
            );
        }
        if brief
            .get("ics_ot_pulse")
            .and_then(|v| v.get("ok"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            coverage.push_str(" ICS/OT Advisory Pulse هم از CISA ICS Advisories به‌صورت metadata-only ساخته شده است.");
        }
        if brief
            .get("poc_watch")
            .and_then(|v| v.get("ok"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            coverage.push_str(" Latest PoC Watch نیز از GitHub Search به‌صورت latest-first ساخته شده، CVE را از metadata استخراج می‌کند و کد exploit نمایش نمی‌دهد.");
        }
        if failed_sources > 0 {
            coverage.push_str(&format!(
                " {failed_sources} منبع RSS در این اجرا skip شد و در Source Health ثبت شده است."
            ));
        }
        notes.push(coverage);
    }

    notes.into_iter().take(2).collect()
}

pub(crate) fn concise_title(input: &str, max_chars: usize) -> String {
    let mut title = clean_text(input);
    let replacements = [
        ("A vulnerability was found in ", ""),
        ("A vulnerability has been found in ", ""),
        ("A vulnerability in ", ""),
        ("A flaw was found in ", ""),
        ("An issue was discovered in ", ""),
        ("This vulnerability allows ", "Allows "),
        ("The vulnerability allows ", "Allows "),
        ("Multiple vulnerabilities in ", ""),
    ];

    for (from, to) in replacements {
        if title.starts_with(from) {
            title = title.replacen(from, to, 1);
        }
    }

    truncate_chars(title.trim(), max_chars)
}

pub(crate) fn non_empty_summary(input: &str, max_chars: usize) -> String {
    let cleaned = clean_text(input);
    if cleaned.trim().is_empty() {
        "جزئیات کافی در منبع وجود نداشت؛ برای تصمیم‌گیری، advisory اصلی را بررسی کن.".to_string()
    } else {
        truncate_chars(&cleaned, max_chars)
    }
}
