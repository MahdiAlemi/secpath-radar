//! CVE collection: NVD, CISA KEV, EPSS, and CISA Vulnrichment.

use crate::prelude::*;

pub(crate) fn fetch_cves(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<Vec<CveItem>> {
    let client = build_client(config)?;

    let cve_config = &config.cve;
    let now = Utc::now();
    let rounded_end =
        chrono::DateTime::<Utc>::from_timestamp((now.timestamp() / 3600) * 3600, 0).unwrap_or(now);
    let start = rounded_end - ChronoDuration::days(cve_config.lookback_days.max(1));
    let start_s = start.to_rfc3339_opts(SecondsFormat::Millis, true);
    let end_s = rounded_end.to_rfc3339_opts(SecondsFormat::Millis, true);
    let results_per_page = (cve_config.max_cves * 4).max(20).min(2000).to_string();

    let kev_map = match fetch_kev_map(&client, config, cve_config, offline, refresh_cache) {
        Ok(map) => map,
        Err(err) => {
            eprintln!("⚠️  skipped CISA KEV enrichment: {err:#}");
            HashMap::new()
        }
    };

    thread::sleep(Duration::from_millis(cve_config.sleep_ms_between_sources));

    let nvd_result = fetch_nvd_window(
        &client,
        config,
        cve_config,
        &kev_map,
        &start_s,
        &end_s,
        &results_per_page,
        offline,
        refresh_cache,
    );

    let mut cves = match nvd_result {
        Ok(list) if !list.is_empty() => list,
        result => {
            match &result {
                Ok(_) => eprintln!("⚠️  NVD returned no CVEs for this window"),
                Err(err) => eprintln!("⚠️  NVD unavailable: {err:#}"),
            }
            if cve_config.include_fallback {
                fetch_fallback_cves(
                    &client,
                    config,
                    cve_config,
                    &kev_map,
                    offline,
                    refresh_cache,
                )?
            } else {
                result?
            }
        }
    };

    if cve_config.include_epss && !cves.is_empty() {
        thread::sleep(Duration::from_millis(cve_config.sleep_ms_between_sources));
        let ids: Vec<String> = cves.iter().map(|c| c.cve_id.clone()).collect();
        match fetch_epss_map(
            &client,
            config,
            cve_config,
            &ids,
            None,
            offline,
            refresh_cache,
        ) {
            Ok(epss_map) => {
                for cve in &mut cves {
                    if let Some(snapshot) = epss_map.get(&cve.cve_id) {
                        cve.epss = snapshot.epss;
                        cve.epss_percentile = snapshot.percentile;
                    }
                    finalize_cve_score(cve);
                }

                if cve_config.include_epss_momentum {
                    enrich_epss_momentum(
                        &client,
                        config,
                        cve_config,
                        &mut cves,
                        &ids,
                        rounded_end.date_naive(),
                        offline,
                        refresh_cache,
                    );
                }
            }
            Err(err) => eprintln!("⚠️  skipped EPSS enrichment: {err:#}"),
        }
    }

    if cve_config.include_vulnrichment && !cves.is_empty() {
        enrich_vulnrichment(
            &client,
            config,
            cve_config,
            &mut cves,
            offline,
            refresh_cache,
        );
    }

    for cve in &mut cves {
        finalize_cve_score(cve);
    }

    cves.sort_by(|a, b| {
        b.risk_score.cmp(&a.risk_score).then_with(|| {
            b.cvss
                .partial_cmp(&a.cvss)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });
    cves.truncate(cve_config.max_cves);

    eprintln!("✅ CVE engine: {} CVEs selected", cves.len());
    Ok(cves)
}

pub(crate) fn fetch_kev_map(
    client: &Client,
    config: &Config,
    cve_config: &CveConfig,
    offline: bool,
    refresh_cache: bool,
) -> Result<HashMap<String, KevEntry>> {
    eprintln!("→ fetching CISA KEV catalog");
    let bytes = get_bytes_cached(
        client,
        config,
        &cve_config.kev_url,
        &[],
        "CISA KEV catalog",
        offline,
        refresh_cache,
    )?;

    let json: Value = serde_json::from_slice(&bytes).context("invalid JSON from CISA KEV")?;
    Ok(parse_kev_map(&json))
}

pub(crate) fn parse_kev_map(json: &Value) -> HashMap<String, KevEntry> {
    let mut out = HashMap::new();

    if let Some(vulns) = json.get("vulnerabilities").and_then(|v| v.as_array()) {
        for vuln in vulns {
            let Some(id) = vuln.get("cveID").and_then(|v| v.as_str()) else {
                continue;
            };
            let due_date = vuln
                .get("dueDate")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let ransomware = vuln
                .get("knownRansomwareCampaignUse")
                .and_then(|v| v.as_str())
                .map(|s| s.eq_ignore_ascii_case("known"))
                .unwrap_or(false);
            out.insert(
                id.to_string(),
                KevEntry {
                    due_date,
                    ransomware,
                },
            );
        }
    }

    out
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn fetch_nvd_window(
    client: &Client,
    config: &Config,
    cve_config: &CveConfig,
    kev_map: &HashMap<String, KevEntry>,
    start_s: &str,
    end_s: &str,
    results_per_page: &str,
    offline: bool,
    refresh_cache: bool,
) -> Result<Vec<CveItem>> {
    eprintln!("→ fetching NVD CVEs from {start_s} to {end_s}");
    let nvd_bytes = get_bytes_cached(
        client,
        config,
        &cve_config.nvd_url,
        &[
            ("pubStartDate", start_s),
            ("pubEndDate", end_s),
            ("resultsPerPage", results_per_page),
        ],
        "NVD CVE API",
        offline,
        refresh_cache,
    )?;

    let nvd_json: Value = serde_json::from_slice(&nvd_bytes).context("invalid JSON from NVD")?;
    Ok(parse_nvd_cves(&nvd_json, kev_map))
}

pub(crate) fn fetch_fallback_cves(
    client: &Client,
    config: &Config,
    cve_config: &CveConfig,
    kev_map: &HashMap<String, KevEntry>,
    offline: bool,
    refresh_cache: bool,
) -> Result<Vec<CveItem>> {
    eprintln!("→ fetching cvelistV5 delta as NVD fallback");
    let bytes = get_bytes_cached(
        client,
        config,
        &cve_config.fallback_delta_url,
        &[],
        "cvelistV5 delta",
        offline,
        refresh_cache,
    )?;
    let json: Value =
        serde_json::from_slice(&bytes).context("invalid JSON from cvelistV5 delta")?;

    let mut records: Vec<(String, String)> = Vec::new();
    for key in ["new", "updated"] {
        let Some(rows) = json.get(key).and_then(|v| v.as_array()) else {
            continue;
        };
        for row in rows {
            let Some(id) = row.get("cveId").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(link) = row.get("githubLink").and_then(|v| v.as_str()) else {
                continue;
            };
            records.push((id.to_string(), link.to_string()));
        }
    }
    records.truncate(cve_config.max_fallback_records);

    let mut out = Vec::new();
    for (cve_id, link) in &records {
        thread::sleep(Duration::from_millis(
            (cve_config.sleep_ms_between_sources / 4).max(150),
        ));
        let record_bytes = match get_bytes_cached(
            client,
            config,
            link,
            &[],
            &format!("cvelistV5 {cve_id}"),
            offline,
            refresh_cache,
        ) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("⚠️  skipped cvelistV5 record {cve_id}: {err:#}");
                continue;
            }
        };
        let Ok(record_json) = serde_json::from_slice::<Value>(&record_bytes) else {
            continue;
        };
        if let Some(item) = parse_cvelist_record(&record_json, kev_map) {
            out.push(item);
        }
    }

    eprintln!("  ↳ cvelistV5 fallback: {} records usable", out.len());
    Ok(out)
}

pub(crate) fn parse_cvelist_record(
    json: &Value,
    kev_map: &HashMap<String, KevEntry>,
) -> Option<CveItem> {
    let cve_id = json
        .pointer("/cveMetadata/cveId")
        .and_then(|v| v.as_str())?
        .to_string();
    let state = json
        .pointer("/cveMetadata/state")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if state.eq_ignore_ascii_case("rejected") {
        return None;
    }
    let cna = json.pointer("/containers/cna")?;

    let descriptions = cna.get("descriptions").and_then(|v| v.as_array())?;
    let summary = descriptions
        .iter()
        .find(|d| {
            d.get("lang")
                .and_then(|v| v.as_str())
                .map(|s| s.to_ascii_lowercase().starts_with("en"))
                .unwrap_or(false)
        })
        .or_else(|| descriptions.first())
        .and_then(|d| d.get("value"))
        .and_then(|v| v.as_str())
        .map(clean_text)?;
    if summary.is_empty() {
        return None;
    }

    let (severity, cvss, cvss_version) = extract_cvelist_cvss(cna);
    let published = json
        .pointer("/cveMetadata/datePublished")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let title = cna
        .get("title")
        .and_then(|v| v.as_str())
        .map(|s| concise_title(s, 84))
        .unwrap_or_else(|| derive_cve_title(&cve_id, &summary));
    let kev_entry = kev_map.get(&cve_id);
    let url = format!("https://www.cve.org/CVERecord?id={cve_id}");

    let mut item = CveItem {
        cve_id: cve_id.clone(),
        title,
        summary: truncate_chars(&summary, 310),
        severity,
        cvss,
        cvss_version,
        epss: 0.0,
        epss_percentile: 0.0,
        epss_7d: 0.0,
        epss_30d: 0.0,
        epss_delta_7d: 0.0,
        epss_delta_30d: 0.0,
        epss_momentum: "stable".to_string(),
        kev: kev_entry.is_some(),
        kev_due_date: kev_entry.map(|e| e.due_date.clone()).unwrap_or_default(),
        kev_ransomware: kev_entry.map(|e| e.ransomware).unwrap_or(false),
        cisa_vulnrichment: false,
        ssvc_exploitation: String::new(),
        ssvc_automatable: String::new(),
        ssvc_technical_impact: String::new(),
        cisa_priority: "unscored".to_string(),
        published,
        url,
        recommended_action: String::new(),
        risk_score: 1,
        tags: Vec::new(),
    };

    finalize_cve_score(&mut item);
    Some(item)
}

pub(crate) fn extract_cvelist_cvss(cna: &Value) -> (String, f64, String) {
    let Some(metrics) = cna.get("metrics").and_then(|v| v.as_array()) else {
        return ("UNKNOWN".to_string(), 0.0, String::new());
    };

    let keys = [
        ("cvssV4_0", "4.0"),
        ("cvssV3_1", "3.1"),
        ("cvssV3_0", "3.0"),
        ("cvssV2_0", "2.0"),
    ];

    for (key, version) in keys {
        for metric in metrics {
            let Some(data) = metric.get(key) else {
                continue;
            };
            let score = data
                .get("baseScore")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let severity = data
                .get("baseSeverity")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| severity_from_score(score).to_string());
            return (severity.to_uppercase(), score, version.to_string());
        }
    }

    ("UNKNOWN".to_string(), 0.0, String::new())
}

pub(crate) fn fetch_epss_map(
    client: &Client,
    config: &Config,
    cve_config: &CveConfig,
    cve_ids: &[String],
    date: Option<NaiveDate>,
    offline: bool,
    refresh_cache: bool,
) -> Result<HashMap<String, EpssSnapshot>> {
    let label = match date {
        Some(day) => format!("EPSS API {day}"),
        None => "EPSS API".to_string(),
    };
    eprintln!("→ fetching {label} for {} CVEs", cve_ids.len());
    let joined = cve_ids.join(",");
    let mut query = vec![("cve", joined.as_str())];
    let date_s;
    if let Some(day) = date {
        date_s = day.format("%Y-%m-%d").to_string();
        query.push(("date", date_s.as_str()));
    }
    let bytes = get_bytes_cached(
        client,
        config,
        &cve_config.epss_url,
        &query,
        &label,
        offline,
        refresh_cache,
    )?;

    let json: Value = serde_json::from_slice(&bytes).context("invalid JSON from EPSS")?;
    let mut map = HashMap::new();

    if let Some(rows) = json.get("data").and_then(|v| v.as_array()) {
        for row in rows {
            let Some(cve) = row.get("cve").and_then(|v| v.as_str()) else {
                continue;
            };
            let epss = row
                .get("epss")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(0.0);
            let percentile = row
                .get("percentile")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(0.0);
            map.insert(cve.to_string(), EpssSnapshot { epss, percentile });
        }
    }

    Ok(map)
}

pub(crate) fn enrich_epss_momentum(
    client: &Client,
    config: &Config,
    cve_config: &CveConfig,
    cves: &mut [CveItem],
    ids: &[String],
    current_day: NaiveDate,
    offline: bool,
    refresh_cache: bool,
) {
    for days in &cve_config.epss_momentum_days {
        let day = current_day - ChronoDuration::days((*days).max(1));
        thread::sleep(Duration::from_millis(
            cve_config.sleep_ms_between_sources / 2,
        ));
        match fetch_epss_map(
            client,
            config,
            cve_config,
            ids,
            Some(day),
            offline,
            refresh_cache,
        ) {
            Ok(snapshot_map) => {
                for cve in cves.iter_mut() {
                    if let Some(snapshot) = snapshot_map.get(&cve.cve_id) {
                        match *days {
                            7 => {
                                cve.epss_7d = snapshot.epss;
                                cve.epss_delta_7d = cve.epss - snapshot.epss;
                            }
                            30 => {
                                cve.epss_30d = snapshot.epss;
                                cve.epss_delta_30d = cve.epss - snapshot.epss;
                            }
                            _ => {}
                        }
                    }
                    cve.epss_momentum = epss_momentum_label(cve.epss_delta_7d, cve.epss_delta_30d);
                }
            }
            Err(err) => eprintln!("⚠️  skipped EPSS momentum {days}d: {err:#}"),
        }
    }
}

pub(crate) fn epss_momentum_label(delta_7d: f64, delta_30d: f64) -> String {
    if delta_7d >= 0.10 || delta_30d >= 0.20 {
        "rising".to_string()
    } else if delta_7d <= -0.10 || delta_30d <= -0.20 {
        "falling".to_string()
    } else {
        "stable".to_string()
    }
}

pub(crate) fn enrich_vulnrichment(
    client: &Client,
    config: &Config,
    cve_config: &CveConfig,
    cves: &mut [CveItem],
    offline: bool,
    refresh_cache: bool,
) {
    eprintln!("→ fetching CISA Vulnrichment for selected CVEs");
    let mut checked = 0_usize;
    let mut hits = 0_usize;
    let mut missing = 0_usize;
    let mut errors = 0_usize;
    for cve in cves.iter_mut() {
        if checked >= cve_config.max_vulnrichment {
            break;
        }
        checked += 1;
        thread::sleep(Duration::from_millis(
            (cve_config.sleep_ms_between_sources / 3).max(150),
        ));
        match fetch_cisa_vulnrichment(
            client,
            config,
            cve_config,
            &cve.cve_id,
            offline,
            refresh_cache,
        ) {
            Ok(Some(enrichment)) => {
                hits += 1;
                apply_cisa_vulnrichment(cve, enrichment);
            }
            Ok(None) => {
                missing += 1;
            }
            Err(err) => {
                errors += 1;
                eprintln!(
                    "⚠️  CISA Vulnrichment transport error for {}: {err:#}",
                    cve.cve_id
                );
            }
        }
    }
    if checked > 0 {
        eprintln!(
            "  ↳ CISA Vulnrichment summary: {hits}/{checked} enriched, {missing} no-data, {errors} transport errors"
        );
    }
}

pub(crate) fn fetch_cisa_vulnrichment(
    client: &Client,
    config: &Config,
    cve_config: &CveConfig,
    cve_id: &str,
    offline: bool,
    refresh_cache: bool,
) -> Result<Option<CisaVulnrichment>> {
    let Some(url) = vulnrichment_url(&cve_config.vulnrichment_base_url, cve_id) else {
        return Ok(None);
    };

    let bytes = match get_bytes_cached(
        client,
        config,
        &url,
        &[],
        &format!("CISA Vulnrichment {cve_id}"),
        offline,
        refresh_cache,
    ) {
        Ok(bytes) => bytes,
        Err(err) => {
            let err_s = format!("{err:#}");
            if is_vulnrichment_no_data(&err_s) {
                return Ok(None);
            }
            return Err(err);
        }
    };
    let json: Value =
        serde_json::from_slice(&bytes).context("invalid JSON from CISA Vulnrichment")?;
    Ok(extract_cisa_vulnrichment(&json))
}

pub(crate) fn is_vulnrichment_no_data(error_text: &str) -> bool {
    let text = error_text.to_ascii_lowercase();
    text.contains("404")
        || text.contains("not found")
        || text.contains("no cached response")
        || text.contains("offline mode has no cached response")
}

pub(crate) fn vulnrichment_url(base_url: &str, cve_id: &str) -> Option<String> {
    let mut parts = cve_id.split('-');
    let _prefix = parts.next()?;
    let year = parts.next()?;
    let number_s = parts.next()?;
    let number = number_s.parse::<u64>().ok()?;
    let bucket = format!("{}xxx", number / 1000);
    Some(format!(
        "{}/{}/{}/{}.json",
        base_url.trim_end_matches('/'),
        year,
        bucket,
        cve_id
    ))
}

pub(crate) fn extract_cisa_vulnrichment(json: &Value) -> Option<CisaVulnrichment> {
    let mut out = CisaVulnrichment::default();
    let Some(adps) = json.pointer("/containers/adp").and_then(|v| v.as_array()) else {
        return None;
    };

    for adp in adps {
        let short_name = adp
            .pointer("/providerMetadata/shortName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        if !short_name.contains("cisa") {
            continue;
        }
        out.found = true;
        find_ssvc_options(adp, &mut out);
    }

    if out.found {
        out.priority = cisa_priority_from_ssvc(&out);
        Some(out)
    } else {
        None
    }
}

pub(crate) fn find_ssvc_options(value: &Value, out: &mut CisaVulnrichment) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "Exploitation" {
                    if let Some(s) = child.as_str() {
                        out.exploitation = s.to_string();
                    }
                } else if key == "Automatable" {
                    if let Some(s) = child.as_str() {
                        out.automatable = s.to_string();
                    }
                } else if key == "Technical Impact" {
                    if let Some(s) = child.as_str() {
                        out.technical_impact = s.to_string();
                    }
                }
                find_ssvc_options(child, out);
            }
        }
        Value::Array(items) => {
            for child in items {
                find_ssvc_options(child, out);
            }
        }
        _ => {}
    }
}

pub(crate) fn cisa_priority_from_ssvc(enrichment: &CisaVulnrichment) -> String {
    let exploitation = enrichment.exploitation.to_lowercase();
    let automatable = enrichment.automatable.to_lowercase();
    let impact = enrichment.technical_impact.to_lowercase();
    if exploitation.contains("active")
        || exploitation == "poc"
        || (automatable == "yes" && impact == "total")
    {
        "immediate-watch".to_string()
    } else if automatable == "yes" || impact == "total" {
        "elevated".to_string()
    } else {
        "tracked".to_string()
    }
}

pub(crate) fn apply_cisa_vulnrichment(cve: &mut CveItem, enrichment: CisaVulnrichment) {
    cve.cisa_vulnrichment = enrichment.found;
    cve.ssvc_exploitation = enrichment.exploitation;
    cve.ssvc_automatable = enrichment.automatable;
    cve.ssvc_technical_impact = enrichment.technical_impact;
    cve.cisa_priority = enrichment.priority;
}

pub(crate) fn parse_nvd_cves(
    nvd_json: &Value,
    kev_map: &HashMap<String, KevEntry>,
) -> Vec<CveItem> {
    let mut out = Vec::new();
    let Some(vulns) = nvd_json.get("vulnerabilities").and_then(|v| v.as_array()) else {
        return out;
    };

    for vuln in vulns {
        let cve = &vuln["cve"];
        let Some(cve_id) = cve.get("id").and_then(|v| v.as_str()) else {
            continue;
        };

        let summary = extract_description(cve);
        let title = derive_cve_title(cve_id, &summary);
        let (severity, cvss, cvss_version) = extract_cvss(cve);
        let kev_entry = kev_map.get(cve_id);
        let kev = kev_entry.is_some();
        let published = cve
            .get("published")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let url = format!("https://nvd.nist.gov/vuln/detail/{cve_id}");

        let mut item = CveItem {
            cve_id: cve_id.to_string(),
            title,
            summary: truncate_chars(&summary, 310),
            severity,
            cvss,
            cvss_version,
            epss: 0.0,
            epss_percentile: 0.0,
            epss_7d: 0.0,
            epss_30d: 0.0,
            epss_delta_7d: 0.0,
            epss_delta_30d: 0.0,
            epss_momentum: "stable".to_string(),
            kev,
            kev_due_date: kev_entry.map(|e| e.due_date.clone()).unwrap_or_default(),
            kev_ransomware: kev_entry.map(|e| e.ransomware).unwrap_or(false),
            cisa_vulnrichment: false,
            ssvc_exploitation: String::new(),
            ssvc_automatable: String::new(),
            ssvc_technical_impact: String::new(),
            cisa_priority: "unscored".to_string(),
            published,
            url,
            recommended_action: String::new(),
            risk_score: 1,
            tags: Vec::new(),
        };

        finalize_cve_score(&mut item);
        out.push(item);
    }

    out
}

pub(crate) fn extract_description(cve: &Value) -> String {
    let Some(descriptions) = cve.get("descriptions").and_then(|v| v.as_array()) else {
        return "No description provided by NVD.".to_string();
    };

    descriptions
        .iter()
        .find(|d| d.get("lang").and_then(|v| v.as_str()) == Some("en"))
        .or_else(|| descriptions.first())
        .and_then(|d| d.get("value"))
        .and_then(|v| v.as_str())
        .map(clean_text)
        .unwrap_or_else(|| "No description provided by NVD.".to_string())
}

pub(crate) fn extract_cvss(cve: &Value) -> (String, f64, String) {
    let metrics = &cve["metrics"];
    let names = [
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ];

    for (name, version) in names {
        let Some(arr) = metrics.get(name).and_then(|v| v.as_array()) else {
            continue;
        };
        let Some(first) = arr.first() else {
            continue;
        };

        let cvss_data = &first["cvssData"];
        let score = cvss_data
            .get("baseScore")
            .and_then(|v| v.as_f64())
            .or_else(|| first.get("baseScore").and_then(|v| v.as_f64()))
            .unwrap_or(0.0);

        let severity = first
            .get("baseSeverity")
            .and_then(|v| v.as_str())
            .or_else(|| cvss_data.get("baseSeverity").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .unwrap_or_else(|| severity_from_score(score).to_string());

        return (severity.to_uppercase(), score, version.to_string());
    }

    ("UNKNOWN".to_string(), 0.0, String::new())
}

pub(crate) fn severity_from_score(score: f64) -> &'static str {
    if score >= 9.0 {
        "CRITICAL"
    } else if score >= 7.0 {
        "HIGH"
    } else if score >= 4.0 {
        "MEDIUM"
    } else if score > 0.0 {
        "LOW"
    } else {
        "UNKNOWN"
    }
}

pub(crate) fn derive_cve_title(cve_id: &str, summary: &str) -> String {
    let first_sentence = summary
        .split('.')
        .next()
        .unwrap_or(summary)
        .trim()
        .to_string();

    if first_sentence.is_empty() {
        cve_id.to_string()
    } else {
        concise_title(&first_sentence, 84)
    }
}

pub(crate) fn finalize_cve_score(cve: &mut CveItem) {
    let mut score = cve.cvss.round() as i64;
    let mut tags = Vec::new();

    if cve.severity == "CRITICAL" {
        score += 2;
        push_tag(&mut tags, "Critical".to_string());
    } else if cve.severity == "HIGH" {
        score += 1;
        push_tag(&mut tags, "High".to_string());
    }

    if cve.kev {
        score += 3;
        push_tag(&mut tags, "KEV".to_string());
    }

    if cve.kev_ransomware {
        score += 1;
        push_tag(&mut tags, "Ransomware".to_string());
    }

    if cve.epss >= 0.70 {
        score += 2;
        push_tag(&mut tags, "High EPSS".to_string());
    } else if cve.epss >= 0.30 {
        score += 1;
        push_tag(&mut tags, "Medium EPSS".to_string());
    }

    if cve.epss_momentum == "rising" {
        score += 1;
        push_tag(&mut tags, "EPSS rising".to_string());
    }

    if cve.cisa_priority == "immediate-watch" {
        score += 2;
        push_tag(&mut tags, "CISA priority".to_string());
    } else if cve.cisa_priority == "elevated" {
        score += 1;
        push_tag(&mut tags, "CISA elevated".to_string());
    }

    let text = format!("{} {}", cve.title, cve.summary).to_lowercase();
    for kw in [
        "vpn",
        "firewall",
        "router",
        "gateway",
        "exchange",
        "wordpress",
        "linux",
    ] {
        if text.contains(kw) {
            score += 1;
            push_tag(&mut tags, keyword_tag(kw));
        }
    }

    cve.risk_score = score.clamp(1, 10);
    cve.tags = tags.into_iter().take(5).collect();
    cve.recommended_action = recommended_action_for_cve(cve);
}

pub(crate) fn recommended_action_for_cve(cve: &CveItem) -> String {
    if cve.kev && cve.kev_ransomware {
        "Listed in KEV with ransomware usage history; apply patch with highest priority.".to_string()
    } else if cve.kev {
        "Listed in KEV; immediately check exposure and apply patch/mitigation.".to_string()
    } else if cve.cisa_priority == "immediate-watch" {
        "Based on SSVC/Vulnrichment, this CVE should be on the defensive team's immediate watch list.".to_string()
    } else if cve.epss_momentum == "rising" {
        "EPSS for this CVE is rising; increase monitoring priority and asset matching.".to_string()
    } else if cve.severity == "CRITICAL" || cve.cvss >= 9.0 {
        "Match against asset inventory and prioritize patching or mitigation.".to_string()
    } else if cve.epss >= 0.70 {
        "Due to high exploit probability, quickly review related public-facing services.".to_string()
    } else {
        "Assess impact on your environment and track in the normal patching cycle.".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kev_map_extracts_due_date_and_ransomware() {
        let raw = r#"{
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-0001",
                    "dueDate": "2026-08-01",
                    "knownRansomwareCampaignUse": "Known"
                },
                {
                    "cveID": "CVE-2026-0002",
                    "knownRansomwareCampaignUse": "Unknown"
                }
            ]
        }"#;
        let json: Value = serde_json::from_str(raw).unwrap();
        let map = parse_kev_map(&json);
        assert_eq!(map.len(), 2);
        let first = map.get("CVE-2026-0001").unwrap();
        assert_eq!(first.due_date, "2026-08-01");
        assert!(first.ransomware);
        let second = map.get("CVE-2026-0002").unwrap();
        assert!(second.due_date.is_empty());
        assert!(!second.ransomware);
    }

    #[test]
    fn extract_cvelist_cvss_prefers_v4() {
        let raw = r#"{
            "metrics": [
                {
                    "cvssV3_1": {
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH"
                    }
                },
                {
                    "cvssV4_0": {
                        "baseScore": 9.3,
                        "baseSeverity": "CRITICAL"
                    }
                }
            ]
        }"#;
        let cna: Value = serde_json::from_str(raw).unwrap();
        let (severity, score, version) = extract_cvelist_cvss(&cna);
        assert_eq!(severity, "CRITICAL");
        assert!((score - 9.3).abs() < 1e-9);
        assert_eq!(version, "4.0");
    }
}
