#![recursion_limit = "256"]

mod ai;
mod archive;
mod attack;
mod brief;
mod cache;
mod cli;
mod config;
mod cve;
mod history;
mod intel;
mod model;
mod news;
mod output;
mod polish;
mod prelude;
mod quality;
mod render;
mod snapshot;
mod today;
mod trend;
mod util;
mod vendors;
mod weekly;
mod writeups;

use crate::prelude::*;

fn fetch_with_intel_freshness<F>(config: &Config, fetch: F) -> Value
where
    F: FnOnce() -> Value,
{
    let scope_start = begin_intel_freshness_scope();
    let panel = fetch();
    apply_intel_freshness(panel, scope_start, config)
}

fn main() -> Result<()> {
    let args = parse_args()?;

    let network_mode = args.fetch || args.cves;
    let config = load_config(&args.config)?;
    let mut gemini_calls_used = 0_u8;

    let mut brief = if network_mode {
        let (items, rss_failures, rss_stale_fallbacks) = if args.fetch {
            fetch_and_score(&config, args.offline, args.refresh_cache)?
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };

        let (writeup_items, writeup_failures, writeup_stale_fallbacks) = if args.fetch {
            fetch_writeup_feeds(&config, args.offline, args.refresh_cache)?
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };

        let (cves, cve_error) = if args.cves {
            match fetch_cves(&config, args.offline, args.refresh_cache) {
                Ok(cves) => (cves, None),
                Err(err) => {
                    let message = format!("{err:#}");
                    eprintln!("⚠️  CVE engine degraded: {message}");
                    (Vec::new(), Some(message))
                }
            }
        } else {
            (Vec::new(), None)
        };

        let failed_rss_count = rss_failures.len();
        let stale_rss_count = rss_stale_fallbacks.len();
        let failed_writeup_count = writeup_failures.len();
        let stale_writeup_count = writeup_stale_fallbacks.len();

        let mut brief = build_brief(&config, items, writeup_items, cves)?;
        brief["source_health"]["cve_engine_enabled"] = json!(args.cves);
        brief["source_health"]["cve_engine_ok"] = json!(cve_error.is_none());
        brief["source_health"]["cve_error"] = json!(cve_error);
        brief["source_health"]["failed_rss_sources"] = json!(failed_rss_count);
        brief["source_health"]["rss_failures"] = json!(rss_failures);
        brief["source_health"]["stale_rss_sources"] = json!(stale_rss_count);
        brief["source_health"]["rss_stale_fallbacks"] = json!(rss_stale_fallbacks);
        brief["source_health"]["degraded_rss_sources"] = json!(failed_rss_count + stale_rss_count);
        brief["source_health"]["writeup_sources"] = json!(config.writeup_sources.len());
        brief["source_health"]["failed_writeup_sources"] = json!(failed_writeup_count);
        brief["source_health"]["writeup_failures"] = json!(writeup_failures);
        brief["source_health"]["stale_writeup_sources"] = json!(stale_writeup_count);
        brief["source_health"]["writeup_stale_fallbacks"] = json!(writeup_stale_fallbacks);
        brief["source_health"]["degraded_writeup_sources"] =
            json!(failed_writeup_count + stale_writeup_count);
        brief["stats"]["failed_rss_sources"] = brief["source_health"]["failed_rss_sources"].clone();
        brief["stats"]["stale_rss_sources"] = brief["source_health"]["stale_rss_sources"].clone();
        brief["stats"]["degraded_rss_sources"] =
            brief["source_health"]["degraded_rss_sources"].clone();
        brief["stats"]["writeup_feed_sources"] = brief["source_health"]["writeup_sources"].clone();
        brief["stats"]["failed_writeup_sources"] =
            brief["source_health"]["failed_writeup_sources"].clone();
        brief["stats"]["stale_writeup_sources"] =
            brief["source_health"]["stale_writeup_sources"].clone();
        brief["stats"]["degraded_writeup_sources"] =
            brief["source_health"]["degraded_writeup_sources"].clone();
        let intel_scope_start = begin_intel_freshness_scope();
        let attack_pressure = fetch_with_intel_freshness(&config, || {
            fetch_attack_pressure_or_fallback(&config, args.offline, args.refresh_cache)
        });
        brief["attack_pressure"] = attack_pressure;
        let ioc_radar = fetch_with_intel_freshness(&config, || {
            fetch_ioc_radar_or_fallback(&config, args.offline, args.refresh_cache)
        });
        let ioc_total = ioc_radar
            .get("totals")
            .and_then(|totals| totals.get("total"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["iocs"] = json!(ioc_total);
        brief["ioc_radar"] = ioc_radar;

        let infrastructure_radar = fetch_with_intel_freshness(&config, || {
            fetch_infrastructure_radar_or_fallback(
                &config,
                &brief["ioc_radar"],
                args.offline,
                args.refresh_cache,
            )
        });
        let infra_total = infrastructure_radar
            .get("totals")
            .and_then(|totals| totals.get("hosts"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["infrastructure_hosts"] = json!(infra_total);
        brief["infrastructure_radar"] = infrastructure_radar;

        let supply_chain = fetch_with_intel_freshness(&config, || {
            fetch_supply_chain_radar_or_fallback(&config, args.offline, args.refresh_cache)
        });
        let supply_total = supply_chain
            .get("totals")
            .and_then(|totals| totals.get("advisories"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["supply_chain_advisories"] = json!(supply_total);
        brief["supply_chain_radar"] = supply_chain;

        let ransomware_pulse = fetch_with_intel_freshness(&config, || {
            fetch_ransomware_pulse_or_fallback(&config, args.offline, args.refresh_cache)
        });
        let ransomware_total = ransomware_pulse
            .get("totals")
            .and_then(|totals| totals.get("victims"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["ransomware_victims"] = json!(ransomware_total);
        brief["ransomware_pulse"] = ransomware_pulse;

        let botnet_c2_pulse = fetch_with_intel_freshness(&config, || {
            fetch_botnet_c2_pulse_or_fallback(&config, args.offline, args.refresh_cache)
        });
        let botnet_total = botnet_c2_pulse
            .get("totals")
            .and_then(|totals| totals.get("c2"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        let malicious_tls_total = botnet_c2_pulse
            .get("totals")
            .and_then(|totals| totals.get("tls"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["botnet_c2"] = json!(botnet_total);
        brief["stats"]["malicious_tls"] = json!(malicious_tls_total);
        brief["botnet_c2_pulse"] = botnet_c2_pulse;

        let greynoise_context = fetch_with_intel_freshness(&config, || {
            fetch_greynoise_context_or_fallback(
                &config,
                &brief["infrastructure_radar"],
                &brief["botnet_c2_pulse"],
                args.offline,
                args.refresh_cache,
            )
        });
        let greynoise_noise = greynoise_context
            .get("totals")
            .and_then(|totals| totals.get("noise"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        let greynoise_malicious = greynoise_context
            .get("totals")
            .and_then(|totals| totals.get("malicious"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        let greynoise_riot = greynoise_context
            .get("totals")
            .and_then(|totals| totals.get("riot"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        brief["stats"]["greynoise_noise"] = json!(greynoise_noise);
        brief["stats"]["greynoise_malicious"] = json!(greynoise_malicious);
        brief["stats"]["greynoise_riot"] = json!(greynoise_riot);
        brief["greynoise_context"] = greynoise_context;

        let phishing_pulse = fetch_with_intel_freshness(&config, || {
            fetch_phishing_pulse_or_fallback(&config, args.offline, args.refresh_cache)
        });
        brief["stats"]["phishing_urls"] = json!(path_u64(&phishing_pulse, &["totals", "urls"]));
        brief["stats"]["phishing_high"] = json!(path_u64(&phishing_pulse, &["totals", "high"]));
        brief["stats"]["phishing_tlds"] = json!(path_u64(&phishing_pulse, &["totals", "tlds"]));
        brief["phishing_pulse"] = phishing_pulse;

        let ics_ot_pulse = fetch_with_intel_freshness(&config, || {
            fetch_ics_ot_pulse_or_fallback(&config, args.offline, args.refresh_cache)
        });
        brief["stats"]["ics_advisories"] =
            json!(path_u64(&ics_ot_pulse, &["totals", "advisories"]));
        brief["stats"]["ics_high"] = json!(path_u64(&ics_ot_pulse, &["totals", "high"]));
        brief["stats"]["ics_vendors"] = json!(path_u64(&ics_ot_pulse, &["totals", "vendors"]));
        brief["ics_ot_pulse"] = ics_ot_pulse;

        let malware_pulse = fetch_with_intel_freshness(&config, || {
            fetch_malware_pulse_or_fallback(&config, args.offline, args.refresh_cache)
        });
        brief["stats"]["malware_samples"] = json!(path_u64(&malware_pulse, &["totals", "samples"]));
        brief["stats"]["malware_families"] =
            json!(path_u64(&malware_pulse, &["totals", "families"]));
        brief["malware_pulse"] = malware_pulse;

        let drop_pulse = fetch_with_intel_freshness(&config, || {
            fetch_drop_pulse_or_fallback(&config, args.offline, args.refresh_cache)
        });
        brief["stats"]["drop_ranges"] = json!(path_u64(&drop_pulse, &["totals", "ranges"]));
        brief["stats"]["drop_big_ranges"] = json!(path_u64(&drop_pulse, &["totals", "big_ranges"]));
        brief["drop_pulse"] = drop_pulse;

        let csaf_pulse = fetch_with_intel_freshness(&config, || {
            fetch_csaf_pulse_or_fallback(&config, args.offline, args.refresh_cache)
        });
        brief["stats"]["csaf_advisories"] = json!(path_u64(&csaf_pulse, &["totals", "advisories"]));
        brief["stats"]["csaf_critical"] = json!(path_u64(&csaf_pulse, &["totals", "critical"]));
        brief["csaf_pulse"] = csaf_pulse;

        let nuclei_coverage = fetch_with_intel_freshness(&config, || {
            fetch_nuclei_coverage_or_fallback(
                &config,
                &brief["cves"],
                args.offline,
                args.refresh_cache,
            )
        });
        brief["stats"]["nuclei_covered_cves"] =
            json!(path_u64(&nuclei_coverage, &["totals", "covered_cves"]));
        brief["stats"]["nuclei_coverage_pct"] =
            json!(path_u64(&nuclei_coverage, &["totals", "coverage_pct"]));
        brief["nuclei_coverage"] = nuclei_coverage;

        let poc_watch = fetch_with_intel_freshness(&config, || {
            fetch_poc_watch_or_fallback(&config, &brief["cves"], args.offline, args.refresh_cache)
        });
        brief["stats"]["poc_watch"] = json!(path_u64(&poc_watch, &["totals", "repos"]));
        brief["stats"]["poc_watch_high"] = json!(path_u64(&poc_watch, &["totals", "high"]));
        brief["stats"]["poc_watch_cves"] =
            json!(path_u64(&poc_watch, &["totals", "cves_with_poc"]));
        brief["poc_watch"] = poc_watch;
        let intel_freshness = intel_freshness_summary_since(intel_scope_start);
        brief["source_health"]["intel_cache"] = intel_freshness.clone();
        brief["stats"]["intel_tracked_sources"] = intel_freshness["tracked_sources"].clone();
        brief["stats"]["intel_stale_sources"] = intel_freshness["stale_sources"].clone();
        brief["stats"]["intel_cache_age_minutes"] = intel_freshness["cache_age_minutes"].clone();

        let executive_snapshot = build_executive_snapshot(&brief);
        brief["executive_snapshot"] = executive_snapshot;
        brief
    } else {
        let brief_raw = fs::read_to_string(&args.input)
            .with_context(|| format!("failed to read input JSON: {}", args.input.display()))?;
        serde_json::from_str(&brief_raw)
            .with_context(|| format!("invalid JSON in {}", args.input.display()))?
    };

    if args.ai {
        match enhance_brief_with_gemini(&config, &brief, args.refresh_ai, args.offline) {
            Ok(result) => {
                brief = result.brief;
                gemini_calls_used = result.calls_used;
                if result.cache_hit {
                    eprintln!("↳ Gemini cache hit: {}", config.gemini.model);
                } else if result.calls_used > 0 {
                    eprintln!("✅ Gemini editor: {} call used", result.calls_used);
                }
            }
            Err(err) => {
                eprintln!("⚠️  Gemini editor skipped: {err:#}");
                brief["ai_status"] = json!({
                    "enabled": true,
                    "ok": false,
                    "model": config.gemini.model,
                    "calls_used": 0,
                    "error": err.to_string()
                });
            }
        }
    } else {
        brief["ai_status"] = json!({
            "enabled": false,
            "ok": true,
            "calls_used": 0,
            "model": "none"
        });
    }

    if network_mode {
        validate_collected_brief(&brief, &config)?;
    }

    let previous_brief = read_previous_latest_brief();
    let pending_day_state = if network_mode {
        apply_day_accumulation(&mut brief, &config)?
    } else {
        None
    };
    apply_local_polish(&mut brief);
    build_vendor_watchlist(&mut brief);
    build_attack_matrix(&mut brief);
    brief["top_signals"] = build_top_signals(&brief);
    attach_history_snapshot(&mut brief, previous_brief.as_ref());
    brief["triage_signals"] = build_triage_signals(&brief);

    build_trend_pulse(&mut brief);

    let mut archives = read_archive_series(ARCHIVE_DIR, WEEKLY_MAX_DAYS);
    let current_archive = build_daily_archive(&brief);
    let current_archive_date = current_archive
        .get("date")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    archives.retain(|archive| {
        archive.get("date").and_then(|value| value.as_str()) != Some(current_archive_date.as_str())
    });
    archives.push(current_archive);
    archives.sort_by_key(|archive| {
        archive
            .get("date")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string()
    });
    if archives.len() > WEEKLY_MAX_DAYS {
        let skip = archives.len() - WEEKLY_MAX_DAYS;
        archives.drain(0..skip);
    }
    brief["weekly"] = build_weekly_brief(&archives);

    if network_mode {
        validate_collected_brief(&brief, &config)?;
    }

    render_html(&brief, &args.template, &args.out)?;
    copy_static_assets(&args.out)?;
    write_feed_xml(&brief, &config, &args.out)?;
    write_json_api(&brief, &args.out)?;

    if network_mode {
        validate_rendered_outputs(&args.out, &config)?;
    }

    // Persist production state only for collection runs and only after every
    // required output has passed the quality gate. Render-only runs stay read-only.
    if network_mode {
        if let Some(day_state) = pending_day_state.as_ref() {
            persist_day_state(day_state)?;
        }
        write_json_atomic(&PathBuf::from("data/latest_brief.json"), &brief)?;
        write_history_snapshot(&brief)?;
        if let Err(err) = prune_history_snapshots(&config) {
            eprintln!("⚠️  history snapshot pruning skipped: {err:#}");
        }
        if let Err(err) = prune_ai_item_cache(&config) {
            eprintln!("⚠️  AI item cache pruning skipped: {err:#}");
        }
        write_daily_archive(&brief)?;
    }

    let legacy_weekly = site_output_dir(&args.out).join("weekly.html");
    if legacy_weekly.exists() {
        fs::remove_file(&legacy_weekly)
            .with_context(|| format!("failed to remove {}", legacy_weekly.display()))?;
    }
    println!("✅ rendered {}", args.out.display());
    println!("✅ wrote site/feed.xml + site/api");
    if network_mode {
        println!("✅ wrote data/latest_brief.json and snapshots");
    } else {
        println!("ℹ️ render-only mode: production state was not modified");
    }
    println!("ℹ️ Gemini calls used: {gemini_calls_used}");
    if args.offline {
        println!("ℹ️ offline mode: used cached HTTP responses only");
    }
    Ok(())
}
