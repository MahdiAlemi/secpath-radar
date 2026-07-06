//! DShield top-ports attack pressure pulse.

use crate::prelude::*;

pub(crate) fn fetch_attack_pressure_or_fallback(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Value {
    if !config.intel.enabled || !config.intel.attack_pressure.enabled {
        return empty_attack_pressure("disabled");
    }

    match fetch_attack_pressure(config, offline, refresh_cache) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("⚠️  Attack Pressure Radar skipped: {err:#}");
            let mut fallback = empty_attack_pressure("error");
            fallback["error"] = json!(err.to_string());
            fallback
        }
    }
}

pub(crate) fn fetch_attack_pressure(
    config: &Config,
    offline: bool,
    refresh_cache: bool,
) -> Result<Value> {
    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(18))
        .build()
        .context("failed to build HTTP client for Attack Pressure Radar")?;

    let ap = &config.intel.attack_pressure;
    eprintln!("→ fetching DShield Attack Pressure feeds");

    let headline = fetch_dshield_port_feed(
        &client,
        config,
        &ap.top_ports_url,
        "DShield top ports",
        offline,
        refresh_cache,
        ap.max_ports,
    )?;
    thread::sleep(Duration::from_millis(config.intel.sleep_ms_between_sources));

    let scanning = fetch_dshield_port_feed(
        &client,
        config,
        &ap.top_ports_source_url,
        "DShield top ports by source IPs",
        offline,
        refresh_cache,
        ap.max_ports,
    )?;
    thread::sleep(Duration::from_millis(config.intel.sleep_ms_between_sources));

    let reports = fetch_dshield_port_feed(
        &client,
        config,
        &ap.top_ports_reports_url,
        "DShield top ports by reports",
        offline,
        refresh_cache,
        ap.max_ports,
    )?;
    thread::sleep(Duration::from_millis(config.intel.sleep_ms_between_sources));

    let targets = fetch_dshield_port_feed(
        &client,
        config,
        &ap.top_ports_targets_url,
        "DShield top ports by targets",
        offline,
        refresh_cache,
        ap.max_ports,
    )?;

    let all_ports = headline
        .iter()
        .chain(scanning.iter())
        .chain(reports.iter())
        .chain(targets.iter())
        .collect::<Vec<_>>();
    let high_risk_count = all_ports.iter().filter(|port| port.risk == "high").count();
    let medium_risk_count = all_ports
        .iter()
        .filter(|port| port.risk == "medium")
        .count();
    let level = if high_risk_count >= 6 {
        "High"
    } else if high_risk_count >= 2 || medium_risk_count >= 8 {
        "Medium"
    } else {
        "Low"
    };

    let summary_fa = match level {
        "High" => "چندین پورت حساس در feedهای DShield تکرار شده‌اند؛ فشار اسکن اینترنتی بالا ارزیابی می‌شود.",
        "Medium" => "چند سرویس پرریسک در بین پورت‌های هدف دیده می‌شود؛ وضعیت برای پایش روزانه قابل توجه است.",
        _ => "داده‌های DShield فشار غیرعادی شدیدی را نشان نمی‌دهد، اما سرویس‌های رایج همچنان زیر اسکن هستند.",
    };

    Ok(json!({
        "enabled": true,
        "ok": true,
        "provider": "SANS ISC / DShield",
        "source_url": "https://www.dshield.org/feeds_doc.html",
        "level": level,
        "summary_fa": summary_fa,
        "last_updated": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "cache_dir": config.intel.cache_dir.clone(),
        "refresh_hours": config.intel.refresh_hours,
        "top_ports": headline,
        "scanning_ports": scanning,
        "reported_ports": reports,
        "targeted_ports": targets
    }))
}

pub(crate) fn fetch_dshield_port_feed(
    client: &Client,
    config: &Config,
    url: &str,
    label: &str,
    offline: bool,
    refresh_cache: bool,
    limit: usize,
) -> Result<Vec<AttackPort>> {
    let bytes = get_bytes_cached_intel(client, config, url, label, offline, refresh_cache)?;
    let text = String::from_utf8_lossy(&bytes);
    let mut ports = parse_dshield_ports(&text);
    ports.truncate(limit);
    annotate_attack_ports(&mut ports);
    Ok(ports)
}

pub(crate) fn annotate_attack_ports(ports: &mut [AttackPort]) {
    let total = ports.len().max(1);
    for (idx, port) in ports.iter_mut().enumerate() {
        let relative = (((total - idx) as f64 / total as f64) * 100.0).round() as usize;
        port.pressure_score = relative.max(10);
        port.bar_width = relative.clamp(10, 100);
    }
}

pub(crate) fn parse_dshield_ports(text: &str) -> Vec<AttackPort> {
    let tokens = text.split_whitespace().collect::<Vec<_>>();
    let mut out = Vec::new();
    let mut i = 0;

    while i < tokens.len() {
        let Some(port) = tokens[i].parse::<u16>().ok() else {
            i += 1;
            continue;
        };
        i += 1;

        let service = tokens
            .get(i)
            .filter(|token| token.parse::<u16>().is_err())
            .map(|token| (*token).to_string())
            .unwrap_or_else(|| "unknown".to_string());
        if i < tokens.len() && tokens[i].parse::<u16>().is_err() {
            i += 1;
        }

        let mut desc_parts = Vec::new();
        while i < tokens.len() && tokens[i].parse::<u16>().is_err() {
            desc_parts.push(tokens[i]);
            i += 1;
        }

        let description = if desc_parts.is_empty() {
            service.clone()
        } else {
            desc_parts.join(" ")
        };

        let rank = out.len() + 1;
        out.push(AttackPort {
            rank,
            port,
            service: normalize_port_service(&service),
            description: clean_text(&description),
            risk: attack_port_risk(port).to_string(),
            note_fa: attack_port_note(port),
            pressure_score: 0,
            bar_width: 0,
        });
    }

    out
}

pub(crate) fn normalize_port_service(service: &str) -> String {
    let cleaned = service.trim_matches('-').trim();
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned.to_string()
    }
}

pub(crate) fn attack_port_risk(port: u16) -> &'static str {
    match port {
        21 | 22 | 23 | 445 | 3389 | 5900 | 6379 | 9200 | 11211 | 27017 => "high",
        80 | 443 | 8080 | 8443 | 8000 | 2222 | 5060 | 53 | 853 => "medium",
        _ => "watch",
    }
}

pub(crate) fn attack_port_note(port: u16) -> String {
    match port {
        22 | 2222 => "اسکن SSH؛ کلیدها، MFA، rate-limit و دسترسی public را بررسی کن.".to_string(),
        23 => "Telnet روی اینترنت پرریسک است؛ وجود آن در assetها باید سریع حذف یا محدود شود.".to_string(),
        80 | 443 | 8080 | 8000 | 8443 | 8081 => "فشار روی سرویس‌های وب؛ exposure، WAF، patch و لاگ‌های edge را پایش کن.".to_string(),
        445 => "SMB نباید public-facing باشد؛ هر exposure اینترنتی را بحرانی فرض کن.".to_string(),
        3389 => "RDP اینترنتی هدف رایج brute-force و exploit است؛ دسترسی را محدود و مانیتور کن.".to_string(),
        53 | 853 => "فعالیت DNS دیده می‌شود؛ resolverهای باز و policyهای recursive را بررسی کن.".to_string(),
        5060 => "SIP/VoIP زیر اسکن است؛ brute-force و تنظیمات exposed PBX را بررسی کن.".to_string(),
        _ => "این پورت در داده‌های DShield دیده شده؛ در صورت وجود در سطح اینترنت، مالکیت و ضرورت آن را بررسی کن.".to_string(),
    }
}

pub(crate) fn empty_attack_pressure(status: &str) -> Value {
    json!({
        "enabled": status != "disabled",
        "ok": false,
        "provider": "SANS ISC / DShield",
        "level": "Unknown",
        "summary_fa": "داده Attack Pressure در این اجرا در دسترس نبود.",
        "last_updated": "",
        "refresh_hours": 1,
        "top_ports": [],
        "scanning_ports": [],
        "reported_ports": [],
        "targeted_ports": []
    })
}
