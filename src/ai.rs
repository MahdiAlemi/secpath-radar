//! Gemini editorial layer: batched calls, per-item content cache, schema-locked output.

use crate::prelude::*;
use std::collections::HashMap;

pub(crate) const AI_PROMPT_VERSION: &str = "d1";

pub(crate) struct GeminiEditResult {
    pub(crate) brief: Value,
    pub(crate) calls_used: u8,
    pub(crate) cache_hit: bool,
}

const NEWS_SECTIONS: [&str; 1] = ["global_news"];

pub(crate) fn enhance_brief_with_gemini(
    config: &Config,
    brief: &Value,
    refresh_ai: bool,
    offline: bool,
) -> Result<GeminiEditResult> {
    let mut edited = brief.clone();
    let mut cache_hits: u64 = 0;
    let mut pending_news: Vec<(String, String, usize)> = Vec::new();
    let mut pending_cves: Vec<(String, String, usize)> = Vec::new();

    let alert_key = item_cache_key(&config.gemini.model, "alert", &edited["priority_alert"]);
    let mut alert_needed = edited
        .get("priority_alert")
        .and_then(|v| v.as_object())
        .map(|obj| !obj.is_empty())
        .unwrap_or(false);
    if alert_needed && !refresh_ai {
        if let Some(cached) = read_item_cache(config, &alert_key) {
            if merge_batch_alert(&mut edited, &cached) {
                cache_hits += 1;
                alert_needed = false;
            }
        }
    }

    for section in NEWS_SECTIONS {
        let limit = editorial_limit(config, section);
        collect_pending_items(
            config,
            &mut edited,
            section,
            limit,
            refresh_ai,
            "n",
            &mut cache_hits,
            &mut pending_news,
        );
    }
    collect_pending_items(
        config,
        &mut edited,
        "cves",
        config.gemini.max_cves,
        refresh_ai,
        "c",
        &mut cache_hits,
        &mut pending_cves,
    );

    let briefing_input = build_briefing_input(&edited);
    let briefing_key = briefing_cache_key(&config.gemini.model, &briefing_input);
    let mut briefing_needed = briefing_input_has_content(&briefing_input);
    if briefing_needed && !refresh_ai {
        if let Some(cached) = read_item_cache(config, &briefing_key) {
            let clean = sanitize_briefing(&cached);
            if briefing_is_usable(&clean) {
                edited["ai_briefing"] = clean;
                cache_hits += 1;
                briefing_needed = false;
            }
        }
    }

    if pending_news.is_empty() && pending_cves.is_empty() && !alert_needed && !briefing_needed {
        let cache_hit = cache_hits > 0;
        let edited = mark_ai_status(
            edited,
            true,
            cache_hit,
            &config.gemini.model,
            0,
            cache_hits,
            0,
            None,
        );
        return Ok(GeminiEditResult {
            brief: edited,
            calls_used: 0,
            cache_hit,
        });
    }

    if offline {
        let cache_hit = cache_hits > 0;
        let edited = mark_ai_status(
            edited,
            cache_hit,
            cache_hit,
            &config.gemini.model,
            0,
            cache_hits,
            0,
            Some("offline mode: applied cached AI items only".to_string()),
        );
        return Ok(GeminiEditResult {
            brief: edited,
            calls_used: 0,
            cache_hit,
        });
    }

    let api_key = get_env_or_dotenv("GEMINI_API_KEY")
        .context("GEMINI_API_KEY is not set. Put it in .env or export it before using --ai")?;

    let url = format!(
        "{}/models/{}:generateContent",
        config.gemini.api_url.trim_end_matches('/'),
        config.gemini.model
    );

    let client = build_client(config)?;

    let mut calls_used: u8 = 0;
    let mut items_generated: u64 = 0;
    let mut errors: Vec<String> = Vec::new();

    if alert_needed || !pending_news.is_empty() {
        let prompt = build_news_batch_prompt(&edited, alert_needed, &pending_news)?;
        match run_gemini_batch(
            &client,
            &url,
            &api_key,
            &prompt,
            config.gemini.temperature,
            &gemini_news_schema(),
        ) {
            Ok((value, calls)) => {
                calls_used = calls_used.saturating_add(calls);
                if alert_needed {
                    if let Some(alert) = value.get("priority_alert") {
                        let editorial = sanitize_editorial("news", alert);
                        if merge_batch_alert(&mut edited, &editorial) {
                            log_item_cache_write(config, &alert_key, &editorial);
                            items_generated += 1;
                        }
                    }
                }
                items_generated += apply_batch_items(
                    config,
                    &mut edited,
                    &pending_refs(&pending_news),
                    value.get("items"),
                    "news",
                );
            }
            Err(err) => {
                eprintln!("⚠️  Gemini news batch failed: {err:#}");
                errors.push(format!("news batch: {err:#}"));
            }
        }
    }

    if !pending_cves.is_empty() {
        let prompt = build_cve_batch_prompt(&edited, &pending_cves)?;
        match run_gemini_batch(
            &client,
            &url,
            &api_key,
            &prompt,
            config.gemini.temperature,
            &gemini_cve_schema(),
        ) {
            Ok((value, calls)) => {
                calls_used = calls_used.saturating_add(calls);
                items_generated += apply_batch_items(
                    config,
                    &mut edited,
                    &pending_refs(&pending_cves),
                    value.get("items"),
                    "cve",
                );
            }
            Err(err) => {
                eprintln!("⚠️  Gemini CVE batch failed: {err:#}");
                errors.push(format!("cve batch: {err:#}"));
            }
        }
    }

    if briefing_needed {
        match build_briefing_prompt(&briefing_input) {
            Ok(prompt) => match run_gemini_batch(
                &client,
                &url,
                &api_key,
                &prompt,
                config.gemini.temperature,
                &gemini_briefing_schema(),
            ) {
                Ok((value, calls)) => {
                    calls_used = calls_used.saturating_add(calls);
                    let clean = sanitize_briefing(&value);
                    if briefing_is_usable(&clean) {
                        log_item_cache_write(config, &briefing_key, &clean);
                        edited["ai_briefing"] = clean;
                        items_generated += 1;
                    } else {
                        errors
                            .push("briefing batch: response was empty after sanitize".to_string());
                    }
                }
                Err(err) => {
                    eprintln!("⚠️  Gemini briefing batch failed: {err:#}");
                    errors.push(format!("briefing batch: {err:#}"));
                }
            },
            Err(err) => {
                errors.push(format!("briefing prompt: {err:#}"));
            }
        }
    }

    let ok = errors.is_empty();
    let error = if ok { None } else { Some(errors.join(" | ")) };
    let cache_hit = calls_used == 0 && cache_hits > 0;
    let edited = mark_ai_status(
        edited,
        ok,
        cache_hit,
        &config.gemini.model,
        calls_used,
        cache_hits,
        items_generated,
        error,
    );
    Ok(GeminiEditResult {
        brief: edited,
        calls_used,
        cache_hit,
    })
}

pub(crate) fn editorial_limit(config: &Config, section: &str) -> usize {
    match section {
        "global_news" => config.gemini.max_global_news,
        "cves" => config.gemini.max_cves,
        _ => 0,
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_pending_items(
    config: &Config,
    brief: &mut Value,
    section: &str,
    limit: usize,
    refresh_ai: bool,
    ref_prefix: &str,
    cache_hits: &mut u64,
    pending: &mut Vec<(String, String, usize)>,
) {
    let count = brief
        .get(section)
        .and_then(|v| v.as_array())
        .map(|items| items.len())
        .unwrap_or(0)
        .min(limit);
    for index in 0..count {
        let key = {
            let Some(item) = brief
                .get(section)
                .and_then(|v| v.as_array())
                .and_then(|items| items.get(index))
            else {
                continue;
            };
            item_cache_key(&config.gemini.model, section, item)
        };
        let mut cached_applied = false;
        if !refresh_ai {
            if let Some(cached) = read_item_cache(config, &key) {
                if merge_batch_item(brief, section, index, &cached) {
                    *cache_hits += 1;
                    cached_applied = true;
                }
            }
        }
        if !cached_applied {
            let reference = format!("{}{}", ref_prefix, pending.len());
            pending.push((reference, section.to_string(), index));
        }
    }
}

pub(crate) fn pending_refs(
    pending: &[(String, String, usize)],
) -> HashMap<String, (String, usize)> {
    pending
        .iter()
        .map(|(reference, section, index)| (reference.clone(), (section.clone(), *index)))
        .collect()
}

pub(crate) fn apply_batch_items(
    config: &Config,
    brief: &mut Value,
    refs: &HashMap<String, (String, usize)>,
    items: Option<&Value>,
    kind: &str,
) -> u64 {
    let Some(items) = items.and_then(|v| v.as_array()) else {
        return 0;
    };
    let mut applied = 0u64;
    for raw in items {
        let Some(reference) = raw.get("ref").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some((section, index)) = refs.get(reference) else {
            continue;
        };
        let editorial = sanitize_editorial(kind, raw);
        let key = brief
            .get(section.as_str())
            .and_then(|v| v.as_array())
            .and_then(|list| list.get(*index))
            .map(|item| item_cache_key(&config.gemini.model, section, item));
        if merge_batch_item(brief, section, *index, &editorial) {
            if let Some(key) = key {
                log_item_cache_write(config, &key, &editorial);
            }
            applied += 1;
        }
    }
    applied
}

pub(crate) fn merge_batch_item(
    brief: &mut Value,
    section: &str,
    index: usize,
    editorial: &Value,
) -> bool {
    if !editorial_is_usable(editorial) {
        return false;
    }
    let Some(items) = brief.get_mut(section).and_then(|v| v.as_array_mut()) else {
        return false;
    };
    let Some(target) = items.get_mut(index) else {
        return false;
    };
    if !target.is_object() {
        return false;
    }
    merge_object_preserve_existing(target, editorial);
    true
}

pub(crate) fn merge_batch_alert(brief: &mut Value, editorial: &Value) -> bool {
    if !editorial_is_usable(editorial) {
        return false;
    }
    let Some(alert) = brief.get_mut("priority_alert") else {
        return false;
    };
    if !alert.is_object() {
        return false;
    }
    merge_object_preserve_existing(alert, editorial);
    true
}

pub(crate) fn sanitize_editorial(kind: &str, value: &Value) -> Value {
    let mut clean = serde_json::Map::new();
    let Some(obj) = value.as_object() else {
        return Value::Object(clean);
    };
    let keys: &[&str] = if kind == "cve" {
        &[
            "title",
            "summary",
            "why_it_matters",
            "recommended_action",
            "ops_note",
        ]
    } else {
        &["title", "summary", "why_it_matters", "ops_note"]
    };
    for key in keys {
        if let Some(Value::String(text)) = obj.get(*key) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                clean.insert((*key).to_string(), json!(trimmed));
            }
        }
    }
    Value::Object(clean)
}

pub(crate) fn editorial_is_usable(editorial: &Value) -> bool {
    editorial
        .as_object()
        .map(|obj| !obj.is_empty())
        .unwrap_or(false)
}

pub(crate) fn item_identity(section: &str, item: &Value) -> String {
    let mut parts: Vec<String> = vec![section.to_string()];
    for key in ["cve_id", "url", "title", "summary", "severity", "source"] {
        let text = item
            .get(key)
            .map(|v| match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default();
        parts.push(format!("{key}={text}"));
    }
    parts.join("\n")
}

pub(crate) fn item_cache_key(model: &str, section: &str, item: &Value) -> String {
    let raw = format!(
        "{}\n{}\n{}",
        AI_PROMPT_VERSION,
        model,
        item_identity(section, item)
    );
    let mut hasher = DefaultHasher::new();
    raw.hash(&mut hasher);
    format!("{}-{:016x}.json", section_slug(section), hasher.finish())
}

pub(crate) fn section_slug(section: &str) -> &'static str {
    match section {
        "global_news" => "news",
        "cves" => "cve",
        "alert" => "alert",
        _ => "item",
    }
}

pub(crate) fn item_cache_path(config: &Config, key: &str) -> PathBuf {
    PathBuf::from(&config.gemini.cache_dir)
        .join("items")
        .join(key)
}

pub(crate) fn read_item_cache(config: &Config, key: &str) -> Option<Value> {
    let path = item_cache_path(config, key);
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

pub(crate) fn write_item_cache(config: &Config, key: &str, value: &Value) -> Result<()> {
    write_json_atomic(&item_cache_path(config, key), value)
}

fn log_item_cache_write(config: &Config, key: &str, value: &Value) {
    if let Err(err) = write_item_cache(config, key, value) {
        eprintln!("⚠️  AI item cache write failed for {key}: {err:#}");
    }
}

const NEWS_PROMPT_RULES: &str = r#"You are the editorial layer for SecPath Radar, a defensive daily cybersecurity intelligence brief.

Input JSON contains news items in "items" and may contain a "priority_alert" object. Every item has a "ref" identifier.

Hard rules:
- Do not invent facts, sources, URLs, exploitation status, affected products, victim geography, attribution, or exploit details.
- Return editorial fields only: title, summary, why_it_matters, ops_note.
- Return exactly one output entry per input item and copy its "ref" value unchanged.
- If an item is unclear, write a cautious summary and say the original advisory should be checked.
- Use defensive language only. No exploit chains, payloads, bypass steps, or unauthorized access guidance.
- summary: 1 short sentence, max 170 characters.
- why_it_matters: 1 sentence about operational impact, max 150 characters.
- ops_note: 1 action sentence for SOC/admin teams, max 160 characters.
- title: a faithful, concise English headline with product and impact, max 70 characters; not a full sentence.
- If "priority_alert" exists in the input, also return "priority_alert" with title, summary, why_it_matters, ops_note.
- Return valid JSON only, matching the response schema. Never stop mid-string."#;

const CVE_PROMPT_RULES: &str = r#"You are the editorial layer for SecPath Radar, a defensive daily cybersecurity intelligence brief.

Input JSON contains CVE items in "items". Every item has a "ref" identifier.

Hard rules:
- Do not invent facts, CVEs, sources, URLs, exploitation status, affected products, or exploit details.
- Never change or restate cve_id, cvss, epss, kev, severity, or url values; they stay as-is in the site.
- Return editorial fields only: title, summary, why_it_matters, recommended_action, ops_note.
- Return exactly one output entry per input item and copy its "ref" value unchanged.
- If an item is unclear, write a cautious summary and say the original advisory should be checked.
- Use defensive language only. No exploit chains, payloads, bypass steps, or unauthorized access guidance.
- title: concise English headline with product and impact, max 70 characters; not a full NVD sentence.
- summary: 1 short sentence, max 170 characters.
- why_it_matters: 1 sentence about operational impact, max 150 characters.
- recommended_action: 1 short sentence with the safest next step (patching, mitigation, monitoring), max 160 characters.
- ops_note: 1 action sentence for SOC/admin teams, max 160 characters.
- Return valid JSON only, matching the response schema. Never stop mid-string."#;

pub(crate) fn build_news_batch_prompt(
    brief: &Value,
    alert_needed: bool,
    pending: &[(String, String, usize)],
) -> Result<String> {
    let mut input = serde_json::Map::new();
    if alert_needed {
        input.insert(
            "priority_alert".to_string(),
            compact_alert(&brief["priority_alert"]),
        );
    }
    let items: Vec<Value> = pending
        .iter()
        .filter_map(|(reference, section, index)| {
            brief
                .get(section.as_str())
                .and_then(|v| v.as_array())
                .and_then(|list| list.get(*index))
                .map(|item| compact_news_item(reference, section, item))
        })
        .collect();
    input.insert("items".to_string(), json!(items));
    Ok(format!(
        "{}\n\nInput JSON:\n{}",
        NEWS_PROMPT_RULES,
        serde_json::to_string_pretty(&Value::Object(input))?
    ))
}

pub(crate) fn build_cve_batch_prompt(
    brief: &Value,
    pending: &[(String, String, usize)],
) -> Result<String> {
    let items: Vec<Value> = pending
        .iter()
        .filter_map(|(reference, section, index)| {
            brief
                .get(section.as_str())
                .and_then(|v| v.as_array())
                .and_then(|list| list.get(*index))
                .map(|item| compact_cve_item(reference, item))
        })
        .collect();
    let input = json!({ "items": items });
    Ok(format!(
        "{}\n\nInput JSON:\n{}",
        CVE_PROMPT_RULES,
        serde_json::to_string_pretty(&input)?
    ))
}

pub(crate) fn compact_news_item(reference: &str, section: &str, item: &Value) -> Value {
    json!({
        "ref": reference,
        "section": section,
        "title": clip_field(item, "title", 300),
        "summary": clip_field(item, "summary", 700),
        "source": clip_field(item, "source", 80),
        "tags": item.get("tags").cloned().unwrap_or(Value::Null)
    })
}

pub(crate) fn compact_cve_item(reference: &str, item: &Value) -> Value {
    json!({
        "ref": reference,
        "cve_id": item.get("cve_id").cloned().unwrap_or(Value::Null),
        "title": clip_field(item, "title", 300),
        "summary": clip_field(item, "summary", 700),
        "cvss": item.get("cvss").cloned().unwrap_or(Value::Null),
        "epss": item.get("epss").cloned().unwrap_or(Value::Null),
        "kev": item.get("kev").cloned().unwrap_or(Value::Null),
        "severity": item.get("severity").cloned().unwrap_or(Value::Null),
        "tags": item.get("tags").cloned().unwrap_or(Value::Null)
    })
}

pub(crate) fn compact_alert(alert: &Value) -> Value {
    json!({
        "title": clip_field(alert, "title", 300),
        "summary": clip_field(alert, "summary", 700),
        "source": clip_field(alert, "source", 80),
        "cve_id": alert.get("cve_id").cloned().unwrap_or(Value::Null)
    })
}

pub(crate) fn clip_field(item: &Value, key: &str, max_chars: usize) -> Value {
    item.get(key)
        .and_then(|v| v.as_str())
        .map(|s| json!(truncate_chars(s, max_chars)))
        .unwrap_or(Value::Null)
}

pub(crate) fn gemini_news_schema() -> Value {
    json!({
        "type": "OBJECT",
        "properties": {
            "priority_alert": {
                "type": "OBJECT",
                "properties": {
                    "title": {"type": "STRING"},
                    "summary": {"type": "STRING"},
                    "why_it_matters": {"type": "STRING"},
                    "ops_note": {"type": "STRING"}
                }
            },
            "items": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "ref": {"type": "STRING"},
                        "title": {"type": "STRING"},
                        "summary": {"type": "STRING"},
                        "why_it_matters": {"type": "STRING"},
                        "ops_note": {"type": "STRING"}
                    },
                    "required": ["ref", "title", "summary"]
                }
            }
        },
        "required": ["items"]
    })
}

pub(crate) fn gemini_cve_schema() -> Value {
    json!({
        "type": "OBJECT",
        "properties": {
            "items": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "ref": {"type": "STRING"},
                        "title": {"type": "STRING"},
                        "summary": {"type": "STRING"},
                        "why_it_matters": {"type": "STRING"},
                        "recommended_action": {"type": "STRING"},
                        "ops_note": {"type": "STRING"}
                    },
                    "required": ["ref", "title", "summary"]
                }
            }
        },
        "required": ["items"]
    })
}

pub(crate) fn run_gemini_batch(
    client: &Client,
    url: &str,
    api_key: &str,
    prompt: &str,
    temperature: f64,
    schema: &Value,
) -> Result<(Value, u8)> {
    let text = send_gemini_prompt(client, url, api_key, prompt, temperature, 8192, schema)
        .context("Gemini request failed")?;
    let cleaned = clean_json_block(&text);
    match serde_json::from_str::<Value>(&cleaned) {
        Ok(value) => Ok((value, 1)),
        Err(parse_error) => {
            eprintln!("↳ Gemini JSON parse failed; attempting one repair pass");
            let repair_prompt = build_gemini_repair_prompt(&cleaned, &parse_error.to_string());
            let repaired_text =
                send_gemini_prompt(client, url, api_key, &repair_prompt, 0.0, 8192, schema)
                    .context("Gemini repair request failed")?;
            let repaired = clean_json_block(&repaired_text);
            let value: Value = serde_json::from_str(&repaired).with_context(|| {
                format!(
                    "Gemini returned text, but it was not valid JSON after repair: {}",
                    json_parse_hint(&repaired)
                )
            })?;
            Ok((value, 2))
        }
    }
}

pub(crate) fn send_gemini_prompt(
    client: &Client,
    url: &str,
    api_key: &str,
    prompt: &str,
    temperature: f64,
    max_output_tokens: u32,
    schema: &Value,
) -> Result<String> {
    let request_body = json!({
        "contents": [{
            "role": "user",
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "temperature": temperature,
            "candidateCount": 1,
            "maxOutputTokens": max_output_tokens,
            "responseMimeType": "application/json",
            "responseSchema": schema
        }
    });

    let response_json: Value = client
        .post(url)
        .header("x-goog-api-key", api_key)
        .json(&request_body)
        .send()
        .and_then(|response| response.error_for_status())
        .context("Gemini request failed")?
        .json()
        .context("Gemini response was not valid JSON")?;

    extract_gemini_text(&response_json).context("Gemini response did not include text")
}

pub(crate) fn build_gemini_repair_prompt(broken_json: &str, parse_error: &str) -> String {
    format!(
        "Repair the following truncated or invalid JSON so it becomes valid JSON only.\n\nRules:\n- Return JSON only, no markdown.\n- Preserve the same schema and field names.\n- If a string is incomplete, close it safely.\n- If an array/object is incomplete, close it safely.\n- Do not add new source URLs, IOCs, leak links, or user-facing actions.\n- Keep text concise.\n\nParser error: {parse_error}\n\nBroken JSON:\n{broken_json}"
    )
}

pub(crate) fn extract_gemini_text(response: &Value) -> Option<String> {
    response
        .get("candidates")?
        .as_array()?
        .first()?
        .get("content")?
        .get("parts")?
        .as_array()?
        .first()?
        .get("text")?
        .as_str()
        .map(|s| s.to_string())
}

pub(crate) fn clean_json_block(text: &str) -> String {
    let mut out = text.trim().to_string();
    if out.starts_with("```json") {
        out = out.trim_start_matches("```json").trim().to_string();
    } else if out.starts_with("```") {
        out = out.trim_start_matches("```").trim().to_string();
    }
    if out.ends_with("```") {
        out = out.trim_end_matches("```").trim().to_string();
    }
    out
}

pub(crate) fn json_parse_hint(text: &str) -> String {
    let char_count = text.chars().count();
    let preview: String = text.chars().take(180).collect();
    format!("{} chars; starts with {:?}", char_count, preview)
}

pub(crate) fn merge_object_preserve_existing(base: &mut Value, edit: &Value) {
    let Some(base_obj) = base.as_object_mut() else {
        return;
    };
    let Some(edit_obj) = edit.as_object() else {
        return;
    };

    for (key, value) in edit_obj {
        if protected_ai_field(key) && base_obj.contains_key(key) {
            continue;
        }

        let usable = match value {
            Value::Null => false,
            Value::String(s) => !s.trim().is_empty(),
            Value::Array(items) => !items.is_empty(),
            Value::Object(obj) => !obj.is_empty(),
            _ => true,
        };

        if usable {
            base_obj.insert(key.clone(), value.clone());
        }
    }
}

pub(crate) fn protected_ai_field(key: &str) -> bool {
    matches!(
        key,
        "url"
            | "source"
            | "cve_id"
            | "cvss"
            | "epss"
            | "kev"
            | "severity"
            | "risk_score"
            | "published"
            | "summary"
            | "title"
            | "tags"
            | "category"
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn mark_ai_status(
    mut brief: Value,
    ok: bool,
    cache_hit: bool,
    model: &str,
    calls_used: u8,
    item_cache_hits: u64,
    items_generated: u64,
    error: Option<String>,
) -> Value {
    brief["ai_status"] = json!({
        "enabled": true,
        "ok": ok,
        "cache_hit": cache_hit,
        "model": model,
        "calls_used": calls_used,
        "item_cache_hits": item_cache_hits,
        "items_generated": items_generated,
        "prompt_version": AI_PROMPT_VERSION,
        "error": error
    });
    brief
}

pub(crate) fn get_env_or_dotenv(key: &str) -> Option<String> {
    if let Ok(value) = env::var(key) {
        if !value.trim().is_empty() {
            return Some(value);
        }
    }

    let raw = fs::read_to_string(".env").ok()?;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if k.trim() == key {
            let value = v
                .trim()
                .trim_matches('"')
                .trim_matches('\u{27}')
                .to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }

    None
}

const BRIEFING_PROMPT_RULES: &str = r#"You are the executive-briefing layer for SecPath Radar, a defensive daily cybersecurity intelligence brief.

Input JSON contains today's date, an optional "priority_alert", top news items in "news", and top vulnerabilities in "cves".

Hard rules:
- Base every statement only on the provided input. Do not invent facts, sources, URLs, CVEs, exploitation status, victim names, attribution, or numbers.
- Write in plain English for a global audience of security leaders.
- Use defensive language only. No exploit chains, payloads, bypass steps, or unauthorized access guidance.
- headline: one line capturing today's overall threat picture, max 90 characters; not a full sentence.
- narrative: 2-3 sentences, max 420 characters, summarizing the most important developments and their operational impact.
- takeaways: 3-4 strings, each max 160 characters, concrete defensive priorities (patching, monitoring, hardening) drawn from the input.
- watch_items: 0-3 strings, each max 140 characters, developments worth monitoring over the next 24 hours.
- If the input is thin or unclear, keep a cautious tone and note that monitoring continues.
- Return valid JSON only, matching the response schema. Never stop mid-string."#;

pub(crate) fn build_briefing_input(brief: &Value) -> Value {
    let news: Vec<Value> = brief
        .get("global_news")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .take(6)
                .map(|item| {
                    json!({
                        "title": clip_field(item, "title", 200),
                        "summary": clip_field(item, "summary", 400),
                        "source": clip_field(item, "source", 60)
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let cves: Vec<Value> = brief
        .get("cves")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .take(6)
                .map(|item| {
                    json!({
                        "cve_id": item.get("cve_id").cloned().unwrap_or(Value::Null),
                        "title": clip_field(item, "title", 200),
                        "cvss": item.get("cvss").cloned().unwrap_or(Value::Null),
                        "kev": item.get("kev").cloned().unwrap_or(Value::Null),
                        "severity": item.get("severity").cloned().unwrap_or(Value::Null)
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    json!({
        "date": clip_field(brief, "date_en", 40),
        "priority_alert": compact_alert(&brief["priority_alert"]),
        "news": news,
        "cves": cves
    })
}

pub(crate) fn briefing_input_has_content(input: &Value) -> bool {
    let has_items = |key: &str| {
        input
            .get(key)
            .and_then(|v| v.as_array())
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    };
    has_items("news") || has_items("cves")
}

pub(crate) fn briefing_cache_key(model: &str, input: &Value) -> String {
    let raw = format!(
        "{}\n{}\nbriefing\n{}",
        AI_PROMPT_VERSION,
        model,
        serde_json::to_string(input).unwrap_or_default()
    );
    let mut hasher = DefaultHasher::new();
    raw.hash(&mut hasher);
    format!("briefing-{:016x}.json", hasher.finish())
}

pub(crate) fn build_briefing_prompt(input: &Value) -> Result<String> {
    Ok(format!(
        "{}\n\nInput JSON:\n{}",
        BRIEFING_PROMPT_RULES,
        serde_json::to_string_pretty(input)?
    ))
}

pub(crate) fn gemini_briefing_schema() -> Value {
    json!({
        "type": "OBJECT",
        "properties": {
            "headline": {"type": "STRING"},
            "narrative": {"type": "STRING"},
            "takeaways": {"type": "ARRAY", "items": {"type": "STRING"}},
            "watch_items": {"type": "ARRAY", "items": {"type": "STRING"}}
        },
        "required": ["headline", "narrative", "takeaways"]
    })
}

pub(crate) fn sanitize_briefing(value: &Value) -> Value {
    let mut clean = serde_json::Map::new();
    let Some(obj) = value.as_object() else {
        return Value::Object(clean);
    };
    for key in ["headline", "narrative"] {
        if let Some(Value::String(text)) = obj.get(key) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                clean.insert(key.to_string(), json!(truncate_chars(trimmed, 600)));
            }
        }
    }
    for key in ["takeaways", "watch_items"] {
        if let Some(Value::Array(items)) = obj.get(key) {
            let texts: Vec<String> = items
                .iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .take(4)
                .map(|s| truncate_chars(s, 220))
                .collect();
            if !texts.is_empty() {
                clean.insert(key.to_string(), json!(texts));
            }
        }
    }
    Value::Object(clean)
}

pub(crate) fn briefing_is_usable(value: &Value) -> bool {
    value
        .as_object()
        .map(|obj| obj.contains_key("headline") && obj.contains_key("narrative"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_cache_key_is_stable_and_content_sensitive() {
        let item = json!({
            "title": "Example advisory",
            "url": "https://example.com/a",
            "summary": "text"
        });
        let first = item_cache_key("gemini-2.5-flash", "global_news", &item);
        let second = item_cache_key("gemini-2.5-flash", "global_news", &item);
        assert_eq!(first, second);
        assert!(first.starts_with("news-"));
        assert!(first.ends_with(".json"));

        let changed = json!({
            "title": "Example advisory v2",
            "url": "https://example.com/a",
            "summary": "text"
        });
        assert_ne!(
            first,
            item_cache_key("gemini-2.5-flash", "global_news", &changed)
        );
        assert_ne!(first, item_cache_key("gemini-x", "global_news", &item));
    }

    #[test]
    fn sanitize_editorial_keeps_only_editorial_fields() {
        let raw = json!({
            "ref": "n0",
            "url": "https://evil.example",
            "title": "Test Title",
            "summary": " Test Summary ",
            "unexpected": "x"
        });
        let clean = sanitize_editorial("news", &raw);
        assert_eq!(clean["title"], "Test Title");
        assert_eq!(clean["summary"], "Test Summary");
        assert!(clean.get("url").is_none());
        assert!(clean.get("ref").is_none());
        assert!(clean.get("unexpected").is_none());

        let cve = sanitize_editorial("cve", &json!({"recommended_action": "Apply patch"}));
        assert_eq!(cve["recommended_action"], "Apply patch");
    }

    #[test]
    fn sanitize_briefing_keeps_only_expected_fields() {
        let raw = json!({
            "headline": " Global patching pressure rises ",
            "narrative": "Several vendors shipped fixes.",
            "takeaways": ["Patch now", "", 42],
            "watch_items": ["Watch KEV updates"],
            "url": "https://evil.example"
        });
        let clean = sanitize_briefing(&raw);
        assert_eq!(clean["headline"], "Global patching pressure rises");
        assert_eq!(clean["takeaways"], json!(["Patch now"]));
        assert!(clean.get("url").is_none());
        assert!(briefing_is_usable(&clean));
        assert!(!briefing_is_usable(&json!({"headline": "x"})));
    }

    #[test]
    fn merge_batch_item_respects_protected_fields() {
        let mut brief = json!({
            "global_news": [
                {"title": "Original", "url": "https://a.example", "summary": "s"}
            ]
        });
        let editorial = sanitize_editorial(
            "news",
            &json!({
                "title": "New Title",
                "ops_note": "Review needed",
                "url": "https://b.example"
            }),
        );
        assert!(merge_batch_item(&mut brief, "global_news", 0, &editorial));
        assert_eq!(brief["global_news"][0]["title"], "Original");
        assert_eq!(brief["global_news"][0]["ops_note"], "Review needed");
        assert_eq!(brief["global_news"][0]["url"], "https://a.example");
        assert!(merge_batch_item(&mut brief, "missing_section", 0, &editorial) == false);
        assert!(!merge_batch_item(&mut brief, "global_news", 9, &editorial));
    }
}
