//! Gemini editorial layer: prompts, schema, cache, and merge.

use crate::prelude::*;

pub(crate) struct GeminiEditResult {
    pub(crate) brief: Value,
    pub(crate) calls_used: u8,
    pub(crate) cache_hit: bool,
}

pub(crate) fn enhance_brief_with_gemini(
    config: &Config,
    brief: &Value,
    refresh_ai: bool,
    offline: bool,
) -> Result<GeminiEditResult> {
    let compact = compact_brief_for_ai(config, brief);
    let cache_key = ai_cache_key(&config.gemini.model, &compact);

    if !refresh_ai {
        if let Some(cached) = read_ai_cache(config, &cache_key)? {
            let edited = merge_ai_result(brief.clone(), &cached);
            return Ok(GeminiEditResult {
                brief: mark_ai_status(edited, true, true, &config.gemini.model, 0, None),
                calls_used: 0,
                cache_hit: true,
            });
        }
    }

    if offline {
        let edited = mark_ai_status(
            brief.clone(),
            false,
            false,
            &config.gemini.model,
            0,
            Some("offline mode has no matching Gemini cache".to_string()),
        );
        return Ok(GeminiEditResult {
            brief: edited,
            calls_used: 0,
            cache_hit: false,
        });
    }

    let api_key = get_env_or_dotenv("GEMINI_API_KEY")
        .context("GEMINI_API_KEY is not set. Put it in .env or export it before using --ai")?;

    let prompt = build_gemini_prompt(&compact)?;

    let url = format!(
        "{}/models/{}:generateContent",
        config.gemini.api_url.trim_end_matches('/'),
        config.gemini.model
    );

    let client = Client::builder()
        .user_agent(&config.fetch.user_agent)
        .timeout(Duration::from_secs(60))
        .build()
        .context("failed to build HTTP client for Gemini")?;

    let text = send_gemini_prompt(
        &client,
        &url,
        &api_key,
        &prompt,
        config.gemini.temperature,
        8192,
    )
    .context("Gemini request failed")?;
    let cleaned = clean_json_block(&text);
    let (ai_json, calls_used) = match serde_json::from_str::<Value>(&cleaned) {
        Ok(value) => (value, 1),
        Err(parse_error) => {
            eprintln!("↳ Gemini JSON parse failed; attempting one repair pass");
            let repair_prompt = build_gemini_repair_prompt(&cleaned, &parse_error.to_string());
            let repaired_text =
                send_gemini_prompt(&client, &url, &api_key, &repair_prompt, 0.0, 8192)
                    .context("Gemini repair request failed")?;
            let repaired = clean_json_block(&repaired_text);
            let value: Value = serde_json::from_str(&repaired).with_context(|| {
                format!(
                    "Gemini returned text, but it was not valid JSON after repair: {}",
                    json_parse_hint(&repaired)
                )
            })?;
            (value, 2)
        }
    };
    let ai_json = validate_ai_result_shape(&ai_json)?;

    write_ai_cache(config, &cache_key, &ai_json)?;

    let edited = merge_ai_result(brief.clone(), &ai_json);
    Ok(GeminiEditResult {
        brief: mark_ai_status(edited, true, false, &config.gemini.model, calls_used, None),
        calls_used,
        cache_hit: false,
    })
}

pub(crate) fn send_gemini_prompt(
    client: &Client,
    url: &str,
    api_key: &str,
    prompt: &str,
    temperature: f64,
    max_output_tokens: u32,
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
            "responseSchema": gemini_response_schema()
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
        "Repair the following truncated or invalid JSON so it becomes valid JSON only.\n\nRules:\n- Return JSON only, no markdown.\n- Preserve the same schema and field names.\n- If a string is incomplete, close it safely.\n- If an array/object is incomplete, close it safely.\n- Do not add new source URLs, IOCs, leak links, or user-facing actions.\n- Keep Persian text concise.\n\nParser error: {parse_error}\n\nBroken JSON:\n{broken_json}"
    )
}

pub(crate) fn compact_brief_for_ai(config: &Config, brief: &Value) -> Value {
    let mut compact = json!({
        "site_title": brief.get("site_title").cloned().unwrap_or(Value::Null),
        "date_fa": brief.get("date_fa").cloned().unwrap_or(Value::Null),
        "date_en": brief.get("date_en").cloned().unwrap_or(Value::Null),
        "risk_level": brief.get("risk_level").cloned().unwrap_or(Value::Null),
        "stats": brief.get("stats").cloned().unwrap_or(Value::Null),
        "priority_alert": brief.get("priority_alert").cloned().unwrap_or(Value::Null),
        "iran_radar": take_array_items(brief.get("iran_radar"), config.gemini.max_iran_items),
        "global_news": take_array_items(brief.get("global_news"), config.gemini.max_global_news),
        "cves": take_array_items(brief.get("cves"), config.gemini.max_cves),
    });

    truncate_value_strings(&mut compact, 900);
    compact
}

pub(crate) fn take_array_items(value: Option<&Value>, limit: usize) -> Value {
    value
        .and_then(|v| v.as_array())
        .map(|items| Value::Array(items.iter().take(limit).cloned().collect()))
        .unwrap_or_else(|| Value::Array(Vec::new()))
}

pub(crate) fn truncate_value_strings(value: &mut Value, max_chars: usize) {
    match value {
        Value::String(s) => {
            if s.chars().count() > max_chars {
                *s = truncate_chars(s, max_chars);
            }
        }
        Value::Array(items) => {
            for item in items {
                truncate_value_strings(item, max_chars);
            }
        }
        Value::Object(map) => {
            for value in map.values_mut() {
                truncate_value_strings(value, max_chars);
            }
        }
        _ => {}
    }
}

pub(crate) fn gemini_response_schema() -> Value {
    json!({
        "type": "OBJECT",
        "properties": {
            "priority_alert": {
                "type": "OBJECT",
                "properties": {
                    "title_fa": {"type": "STRING"},
                    "summary_fa": {"type": "STRING"},
                    "why_it_matters": {"type": "STRING"},
                    "ops_note": {"type": "STRING"}
                }
            },
            "iran_radar": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "title_fa": {"type": "STRING"},
                        "summary_fa": {"type": "STRING"},
                        "why_it_matters": {"type": "STRING"},
                        "ops_note": {"type": "STRING"}
                    }
                }
            },
            "global_news": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "title_fa": {"type": "STRING"},
                        "summary_fa": {"type": "STRING"},
                        "why_it_matters": {"type": "STRING"},
                        "ops_note": {"type": "STRING"}
                    }
                }
            },
            "cves": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "title_fa": {"type": "STRING"},
                        "summary_fa": {"type": "STRING"},
                        "why_it_matters": {"type": "STRING"},
                        "recommended_action": {"type": "STRING"},
                        "ops_note": {"type": "STRING"}
                    }
                }
            }
        },
        "required": ["priority_alert", "iran_radar", "global_news", "cves"]
    })
}

pub(crate) fn build_gemini_prompt(compact: &Value) -> Result<String> {
    Ok(format!(
        r#"You are the Persian editorial layer for SecPath Radar, a defensive daily cybersecurity intelligence brief.

Input is JSON generated from RSS, NVD, CISA KEV, and EPSS. Your job is to add a Persian display layer while preserving the original machine-generated/source fields.

Hard rules:
- Do not invent facts, CVEs, sources, URLs, exploitation status, affected products, victim geography, attribution, or exploit details.
- Do not rewrite or return immutable fields such as url, source, cve_id, risk_score, cvss, epss, kev, severity, published, iran_context, tags, title, or summary.
- Return editorial fields only: title_fa, summary_fa, why_it_matters, ops_note, and recommended_action for CVEs.
- Keep the same item order and approximate same item count for iran_radar, global_news, and cves.
- If an item is unclear, write a cautious Persian summary and say the original advisory should be checked.
- Do not move Iran-related items between sections. If Iran appears only as attribution, do not imply the target is inside Iran.
- Use defensive language only. No exploit chains, payloads, bypass steps, or unauthorized access guidance.
- summary_fa: 1 short Persian sentence, max 170 characters.
- why_it_matters: 1 Persian sentence about operational impact, max 150 characters.
- ops_note: 1 Persian action sentence for SOC/admin teams, max 160 characters.
- title_fa: concise Persian headline, max 70 characters. For CVEs, include product/impact, not a full NVD sentence.
- Return valid JSON only. No markdown fences, comments, trailing commas, or explanatory text.
- Prefer short strings over complete sentences if needed; never stop mid-string.

Return this exact top-level shape:
{{
  "priority_alert": {{"title_fa":"...", "summary_fa":"...", "why_it_matters":"...", "ops_note":"..."}},
  "iran_radar": [{{"title_fa":"...", "summary_fa":"...", "why_it_matters":"...", "ops_note":"..."}}],
  "global_news": [{{"title_fa":"...", "summary_fa":"...", "why_it_matters":"...", "ops_note":"..."}}],
  "cves": [{{"title_fa":"...", "summary_fa":"...", "why_it_matters":"...", "recommended_action":"...", "ops_note":"..."}}]
}}

Input JSON:
{}"#,
        serde_json::to_string_pretty(compact)?
    ))
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

pub(crate) fn validate_ai_result_shape(ai_json: &Value) -> Result<Value> {
    let obj = ai_json
        .as_object()
        .context("Gemini returned JSON, but the top-level value was not an object")?;

    let mut clean = serde_json::Map::new();

    if let Some(value) = obj.get("priority_alert") {
        if value.is_object() {
            clean.insert("priority_alert".to_string(), value.clone());
        }
    }

    for key in ["iran_radar", "global_news", "cves"] {
        if let Some(value) = obj.get(key) {
            if let Some(items) = value.as_array() {
                let safe_items = items
                    .iter()
                    .filter(|item| item.is_object())
                    .cloned()
                    .collect::<Vec<_>>();
                clean.insert(key.to_string(), Value::Array(safe_items));
            }
        }
    }

    if clean.is_empty() {
        anyhow::bail!("Gemini returned JSON, but it did not contain any usable brief fields");
    }

    Ok(Value::Object(clean))
}

pub(crate) fn merge_ai_result(mut brief: Value, ai_json: &Value) -> Value {
    if let Some(value) = ai_json.get("priority_alert") {
        merge_object_preserve_existing(&mut brief["priority_alert"], value);
    }

    for key in ["iran_radar", "global_news", "cves"] {
        if let Some(value) = ai_json.get(key) {
            merge_array_items_by_index(&mut brief[key], value);
        }
    }

    brief
}

pub(crate) fn merge_array_items_by_index(base: &mut Value, edits: &Value) {
    let Some(base_items) = base.as_array_mut() else {
        return;
    };
    let Some(edit_items) = edits.as_array() else {
        return;
    };

    for (base_item, edit_item) in base_items.iter_mut().zip(edit_items.iter()) {
        merge_object_preserve_existing(base_item, edit_item);
    }
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
            | "iran_context"
            | "summary"
            | "title"
            | "tags"
            | "category"
    )
}

pub(crate) fn mark_ai_status(
    mut brief: Value,
    ok: bool,
    cache_hit: bool,
    model: &str,
    calls_used: u8,
    error: Option<String>,
) -> Value {
    brief["ai_status"] = json!({
        "enabled": true,
        "ok": ok,
        "cache_hit": cache_hit,
        "model": model,
        "calls_used": calls_used,
        "error": error
    });
    brief
}

pub(crate) fn ai_cache_key(model: &str, compact: &Value) -> String {
    let raw = format!(
        "{}\n{}",
        model,
        serde_json::to_string(compact).unwrap_or_default()
    );
    let mut hasher = DefaultHasher::new();
    raw.hash(&mut hasher);
    format!("{:016x}.json", hasher.finish())
}

pub(crate) fn ai_cache_path(config: &Config, key: &str) -> PathBuf {
    PathBuf::from(&config.gemini.cache_dir).join(key)
}

pub(crate) fn read_ai_cache(config: &Config, key: &str) -> Result<Option<Value>> {
    let path = ai_cache_path(config, key);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read AI cache: {}", path.display()))?;
    serde_json::from_str(&raw)
        .map(Some)
        .with_context(|| format!("invalid AI cache JSON: {}", path.display()))
}

pub(crate) fn write_ai_cache(config: &Config, key: &str, value: &Value) -> Result<()> {
    let path = ai_cache_path(config, key);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("failed to create AI cache directory: {}", parent.display())
        })?;
    }
    fs::write(&path, serde_json::to_string_pretty(value)?)
        .with_context(|| format!("failed to write AI cache: {}", path.display()))?;
    Ok(())
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
            let value = v.trim().trim_matches('"').trim_matches('\'').to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }

    None
}
