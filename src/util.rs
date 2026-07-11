//! Small shared text utilities.

use anyhow::{Context, Result};
use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub(crate) fn normalize_key(title: &str, url: &str) -> String {
    let raw = if !url.is_empty() { url } else { title };
    raw.trim()
        .trim_end_matches('/')
        .to_lowercase()
        .replace("https://", "")
        .replace("http://", "")
}

pub(crate) fn clean_text(input: &str) -> String {
    let mut without_tags = String::with_capacity(input.len());
    let mut in_tag = false;

    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => without_tags.push(ch),
            _ => {}
        }
    }

    // Two passes handle double-escaped feed content such as &amp;#8217;.
    let decoded_once = decode_html_entities(&without_tags);
    decode_html_entities(&decoded_once)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn decode_html_entities(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut index = 0usize;

    while index < chars.len() {
        if chars[index] != '&' {
            out.push(chars[index]);
            index += 1;
            continue;
        }

        let mut end = index + 1;
        while end < chars.len() && end.saturating_sub(index) <= 12 && chars[end] != ';' {
            end += 1;
        }
        if end >= chars.len() || chars[end] != ';' {
            out.push('&');
            index += 1;
            continue;
        }

        let entity: String = chars[index + 1..end].iter().collect();
        let decoded = match entity.as_str() {
            "nbsp" => Some(' '),
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" | "#39" => Some('\''),
            _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                u32::from_str_radix(&entity[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
            }
            _ if entity.starts_with('#') => {
                entity[1..].parse::<u32>().ok().and_then(char::from_u32)
            }
            _ => None,
        };

        if let Some(ch) = decoded {
            out.push(ch);
        } else {
            out.push('&');
            out.push_str(&entity);
            out.push(';');
        }
        index = end + 1;
    }

    out
}

pub(crate) fn truncate_chars(input: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (idx, ch) in input.chars().enumerate() {
        if idx >= max_chars {
            out.push('…');
            return out;
        }
        out.push(ch);
    }
    out
}

pub(crate) fn keyword_tag(keyword: &str) -> String {
    match keyword.to_lowercase().as_str() {
        "zero-day" | "zeroday" => "Zero-day".to_string(),
        "actively exploited" | "exploited in the wild" => "Active Exploit".to_string(),
        "data breach" | "breach" => "Breach".to_string(),
        "vulnerability" | "critical" => "Vulnerability".to_string(),
        "cve-" => "CVE".to_string(),
        "vpn" => "VPN".to_string(),
        "firewall" => "Firewall".to_string(),
        "router" => "Router".to_string(),
        "gateway" => "Gateway".to_string(),
        "exchange" => "Exchange".to_string(),
        "wordpress" => "WordPress".to_string(),
        "linux" => "Linux".to_string(),
        other => {
            let mut chars = other.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => "Security".to_string(),
            }
        }
    }
}

pub(crate) fn push_tag(tags: &mut Vec<String>, tag: String) {
    if !tags.iter().any(|t| t == &tag) {
        tags.push(tag);
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PruneStats {
    pub(crate) scanned: usize,
    pub(crate) removed_by_age: usize,
    pub(crate) removed_by_count: usize,
}

impl PruneStats {
    pub(crate) fn removed(self) -> usize {
        self.removed_by_age + self.removed_by_count
    }
}

pub(crate) fn prune_regular_files(
    dir: &PathBuf,
    max_age_days: u64,
    max_files: usize,
    protected_names: &[&str],
) -> Result<PruneStats> {
    if !dir.exists() {
        return Ok(PruneStats::default());
    }

    let now = SystemTime::now();
    let max_age = Duration::from_secs(max_age_days.saturating_mul(86_400));
    let mut candidates = Vec::new();
    let mut stats = PruneStats::default();

    for entry in fs::read_dir(dir)
        .with_context(|| format!("failed to read retention directory: {}", dir.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().to_string();
        if protected_names.iter().any(|protected| name == *protected) {
            continue;
        }

        stats.scanned += 1;
        let modified = entry.metadata()?.modified().unwrap_or(UNIX_EPOCH);
        let path = entry.path();
        let too_old = now
            .duration_since(modified)
            .map(|age| age > max_age)
            .unwrap_or(false);

        if too_old {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove expired file: {}", path.display()))?;
            stats.removed_by_age += 1;
        } else {
            candidates.push((path, modified));
        }
    }

    candidates.sort_by(|a, b| b.1.cmp(&a.1));
    for (path, _) in candidates.into_iter().skip(max_files) {
        fs::remove_file(&path)
            .with_context(|| format!("failed to remove excess file: {}", path.display()))?;
        stats.removed_by_count += 1;
    }

    Ok(stats)
}

pub(crate) fn write_json_atomic(path: &PathBuf, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory: {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    let temp = path.with_extension(format!("json.tmp-{}", std::process::id()));
    fs::write(&temp, bytes)
        .with_context(|| format!("failed to write temporary JSON: {}", temp.display()))?;
    fs::rename(&temp, path).with_context(|| {
        format!(
            "failed to atomically replace JSON {} with {}",
            path.display(),
            temp.display()
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_chars_adds_ellipsis_only_when_needed() {
        assert_eq!(truncate_chars("abcdef", 3), "abc…");
        assert_eq!(truncate_chars("ab", 5), "ab");
        assert_eq!(truncate_chars("", 5), "");
    }

    #[test]
    fn clean_text_strips_tags_and_entities() {
        assert_eq!(clean_text("<b>hello</b>&nbsp;world"), "hello world");
        assert_eq!(clean_text("a  b\n c"), "a b c");
        assert_eq!(clean_text("Microsoft&amp;#8217;s"), "Microsoft’s");
        assert_eq!(clean_text("A &#x2014; B"), "A — B");
    }

    #[test]
    fn normalize_key_prefers_url_and_normalizes() {
        assert_eq!(
            normalize_key("Title", "https://Example.com/x/"),
            "example.com/x"
        );
        assert_eq!(normalize_key("My Title", ""), "my title");
    }

    #[test]
    fn push_tag_deduplicates() {
        let mut tags = vec!["A".to_string()];
        push_tag(&mut tags, "A".to_string());
        push_tag(&mut tags, "B".to_string());
        assert_eq!(tags, vec!["A".to_string(), "B".to_string()]);
    }

    #[test]
    fn keyword_tag_maps_known_keywords() {
        assert_eq!(keyword_tag("vpn"), "VPN");
        assert_eq!(keyword_tag("zero-day"), "Zero-day");
        assert_eq!(keyword_tag("ransomware"), "Ransomware");
    }
    #[test]
    fn prune_regular_files_enforces_count_and_protects_named_files() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "secpath-radar-prune-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp directory");
        fs::write(dir.join("latest.json"), b"latest").expect("write protected file");
        for index in 0..4 {
            fs::write(dir.join(format!("{index}.json")), b"item").expect("write item");
        }

        let stats = prune_regular_files(&dir, 365, 2, &["latest.json"]).expect("pruning succeeds");
        assert_eq!(stats.removed_by_count, 2);
        assert!(dir.join("latest.json").exists());
        let remaining = fs::read_dir(&dir).expect("read temp directory").count();
        assert_eq!(remaining, 3);

        fs::remove_dir_all(&dir).expect("remove temp directory");
    }
}
