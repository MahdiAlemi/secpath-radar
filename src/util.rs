//! Small shared text utilities.

pub(crate) fn normalize_key(title: &str, url: &str) -> String {
    let raw = if !url.is_empty() { url } else { title };
    raw.trim()
        .trim_end_matches('/')
        .to_lowercase()
        .replace("https://", "")
        .replace("http://", "")
}

pub(crate) fn clean_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_tag = false;

    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }

    out.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
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

/// Human-readable phase suffix appended to the crate version in the brief.
/// Update this once per phase; the numeric version comes from Cargo.toml.
pub(crate) const PHASE_NAME: &str = "nuclei-template-coverage";

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
}
