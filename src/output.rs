//! Static read-only outputs rendered next to the site: RSS feed and JSON API.

use crate::prelude::*;

pub(crate) const SITE_LINK: &str = "https://radar.secpath.space";
pub(crate) const FEED_MAX_CVES: usize = 8;
pub(crate) const FEED_MAX_NEWS: usize = 8;

pub(crate) fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

pub(crate) fn item_text(item: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(text) = item.get(*key).and_then(|v| v.as_str()) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

pub(crate) fn feed_pub_date(item: &Value) -> Option<String> {
    let raw = item.get("published").and_then(|v| v.as_str())?;
    let parsed = chrono::DateTime::parse_from_rfc3339(raw.trim()).ok()?;
    Some(parsed.to_rfc2822())
}

pub(crate) fn feed_entry(item: &Value) -> Value {
    let mut title = item_text(item, &["title_fa", "title"]);
    let cve_id = item_text(item, &["cve_id"]);
    if !cve_id.is_empty() && !title.contains(&cve_id) {
        title = format!("{cve_id}: {title}");
    }
    json!({
        "title": title,
        "link": item_text(item, &["url"]),
        "description": item_text(item, &["summary_fa", "summary", "why_it_matters"]),
        "pub_date": feed_pub_date(item)
    })
}

pub(crate) fn collect_feed_entries(brief: &Value) -> Vec<Value> {
    let mut entries: Vec<Value> = Vec::new();
    if let Some(alert) = brief.get("priority_alert").filter(|v| v.is_object()) {
        entries.push(feed_entry(alert));
    }
    if let Some(cves) = brief.get("cves").and_then(|v| v.as_array()) {
        for cve in cves.iter().take(FEED_MAX_CVES) {
            entries.push(feed_entry(cve));
        }
    }
    if let Some(news) = brief.get("global_news").and_then(|v| v.as_array()) {
        for item in news.iter().take(FEED_MAX_NEWS) {
            entries.push(feed_entry(item));
        }
    }
    entries
}

pub(crate) fn build_feed_xml(brief: &Value, channel_title: &str) -> String {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<rss version=\"2.0\">\n<channel>\n");
    xml.push_str(&format!("<title>{}</title>\n", xml_escape(channel_title)));
    xml.push_str(&format!("<link>{SITE_LINK}/</link>\n"));
    xml.push_str("<description>رصد استاتیک تهدیدهای سایبری، CVEها و اخبار امنیتی</description>\n");
    xml.push_str("<language>fa</language>\n");
    xml.push_str(&format!(
        "<lastBuildDate>{}</lastBuildDate>\n",
        Utc::now().to_rfc2822()
    ));
    for entry in collect_feed_entries(brief) {
        let title = entry.get("title").and_then(|v| v.as_str()).unwrap_or("");
        let link = entry.get("link").and_then(|v| v.as_str()).unwrap_or("");
        if title.is_empty() || link.is_empty() {
            continue;
        }
        xml.push_str("<item>\n");
        xml.push_str(&format!("<title>{}</title>\n", xml_escape(title)));
        xml.push_str(&format!("<link>{}</link>\n", xml_escape(link)));
        xml.push_str(&format!(
            "<guid isPermaLink=\"false\">{}</guid>\n",
            xml_escape(link)
        ));
        let description = entry
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !description.is_empty() {
            xml.push_str(&format!(
                "<description>{}</description>\n",
                xml_escape(description)
            ));
        }
        if let Some(pub_date) = entry.get("pub_date").and_then(|v| v.as_str()) {
            xml.push_str(&format!("<pubDate>{pub_date}</pubDate>\n"));
        }
        xml.push_str("</item>\n");
    }
    xml.push_str("</channel>\n</rss>\n");
    xml
}

pub(crate) fn site_output_dir(out_path: &PathBuf) -> PathBuf {
    out_path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub(crate) fn write_feed_xml(brief: &Value, config: &Config, out_path: &PathBuf) -> Result<()> {
    let dir = site_output_dir(out_path);
    fs::create_dir_all(&dir).context("failed to create site output directory")?;
    let xml = build_feed_xml(brief, &config.site.title);
    fs::write(dir.join("feed.xml"), xml).context("failed to write site feed.xml")?;
    Ok(())
}

pub(crate) fn write_json_api(brief: &Value, out_path: &PathBuf) -> Result<()> {
    let dir = site_output_dir(out_path).join("api");
    fs::create_dir_all(&dir).context("failed to create site api directory")?;
    fs::write(dir.join("brief.json"), serde_json::to_string_pretty(brief)?)
        .context("failed to write site api brief.json")?;
    let summary = json!({
        "version": brief.get("version").cloned().unwrap_or_else(|| json!("unknown")),
        "generated_at": brief.get("generated_at").cloned().unwrap_or_else(|| json!("")),
        "date_fa": brief.get("date_fa").cloned().unwrap_or_else(|| json!("")),
        "stats": brief.get("stats").cloned().unwrap_or_else(|| json!({})),
        "executive_snapshot": brief
            .get("executive_snapshot")
            .cloned()
            .unwrap_or_else(|| json!({})),
        "priority_alert": brief.get("priority_alert").cloned().unwrap_or(Value::Null)
    });
    fs::write(
        dir.join("summary.json"),
        serde_json::to_string_pretty(&summary)?,
    )
    .context("failed to write site api summary.json")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_escape_escapes_reserved_characters() {
        assert_eq!(
            xml_escape("a<'b'>&\"d\""),
            "a&lt;&apos;b&apos;&gt;&amp;&quot;d&quot;"
        );
    }

    #[test]
    fn build_feed_xml_escapes_titles_and_links() {
        let brief = json!({
            "cves": [{
                "title": "Bug <critical> & bad",
                "url": "https://example.com/a?x=1&y=2",
                "summary_fa": "خلاصه"
            }]
        });
        let xml = build_feed_xml(&brief, "SecPath Radar");
        assert!(xml.contains("Bug &lt;critical&gt; &amp; bad"));
        assert!(xml.contains("https://example.com/a?x=1&amp;y=2"));
        assert!(!xml.contains("<critical>"));
        assert!(xml.contains("<language>fa</language>"));
    }
}
