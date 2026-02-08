//! Provider feature table support.
//!
//! Mirrors PowerShell's Get-rcloneFeaturesTable by parsing the rclone
//! overview table and extracting Name/Hash data for a provider.

use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::providers::discovery::is_bad_provider;
use crate::providers::{CloudProvider, ProviderEntry};

const DEFAULT_FEATURES_URL: &str = "https://rclone.org/overview/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFeatureRow {
    pub name: String,
    pub hash: String,
}

static FEATURES_PAGE_CACHE: OnceLock<Arc<String>> = OnceLock::new();

/// Fetch and parse the rclone features table for a provider.
pub fn get_rclone_features_table(provider: &str) -> Result<Vec<ProviderFeatureRow>> {
    get_rclone_features_table_with_url(provider, DEFAULT_FEATURES_URL)
}

/// Fetch the rclone features table from a custom URL.
pub fn get_rclone_features_table_with_url(
    provider: &str,
    url: &str,
) -> Result<Vec<ProviderFeatureRow>> {
    let html = fetch_features_page(url)?;
    get_rclone_features_table_from_html(provider, html.as_ref())
}

/// Parse the rclone features table from HTML (used by tests).
pub fn get_rclone_features_table_from_html(
    provider: &str,
    html: &str,
) -> Result<Vec<ProviderFeatureRow>> {
    let provider_id = provider.trim().to_lowercase();
    let display_name = resolve_provider_display_name(provider);

    if is_bad_provider(&provider_id, Some(&display_name)) {
        return Ok(Vec::new());
    }

    let rows = parse_features_table(html)?;
    let filtered = rows
        .into_iter()
        .filter(|row| row.name.eq_ignore_ascii_case(&display_name))
        .collect();

    Ok(filtered)
}

/// Best-effort check whether a provider supports any hashes according to the rclone overview table.
///
/// Returns:
/// - `Ok(Some(true))` when the provider has a row and its Hash column is supported.
/// - `Ok(Some(false))` when the provider has a row and its Hash column is "Not Supported".
/// - `Ok(None)` if no matching row exists (unknown display name / table changed / provider excluded).
pub fn provider_supports_hashes(provider: &ProviderEntry) -> Result<Option<bool>> {
    if is_bad_provider(&provider.id, Some(&provider.name)) {
        return Ok(None);
    }

    let rows = get_rclone_features_table(&provider.name)?;
    if rows.is_empty() {
        return Ok(None);
    }

    Ok(Some(
        rows.iter().any(|row| row.hash != "Not Supported"),
    ))
}

fn resolve_provider_display_name(provider: &str) -> String {
    let trimmed = provider.trim();
    if let Ok(parsed) = trimmed.parse::<CloudProvider>() {
        return parsed.display_name().to_string();
    }
    trimmed.to_string()
}

fn fetch_features_page(url: &str) -> Result<Arc<String>> {
    if url == DEFAULT_FEATURES_URL {
        if let Some(html) = FEATURES_PAGE_CACHE.get() {
            return Ok(html.clone());
        }

        let html = Arc::new(fetch_features_page_uncached(url)?);
        let _ = FEATURES_PAGE_CACHE.set(html.clone());
        return Ok(html);
    }

    Ok(Arc::new(fetch_features_page_uncached(url)?))
}

fn fetch_features_page_uncached(url: &str) -> Result<String> {
    // Best-effort: keep this lookup fast so we don't stall the TUI when offline/restricted.
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(Duration::from_secs(10))
        .timeout_write(Duration::from_secs(10))
        .build();

    let response = match agent.get(url).call() {
        Ok(response) => response,
        Err(ureq::Error::Status(code, response)) => {
            let body = response.into_string().unwrap_or_default();
            bail!("Failed to fetch features page (HTTP {}): {}", code, body);
        }
        Err(err) => return Err(anyhow!(err)).context("Failed to fetch features page"),
    };

    response
        .into_string()
        .context("Failed to read features page response body")
}

fn parse_features_table(html: &str) -> Result<Vec<ProviderFeatureRow>> {
    let table = extract_first_table(html).ok_or_else(|| anyhow!("No table found in HTML"))?;
    let headers = extract_headers(&table);
    let name_idx = headers
        .iter()
        .position(|h| h.eq_ignore_ascii_case("name"))
        .ok_or_else(|| anyhow!("Features table missing Name column"))?;
    let hash_idx = headers
        .iter()
        .position(|h| h.eq_ignore_ascii_case("hash"))
        .ok_or_else(|| anyhow!("Features table missing Hash column"))?;

    let row_re = Regex::new(r"(?is)<tr[^>]*>(.*?)</tr>").unwrap();
    let td_re = Regex::new(r"(?is)<td[^>]*>(.*?)</td>").unwrap();

    let mut rows = Vec::new();
    for row_cap in row_re.captures_iter(&table) {
        let row_html = row_cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let cells: Vec<String> = td_re
            .captures_iter(row_html)
            .map(|cap| clean_cell(cap.get(1).map(|m| m.as_str()).unwrap_or("")))
            .collect();

        if cells.is_empty() {
            continue;
        }

        let name = cells.get(name_idx).cloned().unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let hash_raw = cells.get(hash_idx).cloned().unwrap_or_default();
        let hash = normalize_hash_value(&name, &hash_raw);

        rows.push(ProviderFeatureRow { name, hash });
    }

    Ok(rows)
}

fn extract_first_table(html: &str) -> Option<String> {
    let table_re = Regex::new(r"(?is)<table[^>]*>.*?</table>").ok()?;
    table_re
        .find(html)
        .map(|mat| mat.as_str().to_string())
}

fn extract_headers(table_html: &str) -> Vec<String> {
    let th_re = Regex::new(r"(?is)<th[^>]*>(.*?)</th>").unwrap();
    th_re
        .captures_iter(table_html)
        .map(|cap| clean_cell(cap.get(1).map(|m| m.as_str()).unwrap_or("")))
        .collect()
}

fn clean_cell(html: &str) -> String {
    let br_re = Regex::new(r"(?i)<br\s*/?>").unwrap();
    let mut text = br_re.replace_all(html, "\n").to_string();
    let tag_re = Regex::new(r"(?is)<[^>]+>").unwrap();
    text = tag_re.replace_all(&text, "").to_string();
    text = decode_html_entities(&text);
    let no_re = Regex::new(r"\p{No}").unwrap();
    text = no_re.replace_all(&text, "").to_string();
    let ws_re = Regex::new(r"\s+").unwrap();
    text = ws_re.replace_all(&text, " ").to_string();
    text.trim().to_string()
}

fn decode_html_entities(input: &str) -> String {
    let mut text = input
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");

    let dec_re = Regex::new(r"&#(\d+);").unwrap();
    text = dec_re
        .replace_all(&text, |caps: &regex::Captures| {
            let value = caps.get(1).and_then(|m| m.as_str().parse::<u32>().ok());
            value
                .and_then(std::char::from_u32)
                .map(|c| c.to_string())
                .unwrap_or_else(|| caps.get(0).map(|m| m.as_str()).unwrap_or("").to_string())
        })
        .to_string();

    let hex_re = Regex::new(r"&#x([0-9a-fA-F]+);").unwrap();
    text = hex_re
        .replace_all(&text, |caps: &regex::Captures| {
            let value = caps
                .get(1)
                .and_then(|m| u32::from_str_radix(m.as_str(), 16).ok());
            value
                .and_then(std::char::from_u32)
                .map(|c| c.to_string())
                .unwrap_or_else(|| caps.get(0).map(|m| m.as_str()).unwrap_or("").to_string())
        })
        .to_string();

    text
}

fn normalize_hash_value(row_name: &str, raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "-" {
        return "Not Supported".to_string();
    }

    let normalized_hash = trimmed.replace(char::is_whitespace, "").to_lowercase();
    let normalized_name = row_name.replace(char::is_whitespace, "").to_lowercase();

    if !normalized_name.is_empty() && normalized_hash == normalized_name {
        return "Not Supported".to_string();
    }

    match normalized_hash.as_str() {
        "yes" | "no" | "r" | "rw" | "r/w" | "dr" | "drw" | "drwu" | "w" => {
            "Not Supported".to_string()
        }
        _ => trimmed.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_features_table_basic() {
        let html = r#"
        <html><body>
        <table>
          <tr><th>Name</th><th>Hash</th><th>Other</th></tr>
          <tr><td>Google Drive</td><td>MD5 SHA1</td><td>x</td></tr>
          <tr><td>Local</td><td>-</td><td>x</td></tr>
          <tr><td>Example</td><td>r/w</td><td>x</td></tr>
        </table>
        </body></html>
        "#;

        let rows = parse_features_table(html).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].name, "Google Drive");
        assert_eq!(rows[0].hash, "MD5 SHA1");
        assert_eq!(rows[1].hash, "Not Supported");
        assert_eq!(rows[2].hash, "Not Supported");
    }

    #[test]
    fn test_features_table_filters_provider_and_bad() {
        let html = r#"
        <html><body>
        <table>
          <tr><th>Name</th><th>Hash</th></tr>
          <tr><td>Google Drive</td><td>md5</td></tr>
          <tr><td>Local</td><td>md5</td></tr>
        </table>
        </body></html>
        "#;

        let drive = get_rclone_features_table_from_html("drive", html).unwrap();
        assert_eq!(drive.len(), 1);
        assert_eq!(drive[0].name, "Google Drive");

        let local = get_rclone_features_table_from_html("local", html).unwrap();
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].name, "Local");

        let crypt = get_rclone_features_table_from_html("crypt", html).unwrap();
        assert!(crypt.is_empty());
    }
}
