use anyhow::{bail, Result};
use chrono::Local;
use ratatui::Terminal;
use serde::Serialize;
use std::path::PathBuf;

use crate::providers::CloudProvider;
use crate::rclone::RcloneConfig;
use crate::ui::prompt::prompt_text_in_tui;
use crate::ui::App;
use crate::utils::open_file_dialog;

pub(crate) fn perform_show_oauth_credentials(app: &mut App) -> Result<()> {
    let mut selected_path: Option<PathBuf> = None;

    if cfg!(windows) {
        let initial_dir = app.forensics.directories.as_ref().map(|d| d.config.as_path());
        match open_file_dialog(
            Some("Select rclone config file"),
            initial_dir,
            Some("rclone.conf (*.conf)|*.conf|All Files (*.*)|*.*"),
        ) {
            Ok(Some(path)) => selected_path = Some(path),
            Ok(None) => {
                app.menu_status = "File selection cancelled.".to_string();
                return Ok(());
            }
            Err(e) => {
                app.menu_status = format!("File dialog failed: {}", e);
                return Ok(());
            }
        }
    } else {
        if let Ok(path) = std::env::var("RCLONE_CONFIG") {
            if !path.trim().is_empty() {
                selected_path = Some(PathBuf::from(path));
            }
        }
        if selected_path.is_none() {
            if let Some(config_dir) = dirs::config_dir() {
                let default_path = config_dir.join("rclone").join("rclone.conf");
                if default_path.exists() {
                    selected_path = Some(default_path);
                }
            }
        }
    }

    let config_path = match selected_path {
        Some(path) => path,
        None => {
            app.menu_status =
                "No rclone config selected. Set RCLONE_CONFIG or run on Windows for file picker."
                    .to_string();
            return Ok(());
        }
    };

    if !config_path.exists() {
        app.menu_status = format!("Config file not found: {:?}", config_path);
        return Ok(());
    }

    let config = RcloneConfig::open_existing(&config_path)?;
    let parsed = config.parse()?;

    let mut lines = Vec::new();
    lines.push("OAuth Credentials".to_string());
    lines.push(format!("Config: {:?}", config_path));
    lines.push(String::new());

    if parsed.remotes.is_empty() {
        lines.push("No remotes found in config.".to_string());
    } else {
        for remote in parsed.remotes.iter() {
            let creds = config.get_oauth_credentials(&remote.name)?;
            lines.push(format!("Remote: {}", creds.remote_name));
            lines.push(format!(
                "Client ID: {}",
                creds.client_id.as_deref().unwrap_or("<none>")
            ));
            lines.push(format!(
                "Client Secret: {}",
                creds.client_secret.as_deref().unwrap_or("<none>")
            ));
            lines.push(format!("Has Client ID: {}", creds.has_client_id));
            lines.push(format!("Has Client Secret: {}", creds.has_client_secret));
            lines.push(format!(
                "Custom Credentials: {}",
                creds.is_using_custom_credentials
            ));
            lines.push(format!(
                "Using Default rclone Credentials: {}",
                creds.using_default_rclone_credentials
            ));
            lines.push(String::new());
        }
    }

    app.download.report_lines = lines;
    app.state = crate::ui::AppState::OAuthCredentials;
    Ok(())
}

#[derive(Debug, Serialize)]
struct ExportedBrowserSessions {
    tool: &'static str,
    version: &'static str,
    captured_at: String,
    sessions: Vec<ExportedBrowserSession>,
    errors: Vec<ExportedBrowserSessionError>,
}

#[derive(Debug, Serialize)]
struct ExportedBrowserSession {
    provider_id: String,
    provider_name: String,
    browser_type: crate::providers::browser::BrowserType,
    browser_name: String,
    browser_profile_path: Option<PathBuf>,
    browser_executable_path: Option<PathBuf>,
    browser_is_default: bool,
    is_valid: bool,
    user_hint: Option<String>,
    cookies: Vec<crate::providers::session::Cookie>,
}

#[derive(Debug, Serialize)]
struct ExportedBrowserSessionError {
    provider_id: String,
    provider_name: String,
    browser_type: crate::providers::browser::BrowserType,
    browser_name: String,
    error: String,
}

pub(crate) fn perform_export_browser_sessions(app: &mut App) -> Result<()> {
    if app.forensics.case.is_none() || app.forensics.directories.is_none() {
        let output_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        app.init_case(output_dir)?;
    }

    let dirs = match app.forensics.directories.as_ref() {
        Some(d) => d,
        None => bail!("Case directories not initialized"),
    };

    let ts = Local::now().format("%Y%m%d-%H%M%S").to_string();
    let out_path = dirs.listings.join(format!("browser_sessions_{}.json", ts));

    let extractor = crate::providers::session::SessionExtractor::new()?;
    let browsers = crate::providers::browser::BrowserDetector::detect_all();

    let mut sessions = Vec::new();
    let mut errors = Vec::new();

    for provider in CloudProvider::all() {
        for browser in &browsers {
            match extractor.extract_session(browser, *provider) {
                Ok(session) => {
                    if session.cookies.is_empty() {
                        continue;
                    }
                    sessions.push(ExportedBrowserSession {
                        provider_id: provider.rclone_type().to_string(),
                        provider_name: provider.display_name().to_string(),
                        browser_type: browser.browser_type,
                        browser_name: browser.display_name().to_string(),
                        browser_profile_path: browser.profile_path.clone(),
                        browser_executable_path: browser.executable_path.clone(),
                        browser_is_default: browser.is_default,
                        is_valid: session.is_valid,
                        user_hint: session.user_hint.clone(),
                        cookies: session.cookies.clone(),
                    });
                }
                Err(e) => {
                    errors.push(ExportedBrowserSessionError {
                        provider_id: provider.rclone_type().to_string(),
                        provider_name: provider.display_name().to_string(),
                        browser_type: browser.browser_type,
                        browser_name: browser.display_name().to_string(),
                        error: e.to_string(),
                    });
                }
            }
        }
    }

    let payload = ExportedBrowserSessions {
        tool: "rclone-triage",
        version: env!("CARGO_PKG_VERSION"),
        captured_at: Local::now().to_rfc3339(),
        sessions,
        errors,
    };

    let json = serde_json::to_string_pretty(&payload)?;
    std::fs::write(&out_path, json)?;

    app.track_file(&out_path, "Exported browser session cookies");
    app.log_info(format!("Exported browser sessions to {:?}", out_path));
    app.menu_status = format!(
        "Exported {} session(s) to {:?}",
        payload.sessions.len(),
        out_path
    );

    Ok(())
}

#[derive(Debug, Serialize)]
struct ExportedDomainCookies {
    tool: &'static str,
    version: &'static str,
    captured_at: String,
    domain_patterns: Vec<String>,
    results: Vec<ExportedDomainCookiesBrowser>,
    errors: Vec<ExportedDomainCookiesError>,
}

#[derive(Debug, Serialize)]
struct ExportedDomainCookiesBrowser {
    browser_type: crate::providers::browser::BrowserType,
    browser_name: String,
    browser_profile_path: Option<PathBuf>,
    browser_executable_path: Option<PathBuf>,
    browser_is_default: bool,
    cookies: Vec<crate::providers::session::Cookie>,
}

#[derive(Debug, Serialize)]
struct ExportedDomainCookiesError {
    browser_type: crate::providers::browser::BrowserType,
    browser_name: String,
    error: String,
}

fn parse_domain_patterns(raw: &str) -> Vec<String> {
    raw.split([',', '\n', '\r', ';'])
        .flat_map(|chunk| chunk.split_whitespace())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

pub(crate) fn perform_export_domain_cookies<B: ratatui::backend::Backend>(
    app: &mut App,
    terminal: &mut Terminal<B>,
) -> Result<()> {
    if app.forensics.case.is_none() || app.forensics.directories.is_none() {
        let output_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        app.init_case(output_dir)?;
    }

    let patterns = std::env::var("RCLONE_TRIAGE_COOKIE_DOMAINS")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|s| parse_domain_patterns(&s))
        .unwrap_or_default();

    let domain_patterns = if !patterns.is_empty() {
        patterns
    } else {
        let Some(raw) = prompt_text_in_tui(
            app,
            terminal,
            "Cookie Domain Patterns",
            "Enter cookie domain patterns (comma-separated; '*' allowed).",
        )?
        else {
            app.menu_status = "Cancelled domain cookie export.".to_string();
            return Ok(());
        };
        let parsed = parse_domain_patterns(&raw);
        if parsed.is_empty() {
            app.menu_status = "Cancelled domain cookie export (no patterns).".to_string();
            return Ok(());
        }
        parsed
    };

    let listings_dir = app
        .forensics.directories
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Case directories not initialized"))?
        .listings
        .clone();

    let ts = Local::now().format("%Y%m%d-%H%M%S").to_string();
    let out_path = listings_dir.join(format!("domain_cookies_{}.json", ts));

    let extractor = crate::providers::session::SessionExtractor::new()?;
    let browsers = crate::providers::browser::BrowserDetector::detect_all();

    let mut results = Vec::new();
    let mut errors = Vec::new();

    for browser in &browsers {
        match extractor.extract_domain_cookies(browser, &domain_patterns) {
            Ok(cookies) => {
                if cookies.is_empty() {
                    continue;
                }
                results.push(ExportedDomainCookiesBrowser {
                    browser_type: browser.browser_type,
                    browser_name: browser.display_name().to_string(),
                    browser_profile_path: browser.profile_path.clone(),
                    browser_executable_path: browser.executable_path.clone(),
                    browser_is_default: browser.is_default,
                    cookies,
                });
            }
            Err(e) => {
                errors.push(ExportedDomainCookiesError {
                    browser_type: browser.browser_type,
                    browser_name: browser.display_name().to_string(),
                    error: e.to_string(),
                });
            }
        }
    }

    let payload = ExportedDomainCookies {
        tool: "rclone-triage",
        version: env!("CARGO_PKG_VERSION"),
        captured_at: Local::now().to_rfc3339(),
        domain_patterns: domain_patterns.clone(),
        results,
        errors,
    };

    let json = serde_json::to_string_pretty(&payload)?;
    std::fs::write(&out_path, json)?;

    app.track_file(&out_path, "Exported domain cookies");
    app.log_info(format!("Exported domain cookies to {:?}", out_path));
    app.menu_status = format!(
        "Exported {} cookie set(s) for {} pattern(s) to {:?}",
        payload.results.len(),
        payload.domain_patterns.len(),
        out_path
    );

    Ok(())
}

