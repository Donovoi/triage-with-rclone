//! Browser session extraction for SSO/silent authentication
//!
//! Extracts authentication cookies and tokens from browser profiles
//! to enable re-authentication without user interaction.
//!
//! Supports:
//! - Chromium-based browsers (Chrome, Edge, Brave, etc.) - SQLite cookies + DPAPI/keyring
//! - Firefox - SQLite cookies with NSS encryption

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::browser::{Browser, BrowserType};
use crate::providers::CloudProvider;

/// Authentication session extracted from a browser
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSession {
    /// Browser this session came from
    pub browser_type: BrowserType,
    /// Provider this session is for
    pub provider: CloudProvider,
    /// Extracted cookies relevant to the provider
    pub cookies: Vec<Cookie>,
    /// User identifier if detected (email, username)
    pub user_hint: Option<String>,
    /// Whether the session appears valid/unexpired
    pub is_valid: bool,
    /// Local state key (for Chromium DPAPI decryption)
    #[serde(skip)]
    pub local_state_key: Option<Vec<u8>>,
}

/// A browser cookie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    /// Cookie name
    pub name: String,
    /// Cookie value (decrypted)
    pub value: String,
    /// Domain the cookie belongs to
    pub domain: String,
    /// Path
    pub path: String,
    /// Expiry timestamp (Unix seconds)
    pub expires: i64,
    /// Is this a secure cookie
    pub secure: bool,
    /// Is this an HTTP-only cookie
    pub http_only: bool,
}

impl Cookie {
    /// Check if the cookie is expired
    pub fn is_expired(&self) -> bool {
        if self.expires == 0 {
            return false; // Session cookie
        }
        let now = chrono::Utc::now().timestamp();
        self.expires < now
    }
}

/// Provider-specific cookie domains and names to extract
#[derive(Debug, Clone)]
pub struct ProviderCookieConfig {
    /// Domains to search for cookies
    pub domains: Vec<&'static str>,
    /// Cookie names that indicate authentication
    pub auth_cookies: Vec<&'static str>,
    /// Cookie names that contain user identity
    pub identity_cookies: Vec<&'static str>,
}

impl ProviderCookieConfig {
    /// Get cookie configuration for a provider
    pub fn for_provider(provider: CloudProvider) -> Self {
        match provider {
            CloudProvider::GoogleDrive => Self {
                domains: vec![
                    ".google.com",
                    "accounts.google.com",
                    "drive.google.com",
                    ".googleapis.com",
                ],
                auth_cookies: vec![
                    "SID",
                    "HSID",
                    "SSID",
                    "APISID",
                    "SAPISID",
                    "__Secure-1PSID",
                    "__Secure-3PSID",
                    "OSID",
                    "LSID",
                ],
                identity_cookies: vec!["GMAIL_AT", "ACCOUNT_CHOOSER"],
            },
            CloudProvider::OneDrive => Self {
                domains: vec![
                    ".microsoft.com",
                    ".live.com",
                    "login.microsoftonline.com",
                    "onedrive.live.com",
                    ".sharepoint.com",
                ],
                auth_cookies: vec![
                    "ESTSAUTH",
                    "ESTSAUTHPERSISTENT",
                    "SignInStateCookie",
                    "buid",
                    "esctx",
                    "MUID",
                ],
                identity_cookies: vec!["OIDCPartnerSessionID"],
            },
            CloudProvider::Dropbox => Self {
                domains: vec![".dropbox.com", "www.dropbox.com"],
                auth_cookies: vec!["t", "jar", "__Host-js_csrf", "locale"],
                identity_cookies: vec![],
            },
            CloudProvider::Box => Self {
                domains: vec![".box.com", "app.box.com", "account.box.com"],
                auth_cookies: vec!["box_visitor_id", "bv", "site_preference"],
                identity_cookies: vec![],
            },
            CloudProvider::ICloud => Self {
                domains: vec![".icloud.com", ".apple.com"],
                auth_cookies: vec![
                    "X-APPLE-WEBAUTH-TOKEN",
                    "X-APPLE-DS-WEB-SESSION-TOKEN",
                    "acn01",
                ],
                identity_cookies: vec![],
            },
            CloudProvider::GooglePhotos => Self {
                domains: vec![
                    ".google.com",
                    "accounts.google.com",
                    "photos.google.com",
                    ".googleapis.com",
                ],
                auth_cookies: vec![
                    "SID",
                    "HSID",
                    "SSID",
                    "APISID",
                    "SAPISID",
                    "__Secure-1PSID",
                    "__Secure-3PSID",
                    "OSID",
                    "LSID",
                ],
                identity_cookies: vec!["GMAIL_AT", "ACCOUNT_CHOOSER"],
            },
            CloudProvider::PCloud => Self {
                domains: vec![".pcloud.com", "my.pcloud.com", "api.pcloud.com"],
                auth_cookies: vec!["pcauth", "pcloud_auth", "pcid"],
                identity_cookies: vec![],
            },
            CloudProvider::Mega => Self {
                domains: vec![".mega.nz", "mega.nz", ".mega.co.nz"],
                auth_cookies: vec!["sid"],
                identity_cookies: vec![],
            },
            CloudProvider::YandexDisk => Self {
                domains: vec![".yandex.com", ".yandex.ru", "disk.yandex.com"],
                auth_cookies: vec!["Session_id", "yandexuid"],
                identity_cookies: vec![],
            },
            CloudProvider::Mailru => Self {
                domains: vec![".mail.ru", "cloud.mail.ru", "o2.mail.ru"],
                auth_cookies: vec!["Mpop", "t"],
                identity_cookies: vec![],
            },
            // All other providers use generic empty cookie config
            _ => Self {
                domains: vec![],
                auth_cookies: vec![],
                identity_cookies: vec![],
            },
        }
    }
}

/// Extracts browser sessions for authentication
pub struct SessionExtractor {
    /// Temporary directory for working with encrypted data
    temp_dir: PathBuf,
}

impl SessionExtractor {
    /// Create a new session extractor
    pub fn new() -> Result<Self> {
        let temp_dir = std::env::temp_dir().join("rclone-triage-sessions");
        std::fs::create_dir_all(&temp_dir)
            .context("Failed to create temp directory for session extraction")?;

        Ok(Self { temp_dir })
    }

    /// Extract session for a provider from a specific browser
    pub fn extract_session(
        &self,
        browser: &Browser,
        provider: CloudProvider,
    ) -> Result<BrowserSession> {
        let profile_path = browser.profile_path.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Browser {} has no profile path", browser.browser_type)
        })?;

        let config = ProviderCookieConfig::for_provider(provider);

        // Extract cookies based on browser type
        let cookies = match browser.browser_type {
            BrowserType::Chrome
            | BrowserType::ChromeBeta
            | BrowserType::Chromium
            | BrowserType::Edge
            | BrowserType::Brave
            | BrowserType::Opera
            | BrowserType::OperaGX
            | BrowserType::Vivaldi
            | BrowserType::Yandex => self.extract_chromium_cookies(profile_path, &config)?,

            BrowserType::Firefox | BrowserType::Tor => {
                self.extract_firefox_cookies(profile_path, &config)?
            }
        };

        // Check if we have the required auth cookies
        let has_auth = config
            .auth_cookies
            .iter()
            .any(|name| cookies.iter().any(|c| c.name == *name && !c.is_expired()));

        // Try to extract user hint from identity cookies
        let user_hint = self.extract_user_hint(&cookies, &config);

        Ok(BrowserSession {
            browser_type: browser.browser_type,
            provider,
            cookies,
            user_hint,
            is_valid: has_auth,
            local_state_key: None,
        })
    }

    /// Extract cookies matching a user-provided list of domains/patterns.
    ///
    /// This is a triage helper that is not tied to the built-in provider enum.
    pub fn extract_domain_cookies(
        &self,
        browser: &Browser,
        domains: &[String],
    ) -> Result<Vec<Cookie>> {
        let profile_path = browser.profile_path.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Browser {} has no profile path", browser.browser_type)
        })?;

        let domain_patterns = to_like_patterns(domains.iter());
        if domain_patterns.is_empty() {
            bail!("No cookie domain patterns provided");
        }

        match browser.browser_type {
            BrowserType::Chrome
            | BrowserType::ChromeBeta
            | BrowserType::Chromium
            | BrowserType::Edge
            | BrowserType::Brave
            | BrowserType::Opera
            | BrowserType::OperaGX
            | BrowserType::Vivaldi
            | BrowserType::Yandex => {
                self.extract_chromium_cookies_by_patterns(profile_path, &domain_patterns)
            }

            BrowserType::Firefox | BrowserType::Tor => {
                self.extract_firefox_cookies_by_patterns(profile_path, &domain_patterns)
            }
        }
    }

    fn unique_temp_db_path(&self, prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        self.temp_dir
            .join(format!("{}_{}_{}.db", prefix, std::process::id(), nanos))
    }

    /// Extract cookies from Chromium-based browser
    fn extract_chromium_cookies(
        &self,
        profile_path: &Path,
        config: &ProviderCookieConfig,
    ) -> Result<Vec<Cookie>> {
        let domain_patterns = to_like_patterns(config.domains.iter().copied());
        if domain_patterns.is_empty() {
            bail!("Provider cookie domains were empty");
        }
        self.extract_chromium_cookies_by_patterns(profile_path, &domain_patterns)
    }

    fn extract_chromium_cookies_by_patterns(
        &self,
        profile_path: &Path,
        domain_patterns: &[String],
    ) -> Result<Vec<Cookie>> {
        let cookies_path = profile_path.join("Cookies");

        if !cookies_path.exists() {
            // Try Network/Cookies for newer Chrome versions
            let network_cookies = profile_path.join("Network").join("Cookies");
            if !network_cookies.exists() {
                bail!(
                    "Cookies database not found at {:?} or {:?}",
                    cookies_path,
                    network_cookies
                );
            }
            return self.read_chromium_cookies_db(&network_cookies, domain_patterns);
        }

        self.read_chromium_cookies_db(&cookies_path, domain_patterns)
    }

    /// Read Chromium cookies database
    fn read_chromium_cookies_db(
        &self,
        cookies_path: &Path,
        domain_patterns: &[String],
    ) -> Result<Vec<Cookie>> {
        if domain_patterns.is_empty() {
            bail!("No cookie domain patterns provided");
        }

        #[cfg(windows)]
        let local_state_key: Option<Vec<u8>> = {
            // Derive the profile directory from the cookies DB location.
            //
            // Common layouts:
            // - <profile>/Cookies
            // - <profile>/Network/Cookies
            let profile_dir = cookies_path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("Invalid cookies path: {:?}", cookies_path))?;
            let profile_dir = if profile_dir.file_name() == Some(std::ffi::OsStr::new("Network")) {
                profile_dir.parent().unwrap_or(profile_dir)
            } else {
                profile_dir
            };

            self.get_chromium_local_state_key(profile_dir).ok()
        };

        #[cfg(not(windows))]
        let local_state_key: Option<Vec<u8>> = None;

        // Copy the database to temp to avoid locking issues
        let temp_db = self.unique_temp_db_path("chromium_cookies");
        std::fs::copy(cookies_path, &temp_db)
            .with_context(|| format!("Failed to copy cookies db from {:?}", cookies_path))?;

        // Open SQLite database
        let conn =
            rusqlite::Connection::open(&temp_db).context("Failed to open cookies database")?;

        let mut cookies = Vec::new();

        // Query cookies - Chromium uses different schema versions
        let where_sql = build_like_where_clause("host_key", domain_patterns.len());
        let query = format!(
            r#"
            SELECT name, encrypted_value, host_key, path, 
                   expires_utc, is_secure, is_httponly
            FROM cookies 
            WHERE {}
        "#,
            where_sql
        );

        let mut stmt = conn.prepare(&query).context("Failed to prepare SQL")?;

        let rows = stmt
            .query_map(rusqlite::params_from_iter(domain_patterns.iter()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, bool>(5)?,
                    row.get::<_, bool>(6)?,
                ))
            })
            .context("Failed to query cookies")?;

        for (name, encrypted_value, host_key, path, expires_utc, is_secure, is_httponly) in
            rows.flatten()
        {
            // Decrypt the cookie value
            let value = self
                .decrypt_chromium_cookie(&encrypted_value, local_state_key.as_deref())
                .unwrap_or_default();

            // Convert Chrome timestamp (microseconds since 1601) to Unix timestamp
            let expires = if expires_utc > 0 {
                // Chrome epoch is 1601-01-01, Unix epoch is 1970-01-01
                // Difference is 11644473600 seconds
                (expires_utc / 1_000_000) - 11644473600
            } else {
                0
            };

            cookies.push(Cookie {
                name,
                value,
                domain: host_key,
                path,
                expires,
                secure: is_secure,
                http_only: is_httponly,
            });
        }

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_db);

        Ok(cookies)
    }

    /// Decrypt Chromium cookie value
    fn decrypt_chromium_cookie(
        &self,
        encrypted: &[u8],
        local_state_key: Option<&[u8]>,
    ) -> Result<String> {
        #[cfg(not(windows))]
        let _ = local_state_key;

        if encrypted.is_empty() {
            return Ok(String::new());
        }

        // Check for v10/v11 encryption prefix
        if encrypted.starts_with(b"v10") || encrypted.starts_with(b"v11") {
            // AES-256-GCM encrypted with DPAPI-protected key
            #[cfg(windows)]
            {
                return self.decrypt_chromium_v10_windows(&encrypted[3..], local_state_key);
            }

            #[cfg(target_os = "linux")]
            {
                return self.decrypt_chromium_v10_linux(&encrypted[3..]);
            }

            #[cfg(target_os = "macos")]
            {
                return self.decrypt_chromium_v10_macos(&encrypted[3..]);
            }
        }

        // Older format - try DPAPI directly on Windows
        #[cfg(windows)]
        {
            self.decrypt_dpapi(encrypted)
        }

        // On non-Windows, assume plaintext for old format
        #[cfg(not(windows))]
        {
            Ok(String::from_utf8_lossy(encrypted).to_string())
        }
    }

    /// Decrypt v10/v11 Chromium cookie on Windows using DPAPI
    #[cfg(windows)]
    fn decrypt_chromium_v10_windows(
        &self,
        encrypted: &[u8],
        local_state_key: Option<&[u8]>,
    ) -> Result<String> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        // The encrypted data format is: nonce (12 bytes) + ciphertext + tag (16 bytes)
        if encrypted.len() < 28 {
            bail!("Encrypted data too short");
        }

        let key = local_state_key.ok_or_else(|| {
            anyhow::anyhow!("Missing Chromium Local State key (cookie values may be blank)")
        })?;

        if key.len() != 32 {
            bail!("Unexpected Chromium Local State key length: {}", key.len());
        }

        let nonce_bytes = &encrypted[..12];
        let ciphertext = &encrypted[12..];

        let cipher = Aes256Gcm::new_from_slice(key).context("Failed to create cipher")?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("Failed to decrypt Chromium cookie"))?;
        Ok(String::from_utf8_lossy(&plaintext).to_string())
    }

    /// Decrypt using Windows DPAPI
    #[cfg(windows)]
    fn decrypt_dpapi(&self, encrypted: &[u8]) -> Result<String> {
        let decrypted = self.dpapi_decrypt_bytes(encrypted)?;
        Ok(String::from_utf8_lossy(&decrypted).to_string())
    }

    #[cfg(windows)]
    fn dpapi_decrypt_bytes(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::Security::Cryptography::{
            CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        };

        unsafe {
            let input = CRYPT_INTEGER_BLOB {
                cbData: encrypted.len() as u32,
                pbData: encrypted.as_ptr() as *mut u8,
            };
            let mut output = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };

            let result = CryptUnprotectData(
                &input,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            );

            if result.is_ok() && !output.pbData.is_null() {
                let decrypted =
                    std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
                let _ = LocalFree(Some(HLOCAL(output.pbData as _)));
                Ok(decrypted)
            } else {
                bail!("DPAPI decryption failed");
            }
        }
    }

    #[cfg(windows)]
    fn get_chromium_local_state_key(&self, profile_dir: &Path) -> Result<Vec<u8>> {
        let mut candidates = Vec::new();
        candidates.push(profile_dir.join("Local State"));
        if let Some(parent) = profile_dir.parent() {
            candidates.push(parent.join("Local State"));
            if let Some(grand) = parent.parent() {
                candidates.push(grand.join("Local State"));
            }
        }

        let local_state_path = candidates.into_iter().find(|p| p.exists()).ok_or_else(|| {
            anyhow::anyhow!("Chromium Local State file not found near {:?}", profile_dir)
        })?;

        let contents = std::fs::read_to_string(&local_state_path)
            .with_context(|| format!("Failed to read Local State from {:?}", local_state_path))?;

        let json: serde_json::Value = serde_json::from_str(&contents).with_context(|| {
            format!("Failed to parse Local State JSON at {:?}", local_state_path)
        })?;

        let enc_key_b64 = json
            .get("os_crypt")
            .and_then(|v| v.get("encrypted_key"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Local State missing os_crypt.encrypted_key at {:?}",
                    local_state_path
                )
            })?;

        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, enc_key_b64)
                .context("Failed to base64-decode Local State encrypted key")?;

        let dpapi_blob = decoded.strip_prefix(b"DPAPI").unwrap_or(decoded.as_slice());

        self.dpapi_decrypt_bytes(dpapi_blob)
            .context("Failed to DPAPI-decrypt Local State key")
    }

    /// Decrypt v10/v11 Chromium cookie on Linux
    #[cfg(target_os = "linux")]
    fn decrypt_chromium_v10_linux(&self, encrypted: &[u8]) -> Result<String> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        // Linux uses a hardcoded key derived from "peanuts" or from Secret Service
        // Default key for Chrome on Linux when not using keyring
        let default_password = b"peanuts";

        // Derive key using PBKDF2
        let salt = b"saltysalt";
        let iterations = 1;

        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(default_password, salt, iterations, &mut key);

        if encrypted.len() < 28 {
            bail!("Encrypted data too short");
        }

        let nonce_bytes = &encrypted[..12];
        let ciphertext = &encrypted[12..];

        let cipher = Aes256Gcm::new_from_slice(&key).context("Failed to create cipher")?;
        let nonce = Nonce::from_slice(nonce_bytes);

        match cipher.decrypt(nonce, ciphertext) {
            Ok(plaintext) => Ok(String::from_utf8_lossy(&plaintext).to_string()),
            Err(_) => {
                // Try with Secret Service key if available
                tracing::debug!("Default key failed, would try Secret Service");
                Ok(String::new())
            }
        }
    }

    /// Decrypt v10/v11 Chromium cookie on macOS
    #[cfg(target_os = "macos")]
    fn decrypt_chromium_v10_macos(&self, encrypted: &[u8]) -> Result<String> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        // macOS uses Keychain - need to read "Chrome Safe Storage" key
        // For now, return empty
        tracing::debug!("macOS cookie decryption not fully implemented");
        Ok(String::new())
    }

    /// Extract cookies from Firefox browser
    fn extract_firefox_cookies(
        &self,
        profile_path: &Path,
        config: &ProviderCookieConfig,
    ) -> Result<Vec<Cookie>> {
        let domain_patterns = to_like_patterns(config.domains.iter().copied());
        if domain_patterns.is_empty() {
            bail!("Provider cookie domains were empty");
        }
        self.extract_firefox_cookies_by_patterns(profile_path, &domain_patterns)
    }

    fn extract_firefox_cookies_by_patterns(
        &self,
        profile_path: &Path,
        domain_patterns: &[String],
    ) -> Result<Vec<Cookie>> {
        // Firefox stores each profile in a subdirectory with random name
        // profile_path might be the Profiles directory or a specific profile

        let cookies_path = if profile_path.join("cookies.sqlite").exists() {
            profile_path.join("cookies.sqlite")
        } else {
            // Search for profile directories
            let mut found_path = None;
            if let Ok(entries) = std::fs::read_dir(profile_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        let cookies = path.join("cookies.sqlite");
                        if cookies.exists() {
                            found_path = Some(cookies);
                            break;
                        }
                    }
                }
            }
            found_path.ok_or_else(|| anyhow::anyhow!("Firefox cookies.sqlite not found"))?
        };

        // Copy to temp to avoid locking
        let temp_db = self.unique_temp_db_path("firefox_cookies");
        std::fs::copy(&cookies_path, &temp_db)?;

        let conn = rusqlite::Connection::open(&temp_db)?;

        let mut cookies = Vec::new();

        // Firefox cookies are not encrypted (only the passwords are)
        let where_sql = build_like_where_clause("host", domain_patterns.len());
        let query = format!(
            r#"
            SELECT name, value, host, path, expiry, isSecure, isHttpOnly
            FROM moz_cookies
            WHERE {}
        "#,
            where_sql
        );

        let mut stmt = conn.prepare(&query)?;

        let rows = stmt.query_map(rusqlite::params_from_iter(domain_patterns.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i32>(5)?,
                row.get::<_, i32>(6)?,
            ))
        })?;

        for row in rows.flatten() {
            let (name, value, host, path, expiry, is_secure, is_http_only) = row;
            cookies.push(Cookie {
                name,
                value,
                domain: host,
                path,
                expires: expiry,
                secure: is_secure != 0,
                http_only: is_http_only != 0,
            });
        }

        let _ = std::fs::remove_file(&temp_db);

        Ok(cookies)
    }

    /// Try to extract user hint from cookies
    fn extract_user_hint(
        &self,
        cookies: &[Cookie],
        config: &ProviderCookieConfig,
    ) -> Option<String> {
        // Look for identity cookies
        for cookie_name in &config.identity_cookies {
            if let Some(cookie) = cookies.iter().find(|c| c.name == *cookie_name) {
                // Try to extract email or username from cookie value
                if let Some(email) = Self::extract_email_from_value(&cookie.value) {
                    return Some(email);
                }
            }
        }

        // For Google, try to decode ACCOUNT_CHOOSER cookie
        if let Some(account_chooser) = cookies.iter().find(|c| c.name == "ACCOUNT_CHOOSER") {
            if let Some(email) = Self::parse_google_account_chooser(&account_chooser.value) {
                return Some(email);
            }
        }

        None
    }

    /// Extract email from a cookie value
    fn extract_email_from_value(value: &str) -> Option<String> {
        // Simple email regex
        let email_regex =
            regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").ok()?;
        email_regex.find(value).map(|m| m.as_str().to_string())
    }

    /// Parse Google ACCOUNT_CHOOSER cookie
    fn parse_google_account_chooser(value: &str) -> Option<String> {
        // Google ACCOUNT_CHOOSER is base64 encoded and contains email addresses
        // Format varies, try to extract email
        if let Ok(decoded) =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
        {
            let text = String::from_utf8_lossy(&decoded);
            return Self::extract_email_from_value(&text);
        }
        Self::extract_email_from_value(value)
    }

    /// Extract sessions from all installed browsers for a provider
    pub fn extract_all_sessions(&self, provider: CloudProvider) -> Vec<BrowserSession> {
        let browsers = super::browser::BrowserDetector::detect_all();
        let mut sessions = Vec::new();

        for browser in browsers {
            match self.extract_session(&browser, provider) {
                Ok(session) if session.is_valid => {
                    tracing::info!(
                        "Found valid {} session in {}",
                        provider,
                        browser.display_name()
                    );
                    sessions.push(session);
                }
                Ok(_) => {
                    tracing::debug!(
                        "No valid {} session in {}",
                        provider,
                        browser.display_name()
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        "Failed to extract {} session from {}: {}",
                        provider,
                        browser.display_name(),
                        e
                    );
                }
            }
        }

        sessions
    }
}

fn domain_to_like_pattern(domain: &str) -> Option<String> {
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut value = trimmed.trim_start_matches('.').to_string();
    if value.is_empty() {
        return None;
    }
    if value.contains('*') {
        value = value.replace('*', "%");
    }

    // If caller passed an explicit LIKE pattern, use it as-is.
    if value.contains('%') || value.contains('_') {
        return Some(value);
    }

    Some(format!("%{}%", value))
}

fn to_like_patterns<I, S>(domains: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    domains
        .into_iter()
        .filter_map(|d| domain_to_like_pattern(d.as_ref()))
        .collect()
}

fn build_like_where_clause(column: &str, count: usize) -> String {
    let mut parts = Vec::with_capacity(count.max(1));
    for i in 0..count {
        parts.push(format!("{} LIKE ?{}", column, i + 1));
    }
    parts.join(" OR ")
}

impl Default for SessionExtractor {
    fn default() -> Self {
        Self::new().expect("Failed to create session extractor")
    }
}

/// Check if a browser has a valid session for a provider
pub fn has_valid_session(browser: &Browser, provider: CloudProvider) -> bool {
    if let Ok(extractor) = SessionExtractor::new() {
        if let Ok(session) = extractor.extract_session(browser, provider) {
            return session.is_valid;
        }
    }
    false
}

/// Get browsers with valid sessions for a provider
pub fn browsers_with_sessions(provider: CloudProvider) -> Vec<(Browser, BrowserSession)> {
    let extractor = match SessionExtractor::new() {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let browsers = super::browser::BrowserDetector::detect_all();
    let mut results = Vec::new();

    for browser in browsers {
        if let Ok(session) = extractor.extract_session(&browser, provider) {
            if session.is_valid {
                results.push((browser, session));
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_cookie_config() {
        let config = ProviderCookieConfig::for_provider(CloudProvider::GoogleDrive);
        assert!(!config.domains.is_empty());
        assert!(config.domains.iter().any(|d| d.contains("google")));
        assert!(!config.auth_cookies.is_empty());
    }

    #[test]
    fn test_cookie_expiry() {
        let expired = Cookie {
            name: "test".to_string(),
            value: "value".to_string(),
            domain: ".example.com".to_string(),
            path: "/".to_string(),
            expires: 1000000000, // 2001
            secure: true,
            http_only: false,
        };
        assert!(expired.is_expired());

        let session_cookie = Cookie {
            name: "session".to_string(),
            value: "value".to_string(),
            domain: ".example.com".to_string(),
            path: "/".to_string(),
            expires: 0, // Session cookie
            secure: true,
            http_only: false,
        };
        assert!(!session_cookie.is_expired());

        let future = Cookie {
            name: "future".to_string(),
            value: "value".to_string(),
            domain: ".example.com".to_string(),
            path: "/".to_string(),
            expires: 4102444800, // 2100
            secure: true,
            http_only: false,
        };
        assert!(!future.is_expired());
    }

    #[test]
    fn test_extract_email() {
        let email = SessionExtractor::extract_email_from_value("user test@example.com more text");
        assert_eq!(email, Some("test@example.com".to_string()));

        let no_email = SessionExtractor::extract_email_from_value("no email here");
        assert_eq!(no_email, None);
    }

    #[test]
    fn test_session_extractor_creation() {
        let extractor = SessionExtractor::new();
        assert!(extractor.is_ok());
    }
}
