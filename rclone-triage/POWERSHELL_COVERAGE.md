# PowerShell Module Coverage Analysis

This document tracks the implementation coverage of the Rust `rclone-triage` against the PowerShell `rcloned` module features.

**Last Updated:** 2026-02-25

## Coverage Summary

| Category              | PowerShell Functions | Rust Coverage | Status                           |
| --------------------- | -------------------- | ------------- | -------------------------------- |
| Case Management       | 4                    | 100%          | ✅ Complete                      |
| Provider Support      | 8                    | 100%          | ✅ Complete                      |
| Authentication        | 16                   | 90%           | ✅ Mostly complete               |
| Mobile Auth           | 12                   | 80%           | ✅ Mostly complete               |
| Forensic Access Point | 14                   | 85%           | ✅ Mostly complete               |
| File Operations       | 8                    | 100%          | ✅ Complete                      |
| Forensic Logging      | 4                    | 100%          | ✅ Complete                      |
| System State          | 4                    | 100%          | ✅ Complete                      |
| rclone Operations     | 5                    | 100%          | ✅ Complete                      |
| UI/Menu System        | 5                    | 100%          | ✅ Complete (different approach) |
| Utilities             | 15+                  | 70%           | ⚠️ Partial                       |

**Overall Coverage: ~80%**

---

## Detailed Feature Comparison

### 1. Case Management ✅ COMPLETE

| PowerShell Function                    | Rust Equivalent                            | Status |
| -------------------------------------- | ------------------------------------------ | ------ |
| `Get-CaseInformation`                  | `Case::new()` with default name generation | ✅     |
| `Set-CaseLogFile`                      | `ForensicLogger::new()` in case directory  | ✅     |
| `Initialize-CaseEnvironment` (private) | `create_case_directories()`                | ✅     |
| Case directory structure               | `CaseDirectories` struct                   | ✅     |

**Notes:** Rust implementation creates: `logs/`, `downloads/`, `listings/`, `config/` directories.

---

### 2. Provider Support ✅ COMPLETE

| PowerShell Feature         | Rust Equivalent                     | Status     |
| -------------------------- | ----------------------------------- | ---------- |
| `Provider` class           | `CloudProvider` enum                | ✅         |
| `Update-ProviderObjects`   | `CloudProvider::all()`              | ✅         |
| `Get-ProvidersList`        | `supported_providers_from_rclone()` | ✅         |
| `Get-RcloneProvidersJson`  | `supported_providers_from_rclone()` | ✅         |
| `Get-RcloneOAuthProviders` | `supported_providers_from_rclone()` | ✅         |
| `Get-rcloneFeaturesTable`  | `provider_supports_hashes()`        | ✅         |
| Provider hash types        | `CloudProvider::hash_types()`       | ✅         |
| Bad providers filtering    | Dynamic provider discovery          | ✅         |

**Note:** Provider list is now sourced dynamically from `rclone config providers --json`.  
Known backends use specialized flows; unknown backends use the generic rclone config flow.

---

### 3. Authentication ✅ MOSTLY COMPLETE

| PowerShell Function                     | Rust Equivalent                            | Status |
| --------------------------------------- | ------------------------------------------ | ------ |
| `New-RemoteAuthentication`              | `authenticate_with_rclone()`               | ✅     |
| `Browser` class                         | `Browser` struct                           | ✅     |
| `Update-BrowserObjects`                 | `BrowserDetector::detect_all()`            | ✅     |
| Browser switching/detection             | `BrowserDetector::get_default_browser`     | ✅     |
| Browser selection (TUI)                 | `BrowserSelectScreen`                      | ✅     |
| `Set-CustomOAuthCredentials`            | `CustomOAuthConfig` (credentials file)     | ✅     |
| `Set-CustomOAuthCredentialsInteractive` | `perform_configure_oauth_flow()` TUI       | ✅     |
| `Get-RcloneOAuthCredentials`            | In-memory token extraction (better design) | ✅     |
| `Start-RcloneSmartAuth` (SSO)           | `smart_authenticate()`                     | ✅     |
| `Test-RcloneSilentSSO`                  | `detect_sso_sessions()`                    | ✅     |
| `Invoke-RcloneSilentProbe`              | `authenticate_with_sso()`                  | ✅     |
| `Start-RcloneAuthorizeCore`             | `OAuthFlow::run()`                         | ✅     |
| `Start-RcloneAuthorizeFallback`         | `authorize_fallback()`                     | ✅     |
| `Get-RcloneTokenFromOutput`             | `OAuthToken::from_json()`                  | ✅     |
| JWT token decoding                      | `UserInfo::from_jwt()`                     | ✅     |
| User info extraction from token         | `UserInfo::best_identifier()`              | ✅     |
| OAuth state CSRF protection             | `OAuthResult::state`                       | ✅     |

---

### 4. Mobile Device Authentication ✅ MOSTLY COMPLETE

| PowerShell Function                      | Rust Equivalent                            | Status |
| ---------------------------------------- | ------------------------------------------ | ------ |
| `New-MobileDeviceAuthentication`         | `perform_mobile_auth_flow()` TUI           | ✅     |
| `Start-DeviceCodeFlow`                   | `authenticate_with_device_code()`          | ✅     |
| `Request-DeviceCode`                     | `request_device_code()`                    | ✅     |
| `Request-TokenFromDeviceCode`            | `poll_device_code_for_token()`             | ✅     |
| `Get-DeviceCodeConfig`                   | `device_code_config()`                     | ✅     |
| `Start-MobileOAuthServer`                | Generic redirect handler (better design)   | ✅     |
| `Start-MobileOAuthCallbackServer`        | `OAuthFlow::wait_for_redirect()`           | ✅     |
| `Build-OAuthAuthorizationUrl`            | `ProviderConfig::build_auth_url_with_client_id()` | ✅ |
| `Complete-OAuthTokenExchange`            | `exchange_code_for_token()`                | ✅     |
| `Get-OAuthTokenFromCode`                 | `exchange_code_for_token()`                | ✅     |
| QR Code generation (`New-ConsoleQRCode`) | `render_qr_code()`                         | ✅     |
| `Get-QRCodeData`                         | Unified into `render_qr_code()`            | ✅     |
| `ConvertTo-ConsoleQRCode`                | Unified into `render_qr_code()`            | ✅     |

**Note:** Three MobileAuthFlow options available in TUI: Redirect, Redirect+AccessPoint, DeviceCode.

---

### 5. Forensic Access Point (WiFi Hotspot) ✅ MOSTLY COMPLETE

| PowerShell Function              | Rust Equivalent                              | Status |
| -------------------------------- | -------------------------------------------- | ------ |
| `Start-ForensicAccessPoint`      | `start_forensic_access_point()`              | ✅     |
| `Stop-ForensicAccessPoint`       | `stop_forensic_access_point()`               | ✅     |
| `Get-ForensicAccessPointStatus`  | `get_forensic_access_point_status()`         | ✅     |
| `Test-NativeAPSupport`           | `test_native_ap_support()`                   | ✅     |
| `Wait-ForUSBWiFiAdapter`         | `wait_for_usb_wifi_adapter()`                | ✅     |
| `New-ForensicAPPassword`         | `generate_password()`                        | ✅     |
| `Set-HostedNetworkConfig`        | `start_forensic_access_point()`              | ✅     |
| `Start-HostedNetwork`            | `start_forensic_access_point()`              | ✅     |
| `Get-ForensicAPIPAddress`        | `start_forensic_access_point()`              | ✅     |
| `Set-ForensicAPDNS` (AdGuard)    | `start_forensic_access_point()`              | ✅     |
| `Restore-OriginalDNS`            | `stop_forensic_access_point()`               | ✅     |
| `Remove-ForensicAPFirewallRules` | `remove_firewall_rules()`                    | ✅     |
| `Start-ForensicAPTimer`          | `start_forensic_ap_timer()`                  | ✅     |
| `New-WiFiConnectionQRCode`       | `render_wifi_qr()`                           | ✅     |

**Note:** TUI flow shows real-time AP setup status via `start_forensic_access_point_with_status()` callback.
Connected client count displayed during AP flow. USB adapter auto-detection integrated.

---

### 6. Provider User Info APIs ⚠️ PARTIAL

| PowerShell Function                 | Rust Equivalent                  | Status |
| ----------------------------------- | -------------------------------- | ------ |
| `Get-ProviderUserInfo` (dispatcher) | `RemoteSection::user_info()`     | ✅     |
| `Get-GoogleDriveUserInfo`           | `UserInfo::from_jwt()` (generic) | ✅     |
| `Get-DropboxUserInfo`               | `UserInfo::from_jwt()` (generic) | ✅     |
| `Get-BoxUserInfo`                   | `UserInfo::from_jwt()` (generic) | ✅     |
| `Get-pCloudUserInfo`                | N/A (provider not supported)     | ❌     |
| `Get-MicrosoftGraphUserInfo`        | `UserInfo::from_jwt()` (generic) | ✅     |

**Note:** User info extraction now uses generic JWT parsing. Works for all providers that include identity claims in their tokens.

---

### 7. File Operations ✅ COMPLETE

| PowerShell Function               | Rust Equivalent                          | Status |
| --------------------------------- | ---------------------------------------- | ------ |
| `Get-RemoteFileList`              | `list_path()`                            | ✅     |
| `Invoke-RemoteFileListGeneration` | `list_path()`                            | ✅     |
| `Invoke-ProcessAndWatchFile`      | `list_path_with_progress()` + TUI callback | ✅   |
| `Invoke-CSVFileDownloader`        | `DownloadQueue` + `read_download_queue()`  | ✅   |
| `Invoke-rcloneCopy`               | `DownloadQueue::download_one()`          | ✅     |
| `Start-DownloadQueue`             | `DownloadQueue::download_all_with_progress()` | ✅ |
| `Invoke-FileSelection` (GUI)      | Mount + selection file import            | ✅     |
| `ConvertTo-Excel`                 | `export_listing_xlsx()`                  | ✅     |
| CSV export                        | `export_listing()`                       | ✅     |

---

### 8. Forensic Logging ✅ COMPLETE

| PowerShell Function               | Rust Equivalent         | Status |
| --------------------------------- | ----------------------- | ------ |
| `Write-Logg`                      | `ForensicLogger::log()` | ✅     |
| Hash-chained logging              | SHA256 hash chain       | ✅     |
| Log levels (INFO, WARNING, ERROR) | `LogLevel` enum         | ✅     |
| Log file verification             | `verify_integrity()`    | ✅     |

---

### 9. System State Management ✅ COMPLETE

| PowerShell Function         | Rust Equivalent                  | Status         |
| --------------------------- | -------------------------------- | -------------- |
| `Start-SystemStateCapture`  | `SystemStateSnapshot::capture()` | ✅             |
| `Restore-SystemState`       | `SystemStateSnapshot::diff()`    | ✅             |
| `Add-TrackedTemporaryFile`  | `ChangeTracker::record_file()`   | ✅             |
| `Get-SystemStateSnapshot`   | `SystemStateSnapshot` struct     | ✅             |
| Registry tracking (Windows) | Windows-specific code            | ⚠️ Conditional |

---

### 10. rclone Operations ✅ COMPLETE

| PowerShell Function                 | Rust Equivalent              | Status                |
| ----------------------------------- | ---------------------------- | --------------------- |
| `Set-rcloneLocation`                | Embedded binary              | ✅ Different approach |
| `Get-rclone` (download)             | `ExtractedBinary::extract()` | ✅ Embedded           |
| `ConvertFrom-rcloneConfig`          | `ParsedConfig::parse()`      | ✅                    |
| `New-rcloneConfig`                  | `RcloneConfig::for_case()`   | ✅                    |
| `Get-ExistingrcloneConfig`          | `RcloneConfig::parse()`      | ✅                    |
| `Start-rcloneWeb` (web GUI)         | `start_web_gui()`            | ✅                    |
| `Start-rcloneMount` (network share) | `MountManager::mount()`      | ✅                    |
| Open file explorer after mount      | `open_file_explorer()`       | ✅                    |
| `Test-RcloneOAuthConnectivity`      | `test_connectivity()`        | ✅                    |

**Missing:** None in this category.

---

### 11. UI/Menu System ✅ COMPLETE (Different Approach)

| PowerShell Feature         | Rust Equivalent                 | Status |
| -------------------------- | ------------------------------- | ------ |
| `MenuItem` class           | `AppState` enum                 | ✅     |
| `Show-Menu` (Terminal.Gui) | Ratatui TUI                     | ✅     |
| `Start-rcloned`            | `main()` with TUI               | ✅     |
| Menu structure             | `ui/screens/` modules           | ✅     |
| Provider selection form    | `ProviderSelect` state          | ✅     |
| Browser selection form     | `BrowserDetector::detect_all()` | ✅     |

**Note:** Rust uses Ratatui TUI instead of Terminal.Gui. Browser selection now supported with `authenticate_with_browser()`.

---

### 12. Utilities ⚠️ PARTIAL

| PowerShell Function          | Rust Equivalent | Status |
| ---------------------------- | --------------- | ------ |
| `Get-FileName` (file dialog) | N/A (TUI-based) | ⚠️     |
| `Format-Bytes`               | `format_bytes()`                | ✅ |
| `Get-LocalIPAddress`         | `get_local_ip_address()`        | ✅ |
| HTTP helpers                 | `http_get_json_with_retry()`    | ✅ |
| `Start-SleepWithCountdown`   | `sleep_with_countdown()`        | ✅ |
| `Invoke-ButtonPress` (FlaUI) | N/A                             | ❌ |
| `Close-Window`               | `close_window_by_title()`       | ✅ |

---

### 13. Report Generation ✅ MOSTLY COMPLETE

| PowerShell Feature | Rust Equivalent                | Status |
| ------------------ | ------------------------------ | ------ |
| Forensic report    | `generate_report()`            | ✅     |
| Hash in report     | Log file hash                  | ✅     |
| System diff report | `StateDiff::generate_report()` | ✅     |
| Excel report       | `write_report_xlsx()`          | ✅     |

---

### 14. OneDrive Specific ✅ COMPLETE

| PowerShell Function  | Rust Equivalent         | Status |
| -------------------- | ----------------------- | ------ |
| `Open-OneDriveVault` | `open_onedrive_vault()` | ✅     |

**Note:** OneDrive Personal Vault requires special handling (Windows Hello, BitLocker). Windows-only feature.

---

### 15. Cleanup ✅ COMPLETE

| PowerShell Feature | Rust Equivalent         | Status |
| ------------------ | ----------------------- | ------ |
| Temp file tracking | `Cleanup::track_file()` | ✅     |
| Cleanup on exit    | `AppGuard::drop()`      | ✅     |
| Signal handling    | `ctrlc` handler         | ✅     |

---

## Priority Implementation Recommendations

### High Priority (Core Functionality Gaps)

1. ~~**Custom OAuth Credentials**~~ - ✅ IMPLEMENTED via custom OAuth config file
2. ~~**Provider User Info APIs**~~ - ✅ IMPLEMENTED via JWT parsing
3. ~~**rclone Config Parsing**~~ - ✅ IMPLEMENTED via `ParsedConfig`
4. ~~**JWT Token Decoding**~~ - ✅ IMPLEMENTED via `UserInfo::from_jwt()`

### Medium Priority (Forensic Enhancements)

5. ~~**Progress Watching**~~ - ✅ IMPLEMENTED via `list_path_with_progress()` + TUI callback
6. ~~**Multi-Browser Support**~~ - ✅ IMPLEMENTED via `BrowserDetector`
7. ~~**Silent/SSO Auth**~~ - ✅ IMPLEMENTED via `smart_authenticate()`
8. ~~**Excel Export**~~ - ✅ IMPLEMENTED via `export_listing_xlsx()` + `write_report_xlsx()`

### Low Priority (Advanced Features)

9. ~~**Mobile Device Auth**~~ - ✅ IMPLEMENTED (Redirect, Redirect+AP, DeviceCode flows)
10. ~~**Forensic Access Point**~~ - ✅ IMPLEMENTED with TUI status callbacks + client count
11. ~~**OneDrive Vault**~~ - ✅ IMPLEMENTED (Windows-only)
12. ~~**rclone Mount**~~ - ✅ IMPLEMENTED via `MountManager`
13. ~~**rclone Web GUI**~~ - ✅ IMPLEMENTED via `start_web_gui()`

---

## Implementation Notes

### Architectural Differences

| Aspect        | PowerShell                           | Rust                            |
| ------------- | ------------------------------------ | ------------------------------- |
| rclone binary | Downloaded at runtime                | Embedded in executable          |
| TUI Framework | Terminal.Gui (.NET)                  | Ratatui (native)                |
| Browser auth  | Multiple browsers, default switching | Multiple browsers, detection    |
| Config format | INI file with JWT decoding           | INI + JWT decoding              |
| Hash chaining | N/A                                  | SHA256 hash chain per log entry |

### Code Quality Comparison

| Metric            | PowerShell | Rust            |
| ----------------- | ---------- | --------------- |
| Functions/Methods | ~100+      | ~200+           |
| Test coverage     | Manual     | 213 unit tests  |
| Type safety       | Limited    | Strong          |
| Error handling    | try/catch  | Result<T>       |

---

## Conclusion

The Rust implementation is at ~80% feature parity with:

- ✅ All core forensic workflows (auth → list → download → report)
- ✅ Excellent forensic logging (hash-chained, tamper-evident)
- ✅ Strong type safety and error handling
- ✅ Modern TUI interface with full menu system
- ✅ Embedded binary (single-file deployment)
- ✅ 213 tests (178 unit + 8 bin + 9 integration + 18 provider)
- ✅ All authentication flows (browser, SSO, device code, mobile redirect, fallback)
- ✅ Mobile auth with three flow options + QR codes
- ✅ Forensic Access Point with TUI status feedback + client count
- ✅ Interactive OAuth credential configuration via TUI
- ✅ Excel (XLSX) and CSV export
- ✅ rclone mount, web GUI, OneDrive vault

Remaining gaps vs PowerShell:

- ⚠️ pCloud user info (requires provider-specific REST API call)
- ⚠️ FlaUI button automation (not needed — users open files manually)
- ⚠️ LRU query caching (acceptable for single-session forensic tool)
- ⚠️ Animated startup logo (TUI takes full control of terminal)

These gaps are intentional design decisions where the Rust approach is better or the feature is unnecessary.
