# PowerShell Module Coverage Analysis

This document tracks the implementation coverage of the Rust `rclone-triage` against the PowerShell `rcloned` module features.

**Last Updated:** 2026-02-02

## Coverage Summary

| Category              | PowerShell Functions | Rust Coverage | Status                           |
| --------------------- | -------------------- | ------------- | -------------------------------- |
| Case Management       | 4                    | 100%          | ✅ Complete                      |
| Provider Support      | 8                    | 62%           | ⚠️ Partial                       |
| Authentication        | 16                   | 75%           | ⚠️ Partial                       |
| Mobile Auth           | 12                   | 45%           | ⚠️ Partial                       |
| Forensic Access Point | 14                   | 45%           | ⚠️ Partial                       |
| File Operations       | 8                    | 75%           | ⚠️ Partial                       |
| Forensic Logging      | 4                    | 100%          | ✅ Complete                      |
| System State          | 4                    | 100%          | ✅ Complete                      |
| rclone Operations     | 5                    | 80%           | ⚠️ Partial                       |
| UI/Menu System        | 5                    | 100%          | ✅ Complete (different approach) |
| Utilities             | 15+                  | 30%           | ⚠️ Partial                       |

**Overall Coverage: ~55%**

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

### 2. Provider Support ⚠️ PARTIAL

| PowerShell Feature         | Rust Equivalent               | Status     |
| -------------------------- | ----------------------------- | ---------- |
| `Provider` class           | `CloudProvider` enum          | ✅         |
| `Update-ProviderObjects`   | `CloudProvider::all()`        | ✅         |
| `Get-ProvidersList`        | N/A (hardcoded)               | ❌         |
| `Get-RcloneProvidersJson`  | N/A                           | ❌         |
| `Get-RcloneOAuthProviders` | N/A                           | ❌         |
| `Get-rcloneFeaturesTable`  | `CloudProvider::hash_types()` | ⚠️ Partial |
| Provider hash types        | `CloudProvider::hash_types()` | ✅         |
| Bad providers filtering    | N/A (not needed)              | ⚠️         |

#### Supported Providers

| Provider      | PowerShell | Rust | Notes       |
| ------------- | ---------- | ---- | ----------- |
| Google Drive  | ✅         | ✅   |             |
| OneDrive      | ✅         | ✅   |             |
| Dropbox       | ✅         | ✅   |             |
| Box           | ✅         | ✅   |             |
| iCloud        | ✅         | ✅   | Limited API |
| Google Photos | ✅         | ❌   | MISSING     |
| pCloud        | ✅         | ❌   | MISSING     |

**Missing:** Dynamic provider discovery from rclone, Google Photos, pCloud support.

---

### 3. Authentication ⚠️ PARTIAL

| PowerShell Function                     | Rust Equivalent                        | Status     |
| --------------------------------------- | -------------------------------------- | ---------- |
| `New-RemoteAuthentication`              | `authenticate_with_rclone()`           | ✅         |
| `Browser` class                         | `Browser` struct                       | ✅         |
| `Update-BrowserObjects`                 | `BrowserDetector::detect_all()`        | ✅         |
| Browser switching/detection             | `BrowserDetector::get_default_browser` | ✅         |
| Browser selection (TUI)                 | `BrowserSelectScreen`                  | ✅         |
| `Set-CustomOAuthCredentials`            | `CustomOAuthConfig` (credentials file) | ✅         |
| `Set-CustomOAuthCredentialsInteractive` | N/A                                    | ❌ MISSING |
| `Get-RcloneOAuthCredentials`            | N/A                                    | ❌ MISSING |
| `Start-RcloneSmartAuth` (SSO)           | `smart_authenticate()`                 | ✅         |
| `Test-RcloneSilentSSO`                  | `detect_sso_sessions()`                | ✅         |
| `Invoke-RcloneSilentProbe`              | `authenticate_with_sso()`              | ✅         |
| `Start-RcloneAuthorizeCore`             | `OAuthFlow::run()`                     | ✅         |
| `Start-RcloneAuthorizeFallback`         | N/A                                    | ❌ MISSING |
| `Get-RcloneTokenFromOutput`             | `OAuthToken::from_json()`              | ✅         |
| JWT token decoding                      | `UserInfo::from_jwt()`                 | ✅         |
| User info extraction from token         | `UserInfo::best_identifier()`          | ✅         |
| OAuth state CSRF protection             | `OAuthResult::state`                   | ✅         |

**Remaining Gaps:**

- Interactive custom OAuth credential setup

---

### 4. Mobile Device Authentication ⚠️ PARTIAL

| PowerShell Function                      | Rust Equivalent               | Status   |
| ---------------------------------------- | ----------------------------- | -------- |
| `New-MobileDeviceAuthentication`         | N/A                           | ❌       |
| `Start-DeviceCodeFlow`                   | N/A                           | ❌       |
| `Request-DeviceCode`                     | N/A                           | ❌       |
| `Request-TokenFromDeviceCode`            | N/A                           | ❌       |
| `Get-DeviceCodeConfig`                   | N/A                           | ❌       |
| `Start-MobileOAuthServer`                | N/A                           | ❌       |
| `Start-MobileOAuthCallbackServer`        | `OAuthFlow::wait_for_redirect()` | ✅    |
| `Build-OAuthAuthorizationUrl`            | `ProviderConfig::build_auth_url_with_client_id()` | ✅ |
| `Complete-OAuthTokenExchange`            | `exchange_code_for_token()`   | ✅       |
| `Get-OAuthTokenFromCode`                 | `exchange_code_for_token()`   | ✅       |
| QR Code generation (`New-ConsoleQRCode`) | `render_qr_code()`            | ✅       |
| `Get-QRCodeData`                         | N/A                           | ❌       |
| `ConvertTo-ConsoleQRCode`                | N/A                           | ❌       |

**Impact:** Mobile authentication allows capturing OAuth tokens from phones where user is already logged in - critical for forensic scenarios.

---

### 5. Forensic Access Point (WiFi Hotspot) ⚠️ PARTIAL

| PowerShell Function              | Rust Equivalent | Status |
| -------------------------------- | --------------- | ------ |
| `Start-ForensicAccessPoint`      | `start_forensic_access_point()` | ✅ |
| `Stop-ForensicAccessPoint`       | `stop_forensic_access_point()`  | ✅ |
| `Get-ForensicAccessPointStatus`  | `get_forensic_access_point_status()` | ✅ |
| `Test-NativeAPSupport`           | N/A             | ❌     |
| `Wait-ForUSBWiFiAdapter`         | N/A             | ❌     |
| `New-ForensicAPPassword`         | `generate_password()` | ✅ |
| `Set-HostedNetworkConfig`        | `start_forensic_access_point()` | ✅ |
| `Start-HostedNetwork`            | `start_forensic_access_point()` | ✅ |
| `Get-ForensicAPIPAddress`        | `start_forensic_access_point()` | ✅ |
| `Set-ForensicAPDNS` (AdGuard)    | `start_forensic_access_point()` | ✅ |
| `Restore-OriginalDNS`            | `stop_forensic_access_point()`  | ✅ |
| `Remove-ForensicAPFirewallRules` | N/A             | ❌     |
| `Start-ForensicAPTimer`          | N/A             | ❌     |
| `New-WiFiConnectionQRCode`       | `render_wifi_qr()` | ✅  |

**Impact:** Creates WiFi hotspot so mobile devices can connect to PC for authentication. Uses AdGuard DNS for security.

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

### 7. File Operations ⚠️ PARTIAL

| PowerShell Function               | Rust Equivalent                 | Status               |
| --------------------------------- | ------------------------------- | -------------------- |
| `Get-RemoteFileList`              | `list_path()`                   | ✅                   |
| `Invoke-RemoteFileListGeneration` | `list_path()`                   | ✅                   |
| `Invoke-ProcessAndWatchFile`      | N/A                             | ❌ Progress watching |
| `Invoke-CSVFileDownloader`        | `DownloadQueue`                 | ⚠️ Basic             |
| `Invoke-rcloneCopy`               | `DownloadQueue::download_one()` | ✅                   |
| `Start-DownloadQueue`             | `DownloadQueue::download_all()` | ✅                   |
| `Invoke-FileSelection` (GUI)      | N/A                             | ❌                   |
| `ConvertTo-Excel`                 | N/A                             | ❌                   |
| CSV export                        | `export_listing()`              | ✅                   |

**Missing:** Progress watching during listing generation, Excel export, GUI file selection.

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

### 10. rclone Operations ✅ MOSTLY COMPLETE

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
| `Format-Bytes`               | N/A             | ❌     |
| `Get-LocalIPAddress`         | N/A             | ❌     |
| HTTP helpers                 | N/A             | ❌     |
| `Start-SleepWithCountdown`   | N/A             | ❌     |
| `Invoke-ButtonPress` (FlaUI) | N/A             | ❌     |
| `Close-Window`               | N/A             | ❌     |

---

### 13. Report Generation ⚠️ PARTIAL

| PowerShell Feature | Rust Equivalent                | Status |
| ------------------ | ------------------------------ | ------ |
| Forensic report    | `generate_report()`            | ✅     |
| Hash in report     | Log file hash                  | ✅     |
| System diff report | `StateDiff::generate_report()` | ✅     |
| Excel report       | N/A                            | ❌     |

---

### 14. OneDrive Specific ⚠️ PARTIAL

| PowerShell Function  | Rust Equivalent | Status |
| -------------------- | --------------- | ------ |
| `Open-OneDriveVault` | `open_onedrive_vault()` | ✅ |

**Impact:** OneDrive Personal Vault requires special handling (Windows Hello, BitLocker).

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

5. **Progress Watching** - Show file count during listing generation
6. ~~**Multi-Browser Support**~~ - ✅ IMPLEMENTED via `BrowserDetector`
7. ~~**Silent/SSO Auth**~~ - ✅ IMPLEMENTED via `smart_authenticate()`
8. **Excel Export** - Law enforcement often needs Excel format

### Low Priority (Advanced Features)

9. **Mobile Device Auth** - QR code and device code flow
10. **Forensic Access Point** - WiFi hotspot for mobile auth
11. **OneDrive Vault** - Windows Hello integration
12. **rclone Mount** - View files as network share
13. **rclone Web GUI** - Alternative interface

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

| Metric            | PowerShell | Rust           |
| ----------------- | ---------- | -------------- |
| Functions/Methods | ~100+      | ~50            |
| Test coverage     | Manual     | 80+ unit tests |
| Type safety       | Limited    | Strong         |
| Error handling    | try/catch  | Result<T>      |

---

## Conclusion

The Rust implementation has a solid foundation with:

- ✅ Excellent forensic logging (hash-chained)
- ✅ Strong type safety and error handling
- ✅ Modern TUI interface
- ✅ Embedded binary (single-file deployment)
- ✅ Comprehensive test coverage

But lacks:

- ❌ Mobile device authentication
- ❌ WiFi Access Point creation
- ❌ Excel export

Recently added:

- ✅ Custom OAuth credentials (config file)
- ✅ Multi-browser authentication workflow
- ✅ Provider user info extraction (JWT)
- ✅ Advanced rclone config parsing
- ✅ Silent/SSO authentication (`smart_authenticate()`)

**Estimated effort to reach parity: 3-4 weeks of focused development**
