# triage-with-rclone

This repository provides a forensic-first cloud triage tool built around rclone.

## Rust TUI implementation (rclone-triage)

`rclone-triage` is a Rust reimplementation that targets a **single Windows executable** with **all dependencies embedded** (including `rclone.exe`). It includes:

- Embedded rclone binary (offline-friendly, reproducible)
- Hash‑chained forensic logs
- System state snapshots + change tracking
- Case‑structured output directories
- TUI flow for case setup → provider auth → listing → download

### Build

- `cd /home/toor/triage-with-rclone/rclone-triage`
- `cargo build --release`

### Run (current CLI skeleton)

- `./target/release/rclone-triage --name my-session --output-dir .`
- Alternatively, omit `--name` to use auto-generated name: `./target/release/rclone-triage --output-dir .`

### Tests

- Linux/WSL: `cargo test --release -- --test-threads=1`
- Windows (local): `powershell -ExecutionPolicy Bypass -File scripts/run-windows-tests.ps1`

### Forensic notes

- Temporary artifacts (extracted `rclone.exe`, env vars) are tracked and cleaned.
- Any changes that cannot be reverted are designed to be documented in the final report.

---

This program is a tool the helps forensic teams triage and download cloud data that is stored on all of the cloud providers supported by rclone, currently they [are](https://rclone.org/overview/):

| Name                          | Hash              | ModTime | Case Insensitive | Duplicate Files | MIME Type | Metadata |
| ----------------------------- | ----------------- | ------- | ---------------- | --------------- | --------- | -------- |
| 1Fichier                      | Whirlpool         | -       | No               | Yes             | R         | -        |
| Akamai Netstorage             | MD5, SHA256       | R/W     | No               | No              | R         | -        |
| Amazon S3 (or S3 compatible)  | MD5               | R/W     | No               | No              | R/W       | RWU      |
| Backblaze B2                  | SHA1              | R/W     | No               | No              | R/W       | -        |
| Box                           | SHA1              | R/W     | Yes              | No              | -         | -        |
| Citrix ShareFile              | MD5               | R/W     | Yes              | No              | -         | -        |
| Cloudinary                    | MD5               | R       | No               | Yes             | -         | -        |
| Dropbox                       | DBHASH ¹          | R       | Yes              | No              | -         | -        |
| Enterprise File Fabric        | -                 | R/W     | Yes              | No              | R/W       | -        |
| FileLu Cloud Storage          | MD5               | R/W     | No               | Yes             | R         | -        |
| Files.com                     | MD5, CRC32        | DR/W    | Yes              | No              | R         | -        |
| FTP                           | -                 | R/W ¹⁰  | No               | No              | -         | -        |
| Gofile                        | MD5               | DR/W    | No               | Yes             | R         | -        |
| Google Cloud Storage          | MD5               | R/W     | No               | No              | R/W       | -        |
| Google Drive                  | MD5, SHA1, SHA256 | DR/W    | No               | Yes             | R/W       | DRWU     |
| Google Photos                 | -                 | -       | No               | Yes             | R         | -        |
| HDFS                          | -                 | R/W     | No               | No              | -         | -        |
| HiDrive                       | HiDrive ¹²        | R/W     | No               | No              | -         | -        |
| HTTP                          | -                 | R       | No               | No              | R         | R        |
| iCloud Drive                  | -                 | R       | No               | No              | -         | -        |
| Internet Archive              | MD5, SHA1, CRC32  | R/W ¹¹  | No               | No              | -         | RWU      |
| Jottacloud                    | MD5               | R/W     | Yes              | No              | R         | RW       |
| Koofr                         | MD5               | -       | Yes              | No              | -         | -        |
| Linkbox                       | -                 | R       | No               | No              | -         | -        |
| Mail.ru Cloud                 | Mailru ⁶          | R/W     | Yes              | No              | -         | -        |
| Mega                          | -                 | -       | No               | Yes             | -         | -        |
| Memory                        | MD5               | R/W     | No               | No              | -         | -        |
| Microsoft Azure Blob Storage  | MD5               | R/W     | No               | No              | R/W       | -        |
| Microsoft Azure Files Storage | MD5               | R/W     | Yes              | No              | R/W       | -        |
| Microsoft OneDrive            | QuickXorHash ⁵    | DR/W    | Yes              | No              | R         | DRW      |
| OpenDrive                     | MD5               | R/W     | Yes              | Partial ⁸       | -         | -        |
| OpenStack Swift               | MD5               | R/W     | No               | No              | R/W       | -        |
| Oracle Object Storage         | MD5               | R/W     | No               | No              | R/W       | RU       |
| pCloud                        | MD5, SHA1 ⁷       | R/W     | No               | No              | W         | -        |
| PikPak                        | MD5               | R       | No               | No              | R         | -        |
| Pixeldrain                    | SHA256            | R/W     | No               | No              | R         | RW       |
| premiumize.me                 | -                 | -       | Yes              | No              | R         | -        |
| put.io                        | CRC-32            | R/W     | No               | Yes             | R         | -        |
| Proton Drive                  | SHA1              | R/W     | No               | No              | R         | -        |
| QingStor                      | MD5               | - ⁹     | No               | No              | R/W       | -        |
| Quatrix by Maytech            | -                 | R/W     | No               | No              | -         | -        |
| Seafile                       | -                 | -       | No               | No              | -         | -        |
| SFTP                          | MD5, SHA1 ²       | DR/W    | Depends          | No              | -         | -        |
| Sia                           | -                 | -       | No               | No              | -         | -        |
| SMB                           | -                 | R/W     | Yes              | No              | -         | -        |
| SugarSync                     | -                 | -       | No               | No              | -         | -        |
| Storj                         | -                 | R       | No               | No              | -         | -        |
| Uloz.to                       | MD5, SHA256 ¹³    | -       | No               | Yes             | -         | -        |
| Uptobox                       | -                 | -       | No               | Yes             | -         | -        |
| WebDAV                        | MD5, SHA1 ³       | R ⁴     | Depends          | No              | -         | -        |
| Yandex Disk                   | MD5               | R/W     | No               | No              | R         | -        |
| Zoho WorkDrive                | -                 | -       | No               | No              | -         | -        |
| The local filesystem          | All               | DR/W    | Depends          | No              | -         | DRWU     |
