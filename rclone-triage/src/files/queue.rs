//! CSV/XLSX download queue import

use anyhow::{bail, Context, Result};
use calamine::{open_workbook_auto, Data, Reader};
use csv::StringRecord;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct DownloadQueueEntry {
    pub path: String,
    pub size: Option<u64>,
    pub hash: Option<String>,
    pub hash_type: Option<String>,
    pub is_dir: bool,
}

pub fn read_download_queue(path: impl AsRef<Path>) -> Result<Vec<DownloadQueueEntry>> {
    let path = path.as_ref();
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "csv" => read_csv_queue(path),
        "xlsx" | "xlsm" | "xls" => read_xlsx_queue(path),
        _ => bail!("Unsupported queue file type: {:?}", path),
    }
}

fn read_csv_queue(path: &Path) -> Result<Vec<DownloadQueueEntry>> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("Failed to open CSV queue: {:?}", path))?;

    let headers = reader
        .headers()
        .context("Failed to read CSV headers")?
        .clone();
    let map = HeaderMap::new(&headers);

    let mut entries = Vec::new();
    for record in reader.records() {
        let record = record.context("Failed to read CSV record")?;
        if let Some(entry) = parse_record(&record, &map) {
            entries.push(entry);
        }
    }

    if entries.is_empty() {
        bail!("CSV queue contained no valid file entries");
    }

    Ok(entries)
}

fn read_xlsx_queue(path: &Path) -> Result<Vec<DownloadQueueEntry>> {
    let mut workbook =
        open_workbook_auto(path).with_context(|| format!("Failed to open XLSX queue: {:?}", path))?;
    let sheet_name = workbook
        .sheet_names()
        .get(0)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("XLSX queue has no sheets"))?;
    let range = workbook
        .worksheet_range(&sheet_name)
        .context("Failed to read XLSX sheet")?;
    if range.is_empty() {
        bail!("XLSX sheet was empty");
    }

    let mut rows = range.rows();
    let headers_row = rows
        .next()
        .ok_or_else(|| anyhow::anyhow!("XLSX queue missing header row"))?;
    let headers: Vec<String> = headers_row.iter().map(cell_to_string).collect();
    let map = HeaderMap::new_vec(&headers);

    let mut entries = Vec::new();
    for row in rows {
        if let Some(entry) = parse_row(row, &map) {
            entries.push(entry);
        }
    }

    if entries.is_empty() {
        bail!("XLSX queue contained no valid file entries");
    }

    Ok(entries)
}

fn parse_record(record: &StringRecord, map: &HeaderMap) -> Option<DownloadQueueEntry> {
    let path = map
        .path
        .and_then(|idx| record.get(idx))
        .or_else(|| record.get(0))
        .map(str::trim)
        .filter(|s| !s.is_empty())?
        .to_string();

    let is_dir = map
        .is_dir
        .and_then(|idx| record.get(idx))
        .map(parse_bool)
        .unwrap_or(false);
    if is_dir {
        return None;
    }

    let size = map
        .size
        .and_then(|idx| record.get(idx))
        .and_then(parse_u64);

    let hash = map
        .hash
        .and_then(|idx| record.get(idx))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let hash_type = map
        .hash_type
        .and_then(|idx| record.get(idx))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    Some(DownloadQueueEntry {
        path,
        size,
        hash,
        hash_type,
        is_dir,
    })
}

fn parse_row(row: &[Data], map: &HeaderMap) -> Option<DownloadQueueEntry> {
    let path = map
        .path
        .and_then(|idx| row.get(idx))
        .map(cell_to_string)
        .or_else(|| row.get(0).map(cell_to_string))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())?;

    let is_dir = map
        .is_dir
        .and_then(|idx| row.get(idx))
        .map(cell_to_bool)
        .unwrap_or(false);
    if is_dir {
        return None;
    }

    let size = map
        .size
        .and_then(|idx| row.get(idx))
        .and_then(cell_to_u64);

    let hash = map
        .hash
        .and_then(|idx| row.get(idx))
        .map(cell_to_string)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let hash_type = map
        .hash_type
        .and_then(|idx| row.get(idx))
        .map(cell_to_string)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    Some(DownloadQueueEntry {
        path,
        size,
        hash,
        hash_type,
        is_dir,
    })
}

fn parse_u64(value: &str) -> Option<u64> {
    value.trim().parse::<u64>().ok()
}

fn parse_bool(value: &str) -> bool {
    matches!(
        value.trim().to_lowercase().as_str(),
        "true" | "1" | "yes" | "y"
    )
}

fn cell_to_string(cell: &Data) -> String {
    match cell {
        Data::String(s) => s.clone(),
        Data::Float(f) => {
            if f.fract() == 0.0 {
                format!("{:.0}", f)
            } else {
                f.to_string()
            }
        }
        Data::Int(i) => i.to_string(),
        Data::Bool(b) => b.to_string(),
        Data::Empty => String::new(),
        _ => cell.to_string(),
    }
}

fn cell_to_u64(cell: &Data) -> Option<u64> {
    match cell {
        Data::Int(i) => (*i).try_into().ok(),
        Data::Float(f) => {
            if *f >= 0.0 {
                Some(*f as u64)
            } else {
                None
            }
        }
        Data::String(s) => parse_u64(s),
        _ => None,
    }
}

fn cell_to_bool(cell: &Data) -> bool {
    match cell {
        Data::Bool(b) => *b,
        Data::Int(i) => *i != 0,
        Data::Float(f) => *f != 0.0,
        Data::String(s) => parse_bool(s),
        _ => false,
    }
}

struct HeaderMap {
    path: Option<usize>,
    size: Option<usize>,
    hash: Option<usize>,
    hash_type: Option<usize>,
    is_dir: Option<usize>,
}

impl HeaderMap {
    fn new(headers: &StringRecord) -> Self {
        let mut map = HashMap::new();
        for (idx, header) in headers.iter().enumerate() {
            let key = normalize_header(header);
            map.insert(key, idx);
        }
        Self::from_map(&map)
    }

    fn new_vec(headers: &[String]) -> Self {
        let mut map = HashMap::new();
        for (idx, header) in headers.iter().enumerate() {
            let key = normalize_header(header);
            map.insert(key, idx);
        }
        Self::from_map(&map)
    }

    fn from_map(map: &HashMap<String, usize>) -> Self {
        let path = find_header(map, &["path", "filepath", "file"]);
        let size = find_header(map, &["size", "sizebytes", "bytes"]);
        let hash = find_header(map, &["hash", "hashifsupported"]);
        let hash_type = find_header(map, &["hashtype", "hashkind"]);
        let is_dir = find_header(map, &["isdir", "is_dir", "directory", "isdirectory"]);

        Self {
            path,
            size,
            hash,
            hash_type,
            is_dir,
        }
    }
}

fn normalize_header(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_lowercase()
}

fn find_header(map: &HashMap<String, usize>, keys: &[&str]) -> Option<usize> {
    for key in keys {
        if let Some(idx) = map.get(*key) {
            return Some(*idx);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_xlsxwriter::Workbook;
    use tempfile::tempdir;

    #[test]
    fn test_read_csv_queue() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("queue.csv");
        std::fs::write(
            &path,
            "Path,Size,IsDir,Hash,HashType\nfile.txt,12,false,abc,md5\nfolder,0,true,,\n",
        )
        .unwrap();

        let entries = read_download_queue(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "file.txt");
        assert_eq!(entries[0].size, Some(12));
        assert_eq!(entries[0].hash.as_deref(), Some("abc"));
        assert_eq!(entries[0].hash_type.as_deref(), Some("md5"));
    }

    #[test]
    fn test_read_xlsx_queue() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("queue.xlsx");

        let mut workbook = Workbook::new();
        let sheet = workbook.add_worksheet().set_name("Listing").unwrap();
        sheet.write_string(0, 0, "Path").unwrap();
        sheet.write_string(0, 1, "Size").unwrap();
        sheet.write_string(0, 2, "IsDir").unwrap();
        sheet.write_string(0, 3, "Hash").unwrap();
        sheet.write_string(0, 4, "HashType").unwrap();

        sheet.write_string(1, 0, "file.txt").unwrap();
        sheet.write_number(1, 1, 42.0).unwrap();
        sheet.write_boolean(1, 2, false).unwrap();
        sheet.write_string(1, 3, "xyz").unwrap();
        sheet.write_string(1, 4, "sha1").unwrap();

        sheet.write_string(2, 0, "folder").unwrap();
        sheet.write_number(2, 1, 0.0).unwrap();
        sheet.write_boolean(2, 2, true).unwrap();

        workbook.save(path.to_str().unwrap()).unwrap();

        let entries = read_download_queue(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "file.txt");
        assert_eq!(entries[0].size, Some(42));
        assert_eq!(entries[0].hash.as_deref(), Some("xyz"));
        assert_eq!(entries[0].hash_type.as_deref(), Some("sha1"));
    }
}
