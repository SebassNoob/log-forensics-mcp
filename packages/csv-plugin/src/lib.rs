use csv::{Reader, ReaderBuilder, StringRecord};
use grep_matcher::Matcher;
use grep_regex::RegexMatcherBuilder;
use napi::{Error, Result};
use napi_derive::napi;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use utils::{blocking, iso8601};

#[napi]
#[derive(Default)]
pub struct CsvPlugin {}

#[napi(object)]
pub struct FileStat {
    pub format: String,
    pub size_bytes: i64,
    pub modified_at: String,
    pub created_at: String,
    pub metadata: HashMap<String, Value>,
}

#[napi]
#[derive(Default)]
pub struct CsvTools {}

#[napi]
impl CsvPlugin {
    #[napi(constructor)]
    pub fn new() -> Self {
        CsvPlugin {}
    }

    #[napi(getter)]
    pub fn name(&self) -> String {
        "csv-plugin".to_string()
    }

    #[napi(getter)]
    pub fn description(&self) -> String {
        "File system access to delimited text files (csv, tsv).".to_string()
    }

    #[napi]
    pub fn identify(&self, file_path: String) -> bool {
        let extension = Path::new(&file_path).extension();
        extension == Some("csv".as_ref()) || extension == Some("tsv".as_ref())
    }

    #[napi(getter)]
    pub fn tools(&self) -> CsvTools {
        CsvTools {}
    }
}

#[napi]
impl CsvTools {
    #[napi]
    pub async fn search(&self, file_path: String, search_term: String) -> Result<Vec<String>> {
        if search_term.trim().is_empty() {
            return Err(Error::from_reason("search_term must not be empty"));
        }

        blocking(move || {
            let matcher = RegexMatcherBuilder::new()
                .fixed_strings(true)
                .case_smart(true)
                .build(&search_term)
                .map_err(|e| Error::from_reason(format!("Invalid search_term: {e}")))?;
            let mut reader = open(&file_path)?;
            let headers = headers(&mut reader, &file_path)?;

            Ok(reader
                .records()
                .flatten()
                .enumerate()
                .map(|(index, record)| line(index, &headers, &record))
                .filter(|line| matcher.is_match(line.as_bytes()).unwrap_or(false))
                .collect())
        })
        .await
    }

    #[napi]
    pub async fn read(
        &self,
        file_path: String,
        offset: i64,
        max_bytes: i64,
    ) -> Result<Vec<String>> {
        if offset < 0 || max_bytes <= 0 {
            return Err(Error::from_reason("need offset >= 0 and max_bytes > 0"));
        }
        let (offset, max_bytes) = (offset as u64, max_bytes as usize);

        blocking(move || {
            let mut reader = open(&file_path)?;
            let headers = headers(&mut reader, &file_path)?;
            let mut lines = Vec::new();
            let mut end = 0u64;
            let mut taken = 0usize;

            for (index, record) in reader.records().flatten().enumerate() {
                let line = line(index, &headers, &record);
                end += line.len() as u64 + 1; // newline the caller joins on
                if end <= offset {
                    continue;
                }
                if taken > 0 && taken + line.len() > max_bytes {
                    break;
                }
                taken += line.len();
                lines.push(line);
            }

            Ok(lines)
        })
        .await
    }

    #[napi]
    pub async fn stat(&self, file_path: String) -> Result<FileStat> {
        blocking(move || {
            let meta = std::fs::metadata(&file_path)
                .map_err(|e| Error::from_reason(format!("Failed to stat \"{file_path}\": {e}")))?;
            let mut reader = open(&file_path)?;
            let headers = headers(&mut reader, &file_path)?;

            let Value::Object(metadata) = json!({
                "delimiter": (delimiter(&file_path) as char).to_string(),
                "columns": headers.iter().collect::<Vec<_>>(),
                "rowCount": reader.records().count(),
            }) else {
                unreachable!()
            };

            Ok(FileStat {
                format: "csv".to_string(),
                size_bytes: meta.len() as i64,
                modified_at: iso8601(meta.modified()),
                created_at: iso8601(meta.created()),
                metadata: metadata.into_iter().collect(),
            })
        })
        .await
    }
}

fn delimiter(file_path: &str) -> u8 {
    if Path::new(file_path).extension() != Some("tsv".as_ref()) {
        return b',';
    }

    // Zeek logs declare their own separator as an escape in the first header line, `#separator \x09`.
    let mut header = String::new();
    if let Ok(file) = File::open(file_path) {
        BufReader::new(file).read_line(&mut header).ok();
    }
    header
        .trim_end()
        .strip_prefix("#separator \\x")
        .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        .unwrap_or(b'\t')
}

fn open(file_path: &str) -> Result<Reader<File>> {
    ReaderBuilder::new()
        .delimiter(delimiter(file_path))
        .flexible(true)
        .from_path(file_path)
        .map_err(|e| Error::from_reason(format!("Failed to open \"{file_path}\" as csv: {e}")))
}

fn headers(reader: &mut Reader<File>, file_path: &str) -> Result<StringRecord> {
    reader
        .headers()
        .cloned()
        .map_err(|e| Error::from_reason(format!("Failed to read \"{file_path}\" header: {e}")))
}

/// One row as `index<TAB>fields-as-json`, keyed by header name, or by column index where a row is
/// wider than the header.
fn line(index: usize, headers: &StringRecord, record: &StringRecord) -> String {
    let fields: Map<String, Value> = record
        .iter()
        .enumerate()
        .map(|(column, value)| {
            let name = headers.get(column).map(str::to_string);
            (name.unwrap_or_else(|| column.to_string()), value.into())
        })
        .collect();
    format!("{index}\t{}", Value::Object(fields))
}
