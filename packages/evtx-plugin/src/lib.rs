mod utils;

use evtx::{EvtxFileHeader, HeaderFlags};
use grep_matcher::Matcher;
use grep_regex::RegexMatcherBuilder;
use napi::{Error, Result};
use napi_derive::napi;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use utils::{blocking, iso8601, open};

#[napi]
pub struct EvtxPlugin {}

#[napi(object)]
pub struct FileStat {
    pub format: String,
    pub size_bytes: i64,
    pub modified_at: String,
    pub created_at: String,
    pub metadata: HashMap<String, Value>,
}

#[napi]
pub struct EvtxTools {}

#[napi]
impl EvtxPlugin {
    #[napi(constructor)]
    pub fn new() -> Self {
        EvtxPlugin {}
    }

    #[napi(getter)]
    pub fn name(&self) -> String {
        "evtx-plugin".to_string()
    }

    #[napi(getter)]
    pub fn description(&self) -> String {
        "File system access to Windows Event Log files (evtx)".to_string()
    }

    #[napi]
    pub fn identify(&self, file_path: String) -> bool {
        if Path::new(&file_path).extension() == Some("evtx".as_ref()) {
            return true;
        }
        let Ok(mut file) = File::open(&file_path) else {
            return false;
        };
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic).is_ok() && &magic == b"ElfFile\x00"
    }

    #[napi(getter)]
    pub fn tools(&self) -> EvtxTools {
        EvtxTools {}
    }
}

#[napi]
impl EvtxTools {
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
            let mut parser = open(&file_path)?;

            Ok(parser
                .records_json()
                .flatten()
                .map(|record| {
                    format!(
                        "{}\t{}\t{}",
                        record.event_record_id, record.timestamp, record.data
                    )
                })
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
            let mut lines = Vec::new();
            let mut end = 0u64;
            let mut taken = 0usize;

            for record in open(&file_path)?.records_json().flatten() {
                let line = format!(
                    "{}\t{}\t{}",
                    record.event_record_id, record.timestamp, record.data
                );
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
            let mut file = File::open(&file_path)
                .map_err(|e| Error::from_reason(format!("Failed to open \"{file_path}\": {e}")))?;
            let header = EvtxFileHeader::from_stream(&mut file).map_err(|e| {
                Error::from_reason(format!("\"{file_path}\" is not a valid evtx file: {e}"))
            })?;
            let meta = file
                .metadata()
                .map_err(|e| Error::from_reason(format!("Failed to stat \"{file_path}\": {e}")))?;

            let size = meta.len();
            let Value::Object(metadata) = json!({
                "version": format!("{}.{}", header.major_version, header.minor_version),
                // header.chunk_count is a u16 and saturates on large logs; derive it instead.
                "chunkCount": size.saturating_sub(header.header_block_size.into()) / 65536,
                "firstChunkNumber": header.first_chunk_number,
                "lastChunkNumber": header.last_chunk_number,
                "nextRecordId": header.next_record_id,
                "isDirty": header.flags.contains(HeaderFlags::DIRTY),
                "isFull": header.flags.contains(HeaderFlags::FULL),
            }) else {
                unreachable!()
            };

            Ok(FileStat {
                format: "evtx".to_string(),
                size_bytes: size as i64,
                modified_at: iso8601(meta.modified()),
                created_at: iso8601(meta.created()),
                metadata: metadata.into_iter().collect(),
            })
        })
        .await
    }
}
