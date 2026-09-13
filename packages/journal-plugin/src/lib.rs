pub mod constants;
pub mod parser;
pub mod parser_utils;

use grep_matcher::Matcher;
use grep_regex::RegexMatcherBuilder;
use napi::{Error, Result};
use napi_derive::napi;
use parser::parse;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::Path;
use utils::{blocking, hex, iso8601, unix_epoch_to_iso8601};

#[napi]
#[derive(Default)]
pub struct JournalPlugin {}

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
pub struct JournalTools {}

#[napi]
impl JournalPlugin {
    #[napi(constructor)]
    pub fn new() -> Self {
        JournalPlugin {}
    }

    #[napi(getter)]
    pub fn name(&self) -> String {
        "journal-plugin".to_string()
    }

    #[napi(getter)]
    pub fn description(&self) -> String {
        "File system access to systemd journal files (journal).".to_string()
    }

    #[napi]
    pub fn identify(&self, file_path: String) -> bool {
        // Rotated and corrupted journals keep the extension but gain a "~".
        let extension = Path::new(&file_path).extension();
        if extension == Some("journal".as_ref()) || extension == Some("journal~".as_ref()) {
            return true;
        }
        parse(&file_path).is_ok()
    }

    #[napi(getter)]
    pub fn tools(&self) -> JournalTools {
        JournalTools {}
    }
}

#[napi]
impl JournalTools {
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

            Ok(open(&file_path)?
                .entries
                .map(|entry| line(entry.seqnum, entry.realtime, &entry.fields))
                .filter(|line| matcher.is_match(line.as_bytes()).unwrap_or(false))
                .collect())
        })
        .await
    }

    #[napi]
    pub async fn read(
        &self,
        file_path: String,
        offset_rows: i64,
        max_rows: i64,
    ) -> Result<Vec<String>> {
        if offset_rows < 0 || max_rows <= 0 {
            return Err(Error::from_reason("need offset_rows >= 0 and max_rows > 0"));
        }
        let (offset_rows, max_rows) = (offset_rows as usize, max_rows as usize);

        blocking(move || {
            Ok(open(&file_path)?
                .entries
                .skip(offset_rows)
                .take(max_rows)
                .map(|entry| line(entry.seqnum, entry.realtime, &entry.fields))
                .collect())
        })
        .await
    }

    #[napi]
    pub async fn stat(&self, file_path: String) -> Result<FileStat> {
        blocking(move || {
            let header = open(&file_path)?.header;
            let meta = std::fs::metadata(&file_path)
                .map_err(|e| Error::from_reason(format!("Failed to stat \"{file_path}\": {e}")))?;

            // Header is packed, so every field has to be copied out before it is read.
            let (entries, objects) = (header.n_entries, header.n_objects);
            let (head_seqnum, tail_seqnum) = (header.head_entry_seqnum, header.tail_entry_seqnum);
            let (first, last) = (header.head_entry_realtime, header.tail_entry_realtime);
            let (machine_id, boot_id) = (header.machine_id, header.tail_entry_boot_id);

            let Value::Object(metadata) = json!({
                "state": match header.state {
                    0 => "offline",
                    1 => "online",
                    2 => "archived",
                    _ => "unknown",
                },
                "entryCount": entries,
                "objectCount": objects,
                "headSeqnum": head_seqnum,
                "tailSeqnum": tail_seqnum,
                "firstEntryAt": unix_epoch_to_iso8601(first),
                "lastEntryAt": unix_epoch_to_iso8601(last),
                "machineId": hex(&machine_id),
                "bootId": hex(&boot_id),
            }) else {
                unreachable!()
            };

            Ok(FileStat {
                format: "journal".to_string(),
                size_bytes: meta.len() as i64,
                modified_at: iso8601(meta.modified()),
                created_at: iso8601(meta.created()),
                metadata: metadata.into_iter().collect(),
            })
        })
        .await
    }
}

fn open(file_path: &str) -> Result<parser::Journal> {
    parse(file_path).map_err(|e| {
        Error::from_reason(format!("Failed to open \"{file_path}\" as a journal: {e}"))
    })
}

/// One entry as `seqnum<TAB>timestamp<TAB>fields-as-json`.
fn line(seqnum: u64, realtime: u64, fields: &[String]) -> String {
    let fields: Map<String, Value> = fields
        .iter()
        .filter_map(|field| field.split_once('='))
        .map(|(name, value)| (name.to_string(), Value::from(value)))
        .collect();
    format!(
        "{seqnum}\t{}\t{}",
        unix_epoch_to_iso8601(realtime),
        Value::Object(fields)
    )
}
