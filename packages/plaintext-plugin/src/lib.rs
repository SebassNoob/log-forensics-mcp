use grep_matcher::Matcher;
use grep_regex::RegexMatcherBuilder;
use napi::{Error, Result};
use napi_derive::napi;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use utils::{blocking, iso8601};

#[napi]
#[derive(Default)]
pub struct PlaintextPlugin {}

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
pub struct PlaintextTools {}

#[napi]
impl PlaintextPlugin {
    #[napi(constructor)]
    pub fn new() -> Self {
        PlaintextPlugin {}
    }

    #[napi(getter)]
    pub fn name(&self) -> String {
        "plaintext-plugin".to_string()
    }

    #[napi(getter)]
    pub fn description(&self) -> String {
        "File system access to plain text files. Fallback for any file no other plugin claims."
            .to_string()
    }

    #[napi]
    pub fn identify(&self, _file_path: String) -> bool {
        true
    }

    #[napi(getter)]
    pub fn tools(&self) -> PlaintextTools {
        PlaintextTools {}
    }
}

#[napi]
impl PlaintextTools {
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

            Ok(lines(&file_path)?
                .enumerate()
                .map(|(index, line)| format!("{}\t{line}", index + 1))
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
            Ok(lines(&file_path)?
                .enumerate()
                .skip(offset_rows)
                .take(max_rows)
                .map(|(index, line)| format!("{}\t{line}", index + 1))
                .collect())
        })
        .await
    }

    #[napi]
    pub async fn stat(&self, file_path: String) -> Result<FileStat> {
        blocking(move || {
            let meta = std::fs::metadata(&file_path)
                .map_err(|e| Error::from_reason(format!("Failed to stat \"{file_path}\": {e}")))?;

            let Value::Object(metadata) = json!({ "lineCount": lines(&file_path)?.count() }) else {
                unreachable!()
            };

            Ok(FileStat {
                format: "plaintext".to_string(),
                size_bytes: meta.len() as i64,
                modified_at: iso8601(meta.modified()),
                created_at: iso8601(meta.created()),
                metadata: metadata.into_iter().collect(),
            })
        })
        .await
    }
}

/// Stops at the first line that is not valid UTF-8, since this plugin also sees binary files.
fn lines(file_path: &str) -> Result<impl Iterator<Item = String>> {
    let file = File::open(file_path)
        .map_err(|e| Error::from_reason(format!("Failed to open \"{file_path}\": {e}")))?;
    Ok(BufReader::new(file).lines().map_while(|line| line.ok()))
}
