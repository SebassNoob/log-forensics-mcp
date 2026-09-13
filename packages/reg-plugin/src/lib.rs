mod constants;
mod parser;

use grep_matcher::Matcher;
use grep_regex::RegexMatcherBuilder;
use napi::{Error, Result};
use napi_derive::napi;
use parser::{parse, version};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use utils::{blocking, iso8601};

#[napi]
#[derive(Default)]
pub struct RegPlugin {}

#[napi(object)]
pub struct FileStat {
    pub format: String,
    pub size_bytes: i64,
    pub modified_at: String,
    pub created_at: String,
    pub metadata: HashMap<String, Value>,
}

#[napi]
pub struct RegTools {}

#[napi]
impl RegPlugin {
    #[napi(constructor)]
    pub fn new() -> Self {
        RegPlugin {}
    }

    #[napi(getter)]
    pub fn name(&self) -> String {
        "reg-plugin".to_string()
    }

    #[napi(getter)]
    pub fn description(&self) -> String {
        "File system access to exported Windows registry files (reg).".to_string()
    }

    #[napi]
    pub fn identify(&self, file_path: String) -> bool {
        Path::new(&file_path).extension() == Some("reg".as_ref())
    }

    #[napi(getter)]
    pub fn tools(&self) -> RegTools {
        RegTools {}
    }
}

#[napi]
impl RegTools {
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
                .skip(offset_rows)
                .take(max_rows)
                .collect())
        })
        .await
    }

    #[napi]
    pub async fn stat(&self, file_path: String) -> Result<FileStat> {
        blocking(move || {
            let meta = std::fs::metadata(&file_path)
                .map_err(|e| Error::from_reason(format!("Failed to stat \"{file_path}\": {e}")))?;

            let mut key_count = 0usize;
            let mut value_count = 0usize;
            for key in parse(&file_path)? {
                key_count += 1;
                value_count += key.values.len();
            }

            let Value::Object(metadata) = json!({
                "version": version(&file_path)?,
                "keyCount": key_count,
                "valueCount": value_count,
            }) else {
                unreachable!()
            };

            Ok(FileStat {
                format: "reg".to_string(),
                size_bytes: meta.len() as i64,
                modified_at: iso8601(meta.modified()),
                created_at: iso8601(meta.created()),
                metadata: metadata.into_iter().collect(),
            })
        })
        .await
    }
}

/// A `[path]` line per key, then its values as `path<TAB>name<TAB>data`, the path repeated so a
/// search hit stands alone. `data` keeps the export's own `type:value` notation.
fn lines(file_path: &str) -> Result<impl Iterator<Item = String>> {
    Ok(parse(file_path)?.flat_map(|key| {
        let path = key.path;
        std::iter::once(format!("[{path}]")).chain(key.values.into_iter().map(move |value| {
            format!(
                "{path}\t{}\t{}",
                value.name.as_deref().unwrap_or("(Default)"),
                match value.kind.is_empty() {
                    true => value.data,
                    false => format!("{}:{}", value.kind, value.data),
                }
            )
        }))
    }))
}
