use napi::bindgen_prelude::{Error, Result, Status};
use napi::tokio::{fs, task};
use napi_derive::napi;

/// A single occurrence of a search term within a file.
#[napi(object)]
pub struct SearchMatch {
  /// Byte offset of the match from the start of the file.
  pub offset: i64,
  /// Encoding the term was found in: `utf8` or `utf16le`.
  pub encoding: String,
  /// Printable bytes surrounding the match, for context.
  pub context: String,
}

/// Search strategy for Windows Event Log files. The plugin declares its own
/// identity and detection rule, so the MCP server registers it without
/// restating anything about it in TypeScript.
#[napi]
pub struct EvtxPlugin {}

#[napi]
impl EvtxPlugin {
  #[napi(constructor)]
  pub fn new() -> Self {
    EvtxPlugin {}
  }

  #[napi(getter)]
  pub fn name(&self) -> String {
    "evtx".to_owned()
  }

  #[napi(getter)]
  pub fn description(&self) -> String {
    "Windows Event Log files (.evtx)".to_owned()
  }

  /// Whether this plugin handles `file_path`. Detection is by path alone.
  #[napi]
  pub fn identify(&self, file_path: String) -> bool {
    file_path.to_lowercase().ends_with(".evtx")
  }

  /// Byte-level scan of an .evtx file for `search_term`.
  ///
  /// EVTX stores its string data as UTF-16LE, but embedded payloads and file
  /// headers are frequently plain ASCII, so both encodings are scanned.
  #[napi]
  pub async fn search(&self, file_path: String, search_term: String) -> Result<Vec<SearchMatch>> {
    if search_term.is_empty() {
      return Err(Error::new(
        Status::InvalidArg,
        "search term must not be empty",
      ));
    }

    let bytes = fs::read(&file_path).await.map_err(|e| {
      Error::new(
        Status::GenericFailure,
        format!("failed to read {file_path}: {e}"),
      )
    })?;

    // Scanning is CPU-bound and files can be large, so keep it off the
    // runtime's async worker threads.
    task::spawn_blocking(move || scan(&bytes, &search_term))
      .await
      .map_err(|e| Error::new(Status::GenericFailure, format!("search task failed: {e}")))
  }
}

fn scan(bytes: &[u8], search_term: &str) -> Vec<SearchMatch> {
  let utf16: Vec<u8> = search_term
    .encode_utf16()
    .flat_map(u16::to_le_bytes)
    .collect();

  let mut matches = Vec::new();
  for (encoding, needle) in [("utf8", search_term.as_bytes()), ("utf16le", &utf16[..])] {
    for offset in offsets_of(bytes, needle) {
      matches.push(SearchMatch {
        offset: offset as i64,
        encoding: encoding.to_owned(),
        context: context(bytes, offset, needle.len()),
      });
    }
  }

  matches.sort_by_key(|m| m.offset);
  matches
}

fn offsets_of(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
  if needle.is_empty() || needle.len() > haystack.len() {
    return Vec::new();
  }
  haystack
    .windows(needle.len())
    .enumerate()
    .filter(|(_, window)| *window == needle)
    .map(|(offset, _)| offset)
    .collect()
}

/// Printable characters surrounding a match, for context in the result.
fn context(bytes: &[u8], offset: usize, len: usize) -> String {
  const PADDING: usize = 24;
  let start = offset.saturating_sub(PADDING);
  let end = (offset + len + PADDING).min(bytes.len());
  bytes[start..end]
    .iter()
    .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
    .collect()
}
