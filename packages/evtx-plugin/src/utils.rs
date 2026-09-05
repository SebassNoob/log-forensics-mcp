use evtx::{EvtxParser, ParserSettings, Timestamp};
use napi::{Error, Result};
use std::fs::File;
use std::time::SystemTime;

pub fn open(file_path: &str) -> Result<EvtxParser<File>> {
    EvtxParser::from_path(file_path)
        .map(|p| p.with_configuration(ParserSettings::default().indent(false)))
        .map_err(|e| Error::from_reason(format!("Failed to open \"{file_path}\" as evtx: {e}")))
}

pub fn iso8601(time: std::io::Result<SystemTime>) -> String {
    time.ok()
        .and_then(|t| Timestamp::try_from(t).ok())
        .map_or(String::new(), |t| t.to_string())
}

pub async fn blocking<T, F>(work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| Error::from_reason(format!("evtx worker failed: {e}")))?
}
