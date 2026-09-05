use napi::{Error, Result};
use std::time::SystemTime;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub fn iso8601(time: std::io::Result<SystemTime>) -> String {
    time.ok()
        .map(OffsetDateTime::from)
        .and_then(|time| time.format(&Rfc3339).ok())
        .unwrap_or_default()
}

pub async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| Error::from_reason(format!("worker failed: {e}")))?
}
